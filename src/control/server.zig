//! Unix-socket control server. One worker thread accepts short-lived clients;
//! the datapath publishes immutable snapshots under a mutex.

const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");
const protocol = @import("protocol.zig");
const state = @import("state.zig");
const types = @import("../types.zig");
const transport = @import("transport.zig");
const unix = @import("unix.zig");
const thread = @import("../thread.zig");

const max_request_bytes = 4096;
const max_response_bytes = 128 * 1024;
const client_timeout_ms = 2_000;
const default_conntrack_limit = 100;

pub const Options = struct {
    mode: u32 = 0o660,
    allow_uid: ?u32 = null,
    kernel_backlog: u31 = 16,
};

pub const Error = error{
    AlreadyRunning,
    PathOccupied,
    Unauthorized,
    PeerCredentials,
};

pub const Server = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    path: []u8,
    listener: std.Io.net.Server,
    lock_file: std.Io.File,
    socket_inode: std.Io.File.INode,
    allowed_uid: u32,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?thread.Thread = null,
    mutex: std.Io.Mutex = .init,
    snapshot: state.Snapshot = .{},

    pub fn init(
        io: std.Io,
        gpa: std.mem.Allocator,
        path: []const u8,
        options: Options,
    ) !Server {
        if (path.len == 0 or path.len > std.Io.net.UnixAddress.max_len) {
            return error.InvalidArgument;
        }
        if (std.fs.path.dirname(path)) |dir| {
            _ = std.Io.Dir.cwd().createDirPathStatus(
                io,
                dir,
                std.Io.File.Permissions.fromMode(0o750),
            ) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }

        const cwd = std.Io.Dir.cwd();
        const lock_path = try std.mem.concat(gpa, u8, &.{ path, ".lock" });
        defer gpa.free(lock_path);
        var lock_file = cwd.createFile(io, lock_path, .{
            .read = true,
            .truncate = false,
            .lock = .exclusive,
            .lock_nonblocking = true,
            .permissions = std.Io.File.Permissions.fromMode(0o600),
        }) catch |err| switch (err) {
            error.WouldBlock => return error.AlreadyRunning,
            else => return err,
        };
        errdefer lock_file.close(io);

        const address = try std.Io.net.UnixAddress.init(path);
        var listener = try listenWithStaleRecovery(io, address, path, options.kernel_backlog);
        errdefer {
            listener.deinit(io);
            cwd.deleteFile(io, path) catch {};
        }

        const permissions: std.Io.File.Permissions = @enumFromInt(
            @as(std.posix.mode_t, @intCast(options.mode)),
        );
        try cwd.setFilePermissions(io, path, permissions, .{});
        const stat = try cwd.statFile(io, path, .{ .follow_symlinks = false });
        if (stat.kind != .unix_domain_socket) return error.PathOccupied;

        return .{
            .io = io,
            .gpa = gpa,
            .path = try gpa.dupe(u8, path),
            .listener = listener,
            .lock_file = lock_file,
            .socket_inode = stat.inode,
            .allowed_uid = options.allow_uid orelse linux.geteuid(),
        };
    }

    pub fn start(self: *Server) !void {
        self.stop.store(false, .release);
        self.thread = try thread.spawn(run, .{self});
    }

    pub fn deinit(self: *Server) void {
        self.stop.store(true, .release);
        if (self.thread) |worker| {
            const stream: std.Io.net.Stream = .{ .socket = self.listener.socket };
            stream.shutdown(self.io, .both) catch {};
            worker.join();
            self.thread = null;
        }
        self.listener.deinit(self.io);
        self.removeOwnedSocket();
        self.lock_file.close(self.io);
        self.gpa.free(self.path);
        self.* = undefined;
    }

    pub fn publish(self: *Server, snapshot: *const state.Snapshot) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.snapshot = snapshot.*;
    }

    fn removeOwnedSocket(self: *Server) void {
        const stat = std.Io.Dir.cwd().statFile(self.io, self.path, .{ .follow_symlinks = false }) catch return;
        if (stat.kind != .unix_domain_socket or stat.inode != self.socket_inode) return;
        std.Io.Dir.cwd().deleteFile(self.io, self.path) catch {};
    }

    fn run(self: *Server) void {
        while (!self.stop.load(.acquire)) {
            const stream = self.listener.accept(self.io) catch |err| switch (err) {
                error.ConnectionAborted => continue,
                else => {
                    if (self.stop.load(.acquire)) return;
                    std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
                    continue;
                },
            };
            self.handleClient(stream);
        }
    }

    fn handleClient(self: *Server, stream: std.Io.net.Stream) void {
        defer stream.close(self.io);

        const credentials = peerCredentials(stream.socket.handle) catch {
            self.sendError(stream, null, null, "unauthorized", "peer credentials unavailable");
            return;
        };
        if (credentials.uid != 0 and credentials.uid != self.allowed_uid) {
            self.sendError(stream, null, null, "unauthorized", "peer uid is not allowed");
            return;
        }

        var request_buf: [max_request_bytes]u8 = undefined;
        const line = transport.readLine(
            self.io,
            stream.socket.handle,
            &request_buf,
            client_timeout_ms,
        ) catch |err| {
            self.sendError(stream, null, null, "invalid_request", @errorName(err));
            return;
        } orelse return;

        var parsed = protocol.parseRequest(std.heap.page_allocator, line) catch {
            self.sendError(stream, null, null, "invalid_request", "malformed JSON request");
            return;
        };
        defer parsed.deinit();

        if (!isSupported(parsed.value.op)) {
            self.sendError(stream, parsed.value.id, parsed.value.op, "unknown_op", "unknown operation");
            return;
        }

        var response_buf: [max_response_bytes]u8 = undefined;
        var response: std.Io.Writer = .fixed(&response_buf);
        self.mutex.lockUncancelable(self.io);
        const written = self.writeResponse(&response, parsed.value);
        self.mutex.unlock(self.io);
        if (!written) {
            self.sendError(stream, parsed.value.id, parsed.value.op, "internal", "response too large");
            return;
        }

        var socket_buf: [4096]u8 = undefined;
        var writer = stream.writer(self.io, &socket_buf);
        writer.interface.writeAll(response.buffered()) catch return;
        writer.interface.flush() catch {};
    }

    fn writeResponse(
        self: *Server,
        writer: *std.Io.Writer,
        request: protocol.Request,
    ) bool {
        const snapshot = &self.snapshot;
        var json: std.json.Stringify = .{ .writer = writer };
        json.beginObject() catch return false;
        writeField(&json, "ok", true) catch return false;
        writeOptionalId(&json, request.id) catch return false;
        writeField(&json, "op", request.op) catch return false;

        if (std.mem.eql(u8, request.op, "ping")) {
            writeField(&json, "version", protocol.version) catch return false;
        } else if (std.mem.eql(u8, request.op, "status")) {
            json.objectField("status") catch return false;
            writeStatus(&json, snapshot) catch return false;
        } else if (std.mem.eql(u8, request.op, "nat.list")) {
            json.objectField("nat") catch return false;
            writeNat(&json, snapshot) catch return false;
        } else if (std.mem.eql(u8, request.op, "conntrack.list")) {
            json.objectField("conntrack") catch return false;
            writeConntrack(&json, snapshot, request.state, request.limit) catch return false;
        } else {
            return false;
        }

        json.endObject() catch return false;
        writer.writeByte('\n') catch return false;
        return true;
    }

    fn sendError(
        self: *Server,
        stream: std.Io.net.Stream,
        id: ?u64,
        op: ?[]const u8,
        code: []const u8,
        message: []const u8,
    ) void {
        var buf: [1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        var json: std.json.Stringify = .{ .writer = &writer };
        json.beginObject() catch return;
        writeField(&json, "ok", false) catch return;
        writeOptionalId(&json, id) catch return;
        if (op) |value| {
            writeField(&json, "op", value) catch return;
        } else {
            json.objectField("op") catch return;
            json.write(null) catch return;
        }
        writeField(&json, "error_code", code) catch return;
        writeField(&json, "message", message) catch return;
        json.endObject() catch return;
        writer.writeByte('\n') catch return;

        var socket_buf: [1024]u8 = undefined;
        var stream_writer = stream.writer(self.io, &socket_buf);
        stream_writer.interface.writeAll(writer.buffered()) catch return;
        stream_writer.interface.flush() catch {};
    }
};

fn isSupported(op: []const u8) bool {
    return std.mem.eql(u8, op, "ping") or
        std.mem.eql(u8, op, "status") or
        std.mem.eql(u8, op, "nat.list") or
        std.mem.eql(u8, op, "conntrack.list");
}

fn writeField(json: *std.json.Stringify, name: []const u8, value: anytype) !void {
    try json.objectField(name);
    try json.write(value);
}

fn writeOptionalId(json: *std.json.Stringify, id: ?u64) !void {
    try json.objectField("id");
    try json.write(id);
}

fn writeStatus(json: *std.json.Stringify, snapshot: *const state.Snapshot) !void {
    try json.beginObject();
    try writeField(json, "instance", snapshot.instance);
    try writeField(json, "version", build_options.version);
    try json.objectField("pid");
    try json.write(linux.getpid());
    try writeField(json, "started_ms", snapshot.started_ms);
    try writeField(json, "updated_ms", snapshot.updated_ms);
    try json.objectField("uptime_ms");
    try json.write(@max(snapshot.updated_ms - snapshot.started_ms, 0));
    try writeField(json, "state_dir", snapshot.state_dir);
    try writeField(json, "control_path", snapshot.control_path);
    try writeField(json, "ports", snapshot.ports);
    try json.objectField("counters");
    try json.write(snapshot.counters);
    try json.endObject();
}

fn writeNat(json: *std.json.Stringify, snapshot: *const state.Snapshot) !void {
    try json.beginObject();
    try writeField(json, "instance", snapshot.instance);
    try json.objectField("snat");
    try json.beginArray();
    for (snapshot.snatSlice()) |rule| {
        try json.beginObject();
        try writeField(json, "out", rule.out);
        try json.objectField("addr");
        try json.print("\"{f}\"", .{rule.addr});
        try json.endObject();
    }
    try json.endArray();

    try json.objectField("port_forward");
    try json.beginArray();
    for (snapshot.portForwardSlice()) |rule| {
        try json.beginObject();
        try writeField(json, "proto", state.protoName(rule.proto));
        try writeField(json, "ext_port", rule.ext_port);
        try json.objectField("to_addr");
        try json.print("\"{f}\"", .{rule.to_addr});
        try writeField(json, "to_port", rule.to_port);
        try json.objectField("ingress");
        if (rule.ingress.len == 0) {
            try json.write(null);
        } else {
            try json.write(rule.ingress);
        }
        try json.endObject();
    }
    try json.endArray();
    try json.endObject();
}

fn writeConntrack(
    json: *std.json.Stringify,
    snapshot: *const state.Snapshot,
    state_filter: ?[]const u8,
    requested_limit: ?u32,
) !void {
    const limit: usize = @min(
        requested_limit orelse default_conntrack_limit,
        state.max_conntrack,
    );
    try json.beginObject();
    try writeField(json, "instance", snapshot.instance);
    try writeField(json, "total", snapshot.conntrack_total);

    var returned: u32 = 0;
    try json.objectField("entries");
    try json.beginArray();
    for (snapshot.conntrackSlice()) |entry| {
        if (state_filter) |wanted| {
            if (!std.mem.eql(u8, wanted, entry.state)) continue;
        }
        if (returned >= limit) break;
        returned += 1;

        try json.beginObject();
        try writeField(json, "proto", state.protoName(entry.proto));
        try writeField(json, "state", entry.state);
        try json.objectField("src");
        try json.print("\"{f}\"", .{entry.src});
        try writeField(json, "sport", entry.sport);
        try json.objectField("dst");
        try json.print("\"{f}\"", .{entry.dst});
        try writeField(json, "dport", entry.dport);

        try json.objectField("translated_src");
        if (entry.translated_src) |addr| {
            try json.print("\"{f}\"", .{addr});
        } else {
            try json.write(null);
        }
        try writeField(json, "translated_sport", entry.translated_sport);
        try json.objectField("translated_dst");
        if (entry.translated_dst) |addr| {
            try json.print("\"{f}\"", .{addr});
        } else {
            try json.write(null);
        }
        try writeField(json, "translated_dport", entry.translated_dport);
        try writeField(json, "packets", entry.packets);
        try writeField(json, "bytes", entry.bytes);
        try writeField(json, "reply_packets", entry.reply_packets);
        try writeField(json, "reply_bytes", entry.reply_bytes);
        try writeField(json, "created_ms", entry.created_ms);
        try writeField(json, "last_seen_ms", entry.last_seen_ms);
        try writeField(json, "timeout_ms", entry.timeout_ms);
        try json.endObject();
    }
    try json.endArray();
    try writeField(json, "returned", returned);
    try json.endObject();
}

fn listenWithStaleRecovery(
    io: std.Io,
    address: std.Io.net.UnixAddress,
    path: []const u8,
    kernel_backlog: u31,
) !std.Io.net.Server {
    var recovered = false;
    while (true) {
        return address.listen(io, .{ .kernel_backlog = kernel_backlog }) catch |err| switch (err) {
            error.AddressInUse => {
                if (recovered) return error.PathOccupied;
                try removeStaleSocket(io, path);
                recovered = true;
                continue;
            },
            else => return err,
        };
    }
}

fn removeStaleSocket(io: std.Io, path: []const u8) !void {
    const cwd = std.Io.Dir.cwd();
    const maybe_stream = unix.connect(path) catch |err| switch (err) {
        error.ConnectionRefused, error.FileNotFound => null,
        else => return error.PathOccupied,
    };
    if (maybe_stream) |stream| {
        var live = stream;
        live.close(io);
        return error.PathOccupied;
    }

    const stat = cwd.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (stat.kind != .unix_domain_socket) return error.PathOccupied;
    try cwd.deleteFile(io, path);
}

const Credentials = extern struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

fn peerCredentials(fd: std.posix.fd_t) Error!Credentials {
    var credentials: Credentials = undefined;
    var len: linux.socklen_t = @sizeOf(Credentials);
    const rc = linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&credentials),
        &len,
    );
    if (std.posix.errno(rc) != .SUCCESS) return error.PeerCredentials;
    if (len < @sizeOf(Credentials)) return error.PeerCredentials;
    return credentials;
}

fn sendRequest(
    io: std.Io,
    path: []const u8,
    payload: []const u8,
    out: []u8,
) ![]const u8 {
    const address = try std.Io.net.UnixAddress.init(path);
    var stream = try address.connect(io);
    defer stream.close(io);
    var out_buf: [256]u8 = undefined;
    var writer = stream.writer(io, &out_buf);
    try writer.interface.writeAll(payload);
    try writer.interface.flush();
    return (try transport.readLine(io, stream.socket.handle, out, 1000)).?;
}

test "server starts, answers status, and removes its socket" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);

    var snapshot: state.Snapshot = .{
        .instance = "test",
        .state_dir = path_buf[0..dir],
        .control_path = path,
        .started_ms = 1,
        .updated_ms = 2,
        .ports = 1,
    };
    snapshot.snat[0] = .{ .out = "wan", .addr = try types.Ipv4.parse("203.0.113.1") };
    snapshot.snat_len = 1;
    snapshot.port_forward[0] = .{
        .proto = 6,
        .ext_port = 8080,
        .to_addr = try types.Ipv4.parse("10.0.0.5"),
        .to_port = 80,
        .ingress = "wan",
    };
    snapshot.port_forward_len = 1;
    snapshot.conntrack[0] = .{
        .proto = 6,
        .state = "established",
        .src = try types.Ipv4.parse("10.0.0.2"),
        .sport = 40000,
        .dst = try types.Ipv4.parse("198.51.100.10"),
        .dport = 443,
        .translated_src = try types.Ipv4.parse("203.0.113.1"),
        .translated_sport = 40001,
        .translated_dst = try types.Ipv4.parse("198.51.100.10"),
        .translated_dport = 443,
        .packets = 3,
        .bytes = 300,
        .reply_packets = 2,
        .reply_bytes = 200,
        .created_ms = 10,
        .last_seen_ms = 20,
        .timeout_ms = 30,
    };
    snapshot.conntrack_len = 1;
    snapshot.conntrack_total = 1;

    var server = try Server.init(testing.io, testing.allocator, path, .{});
    var server_active = true;
    defer if (server_active) server.deinit();
    server.publish(&snapshot);
    try server.start();

    var input: [4096]u8 = undefined;
    const line = try sendRequest(testing.io, path, "{\"id\":1,\"op\":\"status\"}\n", &input);
    var response = try std.json.parseFromSlice(protocol.Response, testing.allocator, line, .{});
    defer response.deinit();
    try testing.expect(response.value.ok);
    try testing.expectEqualStrings("test", response.value.status.?.instance);
    try testing.expectEqual(@as(u32, 1), response.value.status.?.ports);

    const nat_line = try sendRequest(testing.io, path, "{\"id\":2,\"op\":\"nat.list\"}\n", &input);
    var nat = try std.json.parseFromSlice(protocol.Response, testing.allocator, nat_line, .{});
    defer nat.deinit();
    try testing.expect(nat.value.ok);
    try testing.expectEqualStrings("test", nat.value.nat.?.instance);
    try testing.expectEqualStrings("wan", nat.value.nat.?.snat[0].out);
    try testing.expectEqualStrings("203.0.113.1", nat.value.nat.?.snat[0].addr);
    try testing.expectEqual(@as(u16, 8080), nat.value.nat.?.port_forward[0].ext_port);
    try testing.expectEqualStrings("10.0.0.5", nat.value.nat.?.port_forward[0].to_addr);

    const ct_line = try sendRequest(
        testing.io,
        path,
        "{\"id\":3,\"op\":\"conntrack.list\",\"state\":\"established\",\"limit\":5}\n",
        &input,
    );
    var ct = try std.json.parseFromSlice(protocol.Response, testing.allocator, ct_line, .{});
    defer ct.deinit();
    try testing.expect(ct.value.ok);
    try testing.expectEqualStrings("test", ct.value.conntrack.?.instance);
    try testing.expectEqual(@as(u32, 1), ct.value.conntrack.?.returned);
    try testing.expectEqualStrings("203.0.113.1", ct.value.conntrack.?.entries[0].translated_src.?);
    try testing.expectEqual(@as(u16, 40001), ct.value.conntrack.?.entries[0].translated_sport);

    const bad_line = try sendRequest(testing.io, path, "{bad json}\n", &input);
    var bad = try std.json.parseFromSlice(protocol.Response, testing.allocator, bad_line, .{});
    defer bad.deinit();
    try testing.expect(!bad.value.ok);
    try testing.expectEqualStrings("invalid_request", bad.value.error_code.?);

    const unknown_line = try sendRequest(testing.io, path, "{\"id\":2,\"op\":\"bogus\"}\n", &input);
    var unknown = try std.json.parseFromSlice(protocol.Response, testing.allocator, unknown_line, .{});
    defer unknown.deinit();
    try testing.expect(!unknown.value.ok);
    try testing.expectEqualStrings("unknown_op", unknown.value.error_code.?);

    server.deinit();
    server_active = false;
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, "control.sock", .{}));
}

test "server refuses a regular file at the socket path" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "control.sock", .data = "x" });
    try testing.expectError(
        error.PathOccupied,
        Server.init(testing.io, testing.allocator, path, .{}),
    );
    const stat = try tmp.dir.statFile(testing.io, "control.sock", .{});
    try testing.expectEqual(std.Io.File.Kind.file, stat.kind);
}

test "server refuses a second instance while the first is live" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);

    var first = try Server.init(testing.io, testing.allocator, path, .{});
    defer first.deinit();
    try testing.expectError(
        error.AlreadyRunning,
        Server.init(testing.io, testing.allocator, path, .{}),
    );
    try testing.expectEqual(
        std.Io.File.Kind.unix_domain_socket,
        (try tmp.dir.statFile(testing.io, "control.sock", .{})).kind,
    );
}

test "server does not remove a socket it no longer owns" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);

    const cwd = std.Io.Dir.cwd();
    var server = try Server.init(testing.io, testing.allocator, path, .{});
    var server_active = true;
    defer if (server_active) server.deinit();

    try cwd.deleteFile(testing.io, path);
    const address = try std.Io.net.UnixAddress.init(path);
    var replacement = try address.listen(testing.io, .{});
    defer {
        replacement.deinit(testing.io);
        cwd.deleteFile(testing.io, path) catch {};
    }

    server.deinit();
    server_active = false;
    try testing.expectEqual(
        std.Io.File.Kind.unix_domain_socket,
        (try cwd.statFile(testing.io, path, .{ .follow_symlinks = false })).kind,
    );
}

test "server replaces a stale socket" {
    const testing = std.testing;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmp.dir.realPath(testing.io, &path_buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/control.sock", .{path_buf[0..dir]});
    defer testing.allocator.free(path);

    const address = try std.Io.net.UnixAddress.init(path);
    var stale = try address.listen(testing.io, .{});
    stale.deinit(testing.io);
    try testing.expectEqual(
        std.Io.File.Kind.unix_domain_socket,
        (try tmp.dir.statFile(testing.io, "control.sock", .{})).kind,
    );

    var server = try Server.init(testing.io, testing.allocator, path, .{});
    defer server.deinit();
    try testing.expectEqual(
        std.Io.File.Kind.unix_domain_socket,
        (try tmp.dir.statFile(testing.io, "control.sock", .{})).kind,
    );
}
