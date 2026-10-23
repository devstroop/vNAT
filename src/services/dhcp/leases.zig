//! Persistent DHCP lease database.
//!
//! The file is a small JSON document keyed by server address and port id. It
//! is written atomically so a crash never leaves a partial database; expired
//! records are ignored on load.

const std = @import("std");
const types = @import("../../types.zig");
const message = @import("message.zig");
const server_mod = @import("server.zig");

pub const Error = error{
    OutOfMemory,
    InvalidLeaseDb,
};

const max_bytes = 8 * 1024 * 1024;

const WireLease = struct {
    server: []const u8,
    port: u32,
    ip: []const u8,
    mac: []const u8,
    state: []const u8,
    expires_ms: i64,
};

const Wire = struct {
    version: u32,
    leases: []const WireLease,
};

pub const Store = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    owns_dir: bool,

    /// Opens the parent directory of `path`. A missing database is not an
    /// error; `load` returns zero in that case.
    pub fn init(gpa: std.mem.Allocator, io: std.Io, path: []const u8) !Store {
        const parent = std.fs.path.dirname(path) orelse ".";
        const name = std.fs.path.basename(path);
        if (name.len == 0) return error.InvalidLeaseDb;
        try std.Io.Dir.cwd().createDirPath(io, parent);
        const dir = try std.Io.Dir.cwd().openDir(io, parent, .{});
        return .{
            .gpa = gpa,
            .io = io,
            .dir = dir,
            .name = name,
            .owns_dir = true,
        };
    }

    pub fn initDir(
        gpa: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        name: []const u8,
    ) Store {
        return .{
            .gpa = gpa,
            .io = io,
            .dir = dir,
            .name = name,
            .owns_dir = false,
        };
    }

    pub fn deinit(self: *Store) void {
        if (self.owns_dir) self.dir.close(self.io);
        self.* = undefined;
    }

    /// Restores leases for configured servers. Unknown servers and invalid
    /// records are skipped; a malformed database is a hard error so an
    /// operator can inspect it instead of silently losing bindings.
    pub fn load(self: *Store, servers: []server_mod.Server, now_ms: i64) Error!usize {
        const data = self.dir.readFileAlloc(
            self.io,
            self.name,
            self.gpa,
            .limited(max_bytes),
        ) catch |err| switch (err) {
            error.FileNotFound => return 0,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidLeaseDb,
        };
        defer self.gpa.free(data);

        var parsed = std.json.parseFromSlice(Wire, self.gpa, data, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidLeaseDb,
        };
        defer parsed.deinit();
        if (parsed.value.version != 1) return error.InvalidLeaseDb;

        var restored: usize = 0;
        for (parsed.value.leases) |record| {
            const server_ip = types.Ipv4.parse(record.server) catch continue;
            const ip = types.Ipv4.parse(record.ip) catch continue;
            const mac = types.Mac.parse(record.mac) catch continue;
            const state: server_mod.State = std.meta.stringToEnum(server_mod.State, record.state) orelse
                continue;
            if (state == .free) continue;

            for (servers) |*server| {
                if (!server.cfg.server_ip.eql(server_ip) or server.cfg.port.value != record.port) {
                    continue;
                }
                if (server.restore(.{
                    .state = state,
                    .ip = ip,
                    .mac = mac,
                    .expires_ms = record.expires_ms,
                }, now_ms)) restored += 1;
                break;
            }
        }
        return restored;
    }

    /// Writes all active leases atomically. An empty database is still a valid
    /// document so a restart does not resurrect old bindings.
    pub fn save(self: *Store, servers: []const server_mod.Server) !void {
        var out: std.Io.Writer.Allocating = .init(self.gpa);
        defer out.deinit();
        try out.writer.writeAll("{\"version\":1,\"leases\":[");
        var first = true;
        for (servers) |*server| {
            var snapshots = try self.gpa.alloc(server_mod.LeaseSnapshot, server.leaseCapacity());
            defer self.gpa.free(snapshots);
            const count = server.snapshot(snapshots);
            for (snapshots[0..count]) |record| {
                if (!first) try out.writer.writeByte(',');
                first = false;
                try out.writer.print(
                    "{{\"server\":\"{f}\",\"port\":{d},\"ip\":\"{f}\",\"mac\":\"{f}\",\"state\":\"{s}\",\"expires_ms\":{d}}}",
                    .{
                        server.cfg.server_ip,
                        server.cfg.port.value,
                        record.ip,
                        record.mac,
                        @tagName(record.state),
                        record.expires_ms,
                    },
                );
            }
        }
        try out.writer.writeAll("]}\n");

        var atomic = try self.dir.createFileAtomic(self.io, self.name, .{
            .replace = true,
            .permissions = std.Io.File.Permissions.fromMode(0o600),
        });
        defer atomic.deinit(self.io);
        try atomic.file.writeStreamingAll(self.io, out.written());
        try atomic.file.sync(self.io);
        try atomic.replace(self.io);
    }
};

const testing = std.testing;
const test_port: types.PortId = .{ .value = 7 };
const test_mac: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 9 } };

fn testServer(gpa: std.mem.Allocator) !server_mod.Server {
    return server_mod.Server.init(gpa, .{
        .port = test_port,
        .server_ip = .{ .value = 0x0a000101 },
        .prefix = types.Prefix4.parse("10.0.1.1/24") catch unreachable,
        .pool = types.parseIpRange("10.0.1.100-10.0.1.102") catch unreachable,
        .lease_seconds = 3600,
        .dns = .{ .value = 0x0a000101 },
    });
}

fn request(buf: []u8, typ: message.MessageType, xid: u32) ![]u8 {
    var builder = try message.Builder.init(buf, message.op_request, typ, xid, test_mac, 0);
    try builder.addIpv4(50, .{ .value = 0x0a000164 });
    return builder.finish();
}

test "lease store saves and restores a bound lease" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = Store.initDir(testing.allocator, testing.io, tmp.dir, "leases.json");
    defer store.deinit();

    var first = try testServer(testing.allocator);
    defer first.deinit();
    var req_buf: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    const discover = try request(&req_buf, .discover, 1);
    _ = (try first.handle(try message.Message.parse(discover), &out, 1_000)).?;
    const ack_req = try request(&req_buf, .request, 2);
    _ = (try first.handle(try message.Message.parse(ack_req), &out, 2_000)).?;
    try testing.expectEqual(@as(usize, 1), first.leaseCount(.bound));

    try store.save(&.{first});

    var second = try testServer(testing.allocator);
    defer second.deinit();
    var servers = [_]server_mod.Server{second};
    try testing.expectEqual(@as(usize, 1), try store.load(&servers, 3_000));
    try testing.expectEqual(@as(usize, 1), second.leaseCount(.bound));
    var snapshots: [3]server_mod.LeaseSnapshot = undefined;
    const count = second.snapshot(&snapshots);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expect(snapshots[0].mac.eql(test_mac));
}

test "lease store ignores expired and malformed records" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "leases.json",
        .data =
        \\{"version":1,"leases":[
        \\{"server":"10.0.1.1","port":7,"ip":"10.0.1.100","mac":"02:00:00:00:00:09","state":"bound","expires_ms":10},
        \\{"server":"10.0.1.1","port":7,"ip":"not-an-ip","mac":"02:00:00:00:00:09","state":"bound","expires_ms":9999999999999}
        \\]}
        ,
    });
    var store = Store.initDir(testing.allocator, testing.io, tmp.dir, "leases.json");
    defer store.deinit();
    var server = try testServer(testing.allocator);
    defer server.deinit();
    var servers = [_]server_mod.Server{server};
    try testing.expectEqual(@as(usize, 0), try store.load(&servers, 100));
}

test "lease store rejects a corrupt database" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "leases.json", .data = "not json" });
    var store = Store.initDir(testing.allocator, testing.io, tmp.dir, "leases.json");
    defer store.deinit();
    var server = try testServer(testing.allocator);
    defer server.deinit();
    var servers = [_]server_mod.Server{server};
    try testing.expectError(error.InvalidLeaseDb, store.load(&servers, 100));
}
