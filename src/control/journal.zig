//! Journal of host mutations. Each line is the forward operation applied by
//! vNAT; rollback derives the inverse. Lines are written (fsync) before the
//! kernel mutation, so a crash leaves enough information to repair state.

const std = @import("std");
const types = @import("../types.zig");

pub const Error = error{
    InvalidJournal,
    InvalidArgument,
};

const max_bytes = 1024 * 1024;

pub const Address = struct {
    dev: []const u8,
    prefix: types.Prefix4,
};

pub const Link = struct {
    dev: []const u8,
    up: bool,
};

pub const Route = struct {
    prefix: types.Prefix4,
    via: ?types.Ipv4,
    dev: []const u8,
    metric: u32 = 0,
    table: u32 = 0,
};

pub const Op = union(enum) {
    addr_add: Address,
    addr_del: Address,
    link: Link,
    route_add: Route,
    route_del: Route,
};

/// JSON line schema. Strings borrow from the parsed line.
pub const Wire = struct {
    op: []const u8,
    dev: ?[]const u8 = null,
    cidr: ?[]const u8 = null,
    up: ?bool = null,
    dst: ?[]const u8 = null,
    via: ?[]const u8 = null,
    metric: ?u32 = null,
    table: ?u32 = null,
};

pub fn parseLine(gpa: std.mem.Allocator, line: []const u8) !std.json.Parsed(Wire) {
    return std.json.parseFromSlice(Wire, gpa, line, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJournal,
    };
}

pub fn toOp(wire: Wire) Error!Op {
    if (std.mem.eql(u8, wire.op, "addr_add") or std.mem.eql(u8, wire.op, "addr_del")) {
        const dev = wire.dev orelse return error.InvalidJournal;
        const cidr = wire.cidr orelse return error.InvalidJournal;
        const prefix = types.Prefix4.parse(cidr) catch return error.InvalidJournal;
        const address = Address{ .dev = dev, .prefix = prefix };
        return if (std.mem.eql(u8, wire.op, "addr_add"))
            .{ .addr_add = address }
        else
            .{ .addr_del = address };
    }

    if (std.mem.eql(u8, wire.op, "link")) {
        return .{ .link = .{
            .dev = wire.dev orelse return error.InvalidJournal,
            .up = wire.up orelse return error.InvalidJournal,
        } };
    }

    if (std.mem.eql(u8, wire.op, "route_add") or std.mem.eql(u8, wire.op, "route_del")) {
        const dst = wire.dst orelse return error.InvalidJournal;
        const prefix = types.Prefix4.parse(dst) catch return error.InvalidJournal;
        const via: ?types.Ipv4 = if (wire.via) |via_text|
            types.Ipv4.parse(via_text) catch return error.InvalidJournal
        else
            null;
        const route = Route{
            .prefix = prefix,
            .via = via,
            .dev = wire.dev orelse return error.InvalidJournal,
            .metric = wire.metric orelse 0,
            .table = wire.table orelse 0,
        };
        return if (std.mem.eql(u8, wire.op, "route_add"))
            .{ .route_add = route }
        else
            .{ .route_del = route };
    }

    return error.InvalidJournal;
}

pub fn writeLine(buf: []u8, op: Op) ![]const u8 {
    return switch (op) {
        .addr_add => |a| std.fmt.bufPrint(
            buf,
            "{{\"op\":\"addr_add\",\"dev\":\"{s}\",\"cidr\":\"{f}\"}}\n",
            .{ a.dev, a.prefix },
        ),
        .addr_del => |a| std.fmt.bufPrint(
            buf,
            "{{\"op\":\"addr_del\",\"dev\":\"{s}\",\"cidr\":\"{f}\"}}\n",
            .{ a.dev, a.prefix },
        ),
        .link => |l| std.fmt.bufPrint(
            buf,
            "{{\"op\":\"link\",\"dev\":\"{s}\",\"up\":{s}}}\n",
            .{ l.dev, if (l.up) "true" else "false" },
        ),
        .route_add => |r| writeRoute(buf, "route_add", r),
        .route_del => |r| writeRoute(buf, "route_del", r),
    };
}

fn writeRoute(buf: []u8, comptime name: []const u8, route: Route) ![]const u8 {
    if (route.via) |via| {
        return std.fmt.bufPrint(
            buf,
            "{{\"op\":\"{s}\",\"dst\":\"{f}\",\"via\":\"{f}\",\"dev\":\"{s}\",\"metric\":{d},\"table\":{d}}}\n",
            .{ name, route.prefix, via, route.dev, route.metric, route.table },
        );
    }
    return std.fmt.bufPrint(
        buf,
        "{{\"op\":\"{s}\",\"dst\":\"{f}\",\"via\":null,\"dev\":\"{s}\",\"metric\":{d},\"table\":{d}}}\n",
        .{ name, route.prefix, route.dev, route.metric, route.table },
    );
}

pub const Store = struct {
    gpa: std.mem.Allocator,
    dir: std.Io.Dir,
    name: []u8,
    owns_dir: bool,

    pub fn open(
        io: std.Io,
        gpa: std.mem.Allocator,
        state_dir: []const u8,
        instance: []const u8,
    ) !Store {
        try ensureStateDir(io, state_dir);
        const dir = if (std.fs.path.isAbsolute(state_dir))
            try std.Io.Dir.openDirAbsolute(io, state_dir, .{})
        else
            try std.Io.Dir.cwd().openDir(io, state_dir, .{});
        errdefer dir.close(io);
        return init(gpa, dir, instance, true);
    }

    pub fn init(
        gpa: std.mem.Allocator,
        dir: std.Io.Dir,
        instance: []const u8,
        owns_dir: bool,
    ) !Store {
        try validateInstance(instance);
        const name = try std.fmt.allocPrint(gpa, "{s}.journal", .{instance});
        return .{ .gpa = gpa, .dir = dir, .name = name, .owns_dir = owns_dir };
    }

    pub fn deinit(self: *Store, io: std.Io) void {
        self.gpa.free(self.name);
        if (self.owns_dir) self.dir.close(io);
        self.* = undefined;
    }

    pub fn contents(self: *const Store, io: std.Io) !?[]u8 {
        return self.dir.readFileAlloc(io, self.name, self.gpa, .limited(max_bytes)) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
    }

    pub fn append(self: *Store, io: std.Io, op: Op) !void {
        const existing_opt = try self.contents(io);
        const existing = existing_opt orelse try self.gpa.alloc(u8, 0);
        defer self.gpa.free(existing);

        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(self.gpa);
        try out.appendSlice(self.gpa, existing);
        if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') {
            try out.append(self.gpa, '\n');
        }

        var line_buf: [512]u8 = undefined;
        const line = try writeLine(&line_buf, op);
        try out.appendSlice(self.gpa, line);
        try self.writeAtomic(io, out.items);
    }

    /// Drops the last record. Used when a mutation failed after the journal
    /// write, so rollback does not touch state that vNAT never applied.
    pub fn removeLast(self: *Store, io: std.Io) !void {
        const contents_opt = try self.contents(io);
        const data = contents_opt orelse return;
        defer self.gpa.free(data);

        var lines: std.ArrayListUnmanaged([]const u8) = .empty;
        defer lines.deinit(self.gpa);
        var it = std.mem.splitScalar(u8, data, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            try lines.append(self.gpa, line);
        }
        if (lines.items.len == 0) return;
        _ = lines.pop();

        if (lines.items.len == 0) {
            try self.clear(io);
            return;
        }

        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(self.gpa);
        for (lines.items) |line| {
            try out.appendSlice(self.gpa, line);
            try out.append(self.gpa, '\n');
        }
        try self.writeAtomic(io, out.items);
    }

    fn writeAtomic(self: *Store, io: std.Io, data: []const u8) !void {
        var atomic = try self.dir.createFileAtomic(io, self.name, .{
            .replace = true,
            .permissions = std.Io.File.Permissions.fromMode(0o600),
        });
        defer atomic.deinit(io);
        try atomic.file.writeStreamingAll(io, data);
        try atomic.file.sync(io);
        try atomic.replace(io);
    }

    pub fn clear(self: *Store, io: std.Io) !void {
        self.dir.deleteFile(io, self.name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
};

pub fn ownsAddress(
    gpa: std.mem.Allocator,
    contents: []const u8,
    dev: []const u8,
    prefix: types.Prefix4,
) !bool {
    var owned = false;
    var it = std.mem.splitScalar(u8, contents, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        var parsed = try parseLine(gpa, line);
        defer parsed.deinit();
        switch (try toOp(parsed.value)) {
            .addr_add => |a| {
                if (matchesAddress(a, dev, prefix)) owned = true;
            },
            .addr_del => |a| {
                if (matchesAddress(a, dev, prefix)) owned = false;
            },
            else => {},
        }
    }
    return owned;
}

pub fn ownsRoute(
    gpa: std.mem.Allocator,
    contents: []const u8,
    route: Route,
) !bool {
    var owned = false;
    var it = std.mem.splitScalar(u8, contents, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        var parsed = try parseLine(gpa, line);
        defer parsed.deinit();
        switch (try toOp(parsed.value)) {
            .route_add => |r| {
                if (matchesRoute(r, route)) owned = true;
            },
            .route_del => |r| {
                if (matchesRoute(r, route)) owned = false;
            },
            else => {},
        }
    }
    return owned;
}

fn matchesAddress(address: Address, dev: []const u8, prefix: types.Prefix4) bool {
    return std.mem.eql(u8, address.dev, dev) and
        address.prefix.len == prefix.len and
        address.prefix.addr.eql(prefix.addr);
}

fn matchesRoute(a: Route, b: Route) bool {
    return a.prefix.eql(b.prefix) and
        optionalIpEql(a.via, b.via) and
        std.mem.eql(u8, a.dev, b.dev) and
        a.metric == b.metric and
        a.table == b.table;
}

fn optionalIpEql(a: ?types.Ipv4, b: ?types.Ipv4) bool {
    if (a == null or b == null) return a == null and b == null;
    return a.?.eql(b.?);
}

fn validateInstance(instance: []const u8) Error!void {
    if (instance.len == 0 or instance.len > 64) return error.InvalidArgument;
    if (std.mem.eql(u8, instance, ".") or std.mem.eql(u8, instance, "..")) {
        return error.InvalidArgument;
    }
    for (instance) |c| {
        if (c < 0x20 or c == 0x7f) return error.InvalidArgument;
        if (c == '/' or c == '\\') return error.InvalidArgument;
    }
}

fn ensureStateDir(io: std.Io, state_dir: []const u8) !void {
    if (std.fs.path.isAbsolute(state_dir)) {
        std.Io.Dir.createDirAbsolute(io, state_dir, std.Io.File.Permissions.fromMode(0o700)) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    } else {
        _ = try std.Io.Dir.cwd().createDirPathStatus(
            io,
            state_dir,
            std.Io.File.Permissions.fromMode(0o700),
        );
    }
}

const testing = std.testing;

fn testPrefix(comptime s: []const u8) types.Prefix4 {
    return types.Prefix4.parse(s) catch unreachable;
}

fn testIp(comptime s: []const u8) types.Ipv4 {
    return types.Ipv4.parse(s) catch unreachable;
}

test "journal line round trip" {
    var buf: [512]u8 = undefined;

    const ops = [_]Op{
        .{ .addr_add = .{ .dev = "ra", .prefix = testPrefix("10.0.1.1/24") } },
        .{ .addr_del = .{ .dev = "ra", .prefix = testPrefix("10.0.1.1/24") } },
        .{ .link = .{ .dev = "ra", .up = true } },
        .{ .route_add = .{
            .prefix = testPrefix("10.2.0.0/16"),
            .via = testIp("10.0.1.254"),
            .dev = "ra",
            .metric = 50,
            .table = 100,
        } },
        .{ .route_del = .{
            .prefix = testPrefix("10.2.0.0/16"),
            .via = null,
            .dev = "ra",
        } },
    };

    for (ops) |op| {
        const line = try writeLine(&buf, op);
        var parsed = try parseLine(testing.allocator, line);
        defer parsed.deinit();
        const back = try toOp(parsed.value);
        switch (op) {
            .addr_add => |a| {
                try testing.expectEqualStrings(a.dev, back.addr_add.dev);
                try testing.expect(a.prefix.eql(back.addr_add.prefix));
            },
            .addr_del => |a| {
                try testing.expectEqualStrings(a.dev, back.addr_del.dev);
                try testing.expect(a.prefix.eql(back.addr_del.prefix));
            },
            .link => |l| {
                try testing.expectEqualStrings(l.dev, back.link.dev);
                try testing.expectEqual(l.up, back.link.up);
            },
            .route_add => |r| {
                try testing.expect(r.prefix.eql(back.route_add.prefix));
                try testing.expect(r.via.?.eql(back.route_add.via.?));
                try testing.expectEqual(r.metric, back.route_add.metric);
                try testing.expectEqual(r.table, back.route_add.table);
            },
            .route_del => |r| {
                try testing.expect(r.prefix.eql(back.route_del.prefix));
                try testing.expect(back.route_del.via == null);
            },
        }
    }
}

test "journal rejects malformed lines" {
    try testing.expectError(error.InvalidJournal, parseLine(testing.allocator, "{}"));
    try testing.expectError(error.InvalidJournal, parseLine(testing.allocator, "not json"));

    var parsed = try parseLine(testing.allocator, "{\"op\":\"addr_add\",\"dev\":\"ra\"}");
    defer parsed.deinit();
    try testing.expectError(error.InvalidJournal, toOp(parsed.value));
}

test "journal ownership ledger" {
    const contents =
        "{\"op\":\"addr_add\",\"dev\":\"ra\",\"cidr\":\"10.0.1.1/24\"}\n" ++
        "{\"op\":\"addr_add\",\"dev\":\"rb\",\"cidr\":\"10.0.2.1/24\"}\n" ++
        "{\"op\":\"addr_del\",\"dev\":\"ra\",\"cidr\":\"10.0.1.1/24\"}\n";

    try testing.expect(!(try ownsAddress(testing.allocator, contents, "ra", testPrefix("10.0.1.1/24"))));
    try testing.expect(!(try ownsAddress(testing.allocator, contents, "ra", testPrefix("10.0.1.2/24"))));
    try testing.expect(try ownsAddress(testing.allocator, contents, "rb", testPrefix("10.0.2.1/24")));
    try testing.expect(!(try ownsAddress(testing.allocator, contents, "rc", testPrefix("10.0.3.1/24"))));

    const route = Route{
        .prefix = testPrefix("10.9.0.0/16"),
        .via = testIp("10.0.1.254"),
        .dev = "ra",
        .metric = 5,
        .table = 0,
    };
    var add_buf: [512]u8 = undefined;
    var del_buf: [512]u8 = undefined;
    const add_line = try writeLine(&add_buf, .{ .route_add = route });
    const del_line = try writeLine(&del_buf, .{ .route_del = route });
    try testing.expect(try ownsRoute(testing.allocator, add_line, route));
    try testing.expect(!(try ownsRoute(testing.allocator, del_line, route)));
}

test "journal store append read clear" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try Store.init(testing.allocator, tmp.dir, "test", false);
    defer store.deinit(testing.io);

    try store.append(testing.io, .{ .addr_add = .{
        .dev = "ra",
        .prefix = testPrefix("10.0.1.1/24"),
    } });
    try store.append(testing.io, .{ .link = .{ .dev = "ra", .up = false } });

    const contents = (try store.contents(testing.io)).?;
    defer testing.allocator.free(contents);
    try testing.expect(std.mem.indexOf(u8, contents, "\"addr_add\"") != null);
    try testing.expect(std.mem.indexOf(u8, contents, "\"up\":false") != null);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, contents, "\n"));

    try store.append(testing.io, .{ .addr_del = .{
        .dev = "ra",
        .prefix = testPrefix("10.0.1.1/24"),
    } });
    try store.removeLast(testing.io);
    const after_remove = (try store.contents(testing.io)).?;
    defer testing.allocator.free(after_remove);
    try testing.expect(std.mem.indexOf(u8, after_remove, "addr_del") == null);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, after_remove, "\n"));

    try store.clear(testing.io);
    try testing.expect((try store.contents(testing.io)) == null);
}

test "journal store rejects unsafe instance names" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try testing.expectError(error.InvalidArgument, Store.init(testing.allocator, tmp.dir, "../x", false));
    try testing.expectError(error.InvalidArgument, Store.init(testing.allocator, tmp.dir, "a/b", false));
    try testing.expectError(error.InvalidArgument, Store.init(testing.allocator, tmp.dir, ".", false));
}
