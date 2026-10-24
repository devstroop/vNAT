//! Runtime firewall counters exported by `vrouterd` for `vrouter firewall counters`.
//! The daemon rewrites the file atomically every few seconds; a missing file
//! simply means the daemon has not saved yet.

const std = @import("std");

pub const Error = error{
    InvalidCounters,
    InvalidArgument,
};

const max_bytes = 1024 * 1024;

pub const Aggregates = struct {
    firewall_dropped: u64 = 0,
    firewall_spoofed: u64 = 0,
    icmp_rate_limited: u64 = 0,
    arp_rate_limited: u64 = 0,
    dhcp_rate_limited: u64 = 0,
};

pub const Wire = struct {
    version: u32,
    instance: []const u8,
    updated_ms: i64 = 0,
    rules: []const u64,
    firewall_dropped: u64 = 0,
    firewall_spoofed: u64 = 0,
    icmp_rate_limited: u64 = 0,
    arp_rate_limited: u64 = 0,
    dhcp_rate_limited: u64 = 0,
};

pub fn save(
    io: std.Io,
    gpa: std.mem.Allocator,
    state_dir: []const u8,
    instance: []const u8,
    rules: []const u64,
    aggregates: Aggregates,
) !void {
    try ensureStateDir(io, state_dir);
    const dir = if (std.fs.path.isAbsolute(state_dir))
        try std.Io.Dir.openDirAbsolute(io, state_dir, .{})
    else
        try std.Io.Dir.cwd().openDir(io, state_dir, .{});
    defer dir.close(io);
    try saveDir(io, gpa, dir, instance, rules, aggregates);
}

pub fn saveDir(
    io: std.Io,
    gpa: std.mem.Allocator,
    dir: std.Io.Dir,
    instance: []const u8,
    rules: []const u64,
    aggregates: Aggregates,
) !void {
    try validateInstance(instance);
    const name = try std.fmt.allocPrint(gpa, "{s}.firewall.json", .{instance});
    defer gpa.free(name);

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const now_ms = std.Io.Clock.now(.real, io).toMilliseconds();
    try std.json.Stringify.value(Wire{
        .version = 1,
        .instance = instance,
        .updated_ms = now_ms,
        .rules = rules,
        .firewall_dropped = aggregates.firewall_dropped,
        .firewall_spoofed = aggregates.firewall_spoofed,
        .icmp_rate_limited = aggregates.icmp_rate_limited,
        .arp_rate_limited = aggregates.arp_rate_limited,
        .dhcp_rate_limited = aggregates.dhcp_rate_limited,
    }, .{}, &out.writer);
    try out.writer.writeByte('\n');

    var atomic = try dir.createFileAtomic(io, name, .{
        .replace = true,
        .permissions = std.Io.File.Permissions.fromMode(0o600),
    });
    defer atomic.deinit(io);
    try atomic.file.writeStreamingAll(io, out.written());
    try atomic.file.sync(io);
    try atomic.replace(io);
}

pub fn load(
    io: std.Io,
    gpa: std.mem.Allocator,
    state_dir: []const u8,
    instance: []const u8,
) !?std.json.Parsed(Wire) {
    try validateInstance(instance);
    const dir = if (std.fs.path.isAbsolute(state_dir))
        std.Io.Dir.openDirAbsolute(io, state_dir, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        }
    else
        std.Io.Dir.cwd().openDir(io, state_dir, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
    defer dir.close(io);
    return loadDir(io, gpa, dir, instance);
}

pub fn loadDir(
    io: std.Io,
    gpa: std.mem.Allocator,
    dir: std.Io.Dir,
    instance: []const u8,
) !?std.json.Parsed(Wire) {
    try validateInstance(instance);
    const name = try std.fmt.allocPrint(gpa, "{s}.firewall.json", .{instance});
    defer gpa.free(name);

    const data = dir.readFileAlloc(io, name, gpa, .limited(max_bytes)) catch |err| switch (err) {
        error.FileNotFound => return null,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidCounters,
    };
    defer gpa.free(data);

    // The returned value outlives `data`, so force string copies.
    var parsed = std.json.parseFromSlice(Wire, gpa, data, .{ .allocate = .alloc_always }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidCounters,
    };
    if (parsed.value.version != 1) {
        parsed.deinit();
        return error.InvalidCounters;
    }
    return parsed;
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
        try std.Io.Dir.cwd().createDirPath(io, state_dir);
    }
}

test "counters file round trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const rules = [_]u64{ 3, 0, 17 };
    try saveDir(std.testing.io, std.testing.allocator, tmp.dir, "counters", &rules, .{
        .firewall_dropped = 9,
        .firewall_spoofed = 2,
        .icmp_rate_limited = 1,
        .arp_rate_limited = 4,
        .dhcp_rate_limited = 0,
    });

    var loaded = (try loadDir(std.testing.io, std.testing.allocator, tmp.dir, "counters")).?;
    defer loaded.deinit();
    try std.testing.expectEqualStrings("counters", loaded.value.instance);
    try std.testing.expectEqualSlices(u64, &rules, loaded.value.rules);
    try std.testing.expectEqual(@as(u64, 9), loaded.value.firewall_dropped);
    try std.testing.expectEqual(@as(u64, 2), loaded.value.firewall_spoofed);
    try std.testing.expectEqual(@as(u64, 4), loaded.value.arp_rate_limited);

    try std.testing.expect((try loadDir(std.testing.io, std.testing.allocator, tmp.dir, "missing")) == null);
}

test "counters reject unsafe instance names" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try std.testing.expectError(
        error.InvalidArgument,
        saveDir(std.testing.io, std.testing.allocator, tmp.dir, "../x", &.{}, .{}),
    );
    try std.testing.expectError(
        error.InvalidArgument,
        loadDir(std.testing.io, std.testing.allocator, tmp.dir, "a/b"),
    );
}
