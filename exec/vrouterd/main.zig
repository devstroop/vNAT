const std = @import("std");
const vrouter = @import("vrouter");

const max_config_bytes = 4 * 1024 * 1024;
const default_config = "/etc/vrouter/vrouter.json";

var stop = std.atomic.Value(bool).init(false);

fn handleSignal(_: std.posix.SIG) callconv(.c) void {
    stop.store(true, .release);
}

pub fn main(init: std.process.Init) void {
    run(init) catch |err| {
        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "vrouterd: {s}\n", .{@errorName(err)}) catch "vrouterd: error\n";
        std.Io.File.stderr().writeStreamingAll(init.io, msg) catch {};
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var path: []const u8 = default_config;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try usage(io);
            return;
        }
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (i + 1 >= args.len) return error.InvalidArgument;
            i += 1;
            path = args[i];
            continue;
        }
        return error.InvalidArgument;
    }

    const source = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        gpa,
        .limited(max_config_bytes),
    );
    defer gpa.free(source);

    var parsed = try vrouter.config_parse.parse(gpa, source);
    defer parsed.deinit();
    try vrouter.config_validate.validate(&parsed.config);

    const action = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.mem.zeroes(std.posix.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &action, null);
    std.posix.sigaction(std.posix.SIG.TERM, &action, null);

    const run_dir = init.environ_map.get("VROUTER_RUN_DIR") orelse "/run/vrouter";
    try vrouter.app_service.run(io, gpa, &parsed.config, &stop, .{
        .state_dir = run_dir,
    });
}

fn usage(io: std.Io) !void {
    try std.Io.File.stdout().writeStreamingAll(io,
        \\vrouterd — vRouter daemon
        \\
        \\Usage:
        \\  vrouterd [-c <config.json>]
        \\
        \\Defaults to /etc/vrouter/vrouter.json. Stops on SIGINT or SIGTERM.
        \\
    );
}
