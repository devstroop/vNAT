//! Stable C ABI for Android and other hosts.

const std = @import("std");
const linux = std.os.linux;
const build_options = @import("build_options");
const config_parse = @import("config/parse.zig");
const config_validate = @import("config/validate.zig");
const manager = @import("port/manager.zig");
const sys = @import("port/linux/sys.zig");
const service = @import("app/service.zig");
const thread_mod = @import("thread.zig");

pub const ABI_VERSION: u32 = 1;

pub const OK: c_int = 0;
pub const ERR_INVALID_ARGUMENT: c_int = -1;
pub const ERR_INVALID_CONFIG: c_int = -2;
pub const ERR_OUT_OF_MEMORY: c_int = -3;
pub const ERR_BUSY: c_int = -4;
pub const ERR_UNSUPPORTED: c_int = -5;
pub const ERR_PERMISSION: c_int = -6;
pub const ERR_IO: c_int = -7;
pub const ERR_NOT_FOUND: c_int = -8;
pub const ERR_INTERNAL: c_int = -9;

pub const EVENT_STARTED: c_int = 1;
pub const EVENT_STOPPED: c_int = 2;
pub const EVENT_ERROR: c_int = 3;

const STATE_CREATED: u8 = 0;
const STATE_STARTING: u8 = 1;
const STATE_RUNNING: u8 = 2;
const STATE_STOPPING: u8 = 3;
const STATE_STOPPED: u8 = 4;

const State = enum(u8) {
    created = STATE_CREATED,
    starting = STATE_STARTING,
    running = STATE_RUNNING,
    stopping = STATE_STOPPING,
    stopped = STATE_STOPPED,
};

pub const Status = extern struct {
    struct_size: u32,
    abi_version: u32,
    running: u32,
    port_count: u32,
    uptime_ms: u64,
};

pub const EventCb = *const fn (
    ctx: ?*anyopaque,
    event: c_int,
    message: ?[*:0]const u8,
) callconv(.c) void;

const version_z = build_options.version ++ "\x00";
const allocator = std.heap.smp_allocator;

const Handle = struct {
    gpa: std.mem.Allocator,
    threaded: std.Io.Threaded,
    parsed: config_parse.Parsed,
    injected: std.ArrayListUnmanaged(manager.InjectedPort) = .empty,
    thread: ?thread_mod.Thread = null,
    stop: std.atomic.Value(bool) = .init(false),
    state: std.atomic.Value(u8) = .init(STATE_CREATED),
    runtime: service.Runtime = .{},
    event_cb: ?EventCb = null,
    event_ctx: ?*anyopaque = null,
    lock: std.Io.Mutex = .init,
};

const Startup = struct {
    done: std.atomic.Value(bool) = .init(false),
    err: ?anyerror = null,

    fn succeed(self: *Startup) void {
        self.err = null;
        self.done.store(true, .release);
    }

    fn fail(self: *Startup, err: anyerror) void {
        self.err = err;
        self.done.store(true, .release);
    }

    fn wait(self: *Startup) ?anyerror {
        while (!self.done.load(.acquire)) {
            std.Thread.yield() catch {};
        }
        return self.err;
    }
};

pub export fn vnat_version() callconv(.c) [*:0]const u8 {
    return @ptrCast(&version_z);
}

pub export fn vnat_create(config_json: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const json = config_json orelse return null;
    const self = createHandle(std.mem.span(json)) catch return null;
    return @ptrCast(self);
}

pub export fn vnat_start(raw: ?*anyopaque) callconv(.c) c_int {
    const self = castHandle(raw) orelse return ERR_INVALID_ARGUMENT;
    const io = self.threaded.io();
    self.lock.lockUncancelable(io);
    defer self.lock.unlock(io);

    const state: State = @enumFromInt(self.state.load(.acquire));
    switch (state) {
        .starting, .running, .stopping => return ERR_BUSY,
        .created, .stopped => {},
    }

    self.stop.store(false, .release);
    self.runtime.running.store(false, .release);
    self.runtime.port_count.store(0, .release);
    self.runtime.started_ms.store(0, .release);

    var startup = Startup{};
    const thread = thread_mod.spawn(threadMain, .{ self, &startup }) catch |err| switch (err) {
        error.OutOfMemory => return ERR_OUT_OF_MEMORY,
        else => return ERR_INTERNAL,
    };
    self.thread = thread;
    self.state.store(STATE_STARTING, .release);

    if (startup.wait()) |err| {
        thread.join();
        self.thread = null;
        self.state.store(STATE_STOPPED, .release);
        return errorCode(err);
    }

    self.state.store(STATE_RUNNING, .release);
    return OK;
}

pub export fn vnat_stop(raw: ?*anyopaque) callconv(.c) c_int {
    const self = castHandle(raw) orelse return ERR_INVALID_ARGUMENT;
    const io = self.threaded.io();
    self.lock.lockUncancelable(io);

    const state: State = @enumFromInt(self.state.load(.acquire));
    if (state != .starting and state != .running) {
        self.lock.unlock(io);
        return OK;
    }

    self.stop.store(true, .release);
    self.runtime.running.store(false, .release);
    const thread = self.thread orelse {
        self.lock.unlock(io);
        return OK;
    };
    self.thread = null;
    self.state.store(STATE_STOPPING, .release);

    thread.join();
    self.runtime.port_count.store(0, .release);
    self.runtime.started_ms.store(0, .release);
    self.state.store(STATE_STOPPED, .release);
    self.lock.unlock(io);
    return OK;
}

pub export fn vnat_destroy(raw: ?*anyopaque) callconv(.c) void {
    const self = castHandle(raw) orelse return;
    _ = vnat_stop(raw);

    const io = self.threaded.io();
    self.lock.lockUncancelable(io);
    self.injected.deinit(self.gpa);
    self.parsed.deinit();
    self.lock.unlock(io);

    self.threaded.deinit();
    const gpa = self.gpa;
    gpa.destroy(self);
}

pub export fn vnat_set_port_fd(
    raw: ?*anyopaque,
    name_z: ?[*:0]const u8,
    fd: c_int,
) callconv(.c) c_int {
    const self = castHandle(raw) orelse return ERR_INVALID_ARGUMENT;
    const name = std.mem.span(name_z orelse return ERR_INVALID_ARGUMENT);
    if (fd < 0) return ERR_INVALID_ARGUMENT;

    const io = self.threaded.io();
    self.lock.lockUncancelable(io);
    defer self.lock.unlock(io);

    const state: State = @enumFromInt(self.state.load(.acquire));
    if (state != .created) return ERR_BUSY;

    var canonical: ?[]const u8 = null;
    var it = self.parsed.config.ports.iterator();
    while (it.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, name)) {
            canonical = entry.key_ptr.*;
            const port = entry.value_ptr.*;
            if (port.kind != .l3 or port.create != null) return ERR_INVALID_ARGUMENT;
            break;
        }
    }
    const config_name = canonical orelse return ERR_NOT_FOUND;

    for (self.injected.items) |injected| {
        if (std.mem.eql(u8, injected.config_name, config_name)) return ERR_INVALID_ARGUMENT;
    }

    self.injected.append(self.gpa, .{
        .config_name = config_name,
        .fd = fd,
    }) catch return ERR_OUT_OF_MEMORY;
    return OK;
}

pub export fn vnat_set_event_cb(
    raw: ?*anyopaque,
    cb: ?EventCb,
    ctx: ?*anyopaque,
) callconv(.c) c_int {
    const self = castHandle(raw) orelse return ERR_INVALID_ARGUMENT;
    const io = self.threaded.io();
    self.lock.lockUncancelable(io);
    defer self.lock.unlock(io);

    const state: State = @enumFromInt(self.state.load(.acquire));
    if (state != .created and state != .stopped) return ERR_BUSY;
    self.event_cb = cb;
    self.event_ctx = ctx;
    return OK;
}

pub export fn vnat_get_status(
    raw: ?*anyopaque,
    out: ?*Status,
) callconv(.c) c_int {
    const self = castHandle(raw) orelse return ERR_INVALID_ARGUMENT;
    const status = out orelse return ERR_INVALID_ARGUMENT;

    status.* = std.mem.zeroes(Status);
    status.struct_size = @sizeOf(Status);
    status.abi_version = ABI_VERSION;

    const running = self.runtime.running.load(.acquire);
    status.running = @intFromBool(running);
    status.port_count = self.runtime.port_count.load(.acquire);
    if (running) {
        const started_ms = self.runtime.started_ms.load(.acquire);
        if (started_ms != 0) {
            const now_ms = std.Io.Clock.now(.awake, self.threaded.io()).toMilliseconds();
            status.uptime_ms = @as(u64, service.timestamp(now_ms) -% started_ms);
        }
    }
    return OK;
}

fn createHandle(json: []const u8) !*Handle {
    const self = try allocator.create(Handle);
    errdefer allocator.destroy(self);

    self.* = .{
        .gpa = allocator,
        .threaded = undefined,
        .parsed = undefined,
    };
    self.threaded = std.Io.Threaded.init(allocator, .{});
    errdefer self.threaded.deinit();

    var parsed = try config_parse.parse(allocator, json);
    errdefer parsed.deinit();
    try config_validate.validateWithOptions(&parsed.config, .{ .allow_existing_l3 = true });

    self.parsed = parsed;
    return self;
}

fn castHandle(raw: ?*anyopaque) ?*Handle {
    const ptr = raw orelse return null;
    return @ptrCast(@alignCast(ptr));
}

const ReadyCtx = struct {
    handle: *Handle,
    startup: *Startup,
};

fn threadMain(self: *Handle, startup: *Startup) void {
    var ready_ctx: ReadyCtx = .{ .handle = self, .startup = startup };
    service.run(self.threaded.io(), self.gpa, &self.parsed.config, &self.stop, .{
        .state_dir = null,
        .allow_host_changes = false,
        .enable_monitor = false,
        .injected = self.injected.items,
        .runtime = &self.runtime,
        .on_ready = ready,
        .on_ready_ctx = &ready_ctx,
    }) catch |err| {
        startup.fail(err);
        emitError(self, err);
        return;
    };
    emit(self, EVENT_STOPPED, null);
}

fn ready(ctx: ?*anyopaque) void {
    const ready_ctx: *ReadyCtx = @ptrCast(@alignCast(ctx orelse return));
    emit(ready_ctx.handle, EVENT_STARTED, null);
    ready_ctx.startup.succeed();
}

fn emitError(self: *Handle, err: anyerror) void {
    var buf: [160]u8 = undefined;
    const text = std.fmt.bufPrint(buf[0 .. buf.len - 1], "{s}", .{@errorName(err)}) catch {
        const fallback = "vnat error";
        @memcpy(buf[0..fallback.len], fallback);
        buf[fallback.len] = 0;
        emit(self, EVENT_ERROR, buf[0..fallback.len :0].ptr);
        return;
    };
    buf[text.len] = 0;
    emit(self, EVENT_ERROR, buf[0..text.len :0].ptr);
}

fn emit(self: *Handle, event: c_int, message: ?[*:0]const u8) void {
    const cb = self.event_cb orelse return;
    cb(self.event_ctx, event, message);
}

fn errorCode(err: anyerror) c_int {
    return switch (err) {
        error.InvalidJson,
        error.NotAnObject,
        error.UnknownField,
        error.MissingField,
        error.InvalidType,
        error.InvalidValue,
        error.InvalidVersion,
        error.DuplicateName,
        error.UndefinedReference,
        => ERR_INVALID_CONFIG,
        error.OutOfMemory => ERR_OUT_OF_MEMORY,
        error.InvalidArgument => ERR_INVALID_ARGUMENT,
        error.Unsupported => ERR_UNSUPPORTED,
        error.PermissionDenied => ERR_PERMISSION,
        error.NotFound => ERR_NOT_FOUND,
        error.Busy => ERR_BUSY,
        error.Io => ERR_IO,
        else => ERR_INTERNAL,
    };
}

const EventCounter = struct {
    handle: *Handle,
    started: std.atomic.Value(u32) = .init(0),
    stopped: std.atomic.Value(u32) = .init(0),
    running_at_start: std.atomic.Value(bool) = .init(false),
    running_at_stop: std.atomic.Value(bool) = .init(false),
};

fn countEvent(ctx: ?*anyopaque, event: c_int, _: ?[*:0]const u8) callconv(.c) void {
    const counter: *EventCounter = @ptrCast(@alignCast(ctx orelse return));
    var status: Status = undefined;
    switch (event) {
        EVENT_STARTED => {
            _ = counter.started.fetchAdd(1, .monotonic);
            if (vnat_get_status(counter.handle, &status) == OK) {
                counter.running_at_start.store(status.running == 1, .release);
            }
        },
        EVENT_STOPPED => {
            _ = counter.stopped.fetchAdd(1, .monotonic);
            if (vnat_get_status(counter.handle, &status) == OK) {
                counter.running_at_stop.store(status.running == 1, .release);
            }
        },
        else => {},
    }
}

test "C ABI version and invalid config" {
    try std.testing.expect(vnat_version()[0] != 0);
    try std.testing.expect(vnat_create(null) == null);
    try std.testing.expect(vnat_create("not json") == null);
}

test "C ABI starts and stops an injected L3 fd" {
    const config =
        \\{"version":1,"instance":"ffi-test","log":{"level":"err"},
        \\ "ports":{"vpn":{"kind":"l3","device":"vpn0"}}}
    ;
    const handle = vnat_create(config.ptr) orelse return error.TestUnexpectedResult;
    defer vnat_destroy(handle);

    var status: Status = undefined;
    try std.testing.expectEqual(OK, vnat_get_status(handle, &status));
    try std.testing.expectEqual(@as(u32, 0), status.running);
    try std.testing.expectEqual(ABI_VERSION, status.abi_version);

    var fds: [2]i32 = undefined;
    try sys.check(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer sys.close(fds[1]);
    try std.testing.expectEqual(OK, vnat_set_port_fd(handle, "vpn", fds[0]));
    try std.testing.expectEqual(ERR_NOT_FOUND, vnat_set_port_fd(handle, "missing", fds[0]));

    var events = EventCounter{ .handle = castHandle(handle).? };
    try std.testing.expectEqual(OK, vnat_set_event_cb(handle, countEvent, &events));

    try std.testing.expectEqual(OK, vnat_start(handle));
    sys.close(fds[0]);
    try std.testing.expectEqual(OK, vnat_get_status(handle, &status));
    try std.testing.expectEqual(@as(u32, 1), status.running);
    try std.testing.expectEqual(@as(u32, 1), status.port_count);

    try std.testing.expectEqual(OK, vnat_stop(handle));
    try std.testing.expectEqual(OK, vnat_get_status(handle, &status));
    try std.testing.expectEqual(@as(u32, 0), status.running);
    try std.testing.expectEqual(@as(u32, 1), events.started.load(.monotonic));
    try std.testing.expectEqual(@as(u32, 1), events.stopped.load(.monotonic));
    try std.testing.expect(events.running_at_start.load(.acquire));
    try std.testing.expect(!events.running_at_stop.load(.acquire));
}
