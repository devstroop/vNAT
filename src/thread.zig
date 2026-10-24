//! Thread backend for code that may run inside a host process. Zig's raw
//! clone path cannot establish a libc TCB, so C ABI builds use the host's
//! pthread implementation instead. Do not use `std.Io.concurrent` in the FFI
//! profile; it spawns through the raw-clone path.

const std = @import("std");
const build_options = @import("build_options");

pub const use_pthread = build_options.pthread_threads;

const pthread_t = *anyopaque;

extern fn pthread_create(
    thread: *pthread_t,
    attr: ?*const anyopaque,
    start_routine: *const fn (?*anyopaque) callconv(.c) ?*anyopaque,
    arg: ?*anyopaque,
) c_int;
extern fn pthread_join(thread: pthread_t, retval: ?*?*anyopaque) c_int;

const PthreadHandle = struct {
    handle: pthread_t,

    fn join(self: PthreadHandle) void {
        std.debug.assert(pthread_join(self.handle, null) == 0);
    }
};

const Impl = if (use_pthread) PthreadHandle else std.Thread;

pub const Thread = struct {
    impl: Impl,

    pub fn join(self: Thread) void {
        self.impl.join();
    }
};

pub fn spawn(comptime function: anytype, args: anytype) !Thread {
    if (comptime use_pthread) return .{ .impl = try spawnPthread(function, args) };
    return .{ .impl = std.Thread.spawn(.{}, function, args) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ThreadSpawnFailed,
    } };
}

fn spawnPthread(comptime function: anytype, args: anytype) !PthreadHandle {
    const Args = @TypeOf(args);
    const Context = struct {
        args: Args,
    };
    const Entry = struct {
        fn run(raw: ?*anyopaque) callconv(.c) ?*anyopaque {
            const context: *Context = @ptrCast(@alignCast(raw orelse return null));
            const copied = context.args;
            std.heap.page_allocator.destroy(context);
            const result = @call(.auto, function, copied);
            _ = result;
            return null;
        }
    };

    const context = try std.heap.page_allocator.create(Context);
    context.* = .{ .args = args };

    var handle: pthread_t = undefined;
    const rc = pthread_create(&handle, null, Entry.run, context);
    if (rc != 0) {
        std.heap.page_allocator.destroy(context);
        return error.ThreadSpawnFailed;
    }
    return .{ .handle = handle };
}
