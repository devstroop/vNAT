//! Fixed-size buffer pool for the datapath.
//!
//! The pool owns one contiguous allocation and hands out equal-sized slices.
//! `release` validates that a slice belongs to the pool and that it is not
//! already free, so a double-free or a foreign buffer is ignored instead of
//! corrupting the list. Not thread-safe yet; R1 adds per-worker pools.

const std = @import("std");

pub const PoolError = error{
    InvalidArgument,
    OutOfMemory,
};

pub const BufferPool = struct {
    gpa: std.mem.Allocator,
    buf_size: usize,
    storage: []u8,
    in_use: []bool,
    free: std.ArrayListUnmanaged([]u8) = .empty,

    pub fn init(gpa: std.mem.Allocator, buffer_count: usize, buf_size: usize) PoolError!BufferPool {
        if (buffer_count == 0 or buf_size == 0) return error.InvalidArgument;

        const storage = try gpa.alloc(u8, buffer_count * buf_size);
        errdefer gpa.free(storage);

        const in_use = try gpa.alloc(bool, buffer_count);
        errdefer gpa.free(in_use);
        @memset(in_use, false);

        var self = BufferPool{
            .gpa = gpa,
            .buf_size = buf_size,
            .storage = storage,
            .in_use = in_use,
        };
        try self.free.ensureTotalCapacity(gpa, buffer_count);
        for (0..buffer_count) |i| {
            self.free.appendAssumeCapacity(storage[i * buf_size ..][0..buf_size]);
        }
        return self;
    }

    pub fn deinit(self: *BufferPool) void {
        self.free.deinit(self.gpa);
        self.gpa.free(self.in_use);
        self.gpa.free(self.storage);
        self.* = undefined;
    }

    pub fn count(self: *const BufferPool) usize {
        return self.storage.len / self.buf_size;
    }

    pub fn available(self: *const BufferPool) usize {
        return self.free.items.len;
    }

    pub fn acquire(self: *BufferPool) ?[]u8 {
        const buf = self.free.pop() orelse return null;
        self.in_use[self.index(buf)] = true;
        return buf;
    }

    pub fn release(self: *BufferPool, buf: []u8) void {
        if (buf.len != self.buf_size) return;

        const base = @intFromPtr(self.storage.ptr);
        const ptr = @intFromPtr(buf.ptr);
        if (ptr < base or ptr >= base + self.storage.len) return;
        if ((ptr - base) % self.buf_size != 0) return;

        const idx = (ptr - base) / self.buf_size;
        if (!self.in_use[idx]) return;

        self.in_use[idx] = false;
        self.free.appendAssumeCapacity(buf);
    }

    fn index(self: *const BufferPool, buf: []u8) usize {
        return (@intFromPtr(buf.ptr) - @intFromPtr(self.storage.ptr)) / self.buf_size;
    }
};

test "pool hands out every buffer once" {
    var pool = try BufferPool.init(std.testing.allocator, 3, 64);
    defer pool.deinit();

    try std.testing.expectEqual(@as(usize, 3), pool.count());
    try std.testing.expectEqual(@as(usize, 3), pool.available());

    var got: [3][]u8 = undefined;
    for (&got) |*slot| slot.* = pool.acquire().?;
    try std.testing.expectEqual(@as(usize, 0), pool.available());
    try std.testing.expect(pool.acquire() == null);

    for (got) |buf| pool.release(buf);
    try std.testing.expectEqual(@as(usize, 3), pool.available());
}

test "pool rejects double release" {
    var pool = try BufferPool.init(std.testing.allocator, 2, 32);
    defer pool.deinit();

    const a = pool.acquire().?;
    const b = pool.acquire().?;

    pool.release(a);
    pool.release(a); // duplicate: ignored
    try std.testing.expectEqual(@as(usize, 1), pool.available());

    pool.release(b);
    try std.testing.expectEqual(@as(usize, 2), pool.available());

    // Both buffers are usable again.
    _ = pool.acquire().?;
    _ = pool.acquire().?;
}

test "pool ignores foreign buffers" {
    var pool = try BufferPool.init(std.testing.allocator, 1, 32);
    defer pool.deinit();

    var foreign: [32]u8 = undefined;
    pool.release(&foreign);
    try std.testing.expectEqual(@as(usize, 1), pool.available());
}

test "pool rejects empty arguments" {
    try std.testing.expectError(error.InvalidArgument, BufferPool.init(std.testing.allocator, 0, 64));
    try std.testing.expectError(error.InvalidArgument, BufferPool.init(std.testing.allocator, 4, 0));
}
