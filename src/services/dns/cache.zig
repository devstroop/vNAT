//! Bounded DNS response cache. Entries are keyed by the raw question section
//! and expire from the smallest record TTL.

const std = @import("std");
const message = @import("message.zig");

const Entry = struct {
    response: []u8,
    stored_ms: i64,
    expires_ms: i64,
};

pub const Cache = struct {
    gpa: std.mem.Allocator,
    map: std.StringHashMapUnmanaged(Entry) = .empty,
    max_entries: usize,

    pub fn init(gpa: std.mem.Allocator, max_entries: usize) Cache {
        return .{ .gpa = gpa, .max_entries = max_entries };
    }

    pub fn deinit(self: *Cache) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.gpa.free(entry.key_ptr.*);
            self.gpa.free(entry.value_ptr.response);
        }
        self.map.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn get(self: *Cache, key: []const u8, out: []u8, now_ms: i64) ?[]u8 {
        if (self.max_entries == 0) return null;
        const entry = self.map.getEntry(key) orelse return null;
        if (now_ms >= entry.value_ptr.expires_ms) {
            const owned_key = entry.key_ptr.*;
            self.gpa.free(entry.value_ptr.response);
            self.map.removeByPtr(entry.key_ptr);
            self.gpa.free(owned_key);
            return null;
        }
        const response = entry.value_ptr.response;
        if (response.len > out.len) return null;
        @memcpy(out[0..response.len], response);
        const elapsed_ms = if (now_ms > entry.value_ptr.stored_ms)
            now_ms - entry.value_ptr.stored_ms
        else
            0;
        const elapsed_s = @min(@divTrunc(elapsed_ms, 1000), std.math.maxInt(u32));
        message.ageTtls(out[0..response.len], @intCast(elapsed_s));
        return out[0..response.len];
    }

    pub fn put(
        self: *Cache,
        key: []const u8,
        response: []const u8,
        ttl_ms: u32,
        now_ms: i64,
    ) !void {
        if (self.max_entries == 0 or ttl_ms == 0 or response.len == 0) return;
        if (self.map.getEntry(key)) |entry| {
            const replacement = try self.gpa.dupe(u8, response);
            self.gpa.free(entry.value_ptr.response);
            entry.value_ptr.* = .{
                .response = replacement,
                .stored_ms = now_ms,
                .expires_ms = now_ms + ttl_ms,
            };
            return;
        }
        if (self.map.count() >= self.max_entries) {
            self.evictExpired(now_ms);
            if (self.map.count() >= self.max_entries) return;
        }
        const owned_key = try self.gpa.dupe(u8, key);
        errdefer self.gpa.free(owned_key);
        const owned_response = try self.gpa.dupe(u8, response);
        errdefer self.gpa.free(owned_response);
        try self.map.put(self.gpa, owned_key, .{
            .response = owned_response,
            .stored_ms = now_ms,
            .expires_ms = now_ms + ttl_ms,
        });
    }

    pub fn count(self: *const Cache) usize {
        return self.map.count();
    }

    fn evictExpired(self: *Cache, now_ms: i64) void {
        while (true) {
            var expired: ?[]const u8 = null;
            var it = self.map.iterator();
            while (it.next()) |entry| {
                if (now_ms >= entry.value_ptr.expires_ms) {
                    expired = entry.key_ptr.*;
                    break;
                }
            }
            const key = expired orelse return;
            if (self.map.fetchRemove(key)) |removed| {
                self.gpa.free(removed.key);
                self.gpa.free(removed.value.response);
            }
        }
    }
};

const testing = std.testing;

test "cache returns entries until their ttl expires" {
    var cache = Cache.init(testing.allocator, 4);
    defer cache.deinit();

    try cache.put("key", "response", 100, 1_000);
    var out: [32]u8 = undefined;
    try testing.expectEqualStrings("response", cache.get("key", &out, 1_050).?);
    try testing.expect(cache.get("key", &out, 1_100) == null);
    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "cache is bounded and drops new entries when full" {
    var cache = Cache.init(testing.allocator, 1);
    defer cache.deinit();

    try cache.put("a", "one", 100, 0);
    try cache.put("b", "two", 100, 0);
    try testing.expectEqual(@as(usize, 1), cache.count());
    var out: [8]u8 = undefined;
    try testing.expectEqualStrings("one", cache.get("a", &out, 0).?);
    try testing.expect(cache.get("b", &out, 0) == null);
}
