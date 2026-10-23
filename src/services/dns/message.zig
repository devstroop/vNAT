//! Minimal DNS wire-format helpers for the forwarder. Only the fields needed
//! to validate a query, key a cache entry and cap its lifetime are parsed.

const std = @import("std");

pub const Error = error{
    Truncated,
    BadName,
    BadHeader,
    BadQuestion,
};

pub const Header = struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
};

pub fn parseHeader(packet: []const u8) Error!Header {
    if (packet.len < 12) return error.Truncated;
    return .{
        .id = std.mem.readInt(u16, packet[0..2], .big),
        .flags = std.mem.readInt(u16, packet[2..4], .big),
        .qdcount = std.mem.readInt(u16, packet[4..6], .big),
        .ancount = std.mem.readInt(u16, packet[6..8], .big),
        .nscount = std.mem.readInt(u16, packet[8..10], .big),
        .arcount = std.mem.readInt(u16, packet[10..12], .big),
    };
}

/// Returns the end offset of the single question section. Compression
/// pointers are rejected: a client query must not need them.
pub fn questionEnd(packet: []const u8) Error!usize {
    const header = try parseHeader(packet);
    if (header.qdcount != 1) return error.BadQuestion;
    var pos = try skipName(packet, 12, false);
    if (pos + 4 > packet.len) return error.Truncated;
    pos += 4;
    return pos;
}

pub fn isStandardQuery(packet: []const u8) bool {
    const header = parseHeader(packet) catch return false;
    return header.flags & 0x8000 == 0 and (header.flags >> 11) & 0xf == 0 and
        header.qdcount == 1;
}

/// Raw question bytes (name + qtype + qclass), used as the cache key.
pub fn questionKey(packet: []const u8) Error![]const u8 {
    return packet[12..try questionEnd(packet)];
}

pub fn rcode(packet: []const u8) u4 {
    const header = parseHeader(packet) catch return 2;
    return @intCast(header.flags & 0xf);
}

pub fn truncated(packet: []const u8) bool {
    const header = parseHeader(packet) catch return false;
    return header.flags & 0x0200 != 0;
}

/// Returns the smallest TTL among answer and authority records. Responses
/// without records are cached briefly so repeated failures do not hammer an
/// upstream.
pub fn minTtl(packet: []const u8) u32 {
    const header = parseHeader(packet) catch return 0;
    var pos = questionEnd(packet) catch return 0;
    var smallest: ?u32 = null;
    const records = @as(usize, header.ancount) + header.nscount;
    var i: usize = 0;
    while (i < records) : (i += 1) {
        pos = skipName(packet, pos, true) catch return smallest orelse 0;
        if (pos + 10 > packet.len) return smallest orelse 0;
        const typ = std.mem.readInt(u16, packet[pos..][0..2], .big);
        const ttl = std.mem.readInt(u32, packet[pos + 4 ..][0..4], .big);
        const rdlen = std.mem.readInt(u16, packet[pos + 8 ..][0..2], .big);
        pos += 10;
        if (pos + rdlen > packet.len) return smallest orelse 0;
        if (typ != 41) {
            if (smallest == null or ttl < smallest.?) smallest = ttl;
        }
        pos += rdlen;
    }
    return smallest orelse 60;
}

/// Builds a minimal error response that echoes the query ID and question.
pub fn buildError(out: []u8, query: []const u8, code: u4) Error![]u8 {
    const header = try parseHeader(query);
    const end = try questionEnd(query);
    if (out.len < end) return error.Truncated;
    @memcpy(out[0..end], query[0..end]);
    const flags: u16 = 0x8000 | 0x0080 | @as(u16, code);
    std.mem.writeInt(u16, out[0..2], header.id, .big);
    std.mem.writeInt(u16, out[2..4], flags, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], 0, .big);
    std.mem.writeInt(u16, out[8..10], 0, .big);
    std.mem.writeInt(u16, out[10..12], 0, .big);
    return out[0..end];
}

pub fn setHeaderId(packet: []u8, id: u16) void {
    if (packet.len >= 2) std.mem.writeInt(u16, packet[0..2], id, .big);
}

fn skipName(packet: []const u8, start: usize, allow_pointer: bool) Error!usize {
    var pos = start;
    var labels: usize = 0;
    while (true) {
        if (pos >= packet.len) return error.Truncated;
        const len = packet[pos];
        if (len == 0) return pos + 1;
        if (len & 0xc0 == 0xc0) {
            if (!allow_pointer) return error.BadName;
            if (pos + 1 >= packet.len) return error.Truncated;
            return pos + 2;
        }
        if (len & 0xc0 != 0 or len > 63) return error.BadName;
        labels += 1;
        if (labels > 127) return error.BadName;
        pos += 1 + len;
        if (pos > packet.len) return error.Truncated;
    }
}

const testing = std.testing;

fn buildQuery(buf: []u8, id: u16, name: []const u8, typ: u16) []u8 {
    @memset(buf[0..12], 0);
    std.mem.writeInt(u16, buf[0..2], id, .big);
    std.mem.writeInt(u16, buf[4..6], 1, .big);
    var pos: usize = 12;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0) continue;
        buf[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(buf[pos..][0..label.len], label);
        pos += label.len;
    }
    buf[pos] = 0;
    pos += 1;
    std.mem.writeInt(u16, buf[pos..][0..2], typ, .big);
    std.mem.writeInt(u16, buf[pos + 2 ..][0..2], 1, .big);
    return buf[0 .. pos + 4];
}

test "parses a query and builds an error response" {
    var buf: [256]u8 = undefined;
    const query = buildQuery(&buf, 0x1234, "example.com", 1);
    try testing.expect(isStandardQuery(query));
    try testing.expectEqual(@as(usize, query.len), try questionEnd(query));
    try testing.expectEqualSlices(u8, query[12..], try questionKey(query));

    var out: [256]u8 = undefined;
    const response = try buildError(&out, query, 5);
    try testing.expectEqual(@as(u16, 0x1234), std.mem.readInt(u16, response[0..2], .big));
    try testing.expectEqual(@as(u4, 5), rcode(response));
    try testing.expectEqualSlices(u8, query[12..], response[12..]);
}

test "rejects compressed questions and computes record ttl" {
    var buf: [256]u8 = undefined;
    const query = buildQuery(&buf, 1, "example.com", 1);
    var compressed: [256]u8 = undefined;
    @memcpy(compressed[0..query.len], query);
    compressed[12] = 0xc0;
    compressed[13] = 0x0c;
    try testing.expectError(error.BadName, questionEnd(compressed[0..query.len]));

    var response: [256]u8 = undefined;
    @memcpy(response[0..query.len], query);
    std.mem.writeInt(u16, response[2..4], 0x8180, .big);
    std.mem.writeInt(u16, response[6..8], 1, .big);
    var pos = query.len;
    response[pos] = 0xc0;
    response[pos + 1] = 0x0c;
    pos += 2;
    std.mem.writeInt(u16, response[pos..][0..2], 1, .big);
    std.mem.writeInt(u16, response[pos + 2 ..][0..2], 1, .big);
    std.mem.writeInt(u32, response[pos + 4 ..][0..4], 120, .big);
    std.mem.writeInt(u16, response[pos + 8 ..][0..2], 4, .big);
    pos += 10;
    std.mem.writeInt(u32, response[pos..][0..4], 0x7f000001, .big);
    pos += 4;
    try testing.expectEqual(@as(u32, 120), minTtl(response[0..pos]));
}
