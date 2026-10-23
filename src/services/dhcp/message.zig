//! DHCPv4 wire format (RFC 2131/2132). Parsers are bounds-checked; builders
//! never write past the caller's buffer.

const std = @import("std");
const types = @import("../../types.zig");

pub const op_request: u8 = 1;
pub const op_reply: u8 = 2;
pub const magic_cookie = [4]u8{ 99, 130, 83, 99 };
pub const min_message_len = 300;

pub const Error = error{
    Truncated,
    BadCookie,
    BadHeader,
    BadOption,
    OutOfSpace,
};

pub const MessageType = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
};

pub const Options = struct {
    bytes: []const u8,

    pub fn validate(self: Options) Error!void {
        var i: usize = 0;
        while (i < self.bytes.len) {
            const code = self.bytes[i];
            i += 1;
            if (code == 0) continue;
            if (code == 255) return;
            if (i >= self.bytes.len) return error.BadOption;
            const len = self.bytes[i];
            i += 1;
            if (len > self.bytes.len - i) return error.BadOption;
            i += len;
        }
    }

    pub fn get(self: Options, code: u8) ?[]const u8 {
        var i: usize = 0;
        while (i < self.bytes.len) {
            const current = self.bytes[i];
            i += 1;
            if (current == 0) continue;
            if (current == 255) return null;
            if (i >= self.bytes.len) return null;
            const len = self.bytes[i];
            i += 1;
            if (len > self.bytes.len - i) return null;
            if (current == code) return self.bytes[i .. i + len];
            i += len;
        }
        return null;
    }

    pub fn messageType(self: Options) ?MessageType {
        const value = self.get(53) orelse return null;
        if (value.len != 1) return null;
        return switch (value[0]) {
            1 => .discover,
            2 => .offer,
            3 => .request,
            4 => .decline,
            5 => .ack,
            6 => .nak,
            7 => .release,
            8 => .inform,
            else => null,
        };
    }

    pub fn requestedIp(self: Options) ?types.Ipv4 {
        return ipv4Option(self.get(50));
    }

    pub fn serverId(self: Options) ?types.Ipv4 {
        return ipv4Option(self.get(54));
    }

    pub fn maxMessageSize(self: Options) ?u16 {
        const value = self.get(57) orelse return null;
        if (value.len != 2) return null;
        return std.mem.readInt(u16, value[0..2], .big);
    }

    pub fn parameterRequestList(self: Options) []const u8 {
        return self.get(55) orelse &.{};
    }

    pub fn hostname(self: Options) ?[]const u8 {
        return self.get(12);
    }
};

fn ipv4Option(value: ?[]const u8) ?types.Ipv4 {
    const bytes = value orelse return null;
    if (bytes.len != 4) return null;
    return .{ .value = std.mem.readInt(u32, bytes[0..4], .big) };
}

pub const Message = struct {
    op: u8,
    htype: u8,
    hlen: u8,
    xid: u32,
    flags: u16,
    ciaddr: types.Ipv4,
    yiaddr: types.Ipv4,
    siaddr: types.Ipv4,
    giaddr: types.Ipv4,
    chaddr: [16]u8,
    options: Options,

    pub fn parse(packet: []const u8) Error!Message {
        if (packet.len < 240) return error.Truncated;
        if (packet[0] != op_request and packet[0] != op_reply) return error.BadHeader;
        if (packet[2] > 16) return error.BadHeader;
        if (!std.mem.eql(u8, packet[236..240], &magic_cookie)) return error.BadCookie;

        const options = Options{ .bytes = packet[240..] };
        try options.validate();

        var chaddr: [16]u8 = undefined;
        @memcpy(&chaddr, packet[28..44]);
        return .{
            .op = packet[0],
            .htype = packet[1],
            .hlen = packet[2],
            .xid = std.mem.readInt(u32, packet[4..8], .big),
            .flags = std.mem.readInt(u16, packet[10..12], .big),
            .ciaddr = .{ .value = std.mem.readInt(u32, packet[12..16], .big) },
            .yiaddr = .{ .value = std.mem.readInt(u32, packet[16..20], .big) },
            .siaddr = .{ .value = std.mem.readInt(u32, packet[20..24], .big) },
            .giaddr = .{ .value = std.mem.readInt(u32, packet[24..28], .big) },
            .chaddr = chaddr,
            .options = options,
        };
    }

    pub fn messageType(self: Message) ?MessageType {
        return self.options.messageType();
    }

    pub fn clientMac(self: Message) ?types.Mac {
        if (self.htype != 1 or self.hlen != 6) return null;
        var mac: types.Mac = undefined;
        @memcpy(&mac.bytes, self.chaddr[0..6]);
        return mac;
    }
};

pub const Builder = struct {
    buf: []u8,
    len: usize,

    pub fn init(
        buf: []u8,
        op: u8,
        typ: MessageType,
        xid: u32,
        client_mac: types.Mac,
        flags: u16,
    ) Error!Builder {
        if (buf.len < 240) return error.OutOfSpace;
        if (op != op_request and op != op_reply) return error.BadHeader;

        @memset(buf[0..240], 0);
        buf[0] = op;
        buf[1] = 1;
        buf[2] = 6;
        writeU32(buf, 4, xid);
        writeU16(buf, 10, flags);
        @memcpy(buf[28..34], &client_mac.bytes);
        @memcpy(buf[236..240], &magic_cookie);

        var self = Builder{ .buf = buf, .len = 240 };
        try self.addOption(53, &.{@intFromEnum(typ)});
        return self;
    }

    pub fn setYiaddr(self: *Builder, addr: types.Ipv4) void {
        writeU32(self.buf, 16, addr.value);
    }

    pub fn setCiaddr(self: *Builder, addr: types.Ipv4) void {
        writeU32(self.buf, 12, addr.value);
    }

    pub fn addOption(self: *Builder, code: u8, data: []const u8) Error!void {
        if (code == 0 or code == 255 or data.len > 255) return error.BadOption;
        if (self.len + 2 + data.len > self.buf.len) return error.OutOfSpace;
        self.buf[self.len] = code;
        self.buf[self.len + 1] = @intCast(data.len);
        @memcpy(self.buf[self.len + 2 ..][0..data.len], data);
        self.len += 2 + data.len;
    }

    pub fn addIpv4(self: *Builder, code: u8, addr: types.Ipv4) Error!void {
        try self.addOption(code, &addr.toBytes());
    }

    pub fn addU16(self: *Builder, code: u8, value: u16) Error!void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .big);
        try self.addOption(code, &bytes);
    }

    pub fn addU32(self: *Builder, code: u8, value: u32) Error!void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        try self.addOption(code, &bytes);
    }

    pub fn finish(self: *Builder) Error![]u8 {
        if (self.len >= self.buf.len) return error.OutOfSpace;
        self.buf[self.len] = 255;
        self.len += 1;
        while (self.len < min_message_len and self.len < self.buf.len) {
            self.buf[self.len] = 0;
            self.len += 1;
        }
        return self.buf[0..self.len];
    }
};

fn writeU16(buf: []u8, off: usize, value: u16) void {
    std.mem.writeInt(u16, buf[off..][0..2], value, .big);
}

fn writeU32(buf: []u8, off: usize, value: u32) void {
    std.mem.writeInt(u32, buf[off..][0..4], value, .big);
}

const testing = std.testing;

const test_mac: types.Mac = .{ .bytes = .{ 0x02, 0, 0, 0, 0, 0x02 } };

test "build and parse a discover" {
    var buf: [512]u8 = undefined;
    var builder = try Builder.init(&buf, op_request, .discover, 0x12345678, test_mac, 0x8000);
    try builder.addIpv4(50, .{ .value = 0x0a000064 });
    const packet = try builder.finish();

    const parsed = try Message.parse(packet);
    try testing.expectEqual(op_request, parsed.op);
    try testing.expectEqual(@as(u32, 0x12345678), parsed.xid);
    try testing.expectEqual(@as(u16, 0x8000), parsed.flags);
    try testing.expectEqual(MessageType.discover, parsed.messageType().?);
    try testing.expect(parsed.clientMac().?.eql(test_mac));
    try testing.expectEqual(@as(u32, 0x0a000064), parsed.options.requestedIp().?.value);
    try testing.expectEqual(@as(u16, 0), parsed.yiaddr.value);
}

test "builder writes offer fields and options" {
    var buf: [512]u8 = undefined;
    var builder = try Builder.init(&buf, op_reply, .offer, 7, test_mac, 0);
    builder.setYiaddr(.{ .value = 0x0a000065 });
    try builder.addIpv4(54, .{ .value = 0x0a000001 });
    try builder.addU32(51, 3600);
    const packet = try builder.finish();

    const parsed = try Message.parse(packet);
    try testing.expectEqual(MessageType.offer, parsed.messageType().?);
    try testing.expectEqual(@as(u32, 0x0a000065), parsed.yiaddr.value);
    try testing.expectEqual(@as(u32, 0x0a000001), parsed.options.serverId().?.value);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0x0e, 0x10 }, parsed.options.get(51).?);
}

test "rejects malformed messages" {
    var buf: [512]u8 = undefined;
    var builder = try Builder.init(&buf, op_request, .discover, 1, test_mac, 0);
    const packet = try builder.finish();

    try testing.expectError(error.Truncated, Message.parse(packet[0..239]));

    var bad_cookie: [512]u8 = undefined;
    @memcpy(bad_cookie[0..packet.len], packet);
    bad_cookie[236] = 0;
    try testing.expectError(error.BadCookie, Message.parse(bad_cookie[0..packet.len]));

    var bad_option: [512]u8 = undefined;
    @memcpy(bad_option[0..packet.len], packet);
    bad_option[240] = 12;
    bad_option[241] = 250;
    try testing.expectError(error.BadOption, Message.parse(bad_option[0..packet.len]));
}
