//! UDP DNS forwarder. Queries are answered from a TTL cache or relayed to the
//! configured upstreams; the listener is a normal kernel socket bound to a
//! router address, so it never shares the AF_PACKET datapath.

const std = @import("std");
const types = @import("../../types.zig");
const message = @import("message.zig");
const cache_mod = @import("cache.zig");

pub const Zone = struct {
    suffix: []const u8,
    upstreams: []const types.Ipv4,
};

pub const Config = struct {
    listen_ip: types.Ipv4,
    listen_port: u16 = 53,
    upstreams: []const types.Ipv4,
    upstream_port: u16 = 53,
    cache: bool = true,
    cache_max_entries: u32 = 1024,
    tcp: bool = true,
    zones: []const Zone = &.{},
};

pub const Counters = struct {
    queries: std.atomic.Value(u64) = .init(0),
    responses: std.atomic.Value(u64) = .init(0),
    cache_hits: std.atomic.Value(u64) = .init(0),
    upstream_errors: std.atomic.Value(u64) = .init(0),
    dropped: std.atomic.Value(u64) = .init(0),

    fn inc(counter: *std.atomic.Value(u64)) void {
        _ = counter.fetchAdd(1, .monotonic);
    }
};

const tcp_query_timeout_ms: i64 = 5_000;
const max_tcp_query_len: usize = 4096;

pub const Error = error{
    OutOfMemory,
    ListenBindFailed,
    UpstreamBindFailed,
    ConcurrencyUnavailable,
};

pub const Service = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    cfg: Config,
    socket: std.Io.net.Socket,
    upstream_socket: std.Io.net.Socket,
    upstream_socket_tcp: std.Io.net.Socket,
    tcp_listener: ?std.Io.net.Server = null,
    cache: cache_mod.Cache,
    cache_mutex: std.Io.Mutex = .init,
    counters: Counters = .{},
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    udp_future: std.Io.Future(void) = undefined,
    tcp_future: std.Io.Future(void) = undefined,
    udp_started: bool = false,
    tcp_started: bool = false,

    pub fn init(io: std.Io, gpa: std.mem.Allocator, cfg: Config) Error!Service {
        if (cfg.upstreams.len == 0 and cfg.zones.len == 0) return error.UpstreamBindFailed;
        const listen = std.Io.net.IpAddress{ .ip4 = .{
            .bytes = cfg.listen_ip.toBytes(),
            .port = cfg.listen_port,
        } };
        const socket = listen.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch
            return error.ListenBindFailed;
        errdefer socket.close(io);

        const any = std.Io.net.IpAddress{ .ip4 = .unspecified(0) };
        const upstream_socket = any.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch
            return error.UpstreamBindFailed;
        errdefer upstream_socket.close(io);

        const upstream_socket_tcp = any.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch
            return error.UpstreamBindFailed;
        errdefer upstream_socket_tcp.close(io);

        var tcp_listener: ?std.Io.net.Server = null;
        if (cfg.tcp) {
            tcp_listener = std.Io.net.IpAddress.listen(&listen, io, .{
                .mode = .stream,
                .protocol = .tcp,
            }) catch return error.ListenBindFailed;
        }
        errdefer if (tcp_listener) |*listener| listener.deinit(io);

        return .{
            .io = io,
            .gpa = gpa,
            .cfg = cfg,
            .socket = socket,
            .upstream_socket = upstream_socket,
            .upstream_socket_tcp = upstream_socket_tcp,
            .tcp_listener = tcp_listener,
            .cache = cache_mod.Cache.init(gpa, if (cfg.cache) cfg.cache_max_entries else 0),
        };
    }

    pub fn start(self: *Service) Error!void {
        self.udp_future = std.Io.concurrent(self.io, runUdp, .{self}) catch
            return error.ConcurrencyUnavailable;
        self.udp_started = true;
        if (self.tcp_listener != null) {
            self.tcp_future = std.Io.concurrent(self.io, runTcp, .{self}) catch
                return error.ConcurrencyUnavailable;
            self.tcp_started = true;
        }
    }

    pub fn deinit(self: *Service) void {
        self.stop.store(true, .release);
        self.socket.close(self.io);
        self.upstream_socket.close(self.io);
        self.upstream_socket_tcp.close(self.io);
        if (self.tcp_listener) |*listener| {
            listener.socket.close(self.io);
            self.tcp_listener = null;
        }
        if (self.udp_started) {
            _ = self.udp_future.await(self.io);
            self.udp_started = false;
        }
        if (self.tcp_started) {
            _ = self.tcp_future.await(self.io);
            self.tcp_started = false;
        }
        self.cache.deinit();
        self.* = undefined;
    }

    pub fn address(self: *const Service) std.Io.net.IpAddress {
        return self.socket.address;
    }

    fn runUdp(self: *Service) void {
        var buf: [4096]u8 = undefined;
        var out: [4096]u8 = undefined;
        while (!self.stop.load(.acquire)) {
            const incoming = self.socket.receiveTimeout(
                self.io,
                &buf,
                timeoutMs(250),
            ) catch |err| switch (err) {
                error.Timeout => continue,
                error.Canceled => return,
                else => {
                    Counters.inc(&self.counters.dropped);
                    continue;
                },
            };
            Counters.inc(&self.counters.queries);
            const response = self.resolve(incoming.data, &out, &self.upstream_socket) catch {
                Counters.inc(&self.counters.dropped);
                continue;
            };
            self.socket.send(self.io, &incoming.from, response) catch {
                Counters.inc(&self.counters.dropped);
                continue;
            };
            Counters.inc(&self.counters.responses);
        }
    }

    fn runTcp(self: *Service) void {
        var listener = self.tcp_listener orelse return;
        while (!self.stop.load(.acquire)) {
            const stream = listener.accept(self.io) catch |err| switch (err) {
                error.ConnectionAborted => continue,
                else => {
                    if (self.stop.load(.acquire)) return;
                    Counters.inc(&self.counters.dropped);
                    continue;
                },
            };
            self.handleTcpStream(stream);
        }
    }

    fn handleTcpStream(self: *Service, stream: std.Io.net.Stream) void {
        defer stream.close(self.io);
        const deadline = nowMs(self.io) + tcp_query_timeout_ms;
        var len_buf: [2]u8 = undefined;
        self.readTcpAll(stream.socket.handle, &len_buf, deadline) catch {
            Counters.inc(&self.counters.dropped);
            return;
        };
        const query_len = std.mem.readInt(u16, &len_buf, .big);
        if (query_len < 12 or query_len > max_tcp_query_len) {
            Counters.inc(&self.counters.dropped);
            return;
        }
        var query_buf: [max_tcp_query_len]u8 = undefined;
        self.readTcpAll(stream.socket.handle, query_buf[0..query_len], deadline) catch {
            Counters.inc(&self.counters.dropped);
            return;
        };
        const query = query_buf[0..query_len];

        Counters.inc(&self.counters.queries);
        var out: [4096]u8 = undefined;
        const response = self.resolve(query, &out, &self.upstream_socket_tcp) catch {
            Counters.inc(&self.counters.dropped);
            return;
        };

        var write_buf: [4096]u8 = undefined;
        var writer = stream.writer(self.io, &write_buf);
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(response.len), .big);
        writer.interface.writeAll(&prefix) catch {
            Counters.inc(&self.counters.dropped);
            return;
        };
        writer.interface.writeAll(response) catch {
            Counters.inc(&self.counters.dropped);
            return;
        };
        writer.interface.flush() catch {
            Counters.inc(&self.counters.dropped);
            return;
        };
        Counters.inc(&self.counters.responses);
    }

    fn readTcpAll(self: *Service, fd: std.posix.fd_t, out: []u8, deadline_ms: i64) !void {
        // std.Io has no deadline-aware stream read, so poll() bounds the
        // whole query and keeps a stalled client from pinning the TCP worker.
        var off: usize = 0;
        while (off < out.len) {
            const remaining = deadline_ms - nowMs(self.io);
            if (remaining <= 0) return error.Timeout;
            var fds = [_]std.posix.pollfd{.{
                .fd = fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = try std.posix.poll(&fds, @intCast(@min(remaining, std.math.maxInt(i32))));
            if (ready == 0) return error.Timeout;
            const n = std.posix.read(fd, out[off..]) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }

    fn resolve(self: *Service, query: []const u8, out: []u8, upstream_socket: *std.Io.net.Socket) ![]u8 {
        if (!message.isStandardQuery(query)) return error.BadQuery;
        const header = message.parseHeader(query) catch return error.BadQuery;
        const key = message.questionKey(query) catch return error.BadQuery;

        var name_buf: [256]u8 = undefined;
        const qname = questionName(query, &name_buf);

        if (qname) |name| {
            if (isLocalZone(name)) {
                if (message.questionType(query) == 1) {
                    return buildLocalResponse(out, query, header.id, self.cfg.listen_ip);
                }
                return message.buildError(out, query, 0);
            }
        }

        if (self.cfg.cache) {
            if (self.cacheGet(key, out, nowMs(self.io))) |cached| {
                message.setHeaderId(cached, header.id);
                Counters.inc(&self.counters.cache_hits);
                return cached;
            }
        }

        const upstreams = if (qname) |name| self.upstreamsFor(name) else self.cfg.upstreams;
        const response = self.queryUpstream(upstream_socket, query, key, upstreams, out) catch {
            Counters.inc(&self.counters.upstream_errors);
            return message.buildError(out, query, 2) catch error.BadQuery;
        };
        const ttl = message.cacheTtl(response);
        const ttl_ms = @as(u64, ttl) * 1000;
        self.cachePut(
            key,
            response,
            @intCast(@min(ttl_ms, std.math.maxInt(u32))),
            nowMs(self.io),
        ) catch {};
        return response;
    }

    fn upstreamsFor(self: *const Service, qname: []const u8) []const types.Ipv4 {
        var best: ?Zone = null;
        var best_len: usize = 0;
        for (self.cfg.zones) |zone| {
            const suffix = normalizeSuffix(zone.suffix);
            if (suffix.len == 0 or zone.upstreams.len == 0) continue;
            if (suffix.len > best_len and suffixMatch(qname, suffix)) {
                best = zone;
                best_len = suffix.len;
            }
        }
        if (best) |zone| return zone.upstreams;
        return self.cfg.upstreams;
    }

    fn cacheGet(self: *Service, key: []const u8, out: []u8, now: i64) ?[]u8 {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
        return self.cache.get(key, out, now);
    }

    fn cachePut(self: *Service, key: []const u8, response: []const u8, ttl_ms: u32, now: i64) !void {
        self.cache_mutex.lockUncancelable(self.io);
        defer self.cache_mutex.unlock(self.io);
        try self.cache.put(key, response, ttl_ms, now);
    }

    fn queryUpstream(self: *Service, socket: *std.Io.net.Socket, query: []const u8, key: []const u8, upstreams: []const types.Ipv4, out: []u8) ![]u8 {
        const header = try message.parseHeader(query);
        for (upstreams) |upstream| {
            const dest = std.Io.net.IpAddress{ .ip4 = .{
                .bytes = upstream.toBytes(),
                .port = self.cfg.upstream_port,
            } };

            // UDP first, with a single retry window.
            socket.send(self.io, &dest, query) catch {};
            var udp_response: ?[]u8 = null;
            var udp_buf: [4096]u8 = undefined;
            var attempts: usize = 0;
            while (attempts < 2) : (attempts += 1) {
                const incoming = socket.receiveTimeout(
                    self.io,
                    &udp_buf,
                    timeoutMs(1_000),
                ) catch |err| switch (err) {
                    error.Timeout => break,
                    error.Canceled => return error.Canceled,
                    else => break,
                };
                if (!incoming.from.eql(&dest)) continue;
                const reply = message.parseHeader(incoming.data) catch continue;
                if (reply.id != header.id or reply.flags & 0x8000 == 0) continue;
                const reply_key = message.questionKey(incoming.data) catch continue;
                if (!std.mem.eql(u8, reply_key, key)) continue;
                if (incoming.data.len > out.len) return error.ResponseTooLarge;
                @memcpy(out[0..incoming.data.len], incoming.data);
                udp_response = out[0..incoming.data.len];
                break;
            }

            if (udp_response) |response| {
                if (!message.truncated(response)) return response;
                // Truncated UDP response: retry over TCP.
                if (self.queryUpstreamTcp(upstream, query, out)) |tcp_response| {
                    return tcp_response;
                } else |_| {}
                return response;
            }

            // No UDP response: try TCP before moving to the next upstream.
            if (self.queryUpstreamTcp(upstream, query, out)) |tcp_response| {
                return tcp_response;
            } else |_| {}
        }
        return error.NoUpstream;
    }

    fn queryUpstreamTcp(self: *Service, upstream: types.Ipv4, query: []const u8, out: []u8) ![]u8 {
        const dest = std.Io.net.IpAddress{ .ip4 = .{
            .bytes = upstream.toBytes(),
            .port = self.cfg.upstream_port,
        } };
        var stream = try std.Io.net.IpAddress.connect(&dest, self.io, .{
            .mode = .stream,
            .protocol = .tcp,
            .timeout = timeoutMs(2_000),
        });
        defer stream.close(self.io);

        var write_buf: [4096]u8 = undefined;
        var writer = stream.writer(self.io, &write_buf);
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(query.len), .big);
        try writer.interface.writeAll(&prefix);
        try writer.interface.writeAll(query);
        try writer.interface.flush();

        var read_buf: [4096]u8 = undefined;
        var reader = stream.reader(self.io, &read_buf);
        var len_buf: [2]u8 = undefined;
        try reader.interface.readSliceAll(&len_buf);
        const response_len = std.mem.readInt(u16, &len_buf, .big);
        if (response_len < 12 or response_len > out.len) return error.ResponseTooLarge;
        try reader.interface.readSliceAll(out[0..response_len]);
        return out[0..response_len];
    }
};

fn normalizeSuffix(suffix: []const u8) []const u8 {
    var start: usize = 0;
    var end: usize = suffix.len;
    while (start < end and suffix[start] == '.') start += 1;
    while (end > start and suffix[end - 1] == '.') end -= 1;
    return suffix[start..end];
}

fn suffixMatch(qname: []const u8, suffix: []const u8) bool {
    if (suffix.len > qname.len) return false;
    if (suffix.len == qname.len) return asciiEql(qname, suffix);
    if (qname.len <= suffix.len + 1) return false;
    if (qname[qname.len - suffix.len - 1] != '.') return false;
    return asciiEql(qname[qname.len - suffix.len ..], suffix);
}

fn asciiEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (asciiLower(ca) != asciiLower(cb)) return false;
    }
    return true;
}

fn asciiLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

fn isLocalZone(qname: []const u8) bool {
    return asciiEql(qname, "vnat") or asciiEql(qname, "router.vnat");
}

fn questionName(query: []const u8, out: *[256]u8) ?[]const u8 {
    const header = message.parseHeader(query) catch return null;
    if (header.qdcount != 1) return null;
    var pos: usize = 12;
    var len_out: usize = 0;
    while (pos < query.len) {
        const label_len = query[pos];
        if (label_len == 0) {
            pos += 1;
            break;
        }
        if (label_len & 0xc0 != 0) return null;
        if (pos + 1 + label_len > query.len) return null;
        if (len_out != 0) {
            if (len_out >= out.len) return null;
            out[len_out] = '.';
            len_out += 1;
        }
        if (len_out + label_len > out.len) return null;
        for (query[pos + 1 .. pos + 1 + label_len], 0..) |c, i| {
            out[len_out + i] = asciiLower(c);
        }
        len_out += label_len;
        pos += 1 + label_len;
    } else {
        return null;
    }
    if (pos + 4 > query.len) return null;
    if (query[pos - 1] != 0) return null;
    if (len_out == 0) return null;
    return out[0..len_out];
}

fn buildLocalResponse(out: []u8, query: []const u8, id: u16, ip: types.Ipv4) ![]u8 {
    const qend = try message.questionEnd(query);
    if (out.len < qend + 16) return error.ResponseTooLarge;
    @memcpy(out[0..qend], query[0..qend]);
    std.mem.writeInt(u16, out[0..2], id, .big);
    std.mem.writeInt(u16, out[2..4], 0x8180, .big);
    std.mem.writeInt(u16, out[4..6], 1, .big);
    std.mem.writeInt(u16, out[6..8], 1, .big);
    std.mem.writeInt(u16, out[8..10], 0, .big);
    std.mem.writeInt(u16, out[10..12], 0, .big);
    var pos = qend;
    out[pos] = 0xc0;
    out[pos + 1] = 0x0c;
    pos += 2;
    std.mem.writeInt(u16, out[pos..][0..2], 1, .big);
    pos += 2;
    std.mem.writeInt(u16, out[pos..][0..2], 1, .big);
    pos += 2;
    std.mem.writeInt(u32, out[pos..][0..4], 60, .big);
    pos += 4;
    std.mem.writeInt(u16, out[pos..][0..2], 4, .big);
    pos += 2;
    @memcpy(out[pos..][0..4], &ip.toBytes());
    pos += 4;
    return out[0..pos];
}

fn nowMs(io: std.Io) i64 {
    return std.Io.Clock.now(.awake, io).toMilliseconds();
}

fn timeoutMs(ms: i64) std.Io.Timeout {
    return .{ .duration = .{
        .raw = std.Io.Duration.fromMilliseconds(ms),
        .clock = .awake,
    } };
}

const testing = std.testing;

test "service rejects configs without upstreams" {
    const cfg = Config{
        .listen_ip = .{ .value = 0x7f000001 },
        .upstreams = &.{},
    };
    try testing.expectError(error.UpstreamBindFailed, Service.init(testing.io, testing.allocator, cfg));
}

test "service accepts a zone-only configuration" {
    const zones = [_]Zone{.{
        .suffix = "lan",
        .upstreams = &.{.{ .value = 0x0a000001 }},
    }};
    var service = try Service.init(testing.io, testing.allocator, .{
        .listen_ip = .{ .value = 0x7f000001 },
        .listen_port = 0,
        .upstreams = &.{},
        .zones = &zones,
        .tcp = false,
    });
    defer service.deinit();
}
