//! UDP DNS forwarder. Queries are answered from a TTL cache or relayed to the
//! configured upstreams; the listener is a normal kernel socket bound to a
//! router address, so it never shares the AF_PACKET datapath.

const std = @import("std");
const types = @import("../../types.zig");
const message = @import("message.zig");
const cache_mod = @import("cache.zig");

pub const Config = struct {
    listen_ip: types.Ipv4,
    listen_port: u16 = 53,
    upstreams: []const types.Ipv4,
    upstream_port: u16 = 53,
    cache: bool = true,
    cache_max_entries: u32 = 1024,
};

pub const Counters = struct {
    queries: u64 = 0,
    responses: u64 = 0,
    cache_hits: u64 = 0,
    upstream_errors: u64 = 0,
    dropped: u64 = 0,
};

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
    cache: cache_mod.Cache,
    counters: Counters = .{},
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    future: std.Io.Future(void) = undefined,
    started: bool = false,

    pub fn init(io: std.Io, gpa: std.mem.Allocator, cfg: Config) Error!Service {
        if (cfg.upstreams.len == 0) return error.UpstreamBindFailed;
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

        return .{
            .io = io,
            .gpa = gpa,
            .cfg = cfg,
            .socket = socket,
            .upstream_socket = upstream_socket,
            .cache = cache_mod.Cache.init(gpa, if (cfg.cache) cfg.cache_max_entries else 0),
        };
    }

    pub fn start(self: *Service) Error!void {
        self.future = std.Io.concurrent(self.io, run, .{self}) catch
            return error.ConcurrencyUnavailable;
        self.started = true;
    }

    pub fn deinit(self: *Service) void {
        self.stop.store(true, .release);
        if (self.started) {
            _ = self.future.await(self.io);
            self.started = false;
        }
        self.socket.close(self.io);
        self.upstream_socket.close(self.io);
        self.cache.deinit();
        self.* = undefined;
    }

    pub fn address(self: *const Service) std.Io.net.IpAddress {
        return self.socket.address;
    }

    fn run(self: *Service) void {
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
                    self.counters.dropped += 1;
                    continue;
                },
            };
            self.counters.queries += 1;
            const response = self.resolve(incoming.data, &out) catch {
                self.counters.dropped += 1;
                continue;
            };
            self.socket.send(self.io, &incoming.from, response) catch {
                self.counters.dropped += 1;
                continue;
            };
            self.counters.responses += 1;
        }
    }

    fn resolve(self: *Service, query: []const u8, out: []u8) ![]u8 {
        if (!message.isStandardQuery(query)) return error.BadQuery;
        const header = message.parseHeader(query) catch return error.BadQuery;
        const key = message.questionKey(query) catch return error.BadQuery;

        if (self.cfg.cache) {
            if (self.cache.get(key, out, nowMs(self.io))) |cached| {
                message.setHeaderId(cached, header.id);
                self.counters.cache_hits += 1;
                return cached;
            }
        }

        const response = self.queryUpstream(query, key, out) catch {
            self.counters.upstream_errors += 1;
            return message.buildError(out, query, 2) catch error.BadQuery;
        };
        const ttl = message.minTtl(response);
        const ttl_ms = @as(u64, ttl) * 1000;
        self.cache.put(
            key,
            response,
            @intCast(@min(ttl_ms, std.math.maxInt(u32))),
            nowMs(self.io),
        ) catch {};
        return response;
    }

    fn queryUpstream(self: *Service, query: []const u8, key: []const u8, out: []u8) ![]u8 {
        const header = try message.parseHeader(query);
        for (self.cfg.upstreams) |upstream| {
            const dest = std.Io.net.IpAddress{ .ip4 = .{
                .bytes = upstream.toBytes(),
                .port = self.cfg.upstream_port,
            } };
            self.upstream_socket.send(self.io, &dest, query) catch continue;

            while (true) {
                var buf: [4096]u8 = undefined;
                const incoming = self.upstream_socket.receiveTimeout(
                    self.io,
                    &buf,
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
                return out[0..incoming.data.len];
            }
        }
        return error.NoUpstream;
    }
};

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
