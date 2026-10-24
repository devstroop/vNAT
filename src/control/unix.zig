//! Unix-domain socket helpers shared by the control client and server.
//! `std.Io.net.UnixAddress.connect` aborts on `ECONNREFUSED` from a stale
//! socket, which is an expected state here.

const std = @import("std");
const linux = std.os.linux;

pub fn connect(path: []const u8) !std.Io.net.Stream {
    if (path.len == 0 or path.len > std.Io.net.UnixAddress.max_len) {
        return error.NameTooLong;
    }

    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (std.posix.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: std.posix.fd_t = @intCast(rc);
    errdefer _ = linux.close(fd);

    var address: linux.sockaddr.un = .{ .path = @splat(0) };
    if (path.len > address.path.len) return error.NameTooLong;
    @memcpy(address.path[0..path.len], path);
    var address_len: linux.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len);
    if (path.len < address.path.len) address_len += 1;
    const result = linux.connect(fd, @ptrCast(&address), address_len);
    switch (std.posix.errno(result)) {
        .SUCCESS => {},
        .CONNREFUSED => return error.ConnectionRefused,
        .NOENT => return error.FileNotFound,
        .ACCES, .PERM => return error.AccessDenied,
        .AGAIN, .INPROGRESS => return error.WouldBlock,
        else => return error.ConnectFailed,
    }

    return .{ .socket = .{
        .handle = fd,
        .address = .{ .ip4 = .loopback(0) },
    } };
}
