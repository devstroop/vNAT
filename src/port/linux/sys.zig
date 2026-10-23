//! Thin, non-blocking Linux socket/syscall helpers.
//!
//! These wrap `std.os.linux` (which returns raw syscall results) and map
//! errno values into `PortError`. All descriptors created here are
//! non-blocking and close-on-exec.

const std = @import("std");
const linux = std.os.linux;
const PortError = @import("../../errors.zig").PortError;

pub const fd_t = linux.fd_t;
pub const IFNAMESIZE = 16;

pub fn mapErr(e: linux.E) PortError {
    return switch (e) {
        .ACCES, .PERM => error.PermissionDenied,
        .NOENT, .NODEV, .NXIO => error.NotFound,
        .BUSY => error.Busy,
        .INVAL => error.InvalidArgument,
        .AGAIN => error.WouldBlock,
        .NOMEM, .NOBUFS => error.NoBufferSpace,
        .MFILE, .NFILE => error.FdLimit,
        .INTR => error.Interrupted,
        .OPNOTSUPP, .AFNOSUPPORT, .PROTONOSUPPORT => error.Unsupported,
        else => error.Io,
    };
}

pub fn check(rc: usize) PortError!void {
    const e = std.posix.errno(rc);
    if (e != .SUCCESS) return mapErr(e);
}

pub fn checkFd(rc: usize) PortError!fd_t {
    const e = std.posix.errno(rc);
    if (e != .SUCCESS) return mapErr(e);
    return @intCast(rc);
}

pub fn close(fd: fd_t) void {
    _ = linux.close(fd);
}

/// Interface names are user input: reject anything that could be a path or
/// produce an ambiguous alias.
pub fn validateName(name: []const u8) PortError!void {
    if (name.len == 0 or name.len >= IFNAMESIZE) return error.InvalidArgument;
    for (name) |c| {
        if (c <= 0x20 or c == 0x7f) return error.InvalidArgument;
        if (c == '/' or c == ':' or c == '%') return error.InvalidArgument;
    }
}

pub fn controlSocket() PortError!fd_t {
    return checkFd(linux.socket(
        linux.AF.INET,
        linux.SOCK.DGRAM | linux.SOCK.CLOEXEC,
        0,
    ));
}

/// Non-blocking read. Returns null on EAGAIN/EINTR (no data right now).
pub fn read(fd: fd_t, buf: []u8) PortError!?usize {
    const rc = linux.read(fd, buf.ptr, buf.len);
    switch (std.posix.errno(rc)) {
        .SUCCESS => return if (rc == 0) null else rc,
        .AGAIN, .INTR => return null,
        else => |e| return mapErr(e),
    }
}

/// Writes one datagram/frame. Partial writes are treated as an I/O error.
pub fn write(fd: fd_t, buf: []const u8) PortError!void {
    const rc = linux.write(fd, buf.ptr, buf.len);
    switch (std.posix.errno(rc)) {
        .SUCCESS => if (rc != buf.len) return error.Io,
        .AGAIN, .INTR => return error.WouldBlock,
        else => |e| return mapErr(e),
    }
}

pub fn ioctl(fd: fd_t, request: u32, arg: *anyopaque) PortError!void {
    const rc = linux.ioctl(fd, request, @intFromPtr(arg));
    const e = std.posix.errno(rc);
    if (e != .SUCCESS) return mapErr(e);
}

test "name validation" {
    try validateName("eth0");
    try validateName("vnat-tun0");
    try std.testing.expectError(error.InvalidArgument, validateName(""));
    try std.testing.expectError(error.InvalidArgument, validateName("eth0/x"));
    try std.testing.expectError(error.InvalidArgument, validateName("eth 0"));
    try std.testing.expectError(error.InvalidArgument, validateName("a" ** 16));
}
