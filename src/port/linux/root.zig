pub const sys = @import("sys.zig");
pub const iface = @import("iface.zig");
pub const tun = @import("tun.zig");
pub const af_packet = @import("af_packet.zig");
pub const netlink = @import("netlink.zig");

test {
    _ = @import("sys.zig");
    _ = @import("iface.zig");
    _ = @import("tun.zig");
    _ = @import("af_packet.zig");
    _ = @import("netlink.zig");
}
