//! Keeps the shipped examples honest: every example must parse and validate.

const std = @import("std");
const vrouter = @import("../src/lib.zig");

test "example configs parse and validate" {
    for ([_][]const u8{
        "examples/minimal.json",
        "examples/travel-router.json",
    }) |path| {
        const source = try std.Io.Dir.cwd().readFileAlloc(
            std.testing.io,
            path,
            std.testing.allocator,
            .limited(1 << 20),
        );
        defer std.testing.allocator.free(source);

        var parsed = try vrouter.config_parse.parse(std.testing.allocator, source);
        defer parsed.deinit();

        try vrouter.config_validate.validate(&parsed.config);
    }
}
