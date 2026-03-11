const std = @import("std");
const zigkit = @import("zigkit");
pub fn main() !void {
    std.debug.print("This is cli.zig", .{});
    const Args = struct {
        verbose: bool = false,
    };
    const parsed: Args = zigkit.cli.parse(Args, std.process.args());
    std.debug.assert(std.mem.eql(bool, parsed.verbose, false));
}
