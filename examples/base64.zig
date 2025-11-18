const std = @import("std");
const zigkit = @import("zigkit");
//just simple comparison
pub fn main() !void {
    const to_encode = "TestMe!";
    const expected_encoded = "VGVzdE1lIQ==";
    const encoded = try zigkit.encoding.base64.encode(to_encode);
    const decoded = zigkit.encoding.base64.decode(expected_encoded);
    std.debug.assert(std.mem.eql(u8, expected_encoded, encoded));
    std.debug.assert(std.mem.eql(u8, decoded, to_encode));
}
