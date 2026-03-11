const std = @import("std");

const String = struct {
    ptr: usize,
    len: usize,
};
pub fn isEqual(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
pub fn startsWith(haystack: []const u8, needle: []const u8) bool {
    return std.mem.startsWith(u8, haystack, needle);
}
