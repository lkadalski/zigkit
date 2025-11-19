const std = @import("std");
//Main Decoder
pub fn decode(allocator: std.mem.Allocator, input: []const u8) []const u8 {
    if (input.len == 0) {
        return "";
    }
    const decoder = Base64.init();
    return decoder.decode(allocator, input);
}
//Main Encoder
pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
    if (input.len == 0) {
        return "";
    }
    const encoder = Base64.init();
    return encoder.encode(allocator, input);
}

const Base64 = struct {
    _table: *const [64]u8,
    _table256: [256]bool,
    _lookupTable256: [256]u8,
    pub fn init() Base64 {
        const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lower = "abcdefghijklmnopqrstuvwxyz";
        const numbers = "0123456789";
        const characters = "+/";
        const table = upper ++ lower ++ numbers ++ characters;
        return Base64{ ._table = table, ._table256 = init_256_table(), ._lookupTable256 = init_lookup_table(table) };
    }
    fn init_256_table() [256]bool {
        var t: [256]bool = .{false} ** 256;
        for ('A'..'Z' + 1) |c| t[c] = true;
        for ('a'..'z' + 1) |c| t[c] = true;
        for ('0'..'9' + 1) |c| t[c] = true;
        t['+'] = true;
        t['/'] = true;
        return t;
    }
    fn init_lookup_table(table: *const [64]u8) [256]u8 {
        var lookup: [256]u8 = .{255} ** 256; // 255 = invalid marker

        for (table, 0..) |c, i| {
            lookup[c] = @intCast(i);
        }

        // '=' traktujemy osobno – dajemy mu wartość np. 64
        lookup['='] = 64;
        return lookup;
    }
    pub fn _char_at(self: Base64, index: usize) u8 {
        return self._table[index];
    }
    pub fn _char_index(self: Base64, char: u8) u8 {
        return self._lookupTable256[char];
    }
    pub fn _char_exists(self: Base64, char: u8) bool {
        return self._table256[char];
    }
    pub fn _calc_encode_length(input: []const u8) !usize {
        return ((input.len + 2) / 3) * 4;
    }
    pub fn _calc_decode_length(self: Base64, input: []const u8) Base64Error!usize {
        const len = input.len;
        if (len == 0) {
            return 0;
        }
        if (len % 4 != 0) {
            return error.InvalidLength;
        }
        var padding: u32 = 0;
        if (input[len - 1] == '=') {
            padding += 1;
        }
        if (input[len - 2] == '=') {
            padding += 1;
        }
        const body_len = len - padding;
        //is valid base64 ?
        for (input[0..body_len]) |char| {
            if (char == '=') return Base64Error.InvalidInput;
            if (!self._char_exists(char)) return Base64Error.InvalidInput;
        }
        if (len == padding) {
            return error.InvalidInput;
        }
        return ((input.len / 4) * 3) - padding;
    }
    pub fn encode(self: Base64, allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
        const out_bytes = try _calc_encode_length(input);
        var out = try allocator.alloc(u8, out_bytes);
        var j: usize = 0;
        var i: usize = 0;
        while (i < input.len) : (i += 3) {
            const end = if (i + 3 < input.len) i + 3 else input.len;
            const chunk: []const u8 = input[i..end];
            const bytes = turn_3_or_less_bytes_into_4(chunk);
            for (bytes) |byte| {
                out[j] = self._char_at(byte);
                j += 1;
            }
        }
        const remainder = input.len % 3;
        const pad_count: usize = if (remainder == 0) 0 else 3 - remainder;

        for (0..pad_count) |p| {
            out[out.len - 1 - p] = '=';
        }
        // std.debug.print("in.len={}, out_bytes={}, j={}\n", .{ input.len, out.len, j });
        return out;
    }
    //@TODO Rewrite it into my fashion. This is from pedro book.
    pub fn decode(self: Base64, allocator: std.mem.Allocator, input: []const u8) ![]const u8 {
        if (input.len == 0) {
            return "";
        }
        const n_output = try self._calc_decode_length(input);
        var output = try allocator.alloc(u8, n_output);
        var count: u8 = 0;
        var iout: u64 = 0;
        var buf = [4]u8{ 0, 0, 0, 0 };

        for (0..input.len) |i| {
            buf[count] = self._char_index(input[i]);
            count += 1;
            if (count == 4) {
                output[iout] = (buf[0] << 2) + (buf[1] >> 4);
                if (buf[2] != 64) {
                    output[iout + 1] = (buf[1] << 4) + (buf[2] >> 2);
                }
                if (buf[3] != 64) {
                    output[iout + 2] = (buf[2] << 6) + buf[3];
                }
                iout += 3;
                count = 0;
            }
        }

        return output;
        // const out_bytes = try _calc_decode_length(input);
        // var out = try allocator.alloc(u8, out_bytes);
        // var j: usize = 0;
        // var i: usize = 0;
        // while (i < input.len) : (i += 4) {
        //     //najpierw usunac pady
        //     //
        //     // //
        //     const end = if (i+4 < input.len) i + 4 else input.len;
        //     const chunk: []const u8 = input[i..end];
        //     const bytes = turn_4_or_less_bytes_into_3(chunk);

        // }
    }
    fn turn_3_or_less_bytes_into_4(input: []const u8) [4]u8 {
        var out: [4]u8 = undefined;
        const b0 = if (input.len > 0) input[0] else 0;
        const b1 = if (input.len > 1) input[1] else 0;
        const b2 = if (input.len > 2) input[2] else 0;
        out[0] = b0 >> 2;
        out[1] = (b0 & 0b00000011) << 4 | (b1 >> 4);
        out[2] = (b1 & 0b00001111) << 2 | (b2 >> 6);
        out[3] = b2 & 0b00111111;
        return out;
    }
    test "should turn 3 bytes into 4" {
        const input = [3]u8{ 0b01000001, 0b01000001, 0b01000011 };
        const output = turn_3_or_less_bytes_into_4(&input);
        try std.testing.expectEqual(4, output.len);
        try std.testing.expectEqual(0b00010000, output[0]);
        try std.testing.expectEqual(0b00010100, output[1]);
        try std.testing.expectEqual(0b00000101, output[2]);
        try std.testing.expectEqual(0b00000011, output[3]);
    }
};

test "encode should work on simple text" {
    const base = Base64.init();
    var input: []const u8 = "AAA";
    const allocator = std.testing.allocator;
    var output = try base.encode(allocator, input);
    try std.testing.expectEqualStrings("QUFB", output);
    allocator.free(output);
    input = "AAAA";
    output = try base.encode(allocator, input);
    try std.testing.expectEqualStrings("QUFBQQ==", output);
    allocator.free(output);
}
test "decode should work on simple text" {
    const base = Base64.init();
    var input: []const u8 = "QUFB";
    const allocator = std.testing.allocator;
    var output = try base.decode(allocator, input);
    try std.testing.expectEqualStrings("AAA", output);
    allocator.free(output);
    input = "QUFBQQ==";
    output = try base.decode(allocator, input);
    try std.testing.expectEqualStrings("AAAA", output);
    allocator.free(output);
}
test "compare base64 alphabet string with std lib" {
    const base = Base64.init();
    const std_lib_chars = std.base64.standard_alphabet_chars;
    try std.testing.expect(std.mem.eql(u8, base._table, &std_lib_chars));
}
test "base64 encoding of empty string should be empty" {
    const base = Base64.init();
    const allocator = std.testing.allocator;
    const result = try base.encode(allocator, "");
    try std.testing.expect(std.mem.eql(u8, result, ""));
}
test "encoder should calculate enough bytes for out" {
    const table = [_]Entry{ .{ .key = "teststring", .val = 16 }, .{ .key = "base64", .val = 8 }, .{ .key = "l", .val = 4 } };
    for (table) |input| {
        const calculated = Base64._calc_encode_length(input.key) catch @panic("Failing!");
        try std.testing.expectEqual(input.val, calculated);
    }
}
test "decoder should calculate enough bytes for out" {
    const table = [_]Entry{ .{ .key = "emln", .val = 3 }, .{ .key = "YmFzZTY0", .val = 6 }, .{ .key = "bA==", .val = 1 } };
    const base64 = Base64.init();
    for (table) |input| {
        const calculated = base64._calc_decode_length(input.key) catch @panic("Failing!");
        try std.testing.expectEqual(input.val, calculated);
    }
}
test "should return correct error" {
    const base64 = Base64.init();
    const table = [_]Entry{ .{ .key = "====", .err = Base64Error.InvalidInput }, .{ .key = "===", .err = Base64Error.InvalidLength }, .{ .key = "a=", .err = Base64Error.InvalidLength } };
    for (table) |input| {
        _ = try std.testing.expectError(input.err, base64._calc_decode_length(input.key));
    }
}
const Entry = struct {
    key: []const u8,
    val: u32 = 0,
    err: Base64Error = Base64Error.InvalidInput,
};
const Base64Error = error{ InvalidInput, InvalidLength };
