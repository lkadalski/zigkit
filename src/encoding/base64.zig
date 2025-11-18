const std = @import("std");

// 🔹 Zadanie: Base64 decoder
// Cel
// Napisz funkcję, która zamienia Base64 string z powrotem na bajty ([]u8). Funkcja powinna obsłużyć padding (=) i różne długości wejścia.
// Krok po kroku
// Sygnatura funkcji
// pub fn decode(allocator: *std.mem.Allocator, input: []const u8) ![]u8
// input → Base64 string (np. "QUFB").
// Zwraca nowy slice alokowany przez allocator z odkodowanymi bajtami.
// Walidacja długości
// Base64 string musi mieć długość będącą wielokrotnością 4.
// Padding = może występować na końcu 1–2 znaki.
// Możesz odrzucić niepoprawne znaki (opcjonalnie na razie zakładamy poprawny input).
// Zamiana znaków Base64 na wartości 6-bitowe
// Stwórz funkcję _value_of(c: u8) u8 → zamienia znak 'A'..'Z', 'a'..'z', '0'..'9', '+', '/' na wartość 0–63.
// = → traktuj jako 0.
// Przetwarzanie po 4 znaki (24 bity)
// Dla każdej grupy 4 znaków Base64:
// Zamień znaki na wartości 6-bitowe: b0, b1, b2, b3.
// Połącz w 3 bajty:
// byte0 = (b0 << 2) | (b1 >> 4)
// byte1 = (b1 << 4) | (b2 >> 2)
// byte2 = (b2 << 6) | b3
// Jeśli padding jest obecny, usuń niepotrzebne bajty:
// 1 = → usuń ostatni bajt
// 2 = → usuń ostatnie 2 bajty
// Alokacja bufora
// Oblicz docelową długość:
// const out_len = (input.len / 4) * 3 - pad_count;
// Alokuj out przez allocator i wpisuj bajty po kolei.
// Zwróć wynik
// Zwróć slice []u8 z odkodowanymi bajtami.
// 🔹 Bonus / dodatkowe zadania
// Obsłuż niepoprawne znaki i zwracaj błąd (error.InvalidChar).
// Zaimplementuj decode tak, aby działał zarówno na stringach z paddingiem jak i bez.
// Dodaj testy:
// "QUFB" → AAA
// "QUFBCg==" → AAA\n
pub fn decode(input: []const u8) []const u8 {
    return input;
}
pub fn encode(input: []const u8) ![]const u8 {
    if (input.len == 0) {
        return "";
    }
    const encoder = Base64.init();
    //expose allocator later
    var buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();
    // defer allocator.free();
    return encoder.encode(allocator, input);
}

const Base64 = struct {
    _table: *const [64]u8,
    pub fn init() Base64 {
        const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lower = "abcdefghijklmnopqrstuvwxyz";
        const numbers = "0123456789";
        const characters = "+/";
        return Base64{
            ._table = upper ++ lower ++ numbers ++ characters,
        };
    }
    pub fn _char_at(self: Base64, index: usize) u8 {
        return self._table[index];
    }
    pub fn _calc_encode_length(input: []const u8) !usize {
        return ((input.len + 2) / 3) * 4;
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
test "compare base64 alphabet string with std lib" {
    const base = Base64.init();
    const std_lib_chars = std.base64.standard_alphabet_chars;
    try std.testing.expect(std.mem.eql(u8, base._table, &std_lib_chars));
}
test "base64 encoding of empty string should be empty" {
    const result = try encode("");
    try std.testing.expect(std.mem.eql(u8, result, ""));
}
test "should calculate enough bytes for out" {
    const input = "teststring";
    const calculated = Base64._calc_encode_length(input) catch @panic("Failing!");
    try std.testing.expectEqual(16, calculated);
}
