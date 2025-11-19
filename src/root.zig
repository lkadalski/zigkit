pub const cli = @import("cli.zig");
pub const encoding = struct {
    pub const base64 = @import("encoding/base64.zig");
};
test "import tests from submodules" {
    _ = cli;
    _ = encoding.base64;
}
