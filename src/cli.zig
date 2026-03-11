const std = @import("std");
const CLIError = error{
    InputNotAStruct,
    MissingCLIName,
    HelpPrinted,
};

const CliParser = struct {
    pub const FlagStyle = enum { Short, Long };
    flag_style: FlagStyle = .Long,

    fn provideDefaultValues(comptime T: type, info: std.builtin.Type.Struct) T {
        var result: T = undefined;

        inline for (info.fields) |field| {
            if (field.defaultValue()) |val| {
                @field(result, field.name) = val;
            } else {
                switch (@typeInfo(field.type)) {
                    .bool => @field(result, field.name) = false,
                    .int, .comptime_int => @field(result, field.name) = @as(field.type, 0),
                    .float => @field(result, field.name) = @as(field.type, 0),
                    .pointer, .optional => @field(result, field.name) = null,
                    else => @field(result, field.name) = @as(field.type, undefined),
                }
            }
        }
        return result;
    }

    fn parseInternal(comptime T: type) !T {
        const ti = @typeInfo(T);
        var result: T = undefined;
        switch (ti) {
            .@"struct" => |info| {
                result = provideDefaultValues(T, info);
            },
            else => {
                return error.InputNotAStruct;
            },
        }
        return result;
    }

    pub fn parse(T: type, args: [][]const u8) !T {
        //1. Analyze fields in T. Check if T is a struct!
        const resultWithDefaults = parseInternal(T);
        //2. Iterate over results, find matching.
        for (args, 0..) |arg, idx| {
            if (idx == 0 and std.mem.startsWith(u8, arg, "-")) {
                return error.MissingCLIName;
            }
            if (idx == 1 and std.mem.eql(u8, arg, "-h")) {
                // var buf: [1024]u8 = undefined;
                var buf: [512]u8 = undefined;
                // Prawidłowe wywołanie: .writer() wymaga bufora
                const stdout_writer = std.fs.File.stdout().writer(&buf);
                try printHelp(stdout_writer);
                // Bardzo ważne: Wymuś zapisanie reszty bufora przed zakończeniem
                try stdout_writer.flush();
                return error.HelpPrinted;
            }
        }
        return resultWithDefaults;
        //3. Use constructor a initialize Struct with default values.
    }
    pub fn printHelp(writer: anytype) !void {
        const message = "HELP PAGE";
        try std.fmt.format(writer, "{s}\n", .{message});
        // try writer.print("HELP PAGE", .{});
    }
};

test "should fail to parse non struct Type" {
    var argv = [_][]const u8{ "mycli", "-v" };
    try std.testing.expectError(CLIError.InputNotAStruct, CliParser.parse(u8, argv[0..]));
}

test "should fail to parse args with no binary name" {
    var argv = [_][]const u8{"-v"};
    const Args = struct { noDefault: u8 };
    try std.testing.expectError(CLIError.MissingCLIName, CliParser.parse(Args, argv[0..]));
}
test "should print help page" {
    // var argv = [_][]const u8{ "cli", "-h" };
    // const Args = struct { noDefault: u8 };
    var buffer: [128]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);

    const writer = fbs.writer();
    try CliParser.printHelp(writer);
    const actualOutput = fbs.getWritten();
    try std.testing.expectEqualStrings("HELP PAGE", actualOutput);
}
test "should parse defaults" {
    const Args = struct { verbose: bool = true, shouldFalse: bool = false, age: u8 = 55, name: []const u8 = "unknown", noDefault: u8 };

    var argv = [_][]const u8{"mycli"};
    const parsed = try CliParser.parse(Args, argv[0..]);

    try std.testing.expect(parsed.verbose == true);
    try std.testing.expect(parsed.shouldFalse == false);
    try std.testing.expect(parsed.age == 55);
    try std.testing.expect(std.mem.eql(u8, parsed.name, "unknown"));
    try std.testing.expect(parsed.noDefault == 0);
    //how to check type ?
}
