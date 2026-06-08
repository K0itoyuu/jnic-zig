const std = @import("std");

pub const Config = struct {
    watermark: []const u8 = "JNIC-zig",
    use_ffm: bool = false,
    anti_debug: bool = true,
    renamer: bool = false,
    remove_native_annotation: bool = false,
    fast_math: bool = false,
    input_jar: []const u8 = "./input.jar",
    output_jar: []const u8 = "./output.jar",
};

/// Minimal TOML parser for flat key-value config
pub fn parseConfig(allocator: std.mem.Allocator, data: []const u8) !Config {
    var config = Config{};
    var lines = std.mem.splitScalar(u8, data, '\n');

    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == '[') continue;

        const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq_pos], " \t");
        const val = std.mem.trim(u8, line[eq_pos + 1 ..], " \t");

        if (std.mem.eql(u8, key, "watermark")) {
            config.watermark = try parseString(allocator, val);
        } else if (std.mem.eql(u8, key, "use_ffm")) {
            config.use_ffm = parseBool(val);
        } else if (std.mem.eql(u8, key, "anti_debug")) {
            config.anti_debug = parseBool(val);
        } else if (std.mem.eql(u8, key, "renamer")) {
            config.renamer = parseBool(val);
        } else if (std.mem.eql(u8, key, "remove_native_annotation")) {
            config.remove_native_annotation = parseBool(val);
        } else if (std.mem.eql(u8, key, "fast_math")) {
            config.fast_math = parseBool(val);
        } else if (std.mem.eql(u8, key, "input_jar")) {
            config.input_jar = try parseString(allocator, val);
        } else if (std.mem.eql(u8, key, "output_jar")) {
            config.output_jar = try parseString(allocator, val);
        }
    }

    return config;
}

fn parseString(allocator: std.mem.Allocator, val: []const u8) ![]const u8 {
    if (val.len >= 2 and val[0] == '"' and val[val.len - 1] == '"') {
        return try allocator.dupe(u8, val[1 .. val.len - 1]);
    }
    return try allocator.dupe(u8, val);
}

fn parseBool(val: []const u8) bool {
    return std.mem.eql(u8, val, "true");
}
