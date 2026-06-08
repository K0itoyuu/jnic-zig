const std = @import("std");

/// Big-endian binary writer for JVM class file format
pub const Writer = struct {
    buffer: std.ArrayList(u8) = .empty,
    gpa: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Writer {
        return .{ .gpa = allocator };
    }

    pub fn deinit(self: *Writer) void {
        self.buffer.deinit(self.gpa);
    }

    pub fn writeU8(self: *Writer, val: u8) !void {
        try self.buffer.append(self.gpa, val);
    }

    pub fn writeU16(self: *Writer, val: u16) !void {
        var buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &buf, val, .big);
        try self.buffer.appendSlice(self.gpa, &buf);
    }

    pub fn writeU32(self: *Writer, val: u32) !void {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, val, .big);
        try self.buffer.appendSlice(self.gpa, &buf);
    }

    pub fn writeBytes(self: *Writer, bytes: []const u8) !void {
        try self.buffer.appendSlice(self.gpa, bytes);
    }

    pub fn toOwnedSlice(self: *Writer) ![]u8 {
        return self.buffer.toOwnedSlice(self.gpa);
    }
};
