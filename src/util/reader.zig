const std = @import("std");

/// Big-endian binary reader for JVM class file format
pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    pub fn readU8(self: *Reader) !u8 {
        if (self.pos >= self.data.len) return error.UnexpectedEof;
        const val = self.data[self.pos];
        self.pos += 1;
        return val;
    }

    pub fn readU16(self: *Reader) !u16 {
        if (self.pos + 2 > self.data.len) return error.UnexpectedEof;
        const val = std.mem.readInt(u16, self.data[self.pos..][0..2], .big);
        self.pos += 2;
        return val;
    }

    pub fn readU32(self: *Reader) !u32 {
        if (self.pos + 4 > self.data.len) return error.UnexpectedEof;
        const val = std.mem.readInt(u32, self.data[self.pos..][0..4], .big);
        self.pos += 4;
        return val;
    }

    pub fn readBytes(self: *Reader, len: usize) ![]const u8 {
        if (self.pos + len > self.data.len) return error.UnexpectedEof;
        const slice = self.data[self.pos .. self.pos + len];
        self.pos += len;
        return slice;
    }

    pub fn remaining(self: *const Reader) usize {
        return self.data.len - self.pos;
    }
};
