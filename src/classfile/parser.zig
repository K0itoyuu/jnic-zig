const std = @import("std");
const types = @import("types.zig");
const Reader = @import("../util/reader.zig").Reader;

const CpInfo = types.CpInfo;
const ClassFile = types.ClassFile;
const AttributeInfo = types.AttributeInfo;
const FieldInfo = types.FieldInfo;
const MethodInfo = types.MethodInfo;

pub const ParseError = error{
    InvalidMagic,
    InvalidConstantPoolTag,
    UnexpectedEof,
    OutOfMemory,
};

pub fn parse(allocator: std.mem.Allocator, data: []const u8) ParseError!ClassFile {
    var reader = Reader.init(data);

    // Magic number: 0xCAFEBABE
    const magic = reader.readU32() catch return error.UnexpectedEof;
    if (magic != 0xCAFEBABE) return error.InvalidMagic;

    const minor = reader.readU16() catch return error.UnexpectedEof;
    const major = reader.readU16() catch return error.UnexpectedEof;

    // Constant pool
    const cp_count = reader.readU16() catch return error.UnexpectedEof;
    const constant_pool = try parseConstantPool(allocator, &reader, cp_count);

    const access_flags = reader.readU16() catch return error.UnexpectedEof;
    const this_class = reader.readU16() catch return error.UnexpectedEof;
    const super_class = reader.readU16() catch return error.UnexpectedEof;

    // Interfaces
    const iface_count = reader.readU16() catch return error.UnexpectedEof;
    const interfaces = try allocator.alloc(u16, iface_count);
    for (0..iface_count) |i| {
        interfaces[i] = reader.readU16() catch return error.UnexpectedEof;
    }

    // Fields
    const field_count = reader.readU16() catch return error.UnexpectedEof;
    const fields = try allocator.alloc(FieldInfo, field_count);
    for (0..field_count) |i| {
        fields[i] = try parseField(allocator, &reader);
    }

    // Methods
    const method_count = reader.readU16() catch return error.UnexpectedEof;
    const methods = try allocator.alloc(MethodInfo, method_count);
    for (0..method_count) |i| {
        methods[i] = try parseMethod(allocator, &reader);
    }

    // Class attributes
    const attributes = try parseAttributes(allocator, &reader);

    return ClassFile{
        .minor_version = minor,
        .major_version = major,
        .constant_pool = constant_pool,
        .access_flags = access_flags,
        .this_class = this_class,
        .super_class = super_class,
        .interfaces = interfaces,
        .fields = fields,
        .methods = methods,
        .attributes = attributes,
    };
}
fn parseConstantPool(allocator: std.mem.Allocator, reader: *Reader, count: u16) ParseError![]CpInfo {
    const pool = try allocator.alloc(CpInfo, count);
    pool[0] = .none;

    var i: u16 = 1;
    while (i < count) {
        const tag = reader.readU8() catch return error.UnexpectedEof;
        pool[i] = switch (tag) {
            types.CONSTANT_Utf8 => blk: {
                const len = reader.readU16() catch return error.UnexpectedEof;
                const bytes = reader.readBytes(len) catch return error.UnexpectedEof;
                break :blk CpInfo{ .utf8 = bytes };
            },
            types.CONSTANT_Integer => blk: {
                const v = reader.readU32() catch return error.UnexpectedEof;
                break :blk CpInfo{ .integer = @bitCast(v) };
            },
            types.CONSTANT_Float => blk: {
                const v = reader.readU32() catch return error.UnexpectedEof;
                break :blk CpInfo{ .float = @bitCast(v) };
            },
            types.CONSTANT_Long => blk: {
                const high = reader.readU32() catch return error.UnexpectedEof;
                const low = reader.readU32() catch return error.UnexpectedEof;
                const val: i64 = @bitCast((@as(u64, high) << 32) | @as(u64, low));
                i += 1;
                pool[i] = .long_continuation;
                break :blk CpInfo{ .long = val };
            },
            types.CONSTANT_Double => blk: {
                const high = reader.readU32() catch return error.UnexpectedEof;
                const low = reader.readU32() catch return error.UnexpectedEof;
                const val: f64 = @bitCast((@as(u64, high) << 32) | @as(u64, low));
                i += 1;
                pool[i] = .long_continuation;
                break :blk CpInfo{ .double = val };
            },
            types.CONSTANT_Class => CpInfo{ .class = reader.readU16() catch return error.UnexpectedEof },
            types.CONSTANT_String => CpInfo{ .string = reader.readU16() catch return error.UnexpectedEof },
            types.CONSTANT_Fieldref => CpInfo{ .fieldref = .{
                .class_index = reader.readU16() catch return error.UnexpectedEof,
                .name_and_type_index = reader.readU16() catch return error.UnexpectedEof,
            } },
            types.CONSTANT_Methodref => CpInfo{ .methodref = .{
                .class_index = reader.readU16() catch return error.UnexpectedEof,
                .name_and_type_index = reader.readU16() catch return error.UnexpectedEof,
            } },
            types.CONSTANT_InterfaceMethodref => CpInfo{ .interface_methodref = .{
                .class_index = reader.readU16() catch return error.UnexpectedEof,
                .name_and_type_index = reader.readU16() catch return error.UnexpectedEof,
            } },
            types.CONSTANT_NameAndType => CpInfo{ .name_and_type = .{
                .name_index = reader.readU16() catch return error.UnexpectedEof,
                .descriptor_index = reader.readU16() catch return error.UnexpectedEof,
            } },
            types.CONSTANT_MethodHandle => CpInfo{ .method_handle = .{
                .reference_kind = reader.readU8() catch return error.UnexpectedEof,
                .reference_index = reader.readU16() catch return error.UnexpectedEof,
            } },
            types.CONSTANT_MethodType => CpInfo{ .method_type = reader.readU16() catch return error.UnexpectedEof },
            types.CONSTANT_Dynamic => CpInfo{ .dynamic = .{
                .bootstrap_method_attr_index = reader.readU16() catch return error.UnexpectedEof,
                .name_and_type_index = reader.readU16() catch return error.UnexpectedEof,
            } },
            types.CONSTANT_InvokeDynamic => CpInfo{ .invoke_dynamic = .{
                .bootstrap_method_attr_index = reader.readU16() catch return error.UnexpectedEof,
                .name_and_type_index = reader.readU16() catch return error.UnexpectedEof,
            } },
            types.CONSTANT_Module => CpInfo{ .module = reader.readU16() catch return error.UnexpectedEof },
            types.CONSTANT_Package => CpInfo{ .package = reader.readU16() catch return error.UnexpectedEof },
            else => return error.InvalidConstantPoolTag,
        };
        i += 1;
    }
    return pool;
}

fn parseField(allocator: std.mem.Allocator, reader: *Reader) ParseError!FieldInfo {
    return FieldInfo{
        .access_flags = reader.readU16() catch return error.UnexpectedEof,
        .name_index = reader.readU16() catch return error.UnexpectedEof,
        .descriptor_index = reader.readU16() catch return error.UnexpectedEof,
        .attributes = try parseAttributes(allocator, reader),
    };
}

fn parseMethod(allocator: std.mem.Allocator, reader: *Reader) ParseError!MethodInfo {
    return MethodInfo{
        .access_flags = reader.readU16() catch return error.UnexpectedEof,
        .name_index = reader.readU16() catch return error.UnexpectedEof,
        .descriptor_index = reader.readU16() catch return error.UnexpectedEof,
        .attributes = try parseAttributes(allocator, reader),
    };
}

fn parseAttributes(allocator: std.mem.Allocator, reader: *Reader) ParseError![]AttributeInfo {
    const count = reader.readU16() catch return error.UnexpectedEof;
    const attrs = try allocator.alloc(AttributeInfo, count);
    for (0..count) |i| {
        const name_index = reader.readU16() catch return error.UnexpectedEof;
        const length = reader.readU32() catch return error.UnexpectedEof;
        const data = reader.readBytes(length) catch return error.UnexpectedEof;
        attrs[i] = .{ .name_index = name_index, .data = data };
    }
    return attrs;
}
