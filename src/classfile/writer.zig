const std = @import("std");
const types = @import("types.zig");
const BinWriter = @import("../util/writer.zig").Writer;

const CpInfo = types.CpInfo;
const ClassFile = types.ClassFile;

pub fn write(allocator: std.mem.Allocator, cf: *const ClassFile) ![]u8 {
    var w = BinWriter.init(allocator);
    defer w.deinit();

    // Magic
    try w.writeU32(0xCAFEBABE);
    try w.writeU16(cf.minor_version);
    try w.writeU16(cf.major_version);

    // Constant pool
    const cp_count: u16 = @intCast(cf.constant_pool.len);
    try w.writeU16(cp_count);
    var i: u16 = 1;
    while (i < cp_count) {
        try writeCpEntry(&w, cf.constant_pool[i]);
        switch (cf.constant_pool[i]) {
            .long, .double => i += 2,
            else => i += 1,
        }
    }

    try w.writeU16(cf.access_flags);
    try w.writeU16(cf.this_class);
    try w.writeU16(cf.super_class);

    // Interfaces
    try w.writeU16(@intCast(cf.interfaces.len));
    for (cf.interfaces) |iface| {
        try w.writeU16(iface);
    }

    // Fields
    try w.writeU16(@intCast(cf.fields.len));
    for (cf.fields) |field| {
        try writeFieldOrMethod(&w, field.access_flags, field.name_index, field.descriptor_index, field.attributes);
    }

    // Methods
    try w.writeU16(@intCast(cf.methods.len));
    for (cf.methods) |method| {
        try writeFieldOrMethod(&w, method.access_flags, method.name_index, method.descriptor_index, method.attributes);
    }

    // Attributes
    try writeAttributes(&w, cf.attributes);

    return w.toOwnedSlice();
}
fn writeCpEntry(w: *BinWriter, entry: CpInfo) !void {
    switch (entry) {
        .none, .long_continuation => {},
        .utf8 => |s| {
            try w.writeU8(types.CONSTANT_Utf8);
            try w.writeU16(@intCast(s.len));
            try w.writeBytes(s);
        },
        .integer => |v| {
            try w.writeU8(types.CONSTANT_Integer);
            try w.writeU32(@bitCast(v));
        },
        .float => |v| {
            try w.writeU8(types.CONSTANT_Float);
            try w.writeU32(@bitCast(v));
        },
        .long => |v| {
            try w.writeU8(types.CONSTANT_Long);
            const bits: u64 = @bitCast(v);
            try w.writeU32(@intCast(bits >> 32));
            try w.writeU32(@intCast(bits & 0xFFFFFFFF));
        },
        .double => |v| {
            try w.writeU8(types.CONSTANT_Double);
            const bits: u64 = @bitCast(v);
            try w.writeU32(@intCast(bits >> 32));
            try w.writeU32(@intCast(bits & 0xFFFFFFFF));
        },
        .class => |idx| {
            try w.writeU8(types.CONSTANT_Class);
            try w.writeU16(idx);
        },
        .string => |idx| {
            try w.writeU8(types.CONSTANT_String);
            try w.writeU16(idx);
        },
        .fieldref => |r| {
            try w.writeU8(types.CONSTANT_Fieldref);
            try w.writeU16(r.class_index);
            try w.writeU16(r.name_and_type_index);
        },
        .methodref => |r| {
            try w.writeU8(types.CONSTANT_Methodref);
            try w.writeU16(r.class_index);
            try w.writeU16(r.name_and_type_index);
        },
        .interface_methodref => |r| {
            try w.writeU8(types.CONSTANT_InterfaceMethodref);
            try w.writeU16(r.class_index);
            try w.writeU16(r.name_and_type_index);
        },
        .name_and_type => |nt| {
            try w.writeU8(types.CONSTANT_NameAndType);
            try w.writeU16(nt.name_index);
            try w.writeU16(nt.descriptor_index);
        },
        .method_handle => |mh| {
            try w.writeU8(types.CONSTANT_MethodHandle);
            try w.writeU8(mh.reference_kind);
            try w.writeU16(mh.reference_index);
        },
        .method_type => |idx| {
            try w.writeU8(types.CONSTANT_MethodType);
            try w.writeU16(idx);
        },
        .dynamic => |d| {
            try w.writeU8(types.CONSTANT_Dynamic);
            try w.writeU16(d.bootstrap_method_attr_index);
            try w.writeU16(d.name_and_type_index);
        },
        .invoke_dynamic => |d| {
            try w.writeU8(types.CONSTANT_InvokeDynamic);
            try w.writeU16(d.bootstrap_method_attr_index);
            try w.writeU16(d.name_and_type_index);
        },
        .module => |idx| {
            try w.writeU8(types.CONSTANT_Module);
            try w.writeU16(idx);
        },
        .package => |idx| {
            try w.writeU8(types.CONSTANT_Package);
            try w.writeU16(idx);
        },
    }
}

fn writeFieldOrMethod(w: *BinWriter, flags: u16, name_idx: u16, desc_idx: u16, attrs: []const types.AttributeInfo) !void {
    try w.writeU16(flags);
    try w.writeU16(name_idx);
    try w.writeU16(desc_idx);
    try writeAttributes(w, attrs);
}

fn writeAttributes(w: *BinWriter, attrs: []const types.AttributeInfo) !void {
    try w.writeU16(@intCast(attrs.len));
    for (attrs) |attr| {
        try w.writeU16(attr.name_index);
        try w.writeU32(@intCast(attr.data.len));
        try w.writeBytes(attr.data);
    }
}
