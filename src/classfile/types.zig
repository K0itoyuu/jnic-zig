const std = @import("std");

// JVM Access Flags
pub const ACC_PUBLIC: u16 = 0x0001;
pub const ACC_PRIVATE: u16 = 0x0002;
pub const ACC_PROTECTED: u16 = 0x0004;
pub const ACC_STATIC: u16 = 0x0008;
pub const ACC_FINAL: u16 = 0x0010;
pub const ACC_SYNCHRONIZED: u16 = 0x0020;
pub const ACC_BRIDGE: u16 = 0x0040;
pub const ACC_VARARGS: u16 = 0x0080;
pub const ACC_NATIVE: u16 = 0x0100;
pub const ACC_ABSTRACT: u16 = 0x0400;
pub const ACC_STRICT: u16 = 0x0800;
pub const ACC_SYNTHETIC: u16 = 0x1000;

// Constant Pool Tags
pub const CONSTANT_Utf8: u8 = 1;
pub const CONSTANT_Integer: u8 = 3;
pub const CONSTANT_Float: u8 = 4;
pub const CONSTANT_Long: u8 = 5;
pub const CONSTANT_Double: u8 = 6;
pub const CONSTANT_Class: u8 = 7;
pub const CONSTANT_String: u8 = 8;
pub const CONSTANT_Fieldref: u8 = 9;
pub const CONSTANT_Methodref: u8 = 10;
pub const CONSTANT_InterfaceMethodref: u8 = 11;
pub const CONSTANT_NameAndType: u8 = 12;
pub const CONSTANT_MethodHandle: u8 = 15;
pub const CONSTANT_MethodType: u8 = 16;
pub const CONSTANT_Dynamic: u8 = 17;
pub const CONSTANT_InvokeDynamic: u8 = 18;
pub const CONSTANT_Module: u8 = 19;
pub const CONSTANT_Package: u8 = 20;

pub const CpInfo = union(enum) {
    none: void,
    utf8: []const u8,
    integer: i32,
    float: f32,
    long: i64,
    double: f64,
    class: u16, // name_index
    string: u16, // string_index
    fieldref: Ref,
    methodref: Ref,
    interface_methodref: Ref,
    name_and_type: NameAndType,
    method_handle: MethodHandle,
    method_type: u16, // descriptor_index
    dynamic: DynamicInfo,
    invoke_dynamic: DynamicInfo,
    module: u16, // name_index
    package: u16, // name_index

    // Placeholder for the second slot of long/double
    long_continuation: void,
};

pub const Ref = struct {
    class_index: u16,
    name_and_type_index: u16,
};

pub const NameAndType = struct {
    name_index: u16,
    descriptor_index: u16,
};

pub const MethodHandle = struct {
    reference_kind: u8,
    reference_index: u16,
};

pub const DynamicInfo = struct {
    bootstrap_method_attr_index: u16,
    name_and_type_index: u16,
};

pub const AttributeInfo = struct {
    name_index: u16,
    data: []const u8,
};

pub const FieldInfo = struct {
    access_flags: u16,
    name_index: u16,
    descriptor_index: u16,
    attributes: []AttributeInfo,
};

pub const MethodInfo = struct {
    access_flags: u16,
    name_index: u16,
    descriptor_index: u16,
    attributes: []AttributeInfo,
};

pub const ClassFile = struct {
    minor_version: u16,
    major_version: u16,
    constant_pool: []CpInfo,
    access_flags: u16,
    this_class: u16,
    super_class: u16,
    interfaces: []u16,
    fields: []FieldInfo,
    methods: []MethodInfo,
    attributes: []AttributeInfo,

    pub fn getUtf8(self: *const ClassFile, index: u16) ?[]const u8 {
        if (index == 0 or index >= self.constant_pool.len) return null;
        return switch (self.constant_pool[index]) {
            .utf8 => |s| s,
            else => null,
        };
    }

    pub fn getClassName(self: *const ClassFile, class_index: u16) ?[]const u8 {
        if (class_index == 0 or class_index >= self.constant_pool.len) return null;
        return switch (self.constant_pool[class_index]) {
            .class => |name_idx| self.getUtf8(name_idx),
            else => null,
        };
    }

    pub fn getThisClassName(self: *const ClassFile) ?[]const u8 {
        return self.getClassName(self.this_class);
    }
};
