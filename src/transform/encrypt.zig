const std = @import("std");
const types = @import("../classfile/types.zig");

const STRING_ENCRYPT_DESC = "Lmaster/koitoyuu/jnic/StringEncrypt;";
const NUMBER_ENCRYPT_DESC = "Lmaster/koitoyuu/jnic/NumberEncrypt;";

pub const EncryptedString = struct {
    key: i64,
    value: []const u8,
    class_name: []const u8,
    decode_key: i64 = 0,
};

pub const NumberKind = enum(u8) {
    int = 0,
    long = 1,
    float = 2,
    double = 3,
};

pub const EncryptedNumber = struct {
    key: i64,
    value: i64,
    kind: NumberKind,
    class_name: []const u8,
    decode_key: i64 = 0,
};

pub const EncryptResult = struct {
    strings: []EncryptedString,
    numbers: []EncryptedNumber,
    modified: bool,
};

/// Decode-key field info for <clinit> initialization
const DkFieldEntry = struct {
    field_ref: u16, // CP Fieldref index (for getstatic)
    dk_long_cp: u16, // CP Long index (for ldc2_w in <clinit>)
};

/// Apply string/number encryption to a class file
pub fn encryptConstants(allocator: std.mem.Allocator, cf: *types.ClassFile, enchanted: bool) !EncryptResult {
    const class_name = cf.getThisClassName() orelse return EncryptResult{ .strings = &.{}, .numbers = &.{}, .modified = false };

    // Check class-level annotations
    const class_str_encrypt = hasAnnotation(cf, cf.attributes, STRING_ENCRYPT_DESC);
    const class_num_encrypt = hasAnnotation(cf, cf.attributes, NUMBER_ENCRYPT_DESC);

    if (!class_str_encrypt and !class_num_encrypt) {
        var any = false;
        for (cf.methods) |m| {
            if (hasAnnotation(cf, m.attributes, STRING_ENCRYPT_DESC) or hasAnnotation(cf, m.attributes, NUMBER_ENCRYPT_DESC)) { any = true; break; }
        }
        for (cf.fields) |f| {
            if (hasAnnotation(cf, f.attributes, STRING_ENCRYPT_DESC) or hasAnnotation(cf, f.attributes, NUMBER_ENCRYPT_DESC)) { any = true; break; }
        }
        if (!any) return EncryptResult{ .strings = &.{}, .numbers = &.{}, .modified = false };
    }

    var strings: std.ArrayList(EncryptedString) = .empty;
    defer strings.deinit(allocator);
    var numbers: std.ArrayList(EncryptedNumber) = .empty;
    defer numbers.deinit(allocator);
    var dk_fields: std.ArrayList(DkFieldEntry) = .empty;
    defer dk_fields.deinit(allocator);

    // Seed for key generation
    var key_seed: u64 = 0xDEADBEEF12345678;
    key_seed ^= @as(u64, @intCast(class_name.len)) *% 0x9E3779B97F4A7C15;

    // Shared CP entries
    const cp_j_desc = if (enchanted) try findOrAddUtf8(allocator, cf, "J") else 0;

    // Add CP entries for synthetic methods
    const cp_yuri_str_name = try findOrAddUtf8(allocator, cf, "jnic$native_string");
    const cp_yuri_int_name = try findOrAddUtf8(allocator, cf, "jnic$native_int");
    const cp_yuri_long_name = try findOrAddUtf8(allocator, cf, "jnic$native_long");
    const cp_yuri_float_name = try findOrAddUtf8(allocator, cf, "jnic$native_float");
    const cp_yuri_double_name = try findOrAddUtf8(allocator, cf, "jnic$native_double");
    // Descriptors: (JJ)X when enchanted (dual-key), (J)X when not (single-key, faster)
    const cp_str_desc = try findOrAddUtf8(allocator, cf, if (enchanted) "(JJ)Ljava/lang/String;" else "(J)Ljava/lang/String;");
    const cp_int_desc = try findOrAddUtf8(allocator, cf, if (enchanted) "(JJ)I" else "(J)I");
    const cp_long_desc = try findOrAddUtf8(allocator, cf, if (enchanted) "(JJ)J" else "(J)J");
    const cp_float_desc = try findOrAddUtf8(allocator, cf, if (enchanted) "(JJ)F" else "(J)F");
    const cp_double_desc = try findOrAddUtf8(allocator, cf, if (enchanted) "(JJ)D" else "(J)D");
    const cp_str_nat = try addCpEntry(allocator, cf, types.CpInfo{ .name_and_type = .{ .name_index = cp_yuri_str_name, .descriptor_index = cp_str_desc } });
    const cp_int_nat = try addCpEntry(allocator, cf, types.CpInfo{ .name_and_type = .{ .name_index = cp_yuri_int_name, .descriptor_index = cp_int_desc } });
    const cp_long_nat = try addCpEntry(allocator, cf, types.CpInfo{ .name_and_type = .{ .name_index = cp_yuri_long_name, .descriptor_index = cp_long_desc } });
    const cp_float_nat = try addCpEntry(allocator, cf, types.CpInfo{ .name_and_type = .{ .name_index = cp_yuri_float_name, .descriptor_index = cp_float_desc } });
    const cp_double_nat = try addCpEntry(allocator, cf, types.CpInfo{ .name_and_type = .{ .name_index = cp_yuri_double_name, .descriptor_index = cp_double_desc } });
    const cp_str_ref = try addCpEntry(allocator, cf, types.CpInfo{ .methodref = .{ .class_index = cf.this_class, .name_and_type_index = cp_str_nat } });
    const cp_int_ref = try addCpEntry(allocator, cf, types.CpInfo{ .methodref = .{ .class_index = cf.this_class, .name_and_type_index = cp_int_nat } });
    const cp_long_ref = try addCpEntry(allocator, cf, types.CpInfo{ .methodref = .{ .class_index = cf.this_class, .name_and_type_index = cp_long_nat } });
    const cp_float_ref = try addCpEntry(allocator, cf, types.CpInfo{ .methodref = .{ .class_index = cf.this_class, .name_and_type_index = cp_float_nat } });
    const cp_double_ref = try addCpEntry(allocator, cf, types.CpInfo{ .methodref = .{ .class_index = cf.this_class, .name_and_type_index = cp_double_nat } });

    // Process each method
    for (cf.methods) |*method| {
        const method_name = cf.getUtf8(method.name_index) orelse "";
        if (std.mem.eql(u8, method_name, "<clinit>")) continue;

        const m_str = class_str_encrypt or hasAnnotation(cf, method.attributes, STRING_ENCRYPT_DESC);
        const m_num = class_num_encrypt or hasAnnotation(cf, method.attributes, NUMBER_ENCRYPT_DESC);
        if (!m_str and !m_num) continue;

        if (method.access_flags & types.ACC_NATIVE != 0) continue;
        if (method.access_flags & types.ACC_ABSTRACT != 0) continue;

        for (method.attributes, 0..) |attr, ai| {
            const attr_name = cf.getUtf8(attr.name_index) orelse continue;
            if (!std.mem.eql(u8, attr_name, "Code")) continue;

            const new_code = try rewriteMethodCode(allocator, cf, attr.data, m_str, m_num, cp_str_ref, cp_int_ref, cp_long_ref, cp_float_ref, cp_double_ref, &strings, &numbers, class_name, &key_seed, &dk_fields, cp_j_desc, enchanted);
            if (new_code) |nc| {
                method.attributes[ai] = .{ .name_index = attr.name_index, .data = nc };
            }
        }
    }

    // Add decode-key static fields to class
    if (dk_fields.items.len > 0) {
        var new_fields = try allocator.alloc(types.FieldInfo, cf.fields.len + dk_fields.items.len);
        @memcpy(new_fields[0..cf.fields.len], cf.fields);
        for (dk_fields.items, 0..) |dk, i| {
            // Get field name from fieldref -> nat -> name
            const fref = cf.constant_pool[dk.field_ref];
            const nat_idx = switch (fref) {
                .fieldref => |r| r.name_and_type_index,
                else => unreachable,
            };
            const nat = cf.constant_pool[nat_idx];
            const name_idx = switch (nat) {
                .name_and_type => |n| n.name_index,
                else => unreachable,
            };
            new_fields[cf.fields.len + i] = .{
                .access_flags = types.ACC_PRIVATE | types.ACC_STATIC,
                .name_index = name_idx,
                .descriptor_index = cp_j_desc,
                .attributes = &.{},
            };
        }
        cf.fields = new_fields;

        // Initialize dk fields in <clinit>
        const cp_code_name = try findOrAddUtf8(allocator, cf, "Code");
        try initDkFieldsInClinit(allocator, cf, dk_fields.items, cp_code_name);
    }

    // Strip ConstantValue attributes from fields to hide plaintext values
    for (cf.fields[0..@min(cf.fields.len, cf.fields.len)]) |*field| {
        if (field.attributes.len == 0) continue;
        var keep: std.ArrayList(types.AttributeInfo) = .empty;
        defer keep.deinit(allocator);
        var had_cv = false;
        for (field.attributes) |attr| {
            const aname = cf.getUtf8(attr.name_index) orelse {
                try keep.append(allocator, attr);
                continue;
            };
            if (std.mem.eql(u8, aname, "ConstantValue")) {
                had_cv = true;
            } else {
                try keep.append(allocator, attr);
            }
        }
        if (had_cv) {
            field.attributes = try keep.toOwnedSlice(allocator);
        }
    }

    // Add synthetic native methods
    var new_methods = try allocator.alloc(types.MethodInfo, cf.methods.len + 5);
    @memcpy(new_methods[0..cf.methods.len], cf.methods);
    new_methods[cf.methods.len] = .{
        .access_flags = types.ACC_PUBLIC | types.ACC_STATIC | types.ACC_NATIVE,
        .name_index = cp_yuri_str_name, .descriptor_index = cp_str_desc, .attributes = &.{},
    };
    new_methods[cf.methods.len + 1] = .{
        .access_flags = types.ACC_PUBLIC | types.ACC_STATIC | types.ACC_NATIVE,
        .name_index = cp_yuri_int_name, .descriptor_index = cp_int_desc, .attributes = &.{},
    };
    new_methods[cf.methods.len + 2] = .{
        .access_flags = types.ACC_PUBLIC | types.ACC_STATIC | types.ACC_NATIVE,
        .name_index = cp_yuri_long_name, .descriptor_index = cp_long_desc, .attributes = &.{},
    };
    new_methods[cf.methods.len + 3] = .{
        .access_flags = types.ACC_PUBLIC | types.ACC_STATIC | types.ACC_NATIVE,
        .name_index = cp_yuri_float_name, .descriptor_index = cp_float_desc, .attributes = &.{},
    };
    new_methods[cf.methods.len + 4] = .{
        .access_flags = types.ACC_PUBLIC | types.ACC_STATIC | types.ACC_NATIVE,
        .name_index = cp_yuri_double_name, .descriptor_index = cp_double_desc, .attributes = &.{},
    };
    cf.methods = new_methods;

    return EncryptResult{
        .strings = try strings.toOwnedSlice(allocator),
        .numbers = try numbers.toOwnedSlice(allocator),
        .modified = true,
    };
}

fn rewriteMethodCode(
    allocator: std.mem.Allocator,
    cf: *types.ClassFile,
    code_attr: []const u8,
    do_str: bool,
    do_num: bool,
    str_ref: u16,
    int_ref: u16,
    long_ref: u16,
    float_ref: u16,
    double_ref: u16,
    strings: *std.ArrayList(EncryptedString),
    numbers: *std.ArrayList(EncryptedNumber),
    class_name: []const u8,
    key_seed: *u64,
    dk_fields: *std.ArrayList(DkFieldEntry),
    j_desc: u16,
    enchanted: bool,
) !?[]u8 {
    if (code_attr.len < 8) return null;

    const max_stack = readU16(code_attr, 0);
    const max_locals = readU16(code_attr, 2);
    const code_len = readU32(code_attr, 4);
    const code = code_attr[8 .. 8 + code_len];
    const rest = code_attr[8 + code_len ..]; // exception table + attrs

    var replacements: std.ArrayList(Replacement) = .empty;
    defer replacements.deinit(allocator);

    var pc: u32 = 0;
    while (pc < code_len) {
        const op = code[pc];
        switch (op) {
            0x12 => { // ldc
                const idx = @as(u16, code[pc + 1]);
                if (try tryReplace(allocator, cf, idx, do_str, do_num, str_ref, int_ref, long_ref, float_ref, double_ref, strings, numbers, class_name, key_seed, dk_fields, j_desc, enchanted)) |rep| {
                    var r = rep;
                    r.old_pc = pc;
                    r.old_len = 2;
                    try replacements.append(allocator, r);
                }
                pc += 2;
            },
            0x13 => { // ldc_w
                const idx = readU16(code, pc + 1);
                if (try tryReplace(allocator, cf, idx, do_str, do_num, str_ref, int_ref, long_ref, float_ref, double_ref, strings, numbers, class_name, key_seed, dk_fields, j_desc, enchanted)) |rep| {
                    var r = rep;
                    r.old_pc = pc;
                    r.old_len = 3;
                    try replacements.append(allocator, r);
                }
                pc += 3;
            },
            0x14 => { // ldc2_w (long/double)
                if (do_num) {
                    const idx = readU16(code, pc + 1);
                    if (idx < cf.constant_pool.len) {
                        switch (cf.constant_pool[idx]) {
                            .long => |v| {
                                const key = nextKey(key_seed);
                                const decode_key = if (enchanted) nextKey(key_seed) else @as(i64, 0);
                                try numbers.append(allocator, .{ .key = key, .value = v, .kind = .long, .class_name = class_name, .decode_key = decode_key });
                                const key_cp = try addCpEntry(allocator, cf, types.CpInfo{ .long = key });
                                _ = try addCpEntry(allocator, cf, .long_continuation);
                                if (enchanted) {
                                    const dk_field_ref = try createDkField(allocator, cf, decode_key, dk_fields, j_desc);
                                    var r = Replacement{ .old_pc = pc, .old_len = 3, .new_bytes = undefined, .new_len = 9 };
                                    r.new_bytes[0] = 0x14; r.new_bytes[1] = @intCast(key_cp >> 8); r.new_bytes[2] = @intCast(key_cp & 0xff);
                                    r.new_bytes[3] = 0xb2; r.new_bytes[4] = @intCast(dk_field_ref >> 8); r.new_bytes[5] = @intCast(dk_field_ref & 0xff);
                                    r.new_bytes[6] = 0xb8; r.new_bytes[7] = @intCast(long_ref >> 8); r.new_bytes[8] = @intCast(long_ref & 0xff);
                                    try replacements.append(allocator, r);
                                } else {
                                    var r = Replacement{ .old_pc = pc, .old_len = 3, .new_bytes = undefined, .new_len = 6 };
                                    r.new_bytes[0] = 0x14; r.new_bytes[1] = @intCast(key_cp >> 8); r.new_bytes[2] = @intCast(key_cp & 0xff);
                                    r.new_bytes[3] = 0xb8; r.new_bytes[4] = @intCast(long_ref >> 8); r.new_bytes[5] = @intCast(long_ref & 0xff);
                                    try replacements.append(allocator, r);
                                }
                            },
                            .double => |v| {
                                const key = nextKey(key_seed);
                                const decode_key = if (enchanted) nextKey(key_seed) else @as(i64, 0);
                                const bits: i64 = @bitCast(v);
                                try numbers.append(allocator, .{ .key = key, .value = bits, .kind = .double, .class_name = class_name, .decode_key = decode_key });
                                const key_cp = try addCpEntry(allocator, cf, types.CpInfo{ .long = key });
                                _ = try addCpEntry(allocator, cf, .long_continuation);
                                if (enchanted) {
                                    const dk_field_ref = try createDkField(allocator, cf, decode_key, dk_fields, j_desc);
                                    var r = Replacement{ .old_pc = pc, .old_len = 3, .new_bytes = undefined, .new_len = 9 };
                                    r.new_bytes[0] = 0x14; r.new_bytes[1] = @intCast(key_cp >> 8); r.new_bytes[2] = @intCast(key_cp & 0xff);
                                    r.new_bytes[3] = 0xb2; r.new_bytes[4] = @intCast(dk_field_ref >> 8); r.new_bytes[5] = @intCast(dk_field_ref & 0xff);
                                    r.new_bytes[6] = 0xb8; r.new_bytes[7] = @intCast(double_ref >> 8); r.new_bytes[8] = @intCast(double_ref & 0xff);
                                    try replacements.append(allocator, r);
                                } else {
                                    var r = Replacement{ .old_pc = pc, .old_len = 3, .new_bytes = undefined, .new_len = 6 };
                                    r.new_bytes[0] = 0x14; r.new_bytes[1] = @intCast(key_cp >> 8); r.new_bytes[2] = @intCast(key_cp & 0xff);
                                    r.new_bytes[3] = 0xb8; r.new_bytes[4] = @intCast(double_ref >> 8); r.new_bytes[5] = @intCast(double_ref & 0xff);
                                    try replacements.append(allocator, r);
                                }
                            },
                            else => {},
                        }
                    }
                }
                pc += 3;
            },
            else => pc += opcodeLen(code, pc, code_len),
        }
    }

    if (replacements.items.len == 0) return null;

    var new_code: std.ArrayList(u8) = .empty;
    defer new_code.deinit(allocator);

    const offset_map = try buildOffsetMap(allocator, code_len, replacements.items);
    defer allocator.free(offset_map);

    var src_pc: u32 = 0;
    var rep_idx: usize = 0;
    while (src_pc < code_len) {
        if (rep_idx < replacements.items.len and replacements.items[rep_idx].old_pc == src_pc) {
            const rep = replacements.items[rep_idx];
            try new_code.appendSlice(allocator, rep.new_bytes[0..rep.new_len]);
            src_pc += rep.old_len;
            rep_idx += 1;
        } else {
            const ilen = opcodeLen(code, src_pc, code_len);
            const op = code[src_pc];
            if (isBranch(op)) {
                try emitFixedBranch(allocator, &new_code, code, src_pc, ilen, offset_map);
            } else {
                try new_code.appendSlice(allocator, code[src_pc .. src_pc + ilen]);
            }
            src_pc += ilen;
        }
    }

    const new_code_len: u32 = @intCast(new_code.items.len);
    const new_max_stack = @max(max_stack, 4) + 4;
    const header_size: usize = 8;
    const total = header_size + new_code_len + rest.len;
    const result = try allocator.alloc(u8, total);

    const fixed_rest = try fixExceptionTable(allocator, rest, offset_map);

    writeU16(result, 0, new_max_stack);
    writeU16(result, 2, max_locals);
    writeU32(result, 4, new_code_len);
    @memcpy(result[8 .. 8 + new_code_len], new_code.items);
    @memcpy(result[8 + new_code_len ..], fixed_rest);

    return result;
}

const Replacement = struct {
    old_pc: u32 = 0,
    old_len: u32 = 0,
    new_bytes: [16]u8 = undefined,
    new_len: u32 = 0,
};

fn tryReplace(
    allocator: std.mem.Allocator,
    cf: *types.ClassFile,
    idx: u16,
    do_str: bool,
    do_num: bool,
    str_ref: u16,
    int_ref: u16,
    long_ref: u16,
    float_ref: u16,
    double_ref: u16,
    strings: *std.ArrayList(EncryptedString),
    numbers: *std.ArrayList(EncryptedNumber),
    class_name: []const u8,
    key_seed: *u64,
    dk_fields: *std.ArrayList(DkFieldEntry),
    j_desc: u16,
    enchanted: bool,
) !?Replacement {
    _ = long_ref;
    _ = double_ref;
    if (idx >= cf.constant_pool.len) return null;

    switch (cf.constant_pool[idx]) {
        .string => |str_idx| {
            if (!do_str) return null;
            const val = cf.getUtf8(str_idx) orelse return null;
            if (val.len == 0) return null;
            const key = nextKey(key_seed);
            const decode_key = if (enchanted) nextKey(key_seed) else @as(i64, 0);
            try strings.append(allocator, .{ .key = key, .value = val, .class_name = class_name, .decode_key = decode_key });
            const key_cp = try addCpEntry(allocator, cf, types.CpInfo{ .long = key });
            _ = try addCpEntry(allocator, cf, .long_continuation);
            if (enchanted) {
                const dk_field_ref = try createDkField(allocator, cf, decode_key, dk_fields, j_desc);
                var r = Replacement{ .new_len = 9 };
                r.new_bytes[0] = 0x14; r.new_bytes[1] = @intCast(key_cp >> 8); r.new_bytes[2] = @intCast(key_cp & 0xff);
                r.new_bytes[3] = 0xb2; r.new_bytes[4] = @intCast(dk_field_ref >> 8); r.new_bytes[5] = @intCast(dk_field_ref & 0xff);
                r.new_bytes[6] = 0xb8; r.new_bytes[7] = @intCast(str_ref >> 8); r.new_bytes[8] = @intCast(str_ref & 0xff);
                return r;
            } else {
                var r = Replacement{ .new_len = 6 };
                r.new_bytes[0] = 0x14; r.new_bytes[1] = @intCast(key_cp >> 8); r.new_bytes[2] = @intCast(key_cp & 0xff);
                r.new_bytes[3] = 0xb8; r.new_bytes[4] = @intCast(str_ref >> 8); r.new_bytes[5] = @intCast(str_ref & 0xff);
                return r;
            }
        },
        .integer => |v| {
            if (!do_num) return null;
            const key = nextKey(key_seed);
            const decode_key = if (enchanted) nextKey(key_seed) else @as(i64, 0);
            try numbers.append(allocator, .{ .key = key, .value = @as(i64, v), .kind = .int, .class_name = class_name, .decode_key = decode_key });
            const key_cp = try addCpEntry(allocator, cf, types.CpInfo{ .long = key });
            _ = try addCpEntry(allocator, cf, .long_continuation);
            if (enchanted) {
                const dk_field_ref = try createDkField(allocator, cf, decode_key, dk_fields, j_desc);
                var r = Replacement{ .new_len = 9 };
                r.new_bytes[0] = 0x14; r.new_bytes[1] = @intCast(key_cp >> 8); r.new_bytes[2] = @intCast(key_cp & 0xff);
                r.new_bytes[3] = 0xb2; r.new_bytes[4] = @intCast(dk_field_ref >> 8); r.new_bytes[5] = @intCast(dk_field_ref & 0xff);
                r.new_bytes[6] = 0xb8; r.new_bytes[7] = @intCast(int_ref >> 8); r.new_bytes[8] = @intCast(int_ref & 0xff);
                return r;
            } else {
                var r = Replacement{ .new_len = 6 };
                r.new_bytes[0] = 0x14; r.new_bytes[1] = @intCast(key_cp >> 8); r.new_bytes[2] = @intCast(key_cp & 0xff);
                r.new_bytes[3] = 0xb8; r.new_bytes[4] = @intCast(int_ref >> 8); r.new_bytes[5] = @intCast(int_ref & 0xff);
                return r;
            }
        },
        .float => |v| {
            if (!do_num) return null;
            const key = nextKey(key_seed);
            const decode_key = if (enchanted) nextKey(key_seed) else @as(i64, 0);
            const bits_u: u32 = @bitCast(v);
            const bits = @as(i64, @intCast(bits_u));
            try numbers.append(allocator, .{ .key = key, .value = bits, .kind = .float, .class_name = class_name, .decode_key = decode_key });
            const key_cp = try addCpEntry(allocator, cf, types.CpInfo{ .long = key });
            _ = try addCpEntry(allocator, cf, .long_continuation);
            if (enchanted) {
                const dk_field_ref = try createDkField(allocator, cf, decode_key, dk_fields, j_desc);
                var r = Replacement{ .new_len = 9 };
                r.new_bytes[0] = 0x14; r.new_bytes[1] = @intCast(key_cp >> 8); r.new_bytes[2] = @intCast(key_cp & 0xff);
                r.new_bytes[3] = 0xb2; r.new_bytes[4] = @intCast(dk_field_ref >> 8); r.new_bytes[5] = @intCast(dk_field_ref & 0xff);
                r.new_bytes[6] = 0xb8; r.new_bytes[7] = @intCast(float_ref >> 8); r.new_bytes[8] = @intCast(float_ref & 0xff);
                return r;
            } else {
                var r = Replacement{ .new_len = 6 };
                r.new_bytes[0] = 0x14; r.new_bytes[1] = @intCast(key_cp >> 8); r.new_bytes[2] = @intCast(key_cp & 0xff);
                r.new_bytes[3] = 0xb8; r.new_bytes[4] = @intCast(float_ref >> 8); r.new_bytes[5] = @intCast(float_ref & 0xff);
                return r;
            }
        },
        else => return null,
    }
}

/// Create a decode-key static field and return its Fieldref CP index
fn createDkField(
    allocator: std.mem.Allocator,
    cf: *types.ClassFile,
    decode_key: i64,
    dk_fields: *std.ArrayList(DkFieldEntry),
    j_desc: u16,
) !u16 {
    // Generate field name: _jnic$dk$N (must be heap-allocated for CP utf8 reference)
    const name = try std.fmt.allocPrint(allocator, "_jnic$dk${d}", .{dk_fields.items.len});
    const name_idx = try findOrAddUtf8(allocator, cf, name);
    const nat_idx = try addCpEntry(allocator, cf, types.CpInfo{ .name_and_type = .{ .name_index = name_idx, .descriptor_index = j_desc } });
    const field_ref = try addCpEntry(allocator, cf, types.CpInfo{ .fieldref = .{ .class_index = cf.this_class, .name_and_type_index = nat_idx } });
    // Store Long value in CP for <clinit> ldc2_w
    const dk_long_cp = try addCpEntry(allocator, cf, types.CpInfo{ .long = decode_key });
    _ = try addCpEntry(allocator, cf, .long_continuation);
    try dk_fields.append(allocator, .{ .field_ref = field_ref, .dk_long_cp = dk_long_cp });
    return field_ref;
}

/// Initialize all decode-key fields in <clinit>
fn initDkFieldsInClinit(allocator: std.mem.Allocator, cf: *types.ClassFile, dk_items: []const DkFieldEntry, cp_code_name: u16) !void {
    // Build init bytecode: for each dk field: ldc2_w dk_long_cp (3) + putstatic field_ref (3)
    const init_len: u32 = @intCast(dk_items.len * 6);
    var init_code = try allocator.alloc(u8, init_len);
    for (dk_items, 0..) |dk, i| {
        const off = i * 6;
        init_code[off] = 0x14; // ldc2_w
        init_code[off + 1] = @intCast(dk.dk_long_cp >> 8);
        init_code[off + 2] = @intCast(dk.dk_long_cp & 0xff);
        init_code[off + 3] = 0xb3; // putstatic
        init_code[off + 4] = @intCast(dk.field_ref >> 8);
        init_code[off + 5] = @intCast(dk.field_ref & 0xff);
    }

    // Find existing <clinit>
    var clinit_idx: ?usize = null;
    for (cf.methods, 0..) |method, idx| {
        const mname = cf.getUtf8(method.name_index) orelse continue;
        if (std.mem.eql(u8, mname, "<clinit>")) { clinit_idx = idx; break; }
    }

    if (clinit_idx) |ci| {
        // Prepend init code to existing <clinit>
        var existing_code: ?[]const u8 = null;
        var code_attr_idx: ?usize = null;
        for (cf.methods[ci].attributes, 0..) |attr, ai| {
            const aname = cf.getUtf8(attr.name_index) orelse continue;
            if (std.mem.eql(u8, aname, "Code")) { existing_code = attr.data; code_attr_idx = ai; break; }
        }
        if (existing_code) |ec| {
            if (ec.len < 8) return;
            const old_max_stack = (@as(u16, ec[0]) << 8) | @as(u16, ec[1]);
            const old_max_locals = (@as(u16, ec[2]) << 8) | @as(u16, ec[3]);
            const old_code_len = (@as(u32, ec[4]) << 24) | (@as(u32, ec[5]) << 16) | (@as(u32, ec[6]) << 8) | @as(u32, ec[7]);
            const old_bytecode = ec[8 .. 8 + old_code_len];
            const rest = ec[8 + old_code_len ..];

            const new_stack = @max(old_max_stack, 2);
            const new_code_len = init_len + old_code_len;

            const new_data = try allocator.alloc(u8, 8 + new_code_len + rest.len);
            new_data[0] = @intCast(new_stack >> 8); new_data[1] = @intCast(new_stack & 0xff);
            new_data[2] = @intCast(old_max_locals >> 8); new_data[3] = @intCast(old_max_locals & 0xff);
            new_data[4] = @intCast(new_code_len >> 24); new_data[5] = @intCast((new_code_len >> 16) & 0xff);
            new_data[6] = @intCast((new_code_len >> 8) & 0xff); new_data[7] = @intCast(new_code_len & 0xff);
            @memcpy(new_data[8 .. 8 + init_len], init_code);
            @memcpy(new_data[8 + init_len .. 8 + new_code_len], old_bytecode);
            @memcpy(new_data[8 + new_code_len ..], rest);

            cf.methods[ci].attributes[code_attr_idx.?] = .{ .name_index = cp_code_name, .data = new_data };
        }
    } else {
        // Create new <clinit> with init code + return
        const clinit_name = try findOrAddUtf8(allocator, cf, "<clinit>");
        const clinit_desc = try findOrAddUtf8(allocator, cf, "()V");

        const total_code_len = init_len + 1; // +1 for return
        const data = try allocator.alloc(u8, 8 + total_code_len + 4); // +4 for exc_table(2) + attrs(2)
        data[0] = 0; data[1] = 2; // max_stack=2
        data[2] = 0; data[3] = 0; // max_locals=0
        data[4] = @intCast(total_code_len >> 24); data[5] = @intCast((total_code_len >> 16) & 0xff);
        data[6] = @intCast((total_code_len >> 8) & 0xff); data[7] = @intCast(total_code_len & 0xff);
        @memcpy(data[8 .. 8 + init_len], init_code);
        data[8 + init_len] = 0xb1; // return
        data[8 + total_code_len] = 0; data[8 + total_code_len + 1] = 0; // exc_table_count=0
        data[8 + total_code_len + 2] = 0; data[8 + total_code_len + 3] = 0; // attrs_count=0

        const attrs = try allocator.alloc(types.AttributeInfo, 1);
        attrs[0] = .{ .name_index = cp_code_name, .data = data };

        const clinit = types.MethodInfo{
            .access_flags = types.ACC_STATIC,
            .name_index = clinit_name,
            .descriptor_index = clinit_desc,
            .attributes = attrs,
        };

        var new_methods = try allocator.alloc(types.MethodInfo, cf.methods.len + 1);
        @memcpy(new_methods[0..cf.methods.len], cf.methods);
        new_methods[cf.methods.len] = clinit;
        cf.methods = new_methods;
    }
}

fn nextKey(seed: *u64) i64 {
    seed.* ^= seed.* >> 12;
    seed.* ^= seed.* << 25;
    seed.* ^= seed.* >> 27;
    seed.* *%= 0x2545F4914F6CDD1D;
    return @bitCast(seed.*);
}

fn buildOffsetMap(allocator: std.mem.Allocator, code_len: u32, replacements: []const Replacement) ![]i32 {
    // Map from old PC to delta (how much the offset shifted)
    const map = try allocator.alloc(i32, code_len + 1);
    @memset(map, 0);
    var delta: i32 = 0;
    var ri: usize = 0;
    for (0..code_len) |pc| {
        if (ri < replacements.len and replacements[ri].old_pc == pc) {
            delta += @as(i32, @intCast(replacements[ri].new_len)) - @as(i32, @intCast(replacements[ri].old_len));
            ri += 1;
        }
        map[pc] = delta;
    }
    map[code_len] = delta;
    return map;
}

fn isBranch(op: u8) bool {
    return (op >= 0x99 and op <= 0xa7) or op == 0xc6 or op == 0xc7 or op == 0xc8;
}

fn emitFixedBranch(allocator: std.mem.Allocator, out: *std.ArrayList(u8), code: []const u8, pc: u32, ilen: u32, offset_map: []const i32) !void {
    const op = code[pc];
    if (op == 0xc8) { // goto_w
        const old_off = readI32(code, pc + 1);
        const target: u32 = @intCast(@as(i64, pc) + @as(i64, old_off));
        const new_pc: i32 = @as(i32, @intCast(pc)) + offset_map[pc];
        const new_target: i32 = @as(i32, @intCast(target)) + offset_map[@min(target, @as(u32, @intCast(offset_map.len - 1)))];
        const new_off = new_target - new_pc;
        try out.append(allocator, op);
        var buf: [4]u8 = undefined;
        buf[0] = @intCast(@as(u32, @bitCast(new_off)) >> 24);
        buf[1] = @intCast((@as(u32, @bitCast(new_off)) >> 16) & 0xff);
        buf[2] = @intCast((@as(u32, @bitCast(new_off)) >> 8) & 0xff);
        buf[3] = @intCast(@as(u32, @bitCast(new_off)) & 0xff);
        try out.appendSlice(allocator, &buf);
    } else if (ilen == 3) { // short branch
        const old_off = readI16(code, pc + 1);
        const target: u32 = @intCast(@as(i64, pc) + @as(i64, old_off));
        const new_pc: i32 = @as(i32, @intCast(pc)) + offset_map[pc];
        const new_target: i32 = @as(i32, @intCast(target)) + offset_map[@min(target, @as(u32, @intCast(offset_map.len - 1)))];
        const new_off: i16 = @intCast(new_target - new_pc);
        try out.append(allocator, op);
        try out.append(allocator, @intCast(@as(u16, @bitCast(new_off)) >> 8));
        try out.append(allocator, @intCast(@as(u16, @bitCast(new_off)) & 0xff));
    } else {
        try out.appendSlice(allocator, code[pc .. pc + ilen]);
    }
}

fn fixExceptionTable(allocator: std.mem.Allocator, rest: []const u8, offset_map: []const i32) ![]u8 {
    if (rest.len < 2) return try allocator.dupe(u8, rest);
    const result = try allocator.alloc(u8, rest.len);
    @memcpy(result, rest);

    const exc_count = (@as(u16, rest[0]) << 8) | @as(u16, rest[1]);
    var i: u16 = 0;
    while (i < exc_count) : (i += 1) {
        const off: usize = 2 + @as(usize, i) * 8;
        if (off + 6 > rest.len) break;
        // Fix start_pc, end_pc, handler_pc
        inline for ([_]usize{ 0, 2, 4 }) |field_off| {
            const old_val = (@as(u16, rest[off + field_off]) << 8) | @as(u16, rest[off + field_off + 1]);
            const map_idx = @min(old_val, @as(u16, @intCast(offset_map.len - 1)));
            const new_val: i32 = @as(i32, old_val) + offset_map[map_idx];
            result[off + field_off] = @intCast(@as(u16, @intCast(new_val)) >> 8);
            result[off + field_off + 1] = @intCast(@as(u16, @intCast(new_val)) & 0xff);
        }
    }
    return result;
}

fn hasAnnotation(cf: *const types.ClassFile, attrs: []const types.AttributeInfo, target: []const u8) bool {
    for (attrs) |attr| {
        const name = cf.getUtf8(attr.name_index) orelse continue;
        if (!std.mem.eql(u8, name, "RuntimeVisibleAnnotations") and !std.mem.eql(u8, name, "RuntimeInvisibleAnnotations")) continue;
        if (attr.data.len < 2) continue;
        const num = (@as(u16, attr.data[0]) << 8) | @as(u16, attr.data[1]);
        var pos: usize = 2;
        for (0..num) |_| {
            if (pos + 2 > attr.data.len) break;
            const type_idx = (@as(u16, attr.data[pos]) << 8) | @as(u16, attr.data[pos + 1]);
            const desc = cf.getUtf8(type_idx) orelse "";
            if (std.mem.eql(u8, desc, target)) return true;
            pos += 2;
            if (pos + 2 > attr.data.len) break;
            const npairs = (@as(u16, attr.data[pos]) << 8) | @as(u16, attr.data[pos + 1]);
            pos += 2;
            // Skip element_value_pairs (simplified: skip npairs * ~4 bytes)
            for (0..npairs) |_| {
                pos += 2; // element_name_index
                if (pos >= attr.data.len) break;
                pos += skipElemValue(attr.data, pos);
            }
        }
    }
    return false;
}

fn skipElemValue(data: []const u8, start: usize) usize {
    if (start >= data.len) return 0;
    const tag = data[start];
    switch (tag) {
        'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z', 's', 'c' => return 3,
        'e' => return 5,
        '@' => return 5, // simplified
        '[' => {
            if (start + 3 > data.len) return 1;
            const count = (@as(u16, data[start + 1]) << 8) | @as(u16, data[start + 2]);
            var sz: usize = 3;
            for (0..count) |_| sz += skipElemValue(data, start + sz);
            return sz;
        },
        else => return 1,
    }
}

// === Utility functions ===
fn findOrAddUtf8(allocator: std.mem.Allocator, cf: *types.ClassFile, value: []const u8) !u16 {
    for (cf.constant_pool, 0..) |entry, idx| {
        switch (entry) { .utf8 => |s| if (std.mem.eql(u8, s, value)) return @intCast(idx), else => {} }
    }
    return addCpEntry(allocator, cf, types.CpInfo{ .utf8 = value });
}

fn addCpEntry(allocator: std.mem.Allocator, cf: *types.ClassFile, entry: types.CpInfo) !u16 {
    const new_idx: u16 = @intCast(cf.constant_pool.len);
    var new_cp = try allocator.alloc(types.CpInfo, cf.constant_pool.len + 1);
    @memcpy(new_cp[0..cf.constant_pool.len], cf.constant_pool);
    new_cp[cf.constant_pool.len] = entry;
    cf.constant_pool = new_cp;
    return new_idx;
}

fn readU16(data: []const u8, off: u32) u16 {
    if (off + 1 >= data.len) return 0;
    return (@as(u16, data[off]) << 8) | @as(u16, data[off + 1]);
}

fn readI16(data: []const u8, off: u32) i16 {
    return @bitCast(readU16(data, off));
}

fn readU32(data: []const u8, off: u32) u32 {
    if (off + 3 >= data.len) return 0;
    return (@as(u32, data[off]) << 24) | (@as(u32, data[off + 1]) << 16) | (@as(u32, data[off + 2]) << 8) | @as(u32, data[off + 3]);
}

fn readI32(data: []const u8, off: u32) i32 { return @bitCast(readU32(data, off)); }

fn writeU16(buf: []u8, off: usize, val: u16) void {
    buf[off] = @intCast(val >> 8); buf[off + 1] = @intCast(val & 0xff);
}

fn writeU32(buf: []u8, off: usize, val: u32) void {
    buf[off] = @intCast(val >> 24); buf[off + 1] = @intCast((val >> 16) & 0xff);
    buf[off + 2] = @intCast((val >> 8) & 0xff); buf[off + 3] = @intCast(val & 0xff);
}

fn opcodeLen(code: []const u8, pc: u32, code_len: u32) u32 {
    if (pc >= code_len) return 1;
    const op = code[pc];
    return switch (op) {
        0x10 => 2, 0x11 => 3, 0x12 => 2, 0x13, 0x14 => 3,
        0x15...0x19 => 2, 0x36...0x3a => 2,
        0x84 => 3,
        0x99...0xa7 => 3, 0xc6, 0xc7 => 3, 0xc8 => 5,
        0xb2...0xb8 => 3, 0xb9 => 5, 0xba => 5,
        0xbb, 0xbd, 0xc0, 0xc1 => 3, 0xbc => 2, 0xc5 => 4,
        0xaa => blk: { // tableswitch
            const pp = (pc + 4) & ~@as(u32, 3);
            if (pp + 12 > code_len) break :blk 1;
            const lo = readI32(code, pp + 4);
            const hi = readI32(code, pp + 8);
            const cnt: u32 = @intCast(@as(i64, hi) - @as(i64, lo) + 1);
            break :blk pp + 12 + cnt * 4 - pc;
        },
        0xab => blk: { // lookupswitch
            const pp = (pc + 4) & ~@as(u32, 3);
            if (pp + 8 > code_len) break :blk 1;
            const np: u32 = @intCast(readI32(code, pp + 4));
            break :blk pp + 8 + np * 8 - pc;
        },
        0xc4 => if (pc + 1 < code_len and code[pc + 1] == 0x84) 6 else 4,
        else => 1,
    };
}
