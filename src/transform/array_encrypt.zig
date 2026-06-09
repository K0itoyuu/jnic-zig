const std = @import("std");
const types = @import("../classfile/types.zig");

pub const ArrayType = enum(u8) {
    int = 0,
    long = 1,
    float = 2,
    double = 3,
    byte = 4,
    short = 5,
    char = 6,
    string = 7,
};

pub const EncryptedArray = struct {
    key: i64,
    data: []const u8, // raw element data (pre-encryption, will be encrypted in codegen)
    elem_type: ArrayType,
    length: u32,
    class_name: []const u8,
    field_name: []const u8,
    field_descriptor: []const u8,
};

pub const ArrayEncryptResult = struct {
    arrays: []EncryptedArray,
    modified: bool,
};

const ARRAY_OBFUSCATION_DESC = "Lmaster/koitoyuu/jnic/ArrayObfuscation;";

/// Scan methods for array initialization patterns and extract them
pub fn encryptArrays(allocator: std.mem.Allocator, cf: *types.ClassFile, enchanted: bool) !ArrayEncryptResult {
    const class_name = cf.getThisClassName() orelse return .{ .arrays = &.{}, .modified = false };

    // Check for @ArrayObfuscation annotation
    const class_annotated = hasAnnotation(cf, cf.attributes, ARRAY_OBFUSCATION_DESC);

    // Collect annotated field names (field-level annotation)
    var annotated_fields: [64][]const u8 = undefined;
    var num_annotated_fields: usize = 0;
    for (cf.fields) |field| {
        if (class_annotated or hasAnnotation(cf, field.attributes, ARRAY_OBFUSCATION_DESC)) {
            const fname = cf.getUtf8(field.name_index) orelse continue;
            if (num_annotated_fields < 64) {
                annotated_fields[num_annotated_fields] = fname;
                num_annotated_fields += 1;
            }
        }
    }

    if (!class_annotated and num_annotated_fields == 0) {
        // Check method-level annotations
        var any_method = false;
        for (cf.methods) |method| {
            if (hasAnnotation(cf, method.attributes, ARRAY_OBFUSCATION_DESC)) { any_method = true; break; }
        }
        if (!any_method) return .{ .arrays = &.{}, .modified = false };
    }

    var arrays: std.ArrayList(EncryptedArray) = .empty;
    defer arrays.deinit(allocator);

    var key_seed: u64 = 0xA7B3C1D9E5F20468;
    key_seed ^= @as(u64, @intCast(class_name.len)) *% 0x6C62272E07BB0142;
    var modified = false;

    // Process <clinit> for static field array inits
    for (cf.methods, 0..) |*method, midx| {
        const mname = cf.getUtf8(method.name_index) orelse continue;
        const should_process = class_annotated or
            std.mem.eql(u8, mname, "<clinit>") or // clinit has field inits
            hasAnnotation(cf, method.attributes, ARRAY_OBFUSCATION_DESC);
        if (!should_process) continue;

        // Find Code attribute
        var code_attr_idx: ?usize = null;
        var code_data: ?[]const u8 = null;
        for (method.attributes, 0..) |attr, ai| {
            const aname = cf.getUtf8(attr.name_index) orelse continue;
            if (std.mem.eql(u8, aname, "Code")) { code_data = attr.data; code_attr_idx = ai; break; }
        }
        if (code_data == null or code_data.?.len < 8) continue;

        const cd = code_data.?;
        const code_len = readU32(cd, 4);
        if (8 + code_len > cd.len) continue;
        const code = cd[8 .. 8 + code_len];

        // Mutable copy
        var new_code = try allocator.alloc(u8, cd.len);
        @memcpy(new_code, cd);
        var mc = new_code[8 .. 8 + code_len];
        var method_modified = false;

        var pc: u32 = 0;
        while (pc < code_len) {
            const match = tryMatchArrayInit(code, pc, code_len, cf);
            if (match) |m| {
                if (m.count >= 8) {
                    // Check if field is annotated (for field-level filtering)
                    const field_idx = readU16(code, m.putstatic_pc + 1);
                    const fi = resolveFieldInfo(cf, field_idx);
                    const field_allowed = class_annotated or (if (fi) |f| blk: {
                        for (annotated_fields[0..num_annotated_fields]) |af| {
                            if (std.mem.eql(u8, af, f.name)) break :blk true;
                        }
                        break :blk hasAnnotation(cf, method.attributes, ARRAY_OBFUSCATION_DESC);
                    } else false);

                    if (field_allowed) {
                        const key = nextKey(&key_seed);
                        const blob = try extractArrayBlob(allocator, code, m, cf);
                        if (blob) |b| {
                            if (fi) |field_info| {
                                try arrays.append(allocator, .{
                                    .key = key,
                                    .data = b,
                                    .elem_type = m.elem_type,
                                    .length = m.count,
                                    .class_name = class_name,
                                    .field_name = field_info.name,
                                    .field_descriptor = field_info.descriptor,
                                });

                                // Generate method name and descriptor based on enchanted mode
                                const arr_method_name = try std.fmt.allocPrint(allocator, "jnic$arr${d}", .{arrays.items.len - 1});
                                const arr_desc = if (enchanted) arrayMethodDescEnchanted(m.elem_type) else arrayMethodDesc(m.elem_type);
                                const cp_arr_name = try findOrAddUtf8(allocator, cf, arr_method_name);
                                const cp_arr_desc = try findOrAddUtf8(allocator, cf, arr_desc);
                                const cp_arr_nat = try addCpEntry(allocator, cf, types.CpInfo{ .name_and_type = .{ .name_index = cp_arr_name, .descriptor_index = cp_arr_desc } });
                                const cp_arr_ref = try addCpEntry(allocator, cf, types.CpInfo{ .methodref = .{ .class_index = cf.this_class, .name_and_type_index = cp_arr_nat } });

                                const cp_key = try addCpEntry(allocator, cf, types.CpInfo{ .long = key });
                                _ = try addCpEntry(allocator, cf, .long_continuation);

                                if (enchanted) {
                                    // Dual-key: ldc2_w key(3) + getstatic dk(3) + invokestatic(3) + putstatic(3) = 12 bytes
                                    const dk = nextKey(&key_seed);
                                    arrays.items[arrays.items.len - 1].key = key; // update with decode info
                                    _ = dk; // TODO: implement dk field for arrays when enchanted
                                    // For now, use same single-key path
                                    mc[m.start_pc] = 0x14;
                                    mc[m.start_pc + 1] = @intCast(cp_key >> 8);
                                    mc[m.start_pc + 2] = @intCast(cp_key & 0xff);
                                    mc[m.start_pc + 3] = 0xb8;
                                    mc[m.start_pc + 4] = @intCast(cp_arr_ref >> 8);
                                    mc[m.start_pc + 5] = @intCast(cp_arr_ref & 0xff);
                                    mc[m.start_pc + 6] = 0xb3;
                                    mc[m.start_pc + 7] = code[m.putstatic_pc + 1];
                                    mc[m.start_pc + 8] = code[m.putstatic_pc + 2];
                                    const end_pc = m.putstatic_pc + 3;
                                    for (m.start_pc + 9..end_pc) |i| mc[i] = 0x00;
                                } else {
                                    // Single-key: ldc2_w key(3) + invokestatic(3) + putstatic(3) = 9 bytes
                                    mc[m.start_pc] = 0x14;
                                    mc[m.start_pc + 1] = @intCast(cp_key >> 8);
                                    mc[m.start_pc + 2] = @intCast(cp_key & 0xff);
                                    mc[m.start_pc + 3] = 0xb8;
                                    mc[m.start_pc + 4] = @intCast(cp_arr_ref >> 8);
                                    mc[m.start_pc + 5] = @intCast(cp_arr_ref & 0xff);
                                    mc[m.start_pc + 6] = 0xb3;
                                    mc[m.start_pc + 7] = code[m.putstatic_pc + 1];
                                    mc[m.start_pc + 8] = code[m.putstatic_pc + 2];
                                    const end_pc = m.putstatic_pc + 3;
                                    for (m.start_pc + 9..end_pc) |i| mc[i] = 0x00;
                                }

                                // Add native method
                                const method_attrs = try allocator.alloc(types.AttributeInfo, 0);
                                var new_methods = try allocator.alloc(types.MethodInfo, cf.methods.len + 1);
                                @memcpy(new_methods[0..cf.methods.len], cf.methods);
                                new_methods[cf.methods.len] = .{
                                    .access_flags = types.ACC_PRIVATE | types.ACC_STATIC | types.ACC_NATIVE,
                                    .name_index = cp_arr_name,
                                    .descriptor_index = cp_arr_desc,
                                    .attributes = method_attrs,
                                };
                                cf.methods = new_methods;

                                method_modified = true;
                                pc = m.putstatic_pc + 3;
                                continue;
                            }
                        }
                    }
                }
            }
            pc += opcodeLen(code, pc, code_len);
        }

        if (method_modified) {
            cf.methods[midx].attributes[code_attr_idx.?] = .{
                .name_index = cf.methods[midx].attributes[code_attr_idx.?].name_index,
                .data = new_code,
            };
            modified = true;
        }
    }

    return .{
        .arrays = try arrays.toOwnedSlice(allocator),
        .modified = modified,
    };
}

// === Pattern matching ===

const ArrayMatch = struct {
    start_pc: u32,
    putstatic_pc: u32,
    count: u32,
    elem_type: ArrayType,
};

fn tryMatchArrayInit(code: []const u8, pc: u32, code_len: u32, cf: *const types.ClassFile) ?ArrayMatch {
    _ = cf;
    var p = pc;
    // Step 1: push array size (iconst/bipush/sipush)
    const arr_size = readPushConst(code, p, code_len) orelse return null;
    if (arr_size < 1 or arr_size > 65535) return null;
    p += pushConstLen(code[p]);

    // Step 2: newarray T or anewarray
    if (p >= code_len) return null;
    const elem_type: ArrayType = switch (code[p]) {
        0xbc => switch (code[p + 1]) { // newarray
            4 => .byte, // T_BOOLEAN (treat as byte)
            5 => .char,
            6 => .float,
            7 => .double,
            8 => .byte,
            9 => .short,
            10 => .int,
            11 => .long,
            else => return null,
        },
        0xbd => .string, // anewarray (assume String for now)
        else => return null,
    };
    p += if (code[p] == 0xbc) @as(u32, 2) else @as(u32, 3);

    // Step 3: match (dup + pushIndex + pushValue + xastore) × N
    var count: u32 = 0;
    while (count < arr_size and p < code_len) {
        // dup
        if (code[p] != 0x59) break;
        p += 1;
        // push index
        const idx_val = readPushConst(code, p, code_len) orelse break;
        if (idx_val != count) break;
        p += pushConstLen(code[p]);
        // push value
        const val_len = valuePushLen(code, p, code_len, elem_type);
        if (val_len == 0) break;
        p += val_len;
        // xastore
        if (!isArrayStore(code[p], elem_type)) break;
        p += 1;
        count += 1;
    }

    if (count != arr_size or count < 8) return null;

    // Step 4: putstatic
    if (p + 2 >= code_len or code[p] != 0xb3) return null;

    return ArrayMatch{
        .start_pc = pc,
        .putstatic_pc = p,
        .count = count,
        .elem_type = elem_type,
    };
}

// === Blob extraction ===

fn extractArrayBlob(allocator: std.mem.Allocator, code: []const u8, m: ArrayMatch, cf: *const types.ClassFile) !?[]u8 {
    var p = m.start_pc;
    p += pushConstLen(code[p]); // skip size push
    p += if (code[p] == 0xbc) @as(u32, 2) else @as(u32, 3); // skip newarray

    const elem_size: u32 = switch (m.elem_type) {
        .byte => 1, .short, .char => 2, .int, .float => 4, .long, .double => 8, .string => 0,
    };

    if (m.elem_type == .string) {
        // String array: collect UTF8 strings as length-prefixed blob
        var blob: std.ArrayList(u8) = .empty;
        defer blob.deinit(allocator);
        for (0..m.count) |_| {
            p += 1; // dup
            p += pushConstLen(code[p]); // index
            // Get string from CP
            const str_val = readStringValue(code, p, cf);
            const sv = str_val orelse "";
            const slen: u16 = @intCast(@min(sv.len, 65535));
            try blob.append(allocator, @intCast(slen >> 8));
            try blob.append(allocator, @intCast(slen & 0xff));
            try blob.appendSlice(allocator, sv[0..slen]);
            p += valuePushLen(code, p, @intCast(code.len), m.elem_type);
            p += 1; // aastore
        }
        return try blob.toOwnedSlice(allocator);
    }

    // Primitive array: extract raw bytes (little-endian for x86 JNI compatibility)
    const blob_size = m.count * elem_size;
    var blob = try allocator.alloc(u8, blob_size);
    for (0..m.count) |i| {
        p += 1; // dup
        p += pushConstLen(code[p]); // index
        // Read value
        const val = readNumericValueWithCp(code, p, @intCast(code.len), cf.constant_pool);
        const off = i * elem_size;
        switch (m.elem_type) {
            .byte => blob[off] = @intCast(@as(u8, @bitCast(@as(i8, @intCast(val))))),
            .short, .char => { const v: u16 = @bitCast(@as(i16, @intCast(val))); blob[off] = @intCast(v & 0xff); blob[off + 1] = @intCast(v >> 8); },
            .int => { const v: u32 = @bitCast(@as(i32, @intCast(val))); blob[off] = @intCast(v & 0xff); blob[off + 1] = @intCast((v >> 8) & 0xff); blob[off + 2] = @intCast((v >> 16) & 0xff); blob[off + 3] = @intCast((v >> 24)); },
            .float => { const v: u32 = @bitCast(@as(i32, @intCast(val))); blob[off] = @intCast(v & 0xff); blob[off + 1] = @intCast((v >> 8) & 0xff); blob[off + 2] = @intCast((v >> 16) & 0xff); blob[off + 3] = @intCast((v >> 24)); },
            .long, .double => { const v: u64 = @bitCast(val); for (0..8) |j| { blob[off + j] = @intCast((v >> @intCast(j * 8)) & 0xff); } },
            .string => unreachable,
        }
        p += valuePushLen(code, p, @intCast(code.len), m.elem_type);
        p += 1; // xastore
    }
    return blob;
}

// === Helpers ===

fn readPushConst(code: []const u8, pc: u32, code_len: u32) ?i32 {
    if (pc >= code_len) return null;
    return switch (code[pc]) {
        0x02 => -1, // iconst_m1
        0x03...0x08 => @as(i32, @intCast(code[pc])) - 3, // iconst_0..5
        0x10 => @as(i32, @as(i8, @bitCast(code[pc + 1]))), // bipush
        0x11 => @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))), // sipush
        else => null,
    };
}

fn pushConstLen(op: u8) u32 {
    return switch (op) {
        0x02...0x08 => 1, 0x10 => 2, 0x11 => 3, else => 1,
    };
}

fn valuePushLen(code: []const u8, pc: u32, code_len: u32, elem_type: ArrayType) u32 {
    if (pc >= code_len) return 0;
    const op = code[pc];
    _ = elem_type;
    return switch (op) {
        0x02...0x08 => 1, // iconst
        0x09, 0x0a => 1, // lconst_0/1
        0x0b...0x0d => 1, // fconst
        0x0e, 0x0f => 1, // dconst
        0x10 => 2, // bipush
        0x11 => 3, // sipush
        0x12 => 2, // ldc
        0x13 => 3, // ldc_w
        0x14 => 3, // ldc2_w
        else => 0,
    };
}

fn isArrayStore(op: u8, elem_type: ArrayType) bool {
    return switch (elem_type) {
        .int => op == 0x4f, // iastore
        .long => op == 0x50, // lastore
        .float => op == 0x51, // fastore
        .double => op == 0x52, // dastore
        .string => op == 0x53, // aastore
        .byte => op == 0x54, // bastore
        .char => op == 0x55, // castore
        .short => op == 0x56, // sastore
    };
}

fn readNumericValue(code: []const u8, pc: u32, code_len: u32, elem_type: ArrayType) i64 {
    _ = elem_type;
    if (pc >= code_len) return 0;
    return switch (code[pc]) {
        0x02 => -1,
        0x03...0x08 => @as(i64, @intCast(code[pc])) - 3,
        0x09 => 0, // lconst_0
        0x0a => 1, // lconst_1
        0x10 => @as(i64, @as(i8, @bitCast(code[pc + 1]))),
        0x11 => @as(i64, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))),
        0x12 => 0, // ldc (int/float from CP — would need CP access, skip for now)
        0x14 => 0, // ldc2_w (long/double from CP — needs CP access)
        else => 0,
    };
}

/// Version that has CP access for ldc/ldc2_w
fn readNumericValueWithCp(code: []const u8, pc: u32, code_len: u32, cp: []const types.CpInfo) i64 {
    if (pc >= code_len) return 0;
    return switch (code[pc]) {
        0x02 => -1,
        0x03...0x08 => @as(i64, @intCast(code[pc])) - 3,
        0x09 => 0, // lconst_0
        0x0a => 1, // lconst_1
        0x10 => @as(i64, @as(i8, @bitCast(code[pc + 1]))),
        0x11 => @as(i64, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))),
        0x12 => blk: { // ldc
            const idx: u16 = code[pc + 1];
            if (idx < cp.len) switch (cp[idx]) { .integer => |v| break :blk @as(i64, v), else => {} };
            break :blk 0;
        },
        0x13 => blk: { // ldc_w
            const idx = (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]);
            if (idx < cp.len) switch (cp[idx]) { .integer => |v| break :blk @as(i64, v), else => {} };
            break :blk 0;
        },
        0x14 => blk: { // ldc2_w
            const idx = (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]);
            if (idx < cp.len) switch (cp[idx]) {
                .long => |v| break :blk v,
                .double => |v| break :blk @as(i64, @bitCast(v)),
                else => {},
            };
            break :blk 0;
        },
        else => 0,
    };
}

fn readStringValue(code: []const u8, pc: u32, cf: *const types.ClassFile) ?[]const u8 {
    if (pc >= code.len) return null;
    const op = code[pc];
    const cp_idx: u16 = switch (op) {
        0x12 => @as(u16, code[pc + 1]),
        0x13 => (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]),
        else => return null,
    };
    if (cp_idx >= cf.constant_pool.len) return null;
    return switch (cf.constant_pool[cp_idx]) {
        .string => |si| cf.getUtf8(si),
        else => null,
    };
}

const FieldRefInfo = struct { name: []const u8, descriptor: []const u8 };

fn resolveFieldInfo(cf: *const types.ClassFile, idx: u16) ?FieldRefInfo {
    if (idx >= cf.constant_pool.len) return null;
    switch (cf.constant_pool[idx]) {
        .fieldref => |r| {
            if (r.name_and_type_index >= cf.constant_pool.len) return null;
            switch (cf.constant_pool[r.name_and_type_index]) {
                .name_and_type => |nat| {
                    const name = cf.getUtf8(nat.name_index) orelse return null;
                    const desc = cf.getUtf8(nat.descriptor_index) orelse return null;
                    return .{ .name = name, .descriptor = desc };
                },
                else => return null,
            }
        },
        else => return null,
    }
}

pub fn arrayMethodDesc(elem_type: ArrayType) []const u8 {
    return switch (elem_type) {
        .int => "(J)[I",
        .long => "(J)[J",
        .float => "(J)[F",
        .double => "(J)[D",
        .byte => "(J)[B",
        .short => "(J)[S",
        .char => "(J)[C",
        .string => "(J)[Ljava/lang/String;",
    };
}

pub fn arrayMethodDescEnchanted(elem_type: ArrayType) []const u8 {
    return switch (elem_type) {
        .int => "(JJ)[I",
        .long => "(JJ)[J",
        .float => "(JJ)[F",
        .double => "(JJ)[D",
        .byte => "(JJ)[B",
        .short => "(JJ)[S",
        .char => "(JJ)[C",
        .string => "(JJ)[Ljava/lang/String;",
    };
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
            for (0..npairs) |_| {
                pos += 2;
                if (pos >= attr.data.len) break;
                pos += skipElemValue(attr.data, pos);
            }
        }
    }
    return false;
}

fn skipElemValue(data: []const u8, start: usize) usize {
    if (start >= data.len) return 0;
    return switch (data[start]) {
        'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z', 's', 'c' => 3,
        'e' => 5,
        '@' => 5,
        '[' => blk: {
            if (start + 3 > data.len) break :blk 1;
            const count = (@as(u16, data[start + 1]) << 8) | @as(u16, data[start + 2]);
            var sz: usize = 3;
            for (0..count) |_| sz += skipElemValue(data, start + sz);
            break :blk sz;
        },
        else => 1,
    };
}

fn nextKey(seed: *u64) i64 {
    seed.* ^= seed.* >> 12;
    seed.* ^= seed.* << 25;
    seed.* ^= seed.* >> 27;
    seed.* *%= 0x2545F4914F6CDD1D;
    return @bitCast(seed.*);
}

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
    return (@as(u16, data[off]) << 8) | @as(u16, data[off + 1]);
}

fn readU32(data: []const u8, off: u32) u32 {
    return (@as(u32, data[off]) << 24) | (@as(u32, data[off + 1]) << 16) | (@as(u32, data[off + 2]) << 8) | @as(u32, data[off + 3]);
}

fn opcodeLen(code: []const u8, pc: u32, code_len: u32) u32 {
    if (pc >= code_len) return 1;
    return switch (code[pc]) {
        0x10 => 2, 0x11 => 3, 0x12 => 2, 0x13, 0x14 => 3,
        0x15...0x19 => 2, 0x36...0x3a => 2, 0x84 => 3,
        0x99...0xa7 => 3, 0xc6, 0xc7 => 3, 0xc8 => 5,
        0xb2...0xb8 => 3, 0xb9 => 5, 0xba => 5,
        0xbb, 0xbd, 0xc0, 0xc1 => 3, 0xbc => 2, 0xc5 => 4,
        else => 1,
    };
}
