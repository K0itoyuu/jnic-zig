const std = @import("std");
const types = @import("../classfile/types.zig");
const nativize = @import("../transform/nativize.zig");

/// Resolved constant pool entry for C code generation
pub const CpEntry = struct {
    tag: u8,
    class_name: []const u8 = "",
    name: []const u8 = "",
    descriptor: []const u8 = "",
    int_val: i32 = 0,
    float_val: f32 = 0,
    long_val: i64 = 0,
    double_val: f64 = 0,
    string_val: []const u8 = "",
    recipe: []const u8 = "", // for invokedynamic string concat
};

/// Extract all CP entries referenced by bytecode into resolved form
pub fn extractReferencedCp(
    allocator: std.mem.Allocator,
    code_data: []const u8,
    class_cp: []const types.CpInfo,
    class_attrs: []const types.AttributeInfo,
) ![]CpEntry {
    // The code_data is the full Code attribute: max_stack(2) + max_locals(2) + code_len(4) + code + exc_table + attrs
    if (code_data.len < 8) return try allocator.alloc(CpEntry, 0);

    const code_len = (@as(u32, code_data[4]) << 24) | (@as(u32, code_data[5]) << 16) |
        (@as(u32, code_data[6]) << 8) | @as(u32, code_data[7]);
    const code = code_data[8..];
    if (code.len < code_len) return try allocator.alloc(CpEntry, 0);

    // Create output array same size as class CP
    const cp_count = class_cp.len;
    const entries = try allocator.alloc(CpEntry, cp_count);
    @memset(entries, CpEntry{ .tag = 0 });

    // Walk bytecode and collect referenced CP indices
    var pc: u32 = 0;
    while (pc < code_len) {
        const op = code[pc];
        switch (op) {
            0x12 => { // ldc
                if (pc + 1 < code_len) resolveEntry(entries, class_cp, class_attrs, @as(u16, code[pc + 1]));
                pc += 2;
            },
            0x13, 0x14 => { // ldc_w, ldc2_w
                if (pc + 2 < code_len) resolveEntry(entries, class_cp, class_attrs, readU16(code, pc + 1));
                pc += 3;
            },
            0xb2, 0xb3, 0xb4, 0xb5, // getstatic, putstatic, getfield, putfield
            0xb6, 0xb7, 0xb8, // invokevirtual, invokespecial, invokestatic
            0xbb, 0xbd, 0xc0, 0xc1, // new, anewarray, checkcast, instanceof
            => {
                if (pc + 2 < code_len) resolveEntry(entries, class_cp, class_attrs, readU16(code, pc + 1));
                pc += 3;
            },
            0xb9 => { // invokeinterface
                if (pc + 2 < code_len) resolveEntry(entries, class_cp, class_attrs, readU16(code, pc + 1));
                pc += 5;
            },
            0xba => { // invokedynamic
                if (pc + 2 < code_len) resolveEntry(entries, class_cp, class_attrs, readU16(code, pc + 1));
                pc += 5;
            },
            0xc5 => { // multianewarray
                if (pc + 2 < code_len) resolveEntry(entries, class_cp, class_attrs, readU16(code, pc + 1));
                pc += 4;
            },
            // Variable-length instructions
            0xaa => { // tableswitch
                const pad_pc = (pc + 4) & ~@as(u32, 3);
                const low = readI32(code, pad_pc + 4);
                const high = readI32(code, pad_pc + 8);
                const count: u32 = @intCast(@as(i64, high) - @as(i64, low) + 1);
                pc = pad_pc + 12 + count * 4;
            },
            0xab => { // lookupswitch
                const pad_pc = (pc + 4) & ~@as(u32, 3);
                const npairs: u32 = @intCast(readI32(code, pad_pc + 4));
                pc = pad_pc + 8 + npairs * 8;
            },
            0xc4 => { // wide
                if (pc + 1 < code_len and code[pc + 1] == 0x84) pc += 6
                else pc += 4;
            },
            else => pc += opcodeLength(op),
        }
    }

    // Also scan exception table for catch_type references
    const exc_offset = 8 + code_len;
    if (exc_offset + 2 <= code_data.len) {
        const exc_count = (@as(u16, code_data[exc_offset]) << 8) | @as(u16, code_data[exc_offset + 1]);
        var ei: u16 = 0;
        while (ei < exc_count) : (ei += 1) {
            const eoff = exc_offset + 2 + @as(u32, ei) * 8;
            if (eoff + 8 <= code_data.len) {
                const catch_type = (@as(u16, code_data[eoff + 6]) << 8) | @as(u16, code_data[eoff + 7]);
                if (catch_type != 0) {
                    resolveEntry(entries, class_cp, class_attrs, catch_type);
                }
            }
        }
    }

    return entries;
}

fn resolveEntry(entries: []CpEntry, class_cp: []const types.CpInfo, class_attrs: []const types.AttributeInfo, idx: u16) void {
    if (idx == 0 or idx >= entries.len or idx >= class_cp.len) return;
    if (entries[idx].tag != 0) return; // already resolved

    switch (class_cp[idx]) {
        .integer => |v| {
            entries[idx] = .{ .tag = 3, .int_val = v };
        },
        .float => |v| {
            entries[idx] = .{ .tag = 4, .float_val = v };
        },
        .long => |v| {
            entries[idx] = .{ .tag = 5, .long_val = v };
        },
        .double => |v| {
            entries[idx] = .{ .tag = 6, .double_val = v };
        },
        .class => |name_idx| {
            const name = getUtf8(class_cp, name_idx);
            entries[idx] = .{ .tag = 7, .class_name = name };
        },
        .string => |str_idx| {
            const val = getUtf8(class_cp, str_idx);
            entries[idx] = .{ .tag = 8, .string_val = val };
        },
        .fieldref => |r| {
            const resolved = resolveRef(class_cp, r);
            entries[idx] = .{ .tag = 9, .class_name = resolved.class_name, .name = resolved.name, .descriptor = resolved.descriptor };
        },
        .methodref => |r| {
            const resolved = resolveRef(class_cp, r);
            entries[idx] = .{ .tag = 10, .class_name = resolved.class_name, .name = resolved.name, .descriptor = resolved.descriptor };
        },
        .interface_methodref => |r| {
            const resolved = resolveRef(class_cp, r);
            entries[idx] = .{ .tag = 11, .class_name = resolved.class_name, .name = resolved.name, .descriptor = resolved.descriptor };
        },
        .invoke_dynamic => |d| {
            const nt = resolveNameAndType(class_cp, d.name_and_type_index);
            // Try to find recipe string from BootstrapMethods attribute
            const recipe = findBsmRecipe(class_cp, class_attrs, d.bootstrap_method_attr_index);
            entries[idx] = .{ .tag = 18, .name = nt.name, .descriptor = nt.descriptor, .recipe = recipe };
        },
        else => {},
    }
}

const ResolvedRef = struct { class_name: []const u8, name: []const u8, descriptor: []const u8 };

/// Parse BootstrapMethods attribute to find the recipe string for a given BSM index
fn findBsmRecipe(class_cp: []const types.CpInfo, class_attrs: []const types.AttributeInfo, bsm_idx: u16) []const u8 {
    // Find the BootstrapMethods attribute
    for (class_attrs) |attr| {
        const attr_name = getUtf8(class_cp, attr.name_index);
        if (!std.mem.eql(u8, attr_name, "BootstrapMethods")) continue;

        // Parse BootstrapMethods attribute:
        // u16 num_bootstrap_methods
        // bootstrap_method[] { u16 bootstrap_method_ref, u16 num_args, u16[] args }
        if (attr.data.len < 2) return "";
        const num_bsm = (@as(u16, attr.data[0]) << 8) | @as(u16, attr.data[1]);
        var pos: u32 = 2;
        var current_bsm: u16 = 0;

        while (current_bsm < num_bsm and pos + 4 <= attr.data.len) {
            // u16 bootstrap_method_ref (skip)
            pos += 2;
            const num_args = (@as(u16, attr.data[pos]) << 8) | @as(u16, attr.data[pos + 1]);
            pos += 2;

            if (current_bsm == bsm_idx) {
                // The first arg of makeConcatWithConstants is the recipe string
                if (num_args >= 1 and pos + 2 <= attr.data.len) {
                    const arg_idx = (@as(u16, attr.data[pos]) << 8) | @as(u16, attr.data[pos + 1]);
                    // arg_idx points to a CONSTANT_String in CP
                    if (arg_idx < class_cp.len) {
                        switch (class_cp[arg_idx]) {
                            .string => |str_idx| return getUtf8(class_cp, str_idx),
                            else => {},
                        }
                    }
                }
                return "";
            }

            // Skip args
            pos += num_args * 2;
            current_bsm += 1;
        }
        return "";
    }
    return "";
}

fn resolveRef(class_cp: []const types.CpInfo, r: types.Ref) ResolvedRef {
    const class_name = blk: {
        if (r.class_index < class_cp.len) {
            switch (class_cp[r.class_index]) {
                .class => |ni| break :blk getUtf8(class_cp, ni),
                else => {},
            }
        }
        break :blk "";
    };
    const nt = resolveNameAndType(class_cp, r.name_and_type_index);
    return .{ .class_name = class_name, .name = nt.name, .descriptor = nt.descriptor };
}

const ResolvedNT = struct { name: []const u8, descriptor: []const u8 };

fn resolveNameAndType(class_cp: []const types.CpInfo, idx: u16) ResolvedNT {
    if (idx < class_cp.len) {
        switch (class_cp[idx]) {
            .name_and_type => |nt| {
                return .{ .name = getUtf8(class_cp, nt.name_index), .descriptor = getUtf8(class_cp, nt.descriptor_index) };
            },
            else => {},
        }
    }
    return .{ .name = "", .descriptor = "" };
}

fn getUtf8(class_cp: []const types.CpInfo, idx: u16) []const u8 {
    if (idx < class_cp.len) {
        switch (class_cp[idx]) {
            .utf8 => |s| return s,
            else => {},
        }
    }
    return "";
}

fn readU16(code: []const u8, offset: u32) u16 {
    if (offset + 1 >= code.len) return 0;
    return (@as(u16, code[offset]) << 8) | @as(u16, code[offset + 1]);
}

fn readI32(code: []const u8, offset: u32) i32 {
    if (offset + 3 >= code.len) return 0;
    const v: u32 = (@as(u32, code[offset]) << 24) | (@as(u32, code[offset + 1]) << 16) |
        (@as(u32, code[offset + 2]) << 8) | @as(u32, code[offset + 3]);
    return @bitCast(v);
}

fn opcodeLength(op: u8) u32 {
    return switch (op) {
        0x00...0x0f => 1,
        0x10 => 2, // bipush
        0x11 => 3, // sipush
        0x12 => 2, // ldc
        0x13, 0x14 => 3, // ldc_w, ldc2_w
        0x15...0x19 => 2, // xload
        0x1a...0x35 => 1, // xload_N, xaload
        0x36...0x3a => 2, // xstore
        0x3b...0x56 => 1, // xstore_N, xastore
        0x57...0x5f => 1, // stack ops
        0x60...0x84 => if (op == 0x84) 3 else 1, // math, iinc
        0x85...0x93 => 1, // conversions
        0x94...0x98 => 1, // comparisons
        0x99...0xa6 => 3, // if*
        0xa7 => 3, // goto
        0xa8 => 3, // jsr (deprecated)
        0xa9 => 2, // ret
        0xac...0xb1 => 1, // returns
        0xb2...0xb8 => 3, // field/method
        0xb9 => 5, // invokeinterface
        0xba => 5, // invokedynamic
        0xbb => 3, // new
        0xbc => 2, // newarray
        0xbd => 3, // anewarray
        0xbe, 0xbf => 1, // arraylength, athrow
        0xc0, 0xc1 => 3, // checkcast, instanceof
        0xc2, 0xc3 => 1, // monitor
        0xc5 => 4, // multianewarray
        0xc6, 0xc7 => 3, // ifnull, ifnonnull
        0xc8 => 5, // goto_w
        else => 1,
    };
}
