const std = @import("std");
const types = @import("../classfile/types.zig");
const nativize = @import("../transform/nativize.zig");
const cp_extract = @import("cp_extract.zig");
const encrypt_mod = @import("../transform/encrypt.zig");

/// Check if a method can be transpiled (pure computation, no JNI calls needed)
pub fn canTranspile(method: nativize.ExtractedMethod) bool {
    const code_data = method.code_data;
    if (code_data.len < 8) return false;
    const code_len = (@as(u32, code_data[4]) << 24) | (@as(u32, code_data[5]) << 16) |
        (@as(u32, code_data[6]) << 8) | @as(u32, code_data[7]);
    const code = code_data[8..];
    if (code.len < code_len) return false;

    var pc: u32 = 0;
    while (pc < code_len) {
        const op = code[pc];
        switch (op) {
            // Only allow pure computation opcodes
            0x00...0x11, 0x14...0x4e, // nop, constants, loads, stores
            0x57...0x84, // stack ops, arithmetic, conversions, iinc
            0x85...0x98, // more conversions, comparisons
            0x99...0xa7, // branches, goto
            0xac...0xb1, // returns
            0xc6, 0xc7, // ifnull/ifnonnull
            => {},
            // ldc with int/float only (checked separately)
            0x12, 0x13 => {},
            0xb8 => {
                const idx = readU16(code, pc + 1);
                if (!isEncryptedNumberLookup(method.class_cp, idx)) return false;
            },
            else => return false, // anything else needs interpreter
        }
        pc += opcodeLen(code, pc, code_len);
    }
    return true;
}

/// Transpile a method to C code
pub fn transpileMethod(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    method: nativize.ExtractedMethod,
    fn_name: []const u8,
    enc_numbers: []const encrypt_mod.EncryptedNumber,
) !void {
    const code_data = method.code_data;
    if (code_data.len < 8) return;

    @as(void, undefined);
    const max_locals = (@as(u16, code_data[2]) << 8) | @as(u16, code_data[3]);
    const code_len = (@as(u32, code_data[4]) << 24) | (@as(u32, code_data[5]) << 16) |
        (@as(u32, code_data[6]) << 8) | @as(u32, code_data[7]);
    const code = code_data[8..];
    const class_cp = method.class_cp;
    

    // Parse descriptor for return type and params
    const desc = method.descriptor;
    const ret_char = getReturnChar(desc);
    const jni_ret = retCharToJni(ret_char);

    // Function signature
    try buf.print(allocator, "/* Transpiled: {s}.{s} */\n", .{ method.class_name, method.method_name });
    try buf.print(allocator, "JNIEXPORT {s} JNICALL {s}(JNIEnv *env, {s}", .{
        jni_ret, fn_name, if (method.is_static) "jclass _cls" else "jobject _this",
    });

    // Parameters
    const params = parseParams(desc);
    var local_idx: u16 = if (method.is_static) 0 else 1;
    for (params.types[0..params.count]) |pt| {
        try buf.print(allocator, ", {s} p{d}", .{ paramToJni(pt), local_idx });
        local_idx += if (pt == 'J' or pt == 'D') 2 else 1;
    }
    try buf.appendSlice(allocator, ") {\n");

    // Declare local variables (JVM locals as C locals)
    try buf.appendSlice(allocator, "    /* locals */\n");
    for (0..max_locals) |li| {
        try buf.print(allocator, "    jlong L{d} = 0;\n", .{li}); // use jlong for all (64-bit union)
    }

    // Initialize locals from params
    local_idx = if (method.is_static) 0 else 1;
    if (!method.is_static) {
        try buf.appendSlice(allocator, "    *(jobject*)&L0 = _this;\n");
    }
    for (params.types[0..params.count]) |pt| {
        switch (pt) {
            'J', 'D' => try buf.print(allocator, "    L{d} = *(jlong*)&p{d};\n", .{ local_idx, local_idx }),
            'L' => try buf.print(allocator, "    *(jobject*)&L{d} = p{d};\n", .{ local_idx, local_idx }),
            else => try buf.print(allocator, "    L{d} = (jlong)(jint)p{d};\n", .{ local_idx, local_idx }),
        }
        local_idx += if (pt == 'J' or pt == 'D') 2 else 1;
    }

    // Declare stack variables
    try buf.appendSlice(allocator, "    /* stack */\n");
    try buf.appendSlice(allocator, "    jlong S[16]; int sp = 0;\n");
    try buf.appendSlice(allocator, "    (void)env; (void)_cls; (void)S; (void)sp;\n\n");

    // Generate labels for branch targets first
    var branch_targets: [4096]bool = .{false} ** 4096;
    findBranchTargets(code, code_len, &branch_targets);

    // Translate bytecode to C
    var pc: u32 = 0;
    while (pc < code_len) {
        // Emit label if this PC is a branch target
        if (pc < 4096 and branch_targets[pc]) {
            try buf.print(allocator, "  L_{d}:\n", .{pc});
        }

        try translateOpcode(allocator, buf, code, pc, code_len, class_cp, method, enc_numbers);
        pc += opcodeLen(code, pc, code_len);
    }

    try buf.appendSlice(allocator, "}\n\n");
}

fn translateOpcode(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    code: []const u8,
    pc: u32,
    code_len: u32,
    class_cp: []const types.CpInfo,
    method: nativize.ExtractedMethod,
    enc_numbers: []const encrypt_mod.EncryptedNumber,
) !void {
    _ = code_len;
    _ = method;
    const op = code[pc];
    switch (op) {
        // Constants
        0x00 => {}, // nop
        0x01 => try buf.appendSlice(allocator, "    S[sp++] = 0; /* aconst_null */\n"),
        0x02 => try buf.appendSlice(allocator, "    S[sp++] = (jlong)(jint)-1;\n"),
        0x03...0x08 => try buf.print(allocator, "    S[sp++] = (jlong)(jint){d};\n", .{@as(i32, @intCast(op)) - 3}),
        0x09 => try buf.appendSlice(allocator, "    S[sp++] = 0LL; sp++;\n"), // lconst_0
        0x0a => try buf.appendSlice(allocator, "    S[sp++] = 1LL; sp++;\n"), // lconst_1
        0x0b...0x0d => try buf.print(allocator, "    *(jfloat*)&S[sp] = {d}.0f; sp++;\n", .{@as(i32, @intCast(op)) - 0x0b}),
        0x0e => try buf.appendSlice(allocator, "    *(jdouble*)&S[sp] = 0.0; sp+=2;\n"),
        0x0f => try buf.appendSlice(allocator, "    *(jdouble*)&S[sp] = 1.0; sp+=2;\n"),
        0x10 => try buf.print(allocator, "    S[sp++] = (jlong)(jint){d};\n", .{@as(i8, @bitCast(code[pc + 1]))}), // bipush
        0x11 => try buf.print(allocator, "    S[sp++] = (jlong)(jint){d};\n", .{@as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))}), // sipush
        // ldc
        0x12 => try emitLdc(allocator, buf, class_cp, @as(u16, code[pc + 1])),
        0x13 => try emitLdc(allocator, buf, class_cp, (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])),
        0x14 => try emitLdc2(allocator, buf, class_cp, (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])),
        // Loads
        0x15 => try buf.print(allocator, "    S[sp++] = L{d}; /* iload */\n", .{code[pc + 1]}),
        0x16 => try buf.print(allocator, "    S[sp] = L{d}; sp+=2; /* lload */\n", .{code[pc + 1]}),
        0x17 => try buf.print(allocator, "    S[sp] = L{d}; sp++; /* fload */\n", .{code[pc + 1]}),
        0x18 => try buf.print(allocator, "    S[sp] = L{d}; sp+=2; /* dload */\n", .{code[pc + 1]}),
        0x19 => try buf.print(allocator, "    S[sp++] = L{d}; /* aload */\n", .{code[pc + 1]}),
        0x1a...0x1d => try buf.print(allocator, "    S[sp++] = L{d};\n", .{@as(u32, op) - 0x1a}), // iload_N
        0x1e...0x21 => try buf.print(allocator, "    S[sp] = L{d}; sp+=2;\n", .{@as(u32, op) - 0x1e}), // lload_N
        0x22...0x25 => try buf.print(allocator, "    S[sp++] = L{d};\n", .{@as(u32, op) - 0x22}), // fload_N
        0x26...0x29 => try buf.print(allocator, "    S[sp] = L{d}; sp+=2;\n", .{@as(u32, op) - 0x26}), // dload_N
        0x2a...0x2d => try buf.print(allocator, "    S[sp++] = L{d};\n", .{@as(u32, op) - 0x2a}), // aload_N
        // Stores
        0x36 => try buf.print(allocator, "    L{d} = S[--sp]; /* istore */\n", .{code[pc + 1]}),
        0x37 => try buf.print(allocator, "    sp-=2; L{d} = S[sp]; /* lstore */\n", .{code[pc + 1]}),
        0x38 => try buf.print(allocator, "    L{d} = S[--sp]; /* fstore */\n", .{code[pc + 1]}),
        0x39 => try buf.print(allocator, "    sp-=2; L{d} = S[sp]; /* dstore */\n", .{code[pc + 1]}),
        0x3a => try buf.print(allocator, "    L{d} = S[--sp]; /* astore */\n", .{code[pc + 1]}),
        0x3b...0x3e => try buf.print(allocator, "    L{d} = S[--sp];\n", .{@as(u32, op) - 0x3b}), // istore_N
        0x3f...0x42 => try buf.print(allocator, "    sp-=2; L{d} = S[sp];\n", .{@as(u32, op) - 0x3f}), // lstore_N
        0x43...0x46 => try buf.print(allocator, "    L{d} = S[--sp];\n", .{@as(u32, op) - 0x43}), // fstore_N
        0x47...0x4a => try buf.print(allocator, "    sp-=2; L{d} = S[sp];\n", .{@as(u32, op) - 0x47}), // dstore_N
        0x4b...0x4e => try buf.print(allocator, "    L{d} = S[--sp];\n", .{@as(u32, op) - 0x4b}), // astore_N
        // Stack ops
        0x57 => try buf.appendSlice(allocator, "    sp--;\n"),
        0x58 => try buf.appendSlice(allocator, "    sp-=2;\n"),
        0x59 => try buf.appendSlice(allocator, "    S[sp]=S[sp-1];sp++;\n"),
        0x5f => try buf.appendSlice(allocator, "    {jlong _t=S[sp-1];S[sp-1]=S[sp-2];S[sp-2]=_t;}\n"),
        // Int arithmetic
        0x60 => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp],_a=(jint)S[--sp]; S[sp++]=(jlong)(jint)(_a+_b);}\n"),
        0x64 => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp],_a=(jint)S[--sp]; S[sp++]=(jlong)(jint)(_a-_b);}\n"),
        0x68 => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp],_a=(jint)S[--sp]; S[sp++]=(jlong)(jint)(_a*_b);}\n"),
        0x6c => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp],_a=(jint)S[--sp]; S[sp++]=(jlong)(jint)(_a/_b);}\n"),
        0x70 => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp],_a=(jint)S[--sp]; S[sp++]=(jlong)(jint)(_a%_b);}\n"),
        0x74 => try buf.appendSlice(allocator, "    S[sp-1]=(jlong)(jint)(-(jint)S[sp-1]);\n"),
        0x78 => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp],_a=(jint)S[--sp]; S[sp++]=(jlong)(jint)(_a<<(_b&31));}\n"),
        0x7a => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp],_a=(jint)S[--sp]; S[sp++]=(jlong)(jint)(_a>>(_b&31));}\n"),
        0x7c => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp]; uint32_t _a=(uint32_t)(jint)S[--sp]; S[sp++]=(jlong)(jint)(_a>>(_b&31));}\n"),
        0x7e => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp],_a=(jint)S[--sp]; S[sp++]=(jlong)(jint)(_a&_b);}\n"),
        0x80 => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp],_a=(jint)S[--sp]; S[sp++]=(jlong)(jint)(_a|_b);}\n"),
        0x82 => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp],_a=(jint)S[--sp]; S[sp++]=(jlong)(jint)(_a^_b);}\n"),
        0x84 => try buf.print(allocator, "    L{d} += {d}; /* iinc */\n", .{ code[pc + 1], @as(i8, @bitCast(code[pc + 2])) }),
        // Long arithmetic
        0x61 => try buf.appendSlice(allocator, "    {sp-=2;jlong _b=S[sp];sp-=2;jlong _a=S[sp]; S[sp]=_a+_b;sp+=2;}\n"),
        0x65 => try buf.appendSlice(allocator, "    {sp-=2;jlong _b=S[sp];sp-=2;jlong _a=S[sp]; S[sp]=_a-_b;sp+=2;}\n"),
        0x69 => try buf.appendSlice(allocator, "    {sp-=2;jlong _b=S[sp];sp-=2;jlong _a=S[sp]; S[sp]=_a*_b;sp+=2;}\n"),
        0x6d => try buf.appendSlice(allocator, "    {sp-=2;jlong _b=S[sp];sp-=2;jlong _a=S[sp]; S[sp]=_a/_b;sp+=2;}\n"),
        0x71 => try buf.appendSlice(allocator, "    {sp-=2;jlong _b=S[sp];sp-=2;jlong _a=S[sp]; S[sp]=_a%_b;sp+=2;}\n"),
        0x75 => try buf.appendSlice(allocator, "    S[sp-2]=-S[sp-2];\n"),
        0x79 => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp];sp-=2;S[sp]=S[sp]<<(_b&63);sp+=2;}\n"),
        0x7b => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp];sp-=2;S[sp]=S[sp]>>(_b&63);sp+=2;}\n"),
        0x7d => try buf.appendSlice(allocator, "    {jint _b=(jint)S[--sp];sp-=2;S[sp]=(jlong)((uint64_t)S[sp]>>(_b&63));sp+=2;}\n"),
        0x7f => try buf.appendSlice(allocator, "    {sp-=2;jlong _b=S[sp];sp-=2;S[sp]&=_b;sp+=2;}\n"),
        0x81 => try buf.appendSlice(allocator, "    {sp-=2;jlong _b=S[sp];sp-=2;S[sp]|=_b;sp+=2;}\n"),
        0x83 => try buf.appendSlice(allocator, "    {sp-=2;jlong _b=S[sp];sp-=2;S[sp]^=_b;sp+=2;}\n"),
        // Float/double arithmetic
        0x62 => try buf.appendSlice(allocator, "    {jfloat _b=*(jfloat*)&S[--sp],_a=*(jfloat*)&S[--sp]; *(jfloat*)&S[sp]=_a+_b;sp++;}\n"),
        0x66 => try buf.appendSlice(allocator, "    {jfloat _b=*(jfloat*)&S[--sp],_a=*(jfloat*)&S[--sp]; *(jfloat*)&S[sp]=_a-_b;sp++;}\n"),
        0x6a => try buf.appendSlice(allocator, "    {jfloat _b=*(jfloat*)&S[--sp],_a=*(jfloat*)&S[--sp]; *(jfloat*)&S[sp]=_a*_b;sp++;}\n"),
        0x6e => try buf.appendSlice(allocator, "    {jfloat _b=*(jfloat*)&S[--sp],_a=*(jfloat*)&S[--sp]; *(jfloat*)&S[sp]=_a/_b;sp++;}\n"),
        0x72 => try buf.appendSlice(allocator, "    {jfloat _b=*(jfloat*)&S[--sp],_a=*(jfloat*)&S[--sp]; *(jfloat*)&S[sp]=fmodf(_a,_b);sp++;}\n"),
        0x76 => try buf.appendSlice(allocator, "    {jfloat _a=*(jfloat*)&S[sp-1]; *(jfloat*)&S[sp-1]=-_a;}\n"),
        0x63 => try buf.appendSlice(allocator, "    {sp-=2;jdouble _b=*(jdouble*)&S[sp];sp-=2;jdouble _a=*(jdouble*)&S[sp]; *(jdouble*)&S[sp]=_a+_b;sp+=2;}\n"),
        0x67 => try buf.appendSlice(allocator, "    {sp-=2;jdouble _b=*(jdouble*)&S[sp];sp-=2;jdouble _a=*(jdouble*)&S[sp]; *(jdouble*)&S[sp]=_a-_b;sp+=2;}\n"),
        0x6b => try buf.appendSlice(allocator, "    {sp-=2;jdouble _b=*(jdouble*)&S[sp];sp-=2;jdouble _a=*(jdouble*)&S[sp]; *(jdouble*)&S[sp]=_a*_b;sp+=2;}\n"),
        0x6f => try buf.appendSlice(allocator, "    {sp-=2;jdouble _b=*(jdouble*)&S[sp];sp-=2;jdouble _a=*(jdouble*)&S[sp]; *(jdouble*)&S[sp]=_a/_b;sp+=2;}\n"),
        0x73 => try buf.appendSlice(allocator, "    {sp-=2;jdouble _b=*(jdouble*)&S[sp];sp-=2;jdouble _a=*(jdouble*)&S[sp]; *(jdouble*)&S[sp]=fmod(_a,_b);sp+=2;}\n"),
        0x77 => try buf.appendSlice(allocator, "    {jdouble _a=*(jdouble*)&S[sp-2]; *(jdouble*)&S[sp-2]=-_a;}\n"),
        // Conversions
        0x85 => try buf.appendSlice(allocator, "    {jint _v=(jint)S[--sp]; S[sp]=(jlong)_v; sp+=2;}\n"), // i2l
        0x86 => try buf.appendSlice(allocator, "    {jint _v=(jint)S[sp-1]; *(jfloat*)&S[sp-1]=(jfloat)_v;}\n"), // i2f
        0x87 => try buf.appendSlice(allocator, "    {jint _v=(jint)S[--sp]; *(jdouble*)&S[sp]=(jdouble)_v; sp+=2;}\n"), // i2d
        0x88 => try buf.appendSlice(allocator, "    {sp-=2; S[sp]=(jlong)(jint)S[sp]; sp++;}\n"), // l2i
        0x89 => try buf.appendSlice(allocator, "    {sp-=2; *(jfloat*)&S[sp]=(jfloat)S[sp]; sp++;}\n"), // l2f
        0x8a => try buf.appendSlice(allocator, "    {sp-=2; *(jdouble*)&S[sp]=(jdouble)S[sp]; sp+=2;}\n"), // l2d
        0x8b => try buf.appendSlice(allocator, "    {jfloat _v=*(jfloat*)&S[sp-1]; S[sp-1]=(jlong)(jint)_v;}\n"), // f2i
        0x8c => try buf.appendSlice(allocator, "    {jfloat _v=*(jfloat*)&S[--sp]; S[sp]=(jlong)_v; sp+=2;}\n"), // f2l
        0x8d => try buf.appendSlice(allocator, "    {jfloat _v=*(jfloat*)&S[--sp]; *(jdouble*)&S[sp]=(jdouble)_v; sp+=2;}\n"), // f2d
        0x8e => try buf.appendSlice(allocator, "    {sp-=2; jdouble _v=*(jdouble*)&S[sp]; S[sp++]=(jlong)(jint)_v;}\n"), // d2i
        0x8f => try buf.appendSlice(allocator, "    {sp-=2; jdouble _v=*(jdouble*)&S[sp]; S[sp]=(jlong)_v; sp+=2;}\n"), // d2l
        0x90 => try buf.appendSlice(allocator, "    {sp-=2; jdouble _v=*(jdouble*)&S[sp]; *(jfloat*)&S[sp]=(jfloat)_v; sp++;}\n"), // d2f
        0x91 => try buf.appendSlice(allocator, "    S[sp-1]=(jlong)(jint)(int8_t)(jint)S[sp-1];\n"), // i2b
        0x92 => try buf.appendSlice(allocator, "    S[sp-1]=(jlong)(jint)(uint16_t)(jint)S[sp-1];\n"), // i2c
        0x93 => try buf.appendSlice(allocator, "    S[sp-1]=(jlong)(jint)(int16_t)(jint)S[sp-1];\n"), // i2s
        // Comparisons
        0x94 => try buf.appendSlice(allocator, "    {sp-=2;jlong _b=S[sp];sp-=2;jlong _a=S[sp]; S[sp++]=(jlong)(_a>_b?1:(_a<_b?-1:0));}\n"),
        0x95 => try buf.appendSlice(allocator, "    {jfloat _b=*(jfloat*)&S[--sp],_a=*(jfloat*)&S[--sp]; S[sp++]=(jlong)(_a>_b?1:(_a<_b?-1:(_a==_b?0:-1)));}\n"),
        0x96 => try buf.appendSlice(allocator, "    {jfloat _b=*(jfloat*)&S[--sp],_a=*(jfloat*)&S[--sp]; S[sp++]=(jlong)(_a>_b?1:(_a<_b?-1:(_a==_b?0:1)));}\n"),
        0x97 => try buf.appendSlice(allocator, "    {sp-=2;jdouble _b=*(jdouble*)&S[sp];sp-=2;jdouble _a=*(jdouble*)&S[sp]; S[sp++]=(jlong)(_a>_b?1:(_a<_b?-1:(_a==_b?0:-1)));}\n"),
        0x98 => try buf.appendSlice(allocator, "    {sp-=2;jdouble _b=*(jdouble*)&S[sp];sp-=2;jdouble _a=*(jdouble*)&S[sp]; S[sp++]=(jlong)(_a>_b?1:(_a<_b?-1:(_a==_b?0:1)));}\n"),
        // Branches
        0x99 => try buf.print(allocator, "    if((jint)S[--sp]==0) goto L_{d};\n", .{@as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]))))}),
        0x9a => try buf.print(allocator, "    if((jint)S[--sp]!=0) goto L_{d};\n", .{@as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]))))}),
        0x9b => try buf.print(allocator, "    if((jint)S[--sp]<0) goto L_{d};\n", .{@as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]))))}),
        0x9c => try buf.print(allocator, "    if((jint)S[--sp]>=0) goto L_{d};\n", .{@as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]))))}),
        0x9d => try buf.print(allocator, "    if((jint)S[--sp]>0) goto L_{d};\n", .{@as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]))))}),
        0x9e => try buf.print(allocator, "    if((jint)S[--sp]<=0) goto L_{d};\n", .{@as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]))))}),
        0x9f => { const off = @as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))); try buf.print(allocator, "    {{jint _b=(jint)S[--sp],_a=(jint)S[--sp]; if(_a==_b) goto L_{d};}}\n", .{off}); },
        0xa0 => { const off = @as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))); try buf.print(allocator, "    {{jint _b=(jint)S[--sp],_a=(jint)S[--sp]; if(_a!=_b) goto L_{d};}}\n", .{off}); },
        0xa1 => { const off = @as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))); try buf.print(allocator, "    {{jint _b=(jint)S[--sp],_a=(jint)S[--sp]; if(_a<_b) goto L_{d};}}\n", .{off}); },
        0xa2 => { const off = @as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))); try buf.print(allocator, "    {{jint _b=(jint)S[--sp],_a=(jint)S[--sp]; if(_a>=_b) goto L_{d};}}\n", .{off}); },
        0xa3 => { const off = @as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))); try buf.print(allocator, "    {{jint _b=(jint)S[--sp],_a=(jint)S[--sp]; if(_a>_b) goto L_{d};}}\n", .{off}); },
        0xa4 => { const off = @as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))); try buf.print(allocator, "    {{jint _b=(jint)S[--sp],_a=(jint)S[--sp]; if(_a<=_b) goto L_{d};}}\n", .{off}); },
        0xa5 => { const off = @as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))); try buf.print(allocator, "    {{jobject _b=(jobject)S[--sp],_a=(jobject)S[--sp]; if(_a==_b) goto L_{d};}}\n", .{off}); },
        0xa6 => { const off = @as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])))); try buf.print(allocator, "    {{jobject _b=(jobject)S[--sp],_a=(jobject)S[--sp]; if(_a!=_b) goto L_{d};}}\n", .{off}); },
        // goto
        0xa7 => try buf.print(allocator, "    goto L_{d};\n", .{@as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]))))}),
        // Returns
        0xac => try buf.appendSlice(allocator, "    return (jint)S[--sp];\n"),
        0xad => try buf.appendSlice(allocator, "    sp-=2; return S[sp];\n"),
        0xae => try buf.appendSlice(allocator, "    return *(jfloat*)&S[--sp];\n"),
        0xaf => try buf.appendSlice(allocator, "    sp-=2; return *(jdouble*)&S[sp];\n"),
        0xb0 => try buf.appendSlice(allocator, "    return (jobject)S[--sp];\n"),
        0xb1 => try buf.appendSlice(allocator, "    return;\n"),
        // Field/method access — fall through to JNI calls
        0xb8 => {
            const idx = (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]);
            if (!try emitEncryptedNumberLookup(allocator, buf, class_cp, idx, enc_numbers)) {
                try emitJniCall(allocator, buf, code, pc);
            }
        },
        0xb2...0xb7, 0xb9 => try emitJniCall(allocator, buf, code, pc),
        // ifnull/ifnonnull
        0xc6 => try buf.print(allocator, "    if(S[--sp]==0) goto L_{d};\n", .{@as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]))))}),
        0xc7 => try buf.print(allocator, "    if(S[--sp]!=0) goto L_{d};\n", .{@as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]))))}),
        else => try buf.print(allocator, "    /* TODO: opcode 0x{x:0>2} */\n", .{op}),
    }
}

fn emitLdc(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), cp: []const types.CpInfo, idx: u16) !void {
    if (idx >= cp.len) return;
    switch (cp[idx]) {
        .integer => |v| try buf.print(allocator, "    S[sp++] = (jlong)(jint){d};\n", .{v}),
        .float => |v| try buf.print(allocator, "    *(jfloat*)&S[sp] = {d}f; sp++;\n", .{v}),
        .string => try buf.appendSlice(allocator, "    /* ldc string - needs JNI */ S[sp++] = 0;\n"),
        else => try buf.appendSlice(allocator, "    S[sp++] = 0;\n"),
    }
}

fn emitLdc2(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), cp: []const types.CpInfo, idx: u16) !void {
    if (idx >= cp.len) return;
    switch (cp[idx]) {
        .long => |v| try buf.print(allocator, "    S[sp] = {d}LL; sp+=2;\n", .{v}),
        .double => |v| try buf.print(allocator, "    *(jdouble*)&S[sp] = {d}; sp+=2;\n", .{v}),
        else => try buf.appendSlice(allocator, "    sp+=2;\n"),
    }
}

fn emitEncryptedNumberLookup(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    cp: []const types.CpInfo,
    method_ref_idx: u16,
    enc_numbers: []const encrypt_mod.EncryptedNumber,
) !bool {
    const lookup = resolveEncryptedLookup(cp, method_ref_idx) orelse return false;
    try buf.appendSlice(allocator, "    sp-=2; /* encrypted constant key */\n");
    try buf.appendSlice(allocator, "    {\n");
    try buf.appendSlice(allocator, "        jlong _key = S[sp];\n");
    try buf.appendSlice(allocator, "        switch (_key) {\n");
    for (enc_numbers) |n| {
        if (n.kind != lookup.kind) continue;
        switch (n.kind) {
            .int => try buf.print(allocator, "        case {d}LL: S[sp++] = (jlong)(jint){d}; break;\n", .{ n.key, @as(i32, @intCast(n.value)) }),
            .long => try buf.print(allocator, "        case {d}LL: S[sp] = {d}LL; sp+=2; break;\n", .{ n.key, n.value }),
            .float => {
                const bits: u32 = @intCast(n.value);
                try buf.print(allocator, "        case {d}LL: {{ uint32_t _bits = 0x{x:0>8}u; memcpy(&S[sp], &_bits, sizeof(_bits)); sp++; break; }}\n", .{ n.key, bits });
            },
            .double => {
                const bits: u64 = @bitCast(n.value);
                try buf.print(allocator, "        case {d}LL: {{ uint64_t _bits = 0x{x:0>16}ull; memcpy(&S[sp], &_bits, sizeof(_bits)); sp+=2; break; }}\n", .{ n.key, bits });
            },
        }
    }
    try buf.appendSlice(allocator, "        default: S[sp++] = 0; break;\n");
    try buf.appendSlice(allocator, "        }\n");
    try buf.appendSlice(allocator, "    }\n");
    return true;
}

const EncryptedLookup = struct {
    kind: encrypt_mod.NumberKind,
};

fn isEncryptedNumberLookup(cp: []const types.CpInfo, idx: u16) bool {
    return resolveEncryptedLookup(cp, idx) != null;
}

fn resolveEncryptedLookup(cp: []const types.CpInfo, idx: u16) ?EncryptedLookup {
    const ref = resolveMethodRef(cp, idx) orelse return null;
    if (std.mem.eql(u8, ref.name, "jnic$native_int") and std.mem.eql(u8, ref.descriptor, "(J)I")) return .{ .kind = .int };
    if (std.mem.eql(u8, ref.name, "jnic$native_long") and std.mem.eql(u8, ref.descriptor, "(J)J")) return .{ .kind = .long };
    if (std.mem.eql(u8, ref.name, "jnic$native_float") and std.mem.eql(u8, ref.descriptor, "(J)F")) return .{ .kind = .float };
    if (std.mem.eql(u8, ref.name, "jnic$native_double") and std.mem.eql(u8, ref.descriptor, "(J)D")) return .{ .kind = .double };
    return null;
}

const MethodRefInfo = struct {
    name: []const u8,
    descriptor: []const u8,
};

fn resolveMethodRef(cp: []const types.CpInfo, idx: u16) ?MethodRefInfo {
    if (idx >= cp.len) return null;
    const nt_idx = switch (cp[idx]) {
        .methodref => |r| r.name_and_type_index,
        else => return null,
    };
    if (nt_idx >= cp.len) return null;
    return switch (cp[nt_idx]) {
        .name_and_type => |nt| .{
            .name = getUtf8(cp, nt.name_index),
            .descriptor = getUtf8(cp, nt.descriptor_index),
        },
        else => null,
    };
}

fn getUtf8(cp: []const types.CpInfo, idx: u16) []const u8 {
    if (idx >= cp.len) return "";
    return switch (cp[idx]) {
        .utf8 => |s| s,
        else => "",
    };
}

fn emitJniCall(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), code: []const u8, pc: u32) !void {
    const op = code[pc];
    
    
    
    // For field/method access, generate a comment and fallback
    const name = switch (op) {
        0xb2 => "getstatic", 0xb3 => "putstatic", 0xb4 => "getfield", 0xb5 => "putfield",
        0xb6 => "invokevirtual", 0xb7 => "invokespecial", 0xb8 => "invokestatic", 0xb9 => "invokeinterface",
        else => "unknown",
    };
    try buf.print(allocator, "    /* {s} #{d} - needs interpreter fallback */\n", .{ name, (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]) });
}

fn findBranchTargets(code: []const u8, code_len: u32, targets: *[4096]bool) void {
    var pc: u32 = 0;
    while (pc < code_len) {
        const op = code[pc];
        if ((op >= 0x99 and op <= 0xa7) or op == 0xc6 or op == 0xc7) {
            const off: i16 = @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]));
            const target: i32 = @as(i32, @intCast(pc)) + @as(i32, off);
            if (target >= 0 and target < 4096) targets[@intCast(target)] = true;
        }
        pc += opcodeLen(code, pc, code_len);
    }
}

// === Helpers ===
fn readU16(code: []const u8, offset: u32) u16 {
    if (offset + 1 >= code.len) return 0;
    return (@as(u16, code[offset]) << 8) | @as(u16, code[offset + 1]);
}

fn getReturnChar(desc: []const u8) u8 {
    for (desc, 0..) |ch, i| { if (ch == ')' and i + 1 < desc.len) return desc[i + 1]; }
    return 'V';
}
fn retCharToJni(c: u8) []const u8 {
    return switch (c) { 'V' => "void", 'Z', 'B', 'C', 'S', 'I' => "jint", 'J' => "jlong", 'F' => "jfloat", 'D' => "jdouble", else => "jobject" };
}
fn paramToJni(c: u8) []const u8 {
    return switch (c) { 'J' => "jlong", 'D' => "jdouble", 'F' => "jfloat", 'L' => "jobject", else => "jint" };
}
const ParamInfo = struct { types: [64]u8 = undefined, count: u16 = 0 };
fn parseParams(desc: []const u8) ParamInfo {
    var info = ParamInfo{};
    var i: usize = 0;
    if (i >= desc.len or desc[i] != '(') return info;
    i += 1;
    while (i < desc.len and desc[i] != ')') {
        switch (desc[i]) {
            'B', 'C', 'S', 'I', 'Z' => { info.types[info.count] = 'I'; info.count += 1; i += 1; },
            'J' => { info.types[info.count] = 'J'; info.count += 1; i += 1; },
            'F' => { info.types[info.count] = 'F'; info.count += 1; i += 1; },
            'D' => { info.types[info.count] = 'D'; info.count += 1; i += 1; },
            'L' => { info.types[info.count] = 'L'; info.count += 1; while (i < desc.len and desc[i] != ';') i += 1; i += 1; },
            '[' => { info.types[info.count] = 'L'; info.count += 1; i += 1; while (i < desc.len and desc[i] == '[') i += 1;
                if (i < desc.len and desc[i] == 'L') { while (i < desc.len and desc[i] != ';') i += 1; i += 1; } else if (i < desc.len) i += 1; },
            else => { i += 1; },
        }
    }
    return info;
}

fn opcodeLen(code: []const u8, pc: u32, code_len: u32) u32 {
    if (pc >= code_len) return 1;
    const op = code[pc];
    return switch (op) {
        0x10 => 2, 0x11 => 3, 0x12 => 2, 0x13, 0x14 => 3,
        0x15...0x19 => 2, 0x36...0x3a => 2, 0x84 => 3,
        0x99...0xa7 => 3, 0xc6, 0xc7 => 3, 0xc8 => 5,
        0xb2...0xb8 => 3, 0xb9 => 5, 0xba => 5,
        0xbb, 0xbd, 0xc0, 0xc1 => 3, 0xbc => 2, 0xc5 => 4,
        0xaa, 0xab => 1, // handled separately
        0xc4 => if (pc + 1 < code_len and code[pc + 1] == 0x84) 6 else 4,
        else => 1,
    };
}
