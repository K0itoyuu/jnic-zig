const std = @import("std");
const types = @import("../classfile/types.zig");
const nativize = @import("../transform/nativize.zig");
const cp_extract = @import("cp_extract.zig");
const encrypt_mod = @import("../transform/encrypt.zig");

/// Check if a method can be transpiled to native C with JNI calls
pub fn canTranspile(method: nativize.ExtractedMethod) bool {
    const code_data = method.code_data;
    if (code_data.len < 8) return false;
    const code_len = (@as(u32, code_data[4]) << 24) | (@as(u32, code_data[5]) << 16) |
        (@as(u32, code_data[6]) << 8) | @as(u32, code_data[7]);
    const code = code_data[8..];
    if (code.len < code_len) return false;

    // Reject methods with exception tables (too complex for first pass)
    const exc_offset = 8 + code_len;
    if (code_data.len >= exc_offset + 2) {
        const exc_count = (@as(u16, code_data[exc_offset]) << 8) | @as(u16, code_data[exc_offset + 1]);
        if (exc_count > 0) return false;
    }

    var has_jni_ops = false;
    var has_loop = false;
    var pc: u32 = 0;
    while (pc < code_len) {
        const op = code[pc];
        switch (op) {
            // Pure computation opcodes
            0x00...0x11, 0x14...0x56, // nop, constants, loads, array loads, stores, array stores
            0x57...0x84, // stack ops (including dup variants), arithmetic, iinc
            0x85...0x98, // conversions, comparisons
            0xac...0xb1, // returns
            0xc6, 0xc7, // ifnull/ifnonnull
            0xc8, // goto_w
            => {},
            // branches — check for backward jumps (loops)
            0x99...0xa7 => {
                const off = @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])));
                if (off < 0) has_loop = true;
            },
            // ldc with int/float only (checked separately)
            0x12, 0x13 => {},
            // JNI operations (non-invoke)
            0xb2...0xb5, // field access
            0xbb...0xc1, // new, newarray, anewarray, arraylength, athrow, checkcast, instanceof
            0xc2, 0xc3, // monitorenter, monitorexit
            => { has_jni_ops = true; },
            // Method invocation — check for un-inlinable jnic$native_string
            0xb6...0xb9 => {
                has_jni_ops = true;
                if (op == 0xb8) { // invokestatic
                    const midx = (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]);
                    if (isJnicNativeString(method.class_cp, midx)) return false;
                }
            },
            // Reject: invokedynamic (0xba), tableswitch (0xaa), lookupswitch (0xab)
            0xaa, 0xab, 0xba => return false,
            else => return false,
        }
        pc += opcodeLen(code, pc, code_len);
    }
    // Pure computation methods: always transpile
    if (!has_jni_ops) return true;
    // Methods with JNI ops: only transpile if they have loops
    // (avoid regression from JNI crossing overhead on small non-loop helpers)
    return has_loop;
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
    try buf.appendSlice(allocator, "    (void)S; (void)sp;\n");
    // Exception-check return macro (type-appropriate default)
    const exc_ret: []const u8 = switch (ret_char) {
        'V' => "#define _CHK() if((*env)->ExceptionCheck(env)) return\n",
        'J' => "#define _CHK() if((*env)->ExceptionCheck(env)) return 0LL\n",
        'F' => "#define _CHK() if((*env)->ExceptionCheck(env)) return 0.0f\n",
        'D' => "#define _CHK() if((*env)->ExceptionCheck(env)) return 0.0\n",
        'L', '[' => "#define _CHK() if((*env)->ExceptionCheck(env)) return NULL\n",
        else => "#define _CHK() if((*env)->ExceptionCheck(env)) return 0\n",
    };
    try buf.appendSlice(allocator, exc_ret);
    try buf.appendSlice(allocator, "\n");

    // Generate labels for branch targets first
    var branch_targets: [4096]bool = .{false} ** 4096;
    findBranchTargets(code, code_len, &branch_targets);

    // Counter for unique static variable names in JNI calls
    var method_idx: u32 = 0;

    // Translate bytecode to C
    var pc: u32 = 0;
    while (pc < code_len) {
        // Emit label if this PC is a branch target
        if (pc < 4096 and branch_targets[pc]) {
            try buf.print(allocator, "  L_{d}:\n", .{pc});
        }

        try translateOpcode(allocator, buf, code, pc, code_len, class_cp, method, enc_numbers, &method_idx);
        pc += opcodeLen(code, pc, code_len);
    }

    try buf.appendSlice(allocator, "#undef _CHK\n}\n\n");
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
    method_idx: *u32,
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
        // Array loads
        0x2e => try buf.appendSlice(allocator, "    {jint _i=(jint)S[--sp]; jintArray _a=(jintArray)(intptr_t)S[--sp]; jint _v; (*env)->GetIntArrayRegion(env,_a,_i,1,&_v); S[sp++]=(jlong)_v;} /* iaload */\n"),
        0x2f => try buf.appendSlice(allocator, "    {jint _i=(jint)S[--sp]; jlongArray _a=(jlongArray)(intptr_t)S[--sp]; jlong _v; (*env)->GetLongArrayRegion(env,_a,_i,1,&_v); S[sp]=_v; sp+=2;} /* laload */\n"),
        0x30 => try buf.appendSlice(allocator, "    {jint _i=(jint)S[--sp]; jfloatArray _a=(jfloatArray)(intptr_t)S[--sp]; jfloat _v; (*env)->GetFloatArrayRegion(env,_a,_i,1,&_v); *(jfloat*)&S[sp]=_v; sp++;} /* faload */\n"),
        0x31 => try buf.appendSlice(allocator, "    {jint _i=(jint)S[--sp]; jdoubleArray _a=(jdoubleArray)(intptr_t)S[--sp]; jdouble _v; (*env)->GetDoubleArrayRegion(env,_a,_i,1,&_v); *(jdouble*)&S[sp]=_v; sp+=2;} /* daload */\n"),
        0x32 => try buf.appendSlice(allocator, "    {jint _i=(jint)S[--sp]; jobjectArray _a=(jobjectArray)(intptr_t)S[--sp]; S[sp++]=(jlong)(intptr_t)(*env)->GetObjectArrayElement(env,_a,_i);} /* aaload */\n"),
        0x33 => try buf.appendSlice(allocator, "    {jint _i=(jint)S[--sp]; jbyteArray _a=(jbyteArray)(intptr_t)S[--sp]; jbyte _v; (*env)->GetByteArrayRegion(env,_a,_i,1,&_v); S[sp++]=(jlong)(jint)_v;} /* baload */\n"),
        0x34 => try buf.appendSlice(allocator, "    {jint _i=(jint)S[--sp]; jcharArray _a=(jcharArray)(intptr_t)S[--sp]; jchar _v; (*env)->GetCharArrayRegion(env,_a,_i,1,&_v); S[sp++]=(jlong)(jint)_v;} /* caload */\n"),
        0x35 => try buf.appendSlice(allocator, "    {jint _i=(jint)S[--sp]; jshortArray _a=(jshortArray)(intptr_t)S[--sp]; jshort _v; (*env)->GetShortArrayRegion(env,_a,_i,1,&_v); S[sp++]=(jlong)(jint)_v;} /* saload */\n"),
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
        // Array stores
        0x4f => try buf.appendSlice(allocator, "    {jint _v=(jint)S[--sp]; jint _i=(jint)S[--sp]; jintArray _a=(jintArray)(intptr_t)S[--sp]; (*env)->SetIntArrayRegion(env,_a,_i,1,&_v);} /* iastore */\n"),
        0x50 => try buf.appendSlice(allocator, "    {sp-=2; jlong _v=S[sp]; jint _i=(jint)S[--sp]; jlongArray _a=(jlongArray)(intptr_t)S[--sp]; (*env)->SetLongArrayRegion(env,_a,_i,1,&_v);} /* lastore */\n"),
        0x51 => try buf.appendSlice(allocator, "    {jfloat _v=*(jfloat*)&S[--sp]; jint _i=(jint)S[--sp]; jfloatArray _a=(jfloatArray)(intptr_t)S[--sp]; (*env)->SetFloatArrayRegion(env,_a,_i,1,&_v);} /* fastore */\n"),
        0x52 => try buf.appendSlice(allocator, "    {sp-=2; jdouble _v=*(jdouble*)&S[sp]; jint _i=(jint)S[--sp]; jdoubleArray _a=(jdoubleArray)(intptr_t)S[--sp]; (*env)->SetDoubleArrayRegion(env,_a,_i,1,&_v);} /* dastore */\n"),
        0x53 => try buf.appendSlice(allocator, "    {jobject _v=(jobject)(intptr_t)S[--sp]; jint _i=(jint)S[--sp]; jobjectArray _a=(jobjectArray)(intptr_t)S[--sp]; (*env)->SetObjectArrayElement(env,_a,_i,_v);} /* aastore */\n"),
        0x54 => try buf.appendSlice(allocator, "    {jbyte _v=(jbyte)(jint)S[--sp]; jint _i=(jint)S[--sp]; jbyteArray _a=(jbyteArray)(intptr_t)S[--sp]; (*env)->SetByteArrayRegion(env,_a,_i,1,&_v);} /* bastore */\n"),
        0x55 => try buf.appendSlice(allocator, "    {jchar _v=(jchar)(jint)S[--sp]; jint _i=(jint)S[--sp]; jcharArray _a=(jcharArray)(intptr_t)S[--sp]; (*env)->SetCharArrayRegion(env,_a,_i,1,&_v);} /* castore */\n"),
        0x56 => try buf.appendSlice(allocator, "    {jshort _v=(jshort)(jint)S[--sp]; jint _i=(jint)S[--sp]; jshortArray _a=(jshortArray)(intptr_t)S[--sp]; (*env)->SetShortArrayRegion(env,_a,_i,1,&_v);} /* sastore */\n"),
        // Stack ops
        0x57 => try buf.appendSlice(allocator, "    sp--;\n"),
        0x58 => try buf.appendSlice(allocator, "    sp-=2;\n"),
        0x59 => try buf.appendSlice(allocator, "    S[sp]=S[sp-1];sp++;\n"),
        0x5a => try buf.appendSlice(allocator, "    {jlong _t=S[sp-1];S[sp-1]=S[sp-2];S[sp-2]=_t;S[sp]=_t;sp++;} /* dup_x1 */\n"),
        0x5b => try buf.appendSlice(allocator, "    {jlong _t=S[sp-1];S[sp-1]=S[sp-2];S[sp-2]=S[sp-3];S[sp-3]=_t;S[sp]=_t;sp++;} /* dup_x2 */\n"),
        0x5c => try buf.appendSlice(allocator, "    {S[sp]=S[sp-2];S[sp+1]=S[sp-1];sp+=2;} /* dup2 */\n"),
        0x5d => try buf.appendSlice(allocator, "    {jlong _a=S[sp-1],_b=S[sp-2];S[sp-1]=S[sp-3];S[sp-2]=_a;S[sp-3]=_b;S[sp]=_b;S[sp+1]=_a;sp+=2;} /* dup2_x1 */\n"),
        0x5e => try buf.appendSlice(allocator, "    {jlong _a=S[sp-1],_b=S[sp-2];S[sp+1]=_a;S[sp]=_b;S[sp-1]=S[sp-3];S[sp-2]=S[sp-4];S[sp-3]=_a;S[sp-4]=_b;sp+=2;} /* dup2_x2 */\n"),
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
        // Field/method access — emit proper JNI calls
        0xb2...0xb5 => try emitFieldAccess(allocator, buf, code, pc, class_cp, method_idx),
        0xb6, 0xb7, 0xb9 => try emitMethodCall(allocator, buf, code, pc, class_cp, method_idx),
        0xb8 => {
            const idx = (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]);
            if (!try emitEncryptedNumberLookup(allocator, buf, class_cp, idx, enc_numbers)) {
                try emitMethodCall(allocator, buf, code, pc, class_cp, method_idx);
            }
        },
        // Object operations
        0xbb => try emitNew(allocator, buf, code, pc, class_cp, method_idx), // new
        0xbc => try emitNewArray(allocator, buf, code, pc), // newarray
        0xbd => try emitANewArray(allocator, buf, code, pc, class_cp, method_idx), // anewarray
        0xbe => try buf.appendSlice(allocator, "    {jarray _a=(jarray)(intptr_t)S[sp-1]; S[sp-1]=(jlong)(*env)->GetArrayLength(env,_a);} /* arraylength */\n"),
        0xbf => try buf.appendSlice(allocator, "    (*env)->Throw(env,(jthrowable)(intptr_t)S[--sp]); return 0; /* athrow */\n"),
        0xc0 => { // checkcast
            const idx = (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]);
            const cn = resolveClassName(class_cp, idx);
            const n = method_idx.*;
            method_idx.* += 1;
            try buf.print(allocator, "    {{ static jclass _c_{d}=NULL;", .{n});
            try buf.print(allocator, " if(!_c_{d}) _c_{d}=(*env)->FindClass(env,\"{s}\");", .{ n, n, cn });
            try buf.print(allocator, " if(!(*env)->IsInstanceOf(env,(jobject)(intptr_t)S[sp-1],_c_{d})){{(*env)->ThrowNew(env,(*env)->FindClass(env,\"java/lang/ClassCastException\"),\"\");return 0;}} }}\n", .{n});
        },
        0xc1 => { // instanceof
            const idx = (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]);
            const cn = resolveClassName(class_cp, idx);
            const n = method_idx.*;
            method_idx.* += 1;
            try buf.print(allocator, "    {{ static jclass _c_{d}=NULL;", .{n});
            try buf.print(allocator, " if(!_c_{d}) _c_{d}=(*env)->FindClass(env,\"{s}\");", .{ n, n, cn });
            try buf.print(allocator, " jobject _o=(jobject)(intptr_t)S[--sp]; S[sp++]=(jlong)(_o?(*env)->IsInstanceOf(env,_o,_c_{d}):0); }}\n", .{n});
        },
        // Monitor operations
        0xc2 => try buf.appendSlice(allocator, "    (*env)->MonitorEnter(env,(jobject)(intptr_t)S[--sp]); /* monitorenter */\n"),
        0xc3 => try buf.appendSlice(allocator, "    (*env)->MonitorExit(env,(jobject)(intptr_t)S[--sp]); /* monitorexit */\n"),
        // ifnull/ifnonnull
        0xc6 => try buf.print(allocator, "    if(S[--sp]==0) goto L_{d};\n", .{@as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]))))}),
        0xc7 => try buf.print(allocator, "    if(S[--sp]!=0) goto L_{d};\n", .{@as(i32, @intCast(pc)) + @as(i32, @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]))))}),
        // goto_w
        0xc8 => {
            const off = @as(i32, @bitCast((@as(u32, code[pc + 1]) << 24) | (@as(u32, code[pc + 2]) << 16) | (@as(u32, code[pc + 3]) << 8) | @as(u32, code[pc + 4])));
            try buf.print(allocator, "    goto L_{d};\n", .{@as(i32, @intCast(pc)) + off});
        },
        else => try buf.print(allocator, "    /* TODO: opcode 0x{x:0>2} */\n", .{op}),
    }
}

fn emitLdc(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), cp: []const types.CpInfo, idx: u16) !void {
    if (idx >= cp.len) return;
    switch (cp[idx]) {
        .integer => |v| try buf.print(allocator, "    S[sp++] = (jlong)(jint){d};\n", .{v}),
        .float => |v| try buf.print(allocator, "    *(jfloat*)&S[sp] = {d}f; sp++;\n", .{v}),
        .string => |str_idx| {
            const str_val = if (str_idx < cp.len) switch (cp[str_idx]) {
                .utf8 => |s| s,
                else => null,
            } else null;
            if (str_val) |sv| {
                try buf.appendSlice(allocator, "    { static jobject _s_c = NULL;\n");
                try buf.appendSlice(allocator, "      if(!_s_c) _s_c=(*env)->NewGlobalRef(env,(*env)->NewStringUTF(env,\"");
                // Escape the string for C
                for (sv) |ch| {
                    switch (ch) {
                        '"' => try buf.appendSlice(allocator, "\\\""),
                        '\\' => try buf.appendSlice(allocator, "\\\\"),
                        '\n' => try buf.appendSlice(allocator, "\\n"),
                        '\r' => try buf.appendSlice(allocator, "\\r"),
                        '\t' => try buf.appendSlice(allocator, "\\t"),
                        0 => try buf.appendSlice(allocator, "\\0"),
                        else => {
                            if (ch >= 0x20 and ch < 0x7f) {
                                try buf.append(allocator, ch);
                            } else {
                                try buf.print(allocator, "\\x{x:0>2}", .{ch});
                            }
                        },
                    }
                }
                try buf.appendSlice(allocator, "\"));\n");
                try buf.appendSlice(allocator, "      S[sp++]=(jlong)(intptr_t)_s_c; }\n");
            } else {
                try buf.appendSlice(allocator, "    S[sp++] = 0;\n");
            }
        },
        .class => {
            // ldc class - push the Class object
            try buf.appendSlice(allocator, "    S[sp++] = 0; /* ldc class TODO */\n");
        },
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

fn isJnicNativeString(cp: []const types.CpInfo, idx: u16) bool {
    const ref = resolveMethodRef(cp, idx) orelse return false;
    return std.mem.eql(u8, ref.name, "jnic$native_string");
}

fn resolveEncryptedLookup(cp: []const types.CpInfo, idx: u16) ?EncryptedLookup {
    const ref = resolveMethodRef(cp, idx) orelse return null;
    // Match both old (J)X and new dual-key (JJ)X descriptors
    if (std.mem.eql(u8, ref.name, "jnic$native_int") and (std.mem.eql(u8, ref.descriptor, "(J)I") or std.mem.eql(u8, ref.descriptor, "(JJ)I"))) return .{ .kind = .int };
    if (std.mem.eql(u8, ref.name, "jnic$native_long") and (std.mem.eql(u8, ref.descriptor, "(J)J") or std.mem.eql(u8, ref.descriptor, "(JJ)J"))) return .{ .kind = .long };
    if (std.mem.eql(u8, ref.name, "jnic$native_float") and (std.mem.eql(u8, ref.descriptor, "(J)F") or std.mem.eql(u8, ref.descriptor, "(JJ)F"))) return .{ .kind = .float };
    if (std.mem.eql(u8, ref.name, "jnic$native_double") and (std.mem.eql(u8, ref.descriptor, "(J)D") or std.mem.eql(u8, ref.descriptor, "(JJ)D"))) return .{ .kind = .double };
    // Also check for jnic$native_string
    if (std.mem.startsWith(u8, ref.name, "jnic$native_")) return null; // known jnic method but can't inline → signal to reject
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

// === JNI Code Generation ===

fn resolveClassName(cp: []const types.CpInfo, class_idx: u16) []const u8 {
    if (class_idx >= cp.len) return "java/lang/Object";
    return switch (cp[class_idx]) {
        .class => |name_idx| getUtf8(cp, name_idx),
        else => "java/lang/Object",
    };
}

const FieldRefInfo = struct {
    class_name: []const u8,
    field_name: []const u8,
    descriptor: []const u8,
};

fn resolveFieldRef(cp: []const types.CpInfo, idx: u16) ?FieldRefInfo {
    if (idx >= cp.len) return null;
    const ref = switch (cp[idx]) {
        .fieldref => |r| r,
        else => return null,
    };
    const class_name = resolveClassName(cp, ref.class_index);
    if (ref.name_and_type_index >= cp.len) return null;
    const nt = switch (cp[ref.name_and_type_index]) {
        .name_and_type => |n| n,
        else => return null,
    };
    return .{
        .class_name = class_name,
        .field_name = getUtf8(cp, nt.name_index),
        .descriptor = getUtf8(cp, nt.descriptor_index),
    };
}

const FullMethodRefInfo = struct {
    class_name: []const u8,
    method_name: []const u8,
    descriptor: []const u8,
};

fn resolveFullMethodRef(cp: []const types.CpInfo, idx: u16) ?FullMethodRefInfo {
    if (idx >= cp.len) return null;
    const ref = switch (cp[idx]) {
        .methodref => |r| r,
        .interface_methodref => |r| r,
        else => return null,
    };
    const class_name = resolveClassName(cp, ref.class_index);
    if (ref.name_and_type_index >= cp.len) return null;
    const nt = switch (cp[ref.name_and_type_index]) {
        .name_and_type => |n| n,
        else => return null,
    };
    return .{
        .class_name = class_name,
        .method_name = getUtf8(cp, nt.name_index),
        .descriptor = getUtf8(cp, nt.descriptor_index),
    };
}

/// Count slots consumed by method arguments (J/D = 2 slots each, others = 1)
fn countArgSlots(desc: []const u8) u16 {
    var slots: u16 = 0;
    var i: usize = 0;
    if (i >= desc.len or desc[i] != '(') return 0;
    i += 1;
    while (i < desc.len and desc[i] != ')') {
        switch (desc[i]) {
            'J', 'D' => { slots += 2; i += 1; },
            'L' => { slots += 1; while (i < desc.len and desc[i] != ';') i += 1; i += 1; },
            '[' => { slots += 1; i += 1; while (i < desc.len and desc[i] == '[') i += 1;
                if (i < desc.len and desc[i] == 'L') { while (i < desc.len and desc[i] != ';') i += 1; i += 1; } else if (i < desc.len) i += 1; },
            else => { slots += 1; i += 1; },
        }
    }
    return slots;
}

/// Get the types of each argument slot for jvalue array construction
const ArgSlotInfo = struct { types: [128]u8 = undefined, count: u16 = 0 };
fn getArgSlots(desc: []const u8) ArgSlotInfo {
    var info = ArgSlotInfo{};
    var i: usize = 0;
    if (i >= desc.len or desc[i] != '(') return info;
    i += 1;
    while (i < desc.len and desc[i] != ')') {
        if (info.count >= 128) break;
        switch (desc[i]) {
            'B', 'C', 'S', 'I', 'Z' => { info.types[info.count] = 'I'; info.count += 1; i += 1; },
            'J' => { info.types[info.count] = 'J'; info.count += 1; i += 1; },
            'F' => { info.types[info.count] = 'F'; info.count += 1; i += 1; },
            'D' => { info.types[info.count] = 'D'; info.count += 1; i += 1; },
            'L' => { info.types[info.count] = 'L'; info.count += 1; while (i < desc.len and desc[i] != ';') i += 1; i += 1; },
            '[' => { info.types[info.count] = 'L'; info.count += 1; i += 1;
                while (i < desc.len and desc[i] == '[') i += 1;
                if (i < desc.len and desc[i] == 'L') { while (i < desc.len and desc[i] != ';') i += 1; i += 1; } else if (i < desc.len) i += 1; },
            else => { i += 1; },
        }
    }
    return info;
}

fn jniFieldGetter(desc_char: u8, is_static: bool) []const u8 {
    if (is_static) {
        return switch (desc_char) {
            'I', 'Z', 'B', 'S', 'C' => "GetStaticIntField",
            'J' => "GetStaticLongField",
            'F' => "GetStaticFloatField",
            'D' => "GetStaticDoubleField",
            else => "GetStaticObjectField",
        };
    } else {
        return switch (desc_char) {
            'I', 'Z', 'B', 'S', 'C' => "GetIntField",
            'J' => "GetLongField",
            'F' => "GetFloatField",
            'D' => "GetDoubleField",
            else => "GetObjectField",
        };
    }
}

fn jniFieldSetter(desc_char: u8, is_static: bool) []const u8 {
    if (is_static) {
        return switch (desc_char) {
            'I', 'Z', 'B', 'S', 'C' => "SetStaticIntField",
            'J' => "SetStaticLongField",
            'F' => "SetStaticFloatField",
            'D' => "SetStaticDoubleField",
            else => "SetStaticObjectField",
        };
    } else {
        return switch (desc_char) {
            'I', 'Z', 'B', 'S', 'C' => "SetIntField",
            'J' => "SetLongField",
            'F' => "SetFloatField",
            'D' => "SetDoubleField",
            else => "SetObjectField",
        };
    }
}

fn fieldDescChar(desc: []const u8) u8 {
    if (desc.len == 0) return 'L';
    return desc[0];
}

fn emitFieldAccess(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), code: []const u8, pc: u32, cp: []const types.CpInfo, method_idx: *u32) !void {
    const op = code[pc];
    const idx = (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]);
    const ref = resolveFieldRef(cp, idx) orelse {
        try buf.print(allocator, "    /* unresolved field #{d} */\n", .{idx});
        return;
    };
    const n = method_idx.*;
    method_idx.* += 1;
    const dc = fieldDescChar(ref.descriptor);
    const is_static = (op == 0xb2 or op == 0xb3);
    const id_func: []const u8 = if (is_static) "GetStaticFieldID" else "GetFieldID";

    try buf.print(allocator, "    {{ /* {s} {s}.{s}:{s} */\n", .{
        switch (op) { 0xb2 => @as([]const u8, "getstatic"), 0xb3 => "putstatic", 0xb4 => "getfield", else => "putfield" },
        ref.class_name, ref.field_name, ref.descriptor,
    });
    try buf.print(allocator, "      static jclass _c_{d}=NULL; static jfieldID _f_{d}=NULL;\n", .{ n, n });
    try buf.print(allocator, "      if(!_f_{d}){{_c_{d}=(*env)->FindClass(env,\"{s}\");_f_{d}=(*env)->{s}(env,_c_{d},\"{s}\",\"{s}\");}}\n", .{
        n, n, ref.class_name, n, id_func, n, ref.field_name, ref.descriptor,
    });

    switch (op) {
        0xb2 => { // getstatic
            switch (dc) {
                'J' => try buf.print(allocator, "      S[sp]=(*env)->{s}(env,_c_{d},_f_{d}); sp+=2;\n", .{ jniFieldGetter(dc, true), n, n }),
                'D' => try buf.print(allocator, "      *(jdouble*)&S[sp]=(*env)->{s}(env,_c_{d},_f_{d}); sp+=2;\n", .{ jniFieldGetter(dc, true), n, n }),
                'F' => try buf.print(allocator, "      *(jfloat*)&S[sp]=(*env)->{s}(env,_c_{d},_f_{d}); sp++;\n", .{ jniFieldGetter(dc, true), n, n }),
                'L', '[' => try buf.print(allocator, "      S[sp++]=(jlong)(intptr_t)(*env)->{s}(env,_c_{d},_f_{d});\n", .{ jniFieldGetter(dc, true), n, n }),
                else => try buf.print(allocator, "      S[sp++]=(jlong)(jint)(*env)->{s}(env,_c_{d},_f_{d});\n", .{ jniFieldGetter(dc, true), n, n }),
            }
        },
        0xb3 => { // putstatic
            switch (dc) {
                'J' => try buf.print(allocator, "      sp-=2; (*env)->{s}(env,_c_{d},_f_{d},(jlong)S[sp]);\n", .{ jniFieldSetter(dc, true), n, n }),
                'D' => try buf.print(allocator, "      sp-=2; (*env)->{s}(env,_c_{d},_f_{d},*(jdouble*)&S[sp]);\n", .{ jniFieldSetter(dc, true), n, n }),
                'F' => try buf.print(allocator, "      (*env)->{s}(env,_c_{d},_f_{d},*(jfloat*)&S[--sp]);\n", .{ jniFieldSetter(dc, true), n, n }),
                'L', '[' => try buf.print(allocator, "      (*env)->{s}(env,_c_{d},_f_{d},(jobject)(intptr_t)S[--sp]);\n", .{ jniFieldSetter(dc, true), n, n }),
                else => try buf.print(allocator, "      (*env)->{s}(env,_c_{d},_f_{d},(jint)S[--sp]);\n", .{ jniFieldSetter(dc, true), n, n }),
            }
        },
        0xb4 => { // getfield
            try buf.appendSlice(allocator, "      jobject _obj=(jobject)(intptr_t)S[--sp];\n");
            switch (dc) {
                'J' => try buf.print(allocator, "      S[sp]=(*env)->{s}(env,_obj,_f_{d}); sp+=2;\n", .{ jniFieldGetter(dc, false), n }),
                'D' => try buf.print(allocator, "      *(jdouble*)&S[sp]=(*env)->{s}(env,_obj,_f_{d}); sp+=2;\n", .{ jniFieldGetter(dc, false), n }),
                'F' => try buf.print(allocator, "      *(jfloat*)&S[sp]=(*env)->{s}(env,_obj,_f_{d}); sp++;\n", .{ jniFieldGetter(dc, false), n }),
                'L', '[' => try buf.print(allocator, "      S[sp++]=(jlong)(intptr_t)(*env)->{s}(env,_obj,_f_{d});\n", .{ jniFieldGetter(dc, false), n }),
                else => try buf.print(allocator, "      S[sp++]=(jlong)(jint)(*env)->{s}(env,_obj,_f_{d});\n", .{ jniFieldGetter(dc, false), n }),
            }
        },
        0xb5 => { // putfield
            switch (dc) {
                'J' => try buf.print(allocator, "      sp-=2; jlong _val=S[sp]; jobject _obj=(jobject)(intptr_t)S[--sp]; (*env)->{s}(env,_obj,_f_{d},_val);\n", .{ jniFieldSetter(dc, false), n }),
                'D' => try buf.print(allocator, "      sp-=2; jdouble _val=*(jdouble*)&S[sp]; jobject _obj=(jobject)(intptr_t)S[--sp]; (*env)->{s}(env,_obj,_f_{d},_val);\n", .{ jniFieldSetter(dc, false), n }),
                'F' => try buf.print(allocator, "      jfloat _val=*(jfloat*)&S[--sp]; jobject _obj=(jobject)(intptr_t)S[--sp]; (*env)->{s}(env,_obj,_f_{d},_val);\n", .{ jniFieldSetter(dc, false), n }),
                'L', '[' => try buf.print(allocator, "      jobject _val=(jobject)(intptr_t)S[--sp]; jobject _obj=(jobject)(intptr_t)S[--sp]; (*env)->{s}(env,_obj,_f_{d},_val);\n", .{ jniFieldSetter(dc, false), n }),
                else => try buf.print(allocator, "      jint _val=(jint)S[--sp]; jobject _obj=(jobject)(intptr_t)S[--sp]; (*env)->{s}(env,_obj,_f_{d},_val);\n", .{ jniFieldSetter(dc, false), n }),
            }
        },
        else => {},
    }
    try buf.appendSlice(allocator, "    }\n");
}

fn jniCallSuffix(ret_char: u8) []const u8 {
    return switch (ret_char) {
        'V' => "Void",
        'I', 'Z', 'B', 'S', 'C' => "Int",
        'J' => "Long",
        'F' => "Float",
        'D' => "Double",
        else => "Object",
    };
}

fn emitMethodCall(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), code: []const u8, pc: u32, cp: []const types.CpInfo, method_idx: *u32) !void {
    const op = code[pc];
    const idx = (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]);
    const ref = resolveFullMethodRef(cp, idx) orelse {
        try buf.print(allocator, "    /* unresolved method #{d} */\n", .{idx});
        return;
    };
    const n = method_idx.*;
    method_idx.* += 1;
    const is_static = (op == 0xb8);
    const is_interface = (op == 0xb9);
    const desc = ref.descriptor;
    const ret_char = getReturnChar(desc);
    const arg_slots = countArgSlots(desc);
    const args_info = getArgSlots(desc);
    const suffix = jniCallSuffix(ret_char);

    const id_func: []const u8 = if (is_static) "GetStaticMethodID" else "GetMethodID";

    try buf.print(allocator, "    {{ /* {s} {s}.{s}{s} */\n", .{
        switch (op) { 0xb6 => @as([]const u8, "invokevirtual"), 0xb7 => "invokespecial", 0xb8 => "invokestatic", else => "invokeinterface" },
        ref.class_name, ref.method_name, ref.descriptor,
    });
    try buf.print(allocator, "      static jclass _c_{d}=NULL; static jmethodID _m_{d}=NULL;\n", .{ n, n });
    try buf.print(allocator, "      if(!_m_{d}){{_c_{d}=(*env)->FindClass(env,\"{s}\");_m_{d}=(*env)->{s}(env,_c_{d},\"{s}\",\"{s}\");}}\n", .{
        n, n, ref.class_name, n, id_func, n, ref.method_name, ref.descriptor,
    });

    // Emit jvalue array and pop args from stack (right to left already on stack)
    if (args_info.count > 0) {
        try buf.print(allocator, "      jvalue _args_{d}[{d}];\n", .{ n, args_info.count });
        // Pop arguments in reverse order from the stack
        var ai: u16 = args_info.count;
        while (ai > 0) {
            ai -= 1;
            const at = args_info.types[ai];
            switch (at) {
                'J' => try buf.print(allocator, "      sp-=2; _args_{d}[{d}].j=S[sp];\n", .{ n, ai }),
                'D' => try buf.print(allocator, "      sp-=2; _args_{d}[{d}].d=*(jdouble*)&S[sp];\n", .{ n, ai }),
                'F' => try buf.print(allocator, "      _args_{d}[{d}].f=*(jfloat*)&S[--sp];\n", .{ n, ai }),
                'L' => try buf.print(allocator, "      _args_{d}[{d}].l=(jobject)(intptr_t)S[--sp];\n", .{ n, ai }),
                else => try buf.print(allocator, "      _args_{d}[{d}].i=(jint)S[--sp];\n", .{ n, ai }),
            }
        }
    } else {
        // Pop arg_slots even with 0 typed args (shouldn't happen normally but safety)
        _ = arg_slots;
    }

    // Pop receiver for non-static
    if (!is_static) {
        try buf.print(allocator, "      jobject _recv_{d}=(jobject)(intptr_t)S[--sp];\n", .{n});
    }

    // Generate the call
    const has_args = args_info.count > 0;

    if (is_static) {
        try emitCallLine(allocator, buf, "CallStatic", suffix, null, n, n, has_args, ret_char);
    } else if (is_interface) {
        try emitCallLine(allocator, buf, "Call", jniCallSuffix(ret_char), n, n, n, has_args, ret_char);
    } else if (op == 0xb7) {
        // invokespecial - use CallNonvirtual
        try emitNonvirtualCallLine(allocator, buf, suffix, n, has_args, ret_char);
    } else {
        // invokevirtual
        try emitCallLine(allocator, buf, "Call", suffix, n, n, n, has_args, ret_char);
    }
    try buf.appendSlice(allocator, "      if((*env)->ExceptionCheck(env)) { _CHK(); }\n");
    try buf.appendSlice(allocator, "    }\n");
}

fn emitCallLine(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), prefix: []const u8, suffix: []const u8, recv_n: ?u32, cls_n: u32, meth_n: u32, has_args: bool, ret_char: u8) !void {
    // Emit the actual JNI call line
    const ret_prefix: []const u8 = switch (ret_char) {
        'V' => "      ",
        'J' => "      S[sp]=",
        'D' => "      *(jdouble*)&S[sp]=",
        'F' => "      *(jfloat*)&S[sp]=",
        'L', '[' => "      S[sp++]=(jlong)(intptr_t)",
        else => "      S[sp++]=(jlong)(jint)",
    };
    try buf.appendSlice(allocator, ret_prefix);
    try buf.print(allocator, "(*env)->{s}{s}MethodA(env,", .{ prefix, suffix });
    if (recv_n) |rn| {
        try buf.print(allocator, "_recv_{d},_m_{d},", .{ rn, meth_n });
    } else {
        try buf.print(allocator, "_c_{d},_m_{d},", .{ cls_n, meth_n });
    }
    if (has_args) {
        try buf.print(allocator, "_args_{d});\n", .{meth_n});
    } else {
        try buf.appendSlice(allocator, "NULL);\n");
    }
    // Emit sp adjustment for wide returns
    switch (ret_char) {
        'J', 'D' => try buf.appendSlice(allocator, "      sp+=2;\n"),
        else => {},
    }
}

fn emitNonvirtualCallLine(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), suffix: []const u8, n: u32, has_args: bool, ret_char: u8) !void {
    const ret_prefix: []const u8 = switch (ret_char) {
        'V' => "      ",
        'J' => "      S[sp]=",
        'D' => "      *(jdouble*)&S[sp]=",
        'F' => "      *(jfloat*)&S[sp]=",
        'L', '[' => "      S[sp++]=(jlong)(intptr_t)",
        else => "      S[sp++]=(jlong)(jint)",
    };
    try buf.appendSlice(allocator, ret_prefix);
    try buf.print(allocator, "(*env)->CallNonvirtual{s}MethodA(env,_recv_{d},_c_{d},_m_{d},", .{ suffix, n, n, n });
    if (has_args) {
        try buf.print(allocator, "_args_{d});\n", .{n});
    } else {
        try buf.appendSlice(allocator, "NULL);\n");
    }
    switch (ret_char) {
        'J', 'D' => try buf.appendSlice(allocator, "      sp+=2;\n"),
        else => {},
    }
}

fn emitNew(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), code: []const u8, pc: u32, cp: []const types.CpInfo, method_idx: *u32) !void {
    const idx = (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]);
    const cn = resolveClassName(cp, idx);
    const n = method_idx.*;
    method_idx.* += 1;
    try buf.print(allocator, "    {{ static jclass _c_{d}=NULL; if(!_c_{d}) _c_{d}=(*env)->FindClass(env,\"{s}\");\n", .{ n, n, n, cn });
    try buf.print(allocator, "      S[sp++]=(jlong)(intptr_t)(*env)->AllocObject(env,_c_{d}); }} /* new */\n", .{n});
}

fn emitNewArray(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), code: []const u8, pc: u32) !void {
    const atype = code[pc + 1];
    const func: []const u8 = switch (atype) {
        4 => "NewBooleanArray",
        5 => "NewCharArray",
        6 => "NewFloatArray",
        7 => "NewDoubleArray",
        8 => "NewByteArray",
        9 => "NewShortArray",
        10 => "NewIntArray",
        11 => "NewLongArray",
        else => "NewIntArray",
    };
    try buf.print(allocator, "    {{jint _n=(jint)S[--sp]; S[sp++]=(jlong)(intptr_t)(*env)->{s}(env,_n);}} /* newarray */\n", .{func});
}

fn emitANewArray(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), code: []const u8, pc: u32, cp: []const types.CpInfo, method_idx: *u32) !void {
    const idx = (@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]);
    const cn = resolveClassName(cp, idx);
    const n = method_idx.*;
    method_idx.* += 1;
    try buf.print(allocator, "    {{ static jclass _c_{d}=NULL; if(!_c_{d}) _c_{d}=(*env)->FindClass(env,\"{s}\");\n", .{ n, n, n, cn });
    try buf.print(allocator, "      jint _n=(jint)S[--sp]; S[sp++]=(jlong)(intptr_t)(*env)->NewObjectArray(env,_n,_c_{d},NULL); }} /* anewarray */\n", .{n});
}


fn findBranchTargets(code: []const u8, code_len: u32, targets: *[4096]bool) void {
    var pc: u32 = 0;
    while (pc < code_len) {
        const op = code[pc];
        if ((op >= 0x99 and op <= 0xa7) or op == 0xc6 or op == 0xc7) {
            const off: i16 = @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2]));
            const target: i32 = @as(i32, @intCast(pc)) + @as(i32, off);
            if (target >= 0 and target < 4096) targets[@intCast(target)] = true;
        } else if (op == 0xc8) { // goto_w
            const off: i32 = @bitCast((@as(u32, code[pc + 1]) << 24) | (@as(u32, code[pc + 2]) << 16) | (@as(u32, code[pc + 3]) << 8) | @as(u32, code[pc + 4]));
            const target: i32 = @as(i32, @intCast(pc)) + off;
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
