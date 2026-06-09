const std = @import("std");
const nativize = @import("../transform/nativize.zig");
const cp_extract = @import("cp_extract.zig");

/// Generates obfuscated or sequential names for C symbols
const Names = struct {
    seed: u64 = 0,
    use_random: bool = false,
    count: usize = 0,

    fn init(count: usize) Names {
        // Use stack address + count as entropy source (different each run due to ASLR)
        var stack_var: u64 = undefined;
        const addr: u64 = @intFromPtr(&stack_var);
        const seed = addr ^ (@as(u64, @intCast(count)) *% 0x9E3779B97F4A7C15);
        return .{ .seed = seed, .use_random = true, .count = count };
    }

    fn sequential(count: usize) Names {
        return .{ .use_random = false, .count = count };
    }

    /// Generate a function name for method index (IDA-style: sub_XXXXXXXX)
    fn funcName(self: *Names, buf: *[32]u8, idx: usize) []const u8 {
        if (!self.use_random) {
            return std.fmt.bufPrint(buf, "native_{d}", .{idx}) catch "native_0";
        }
        const h = mix(self.seed +% @as(u64, @intCast(idx)) *% 0x9E3779B97F4A7C15);
        const addr = 0x180001000 + (h & 0xFFFFF0); // aligned fake address
        return std.fmt.bufPrint(buf, "sub_{X}", .{addr}) catch "sub_0";
    }

    /// Generate a variable prefix for method index (loc_XXXXXXXX style)
    fn varPrefix(self: *Names, buf: *[32]u8, idx: usize) []const u8 {
        if (!self.use_random) {
            return std.fmt.bufPrint(buf, "{d}", .{idx}) catch "0";
        }
        const h = mix(self.seed +% @as(u64, @intCast(idx)) *% 0x517CC1B727220A95);
        const addr = 0x180004000 + (h & 0xFFFFF0);
        return std.fmt.bufPrint(buf, "loc_{X}", .{addr}) catch "loc_0";
    }

    /// Generate obfuscated parameter names (arg_XX style)
    fn paramName(self: *Names, buf: *[16]u8, idx: u16) []const u8 {
        if (!self.use_random) {
            return std.fmt.bufPrint(buf, "arg{d}", .{idx}) catch "a";
        }
        const h = mix(self.seed +% @as(u64, idx) *% 0x6C62272E07BB0142);
        return std.fmt.bufPrint(buf, "a{X}", .{@as(u16, @truncate(h))}) catch "a0";
    }

    fn mix(x: u64) u64 {
        var v = x;
        v ^= v >> 30;
        v *%= 0xBF58476D1CE4E5B9;
        v ^= v >> 27;
        v *%= 0x94D049BB133111EB;
        v ^= v >> 31;
        return v;
    }
};

const encrypt_mod = @import("../transform/encrypt.zig");

const transpile = @import("transpile.zig");

const array_encrypt_mod = @import("../transform/array_encrypt.zig");

pub fn generateJniSource(
    allocator: std.mem.Allocator,
    methods: []const nativize.ExtractedMethod,
    watermark: []const u8,
    anti_debug: bool,
    renamer: bool,
    enc_strings: []const encrypt_mod.EncryptedString,
    enc_numbers: []const encrypt_mod.EncryptedNumber,
    enc_arrays: []const array_encrypt_mod.EncryptedArray,
    enchanted: bool,
) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    // Generate random name table if renamer enabled
    var names: Names = .{};
    if (renamer) {
        names = Names.init(methods.len);
    } else {
        names = Names.sequential(methods.len);
    }

    // Include interpreter inline
    try buf.appendSlice(allocator, @embedFile("jvm_interp.h"));
    try buf.appendSlice(allocator, "\n");
    try buf.appendSlice(allocator, @embedFile("jvm_interp.c"));
    try buf.appendSlice(allocator, "\n#include <math.h>\n\n");

    if (anti_debug) {
        try buf.appendSlice(allocator,
            \\#ifdef _WIN32
            \\#include <windows.h>
            \\#include <winternl.h>
            \\volatile int __ad_flag = 0;
            \\void __ad_die(void) { ExitProcess(0xDEAD); }
            \\void __anti_debug_check(void) {
            \\    /* Check 1: IsDebuggerPresent */
            \\    if (IsDebuggerPresent()) __ad_die();
            \\    /* Check 2: PEB->BeingDebugged */
            \\    PPEB peb = (PPEB)__readgsqword(0x60);
            \\    if (peb->BeingDebugged) __ad_die();
            \\    /* Check 3: NtQueryInformationProcess - DebugPort */
            \\    typedef NTSTATUS(NTAPI*NtQIP)(HANDLE,ULONG,PVOID,ULONG,PULONG);
            \\    NtQIP fn = (NtQIP)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQueryInformationProcess");
            \\    if (fn) { DWORD_PTR port = 0; fn(GetCurrentProcess(), 7, &port, sizeof(port), NULL); if (port) __ad_die(); }
            \\    /* Check 4: Timing - detect single-stepping */
            \\    LARGE_INTEGER f,t1,t2; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&t1);
            \\    volatile int x = 0; for(int i=0;i<100;i++) x+=i;
            \\    QueryPerformanceCounter(&t2);
            \\    if ((t2.QuadPart-t1.QuadPart)*1000/f.QuadPart > 50) __ad_die(); /* >50ms for trivial loop = debugger */
            \\    __ad_flag = 1;
            \\}
            \\/* Check 5: Integrity - detect breakpoints (0xCC) on our functions */
            \\void __ad_integrity(void *fn, int len) {
            \\    unsigned char *p = (unsigned char*)fn;
            \\    for (int i = 0; i < len && i < 64; i++) { if (p[i] == 0xCC) __ad_die(); }
            \\}
            \\#else
            \\#include <sys/ptrace.h>
            \\#include <signal.h>
            \\#include <stdio.h>
            \\#include <string.h>
            \\#include <time.h>
            \\volatile int __ad_flag = 0;
            \\void __ad_die(void) { raise(SIGKILL); }
            \\void __anti_debug_check(void) {
            \\    /* Check 1: ptrace self-attach */
            \\    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) __ad_die();
            \\    /* Check 2: /proc/self/status TracerPid */
            \\    FILE *f = fopen("/proc/self/status", "r");
            \\    if (f) {
            \\        char line[256];
            \\        while (fgets(line, sizeof(line), f)) {
            \\            if (strncmp(line, "TracerPid:", 10) == 0) {
            \\                int pid = atoi(line + 10);
            \\                if (pid != 0) { fclose(f); __ad_die(); }
            \\                break;
            \\            }
            \\        }
            \\        fclose(f);
            \\    }
            \\    /* Check 3: Timing check */
            \\    struct timespec t1, t2;
            \\    clock_gettime(CLOCK_MONOTONIC, &t1);
            \\    volatile int x = 0; for(int i=0;i<100;i++) x+=i;
            \\    clock_gettime(CLOCK_MONOTONIC, &t2);
            \\    long ns = (t2.tv_sec-t1.tv_sec)*1000000000L + (t2.tv_nsec-t1.tv_nsec);
            \\    if (ns > 50000000) __ad_die(); /* >50ms = single-stepping */
            \\    __ad_flag = 1;
            \\}
            \\void __ad_integrity(void *fn, int len) {
            \\    unsigned char *p = (unsigned char*)fn;
            \\    for (int i = 0; i < len && i < 64; i++) { if (p[i] == 0xCC) __ad_die(); }
            \\}
            \\#endif
            \\
            \\
        );
    }

    try buf.print(allocator, "static const char __watermark[] = \"{s}\";\n\n", .{watermark});

    // Generate compile-time salt for dynamic key derivation
    // Salt is unique per invocation (stack address as entropy)
    var salt_src: u64 = undefined;
    const compile_salt = @as(u64, @intFromPtr(&salt_src)) *% 0x517CC1B727220A95 ^ 0xDEADCAFEBEEF1234;
    try buf.print(allocator, "const uint64_t __compile_salt = 0x{X}ULL;\n\n", .{compile_salt});

    // Pre-compute master key (same formula as runtime) for encrypting values
    var master_key: i64 = undefined;
    {
        var mk: u64 = compile_salt;
        mk ^= mk >> 33;
        mk *%= 0xFF51AFD7ED558CCD;
        mk ^= mk >> 33;
        mk *%= 0xC4CEB9FE1A85EC53;
        mk ^= mk >> 33;
        master_key = @bitCast(mk);
    }

    // Generate bytecode arrays and CP arrays for each method
    var cp_entries_sizes: std.ArrayList(u32) = .empty;
    defer cp_entries_sizes.deinit(allocator);

    for (methods, 0..) |method, idx| {
        var vbuf: [32]u8 = undefined;
        const vp = names.varPrefix(&vbuf, idx);

        // Apply superinstruction optimization to bytecode
        const optimized_code = try applySuperInstructions(allocator, method.code_data);

        // Bytecode array
        try buf.print(allocator, "static const uint8_t _b_{s}[] = {{", .{vp});
        for (optimized_code, 0..) |byte, i| {
            if (i % 16 == 0) try buf.appendSlice(allocator, "\n    ");
            try buf.print(allocator, "0x{x:0>2},", .{byte});
        }
        try buf.appendSlice(allocator, "\n};\n\n");

        // Extract and emit CP
        const cp_entries = try cp_extract.extractReferencedCp(allocator, method.code_data, method.class_cp, method.class_attrs);
        try cp_entries_sizes.append(allocator, @intCast(cp_entries.len));
        try buf.print(allocator, "static const JvmCpEntry _c_{s}[{d}] = {{\n", .{ vp, cp_entries.len });
        for (cp_entries, 0..) |entry, ci| {
            if (entry.tag == 0) {
                try buf.appendSlice(allocator, "    {0},\n");
            } else {
                try emitCpEntry(allocator, &buf, entry, ci);
            }
        }
        try buf.appendSlice(allocator, "};\n\n");
        try buf.print(allocator, "static const uint32_t _n_{s} = {d};\n\n", .{ vp, cp_entries.len });
    }

    // Generate method contexts with resolution caches
    for (methods, 0..) |_, idx| {
        var vb: [32]u8 = undefined;
        const vp2 = names.varPrefix(&vb, idx);
        try buf.print(allocator, "static JvmResolved _r_{s}[{d}];\n", .{ vp2, cp_entries_sizes.items[idx] });
    }
    try buf.appendSlice(allocator, "\n");
    for (methods, 0..) |_, idx| {
        var vb: [32]u8 = undefined;
        const vp2 = names.varPrefix(&vb, idx);
        try buf.print(allocator, "static JvmMethodCtx _m_{s} = {{_b_{s}, sizeof(_b_{s}), _c_{s}, _n_{s}, _r_{s}}};\n", .{ vp2, vp2, vp2, vp2, vp2, vp2 });
    }
    try buf.appendSlice(allocator, "\n");

    // Forward declarations for native array buffers (used by transpiled methods)
    for (enc_arrays, 0..) |arr, idx| {
        const c_type = switch (arr.elem_type) {
            .int => "jint", .long => "jlong", .float => "jfloat",
            .double => "jdouble", .byte => "jbyte", .short => "jshort",
            .char => "jchar", .string => "void*",
        };
        try buf.print(allocator, "extern {s} _narr_{d}[];\n", .{ c_type, idx });
    }
    if (enc_arrays.len > 0) try buf.appendSlice(allocator, "\n");

    // Generate native stubs — transpile when possible, interpreter as fallback
    for (methods, 0..) |method, idx| {
        var fnbuf: [32]u8 = undefined;
        const fn_name = names.funcName(&fnbuf, idx);

        if (transpile.canTranspile(method)) {
            try transpile.transpileMethod(allocator, &buf, method, fn_name, enc_numbers, enc_arrays);
        } else {
            try generateStub(allocator, &buf, method, idx, &names);
        }
    }

    // Generate encrypted constant lookup functions (always emit tables, even if empty)
    try generateEncryptedLookups(allocator, &buf, enc_strings, enc_numbers, master_key, enchanted);

    // Generate encrypted array blob functions
    try generateArrayBlobs(allocator, &buf, enc_arrays, master_key);

    // Generate JNI_OnLoad (including encrypted lookup registrations)
    try generateOnLoad(allocator, &buf, methods, &names, enc_strings, enc_numbers, enc_arrays, anti_debug, enchanted);

    return buf.toOwnedSlice(allocator);
}
fn emitCpEntry(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), entry: cp_extract.CpEntry, idx: usize) !void {
    _ = idx;
    switch (entry.tag) {
        3 => try buf.print(allocator, "    {{.tag=3, .data={{.i={d}}}}},\n", .{entry.int_val}),
        4 => try buf.print(allocator, "    {{.tag=4, .data={{.f={d}}}}},\n", .{entry.float_val}),
        5 => try buf.print(allocator, "    {{.tag=5, .data={{.l={d}}}}},\n", .{entry.long_val}),
        6 => try buf.print(allocator, "    {{.tag=6, .data={{.d={d}}}}},\n", .{entry.double_val}),
        7 => {
            try buf.appendSlice(allocator, "    {.tag=7, .data={.cls={.name=\"");
            try writeEscaped(allocator, buf, entry.class_name);
            try buf.appendSlice(allocator, "\"}}},\n");
        },
        8 => {
            try buf.appendSlice(allocator, "    {.tag=8, .data={.str={.value=\"");
            try writeEscaped(allocator, buf, entry.string_val);
            try buf.appendSlice(allocator, "\"}}},\n");
        },
        9, 10, 11 => {
            try buf.print(allocator, "    {{.tag={d}, .data={{.ref={{.class_name=\"", .{entry.tag});
            try writeEscaped(allocator, buf, entry.class_name);
            try buf.appendSlice(allocator, "\", .name=\"");
            try writeEscaped(allocator, buf, entry.name);
            try buf.appendSlice(allocator, "\", .descriptor=\"");
            try writeEscaped(allocator, buf, entry.descriptor);
            try buf.appendSlice(allocator, "\"}}},\n");
        },
        18 => {
            try buf.appendSlice(allocator, "    {.tag=18, .data={.indy={.bsm_idx=0, .name=\"");
            try writeEscaped(allocator, buf, entry.name);
            try buf.appendSlice(allocator, "\", .descriptor=\"");
            try writeEscaped(allocator, buf, entry.descriptor);
            try buf.appendSlice(allocator, "\", .recipe=\"");
            try writeEscaped(allocator, buf, entry.recipe);
            try buf.appendSlice(allocator, "\"}}},\n");
        },
        else => try buf.appendSlice(allocator, "    {0},\n"),
    }
}

fn writeEscaped(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    try buf.print(allocator, "\\{o:0>3}", .{c});
                } else {
                    try buf.append(allocator, c);
                }
            },
        }
    }
}

fn generateStub(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), method: nativize.ExtractedMethod, idx: usize, names: *Names) !void {
    // Parse descriptor to determine return type and params
    const desc = method.descriptor;
    const ret_char = getReturnChar(desc);
    const jni_ret_type = retCharToJniType(ret_char);
    const ret_enum = retCharToEnum(ret_char);

    // Function signature
    var fnbuf: [32]u8 = undefined;
    const fn_name = names.funcName(&fnbuf, idx);
    var vpbuf: [32]u8 = undefined;
    const vp = names.varPrefix(&vpbuf, idx);

    try buf.print(allocator, "JNIEXPORT {s} JNICALL {s}(JNIEnv *env, {s}", .{
        jni_ret_type,
        fn_name,
        if (method.is_static) "jclass clazz" else "jobject self",
    });

    // Parse parameters from descriptor
    const params = parseParams(desc);
    var local_idx: u16 = if (method.is_static) 0 else 1;
    for (params.types[0..params.count]) |ptype| {
        var pbuf: [16]u8 = undefined;
        const pname = names.paramName(&pbuf, local_idx);
        try buf.print(allocator, ", {s} {s}", .{ paramTypeToJni(ptype), pname });
        local_idx += if (ptype == 'J' or ptype == 'D') 2 else 1;
    }
    try buf.appendSlice(allocator, ") {\n");

    // Pack args into jvalue array
    const total_slots = (if (method.is_static) @as(u16, 0) else @as(u16, 1)) + countSlots(desc);
    try buf.print(allocator, "    jvalue args[{d}];\n", .{@max(total_slots, 1)});

    var arg_idx: u16 = 0;
    if (!method.is_static) {
        try buf.print(allocator, "    args[0].l = self;\n", .{});
        arg_idx = 1;
    }

    local_idx = if (method.is_static) 0 else 1;
    for (params.types[0..params.count]) |ptype| {
        const field = switch (ptype) {
            'J' => "j",
            'D' => "d",
            'F' => "f",
            'L' => "l",
            else => "i",
        };
        var pbuf2: [16]u8 = undefined;
        const pname2 = names.paramName(&pbuf2, local_idx);
        try buf.print(allocator, "    args[{d}].{s} = {s};\n", .{ arg_idx, field, pname2 });
        arg_idx += 1;
        local_idx += if (ptype == 'J' or ptype == 'D') 2 else 1;
    }

    // Call interpreter
    try buf.print(allocator,
        \\    jvalue __ret = jvm_interpret(env, &_m_{s}, args, {d}, {s});
        \\
    , .{ vp, arg_idx, ret_enum });

    // Return
    switch (ret_char) {
        'V' => try buf.appendSlice(allocator, "    (void)__ret;\n"),
        'J' => try buf.appendSlice(allocator, "    return __ret.j;\n"),
        'F' => try buf.appendSlice(allocator, "    return __ret.f;\n"),
        'D' => try buf.appendSlice(allocator, "    return __ret.d;\n"),
        'L', '[' => try buf.appendSlice(allocator, "    return __ret.l;\n"),
        else => try buf.appendSlice(allocator, "    return __ret.i;\n"),
    }
    try buf.appendSlice(allocator, "}\n\n");
}

/// Generate encrypted array blob tables and native array construction functions
fn generateArrayBlobs(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), enc_arrays: []const array_encrypt_mod.EncryptedArray, master_key: i64) !void {
    if (enc_arrays.len == 0) return;

    try buf.appendSlice(allocator, "/* === Encrypted array blobs === */\n");

    for (enc_arrays, 0..) |arr, idx| {
        // Encrypt the blob data using Feistel cipher
        const encrypted = try encryptBlob(allocator, arr.data, arr.key, master_key);

        // Emit encrypted blob as static array
        try buf.print(allocator, "static const uint8_t _earr_{d}[] = {{", .{idx});
        for (encrypted, 0..) |b, i| {
            if (i % 16 == 0) try buf.appendSlice(allocator, "\n    ");
            try buf.print(allocator, "0x{x:0>2},", .{b});
        }
        try buf.appendSlice(allocator, "\n};\n");

        // Emit native C buffer for direct access (zero JNI overhead)
        const c_elem_type = switch (arr.elem_type) {
            .int => "jint", .long => "jlong", .float => "jfloat",
            .double => "jdouble", .byte => "jbyte", .short => "jshort",
            .char => "jchar", .string => "void*",
        };
        try buf.print(allocator, "{s} _narr_{d}[{d}];\nstatic int _narr_{d}_ok = 0;\n", .{ c_elem_type, idx, arr.length, idx });

        // Generate native function: decrypts blob, caches in C buffer, returns JNI array
        const jni_arr_type = switch (arr.elem_type) {
            .int => "jintArray", .long => "jlongArray", .float => "jfloatArray",
            .double => "jdoubleArray", .byte => "jbyteArray", .short => "jshortArray",
            .char => "jcharArray", .string => "jobjectArray",
        };
        const new_func = switch (arr.elem_type) {
            .int => "NewIntArray", .long => "NewLongArray", .float => "NewFloatArray",
            .double => "NewDoubleArray", .byte => "NewByteArray", .short => "NewShortArray",
            .char => "NewCharArray", .string => "SKIP",
        };

        try buf.print(allocator, "static {s} _arr_f{d}(JNIEnv *env, jclass c, jlong key) {{\n    (void)c;\n", .{ jni_arr_type, idx });
        // Decrypt into native buffer (cached, only once)
        try buf.print(allocator, "    if(!_narr_{d}_ok) {{\n", .{idx});
        try buf.print(allocator, "        int64_t dk = key ^ __runtime_master_key;\n        uint8_t *dkb = (uint8_t*)&dk;\n        uint8_t *mk = (uint8_t*)&__runtime_master_key;\n", .{});
        try buf.print(allocator, "        uint8_t dec[{d}];\n", .{arr.data.len});
        try buf.print(allocator, "        for(int i=0;i<{d};i++) dec[i]=_db(_earr_{d}[i],dkb,mk,i);\n", .{ arr.data.len, idx });
        try buf.print(allocator, "        memcpy(_narr_{d}, dec, {d});\n        _narr_{d}_ok = 1;\n    }}\n", .{ idx, arr.data.len, idx });

        if (arr.elem_type == .string) {
            try buf.print(allocator, "    jclass str_cls = (*env)->FindClass(env, \"java/lang/String\");\n", .{});
            try buf.print(allocator, "    jobjectArray arr = (*env)->NewObjectArray(env, {d}, str_cls, NULL);\n", .{arr.length});
            try buf.appendSlice(allocator, "    uint8_t *p = (uint8_t*)_narr_");
            try buf.print(allocator, "{d};\n    for(int i=0;i<{d};i++) {{\n", .{ idx, arr.length });
            try buf.appendSlice(allocator, "        uint16_t slen = (p[0]<<8)|p[1]; p+=2;\n");
            try buf.appendSlice(allocator, "        char *s = (char*)malloc(slen+1); memcpy(s,p,slen); s[slen]=0; p+=slen;\n");
            try buf.appendSlice(allocator, "        (*env)->SetObjectArrayElement(env, arr, i, (*env)->NewStringUTF(env, s)); free(s);\n    }\n");
        } else {
            try buf.print(allocator, "    {s} arr = (*env)->{s}(env, {d});\n", .{ jni_arr_type, new_func, arr.length });
            const set_func = switch (arr.elem_type) {
                .int => "SetIntArrayRegion", .long => "SetLongArrayRegion",
                .float => "SetFloatArrayRegion", .double => "SetDoubleArrayRegion",
                .byte => "SetByteArrayRegion", .short => "SetShortArrayRegion",
                .char => "SetCharArrayRegion", .string => unreachable,
            };
            try buf.print(allocator, "    (*env)->{s}(env, arr, 0, {d}, (void*)_narr_{d});\n", .{ set_func, arr.length, idx });
        }
        try buf.appendSlice(allocator, "    return arr;\n}\n\n");
    }
}

fn encryptBlob(allocator: std.mem.Allocator, data: []const u8, key: i64, master_key: i64) ![]u8 {
    const combined: i64 = key ^ master_key;
    const dk_bytes = @as([8]u8, @bitCast(combined));
    const mk_bytes = @as([8]u8, @bitCast(master_key));

    // Generate S-Box from master_key — MUST match generateEncryptedLookups (Fisher-Yates, 255→1)
    var sbox: [256]u8 = undefined;
    for (0..256) |i| sbox[i] = @intCast(i);
    var rng: u64 = @bitCast(master_key);
    var si: usize = 255;
    while (si > 0) : (si -= 1) {
        rng ^= rng >> 12; rng ^= rng << 25; rng ^= rng >> 27; rng *%= 0x2545F4914F6CDD1D;
        const j = rng % (si + 1);
        const tmp = sbox[si]; sbox[si] = sbox[j]; sbox[j] = tmp;
    }

    var result = try allocator.alloc(u8, data.len);
    for (data, 0..) |byte, i| {
        var v: u8 = byte;
        // 4-round Feistel: sbox → rotate_left(3) → xor(dk) → add(mk)
        for (0..4) |r| {
            v = sbox[v];
            v = (v << 3) | (v >> 5);
            v ^= dk_bytes[(i + r) % 8];
            v +%= mk_bytes[r % 8];
        }
        result[i] = v;
    }
    return result;
}

fn generateOnLoad(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), methods: []const nativize.ExtractedMethod, names: *Names, enc_strings: []const encrypt_mod.EncryptedString, enc_numbers: []const encrypt_mod.EncryptedNumber, enc_arrays: []const array_encrypt_mod.EncryptedArray, anti_debug: bool, enc_mode: bool) !void {
    try buf.appendSlice(allocator,
        \\JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
        \\    JNIEnv *env;
        \\    (void)reserved;
        \\    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) return -1;
        \\
        \\
    );

    // Call runtime key init and anti-debug in JNI_OnLoad
    try buf.appendSlice(allocator,
        \\    __init_runtime_key();
        \\
        \\
    );

    if (anti_debug) {
        try buf.appendSlice(allocator,
            \\    __anti_debug_check();
            \\    __ad_integrity((void*)JNI_OnLoad, 32);
            \\
            \\
        );
    }

    // Register array native methods FIRST (before any FindClass triggers <clinit>)
    if (enc_arrays.len > 0) {
        var arr_classes: [64][]const u8 = undefined;
        var num_arr_classes: usize = 0;
        for (enc_arrays) |arr| {
            var found = false;
            for (0..num_arr_classes) |ci| {
                if (std.mem.eql(u8, arr_classes[ci], arr.class_name)) { found = true; break; }
            }
            if (!found and num_arr_classes < 64) {
                arr_classes[num_arr_classes] = arr.class_name;
                num_arr_classes += 1;
            }
        }
        for (0..num_arr_classes) |ci| {
            try buf.print(allocator, "    {{\n        jclass cls = (*env)->FindClass(env, \"{s}\");\n        if (cls) {{\n            JNINativeMethod nms[] = {{\n", .{arr_classes[ci]});
            var acount: usize = 0;
            var per_class_idx: usize = 0;
            for (enc_arrays, 0..) |arr, aidx| {
                if (!std.mem.eql(u8, arr.class_name, arr_classes[ci])) continue;
                const desc = array_encrypt_mod.arrayMethodDesc(arr.elem_type);
                try buf.print(allocator, "                {{\"jnic$arr${d}\", \"{s}\", (void*)_arr_f{d}}},\n", .{ per_class_idx, desc, aidx });
                acount += 1;
                per_class_idx += 1;
            }
            try buf.print(allocator, "            }};\n            (*env)->RegisterNatives(env, cls, nms, {d});\n        }}\n    }}\n", .{acount});
        }
    }

    try generateEncryptedRegistrations(allocator, buf, enc_strings, enc_numbers, enc_mode);

    // Group methods by class and batch RegisterNatives
    var class_indices: [256]usize = undefined; // start index per class group
    var class_counts: [256]usize = undefined;
    var class_names: [256][]const u8 = undefined;
    var num_classes: usize = 0;

    for (methods) |method| {
        var found = false;
        for (0..num_classes) |ci| {
            if (std.mem.eql(u8, class_names[ci], method.class_name)) { class_counts[ci] += 1; found = true; break; }
        }
        if (!found and num_classes < 256) {
            class_names[num_classes] = method.class_name;
            class_counts[num_classes] = 1;
            class_indices[num_classes] = 0;
            num_classes += 1;
        }
    }

    // Emit batched RegisterNatives per class
    for (0..num_classes) |ci| {
        try buf.print(allocator, "    {{\n        jclass cls = (*env)->FindClass(env, \"{s}\");\n        if (cls) {{\n            JNINativeMethod nms[] = {{\n", .{class_names[ci]});
        var count: usize = 0;
        for (methods, 0..) |method, idx| {
            if (!std.mem.eql(u8, method.class_name, class_names[ci])) continue;
            var fnb: [32]u8 = undefined;
            const fn_name = names.funcName(&fnb, idx);
            try buf.print(allocator, "                {{\"{s}\", \"{s}\", (void*){s}}},\n", .{ method.method_name, method.descriptor, fn_name });
            count += 1;
        }
        try buf.print(allocator, "            }};\n            (*env)->RegisterNatives(env, cls, nms, {d});\n        }}\n    }}\n", .{count});
    }

    try buf.appendSlice(allocator,
        \\    return JNI_VERSION_1_6;
        \\}
        \\
    );
}

// === Descriptor parsing helpers ===

fn generateEncryptedRegistrations(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    enc_strings: []const encrypt_mod.EncryptedString,
    enc_numbers: []const encrypt_mod.EncryptedNumber,
    enc_mode: bool,
) !void {
    if (enc_strings.len == 0 and enc_numbers.len == 0) return;

    try buf.appendSlice(allocator,
        \\    /* Register encrypted constant lookup methods before class initialization can use them */
        \\
    );

    var registered_classes: [64][]const u8 = undefined;
    var num_registered: usize = 0;

    for (enc_strings) |s| {
        if (!classAlreadyRegistered(&registered_classes, num_registered, s.class_name)) {
            if (num_registered < 64) {
                registered_classes[num_registered] = s.class_name;
                num_registered += 1;
            }
            try emitEncryptedRegistration(allocator, buf, s.class_name, enc_mode);
        }
    }
    for (enc_numbers) |n| {
        if (!classAlreadyRegistered(&registered_classes, num_registered, n.class_name)) {
            if (num_registered < 64) {
                registered_classes[num_registered] = n.class_name;
                num_registered += 1;
            }
            try emitEncryptedRegistration(allocator, buf, n.class_name, enc_mode);
        }
    }
}

fn emitEncryptedRegistration(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), class_name: []const u8, enchanted: bool) !void {
    try buf.print(allocator,
        \\    {{
        \\        jclass cls = (*env)->FindClass(env, "{s}");
        \\        if (cls) {{
        \\            JNINativeMethod nms[] = {{
    , .{class_name});
    const key_desc: []const u8 = if (enchanted) "(JJ)" else "(J)";
    try buf.print(allocator, "                {{\"jnic$native_string\", \"{s}Ljava/lang/String;\", (void*)_ns}},\n", .{key_desc});
    try buf.print(allocator, "                {{\"jnic$native_int\", \"{s}I\", (void*)_ni}},\n", .{key_desc});
    try buf.print(allocator, "                {{\"jnic$native_long\", \"{s}J\", (void*)_nl}},\n", .{key_desc});
    try buf.print(allocator, "                {{\"jnic$native_float\", \"{s}F\", (void*)_nf}},\n", .{key_desc});
    try buf.print(allocator, "                {{\"jnic$native_double\", \"{s}D\", (void*)_nd}}\n", .{key_desc});
    try buf.appendSlice(allocator,
        \\            };
        \\            (*env)->RegisterNatives(env, cls, nms, 5);
        \\        }
        \\    }
        \\
    );
}

fn classAlreadyRegistered(list: []const []const u8, count: usize, name: []const u8) bool {
    for (list[0..count]) |n| { if (std.mem.eql(u8, n, name)) return true; }
    return false;
}

fn generateEncryptedLookups(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), enc_strings: []const encrypt_mod.EncryptedString, enc_numbers: []const encrypt_mod.EncryptedNumber, master_key: i64, enchanted: bool) !void {
    try buf.appendSlice(allocator, "\n/* === Encrypted constants (multi-round cipher) === */\n");

    // Generate per-build S-Box from master_key (deterministic but unique per build)
    var sbox: [256]u8 = undefined;
    var sbox_inv: [256]u8 = undefined;
    {
        // Fisher-Yates shuffle seeded from master_key
        for (0..256) |i| sbox[i] = @intCast(i);
        var rng: u64 = @bitCast(master_key);
        var i: usize = 255;
        while (i > 0) : (i -= 1) {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            rng *%= 0x2545F4914F6CDD1D;
            const j = rng % (i + 1);
            const tmp = sbox[i];
            sbox[i] = sbox[j];
            sbox[j] = tmp;
        }
        // Compute inverse
        for (0..256) |idx| sbox_inv[sbox[idx]] = @intCast(idx);
    }

    // Emit S-Box (static, not exported)
    try buf.appendSlice(allocator, "const uint8_t _sbox[256] = {");
    for (sbox, 0..) |v, i| {
        if (i % 16 == 0) try buf.appendSlice(allocator, "\n    ");
        try buf.print(allocator, "{d},", .{v});
    }
    try buf.appendSlice(allocator, "\n};\n");
    try buf.appendSlice(allocator, "const uint8_t _sbox_inv[256] = {");
    for (sbox_inv, 0..) |v, i| {
        if (i % 16 == 0) try buf.appendSlice(allocator, "\n    ");
        try buf.print(allocator, "{d},", .{v});
    }
    try buf.appendSlice(allocator, "\n};\n\n");

    // Multi-round encrypt function (compile-time, in Zig)
    // 4 rounds per byte: sbox[v] → rotate_left(3) → xor(round_key) → add(round_salt)
    const mk_bytes: [8]u8 = @bitCast(master_key);

    // String table with multi-round encrypted bytes
    try buf.print(allocator, "EncStr _enc_strs[] = {{\n", .{});
    for (enc_strings) |s| {
        try buf.print(allocator, "    {{{d}LL, \"", .{s.key});
        const dk: [8]u8 = @bitCast(s.key ^ s.decode_key ^ master_key);
        for (s.value, 0..) |ch, i| {
            var v: u8 = ch;
            // 4 rounds of encryption
            for (0..4) |round| {
                v = sbox[v]; // substitution
                v = (v << 3) | (v >> 5); // rotate left 3
                v ^= dk[(@as(usize, i) + round) % 8]; // XOR with position-dependent key
                v +%= mk_bytes[round % 8]; // modular add
            }
            try buf.print(allocator, "\\{o:0>3}", .{v});
        }
        try buf.print(allocator, "\", {d}}},\n", .{s.value.len});
    }
    try buf.appendSlice(allocator, "    {0, NULL, 0}\n};\n\n");

    // Number table (multi-round on each byte of the value)
    try buf.print(allocator, "EncNum _enc_nums[] = {{\n", .{});
    for (enc_numbers) |n| {
        const plain_bytes: [8]u8 = @bitCast(n.value);
        const dk: [8]u8 = @bitCast(n.key ^ n.decode_key ^ master_key);
        var enc_bytes: [8]u8 = undefined;
        for (0..8) |i| {
            var v: u8 = plain_bytes[i];
            for (0..4) |round| {
                v = sbox[v];
                v = (v << 3) | (v >> 5);
                v ^= dk[(i + round) % 8];
                v +%= mk_bytes[round % 8];
            }
            enc_bytes[i] = v;
        }
        const enc_val: i64 = @bitCast(enc_bytes);
        try buf.print(allocator, "    {{{d}LL, {d}LL, {d}}},\n", .{ n.key, enc_val, @intFromEnum(n.kind) });
    }
    try buf.appendSlice(allocator, "    {0, 0, 0}\n};\n\n");

    // Cache for strings
    try buf.print(allocator, "static jobject _str_cache[{d}];\n", .{@max(enc_strings.len, 1)});
    try buf.appendSlice(allocator, "static int8_t _str_cached[256];\n\n");

    // Static (non-exported) JNI stubs for yuri$native_* registration
    // These use the same multi-round decrypt as the interpreter inline path
    try buf.appendSlice(allocator,
        \\/* Internal decrypt — not exported, obfuscated name */
        \\static uint8_t _db(uint8_t v, const uint8_t *dk, const uint8_t *mk, int pos) {
        \\    for (int r = 3; r >= 0; r--) {
        \\        v -= mk[r % 8];
        \\        v ^= dk[(pos + r) % 8];
        \\        v = (v >> 3) | (v << 5);
        \\        v = _sbox_inv[v];
        \\    }
        \\    return v;
        \\}
        \\
    );
    // Generate stubs with single-key (J) or dual-key (JJ) based on enchanted mode
    if (enchanted) {
        try buf.appendSlice(allocator,
            \\static jobject _ns(JNIEnv *env, jclass c, jlong key, jlong dk) {
            \\    (void)c;
            \\    int64_t dk64 = key ^ dk ^ __runtime_master_key;
            \\    uint8_t *dkb = (uint8_t*)&dk64;
            \\    uint8_t *mk = (uint8_t*)&__runtime_master_key;
            \\    for (int i = 0; _enc_strs[i].enc != NULL; i++) {
            \\        if (_enc_strs[i].key == key) {
            \\            if (i < 256 && _str_cached[i]) return _str_cache[i];
            \\            int32_t len = _enc_strs[i].len;
            \\            char *d = (char*)malloc(len+1);
            \\            for (int j=0;j<len;j++) d[j]=_db((uint8_t)_enc_strs[i].enc[j],dkb,mk,j);
            \\            d[len]=0;
            \\            jstring r=(*env)->NewStringUTF(env,d); free(d);
            \\            if(i<256){_str_cache[i]=(*env)->NewGlobalRef(env,r);_str_cached[i]=1;}
            \\            return r;
            \\        }
            \\    }
            \\    return (*env)->NewStringUTF(env,"");
            \\}
            \\static jint _ni(JNIEnv *e,jclass c,jlong key,jlong dk){(void)e;(void)c;
            \\    int64_t dk64=key^dk^__runtime_master_key;uint8_t*dkb=(uint8_t*)&dk64;uint8_t*mk=(uint8_t*)&__runtime_master_key;
            \\    for(int i=0;_enc_nums[i].key!=0||_enc_nums[i].enc_val!=0;i++){
            \\        if(_enc_nums[i].key==key&&_enc_nums[i].kind==0){uint8_t*ev=(uint8_t*)&_enc_nums[i].enc_val;uint8_t d[8];for(int j=0;j<4;j++)d[j]=_db(ev[j],dkb,mk,j);jint r;memcpy(&r,d,4);return r;}}
            \\    return 0;}
            \\static jlong _nl(JNIEnv *e,jclass c,jlong key,jlong dk){(void)e;(void)c;
            \\    int64_t dk64=key^dk^__runtime_master_key;uint8_t*dkb=(uint8_t*)&dk64;uint8_t*mk=(uint8_t*)&__runtime_master_key;
            \\    for(int i=0;_enc_nums[i].key!=0||_enc_nums[i].enc_val!=0;i++){
            \\        if(_enc_nums[i].key==key&&_enc_nums[i].kind==1){uint8_t*ev=(uint8_t*)&_enc_nums[i].enc_val;uint8_t d[8];for(int j=0;j<8;j++)d[j]=_db(ev[j],dkb,mk,j);jlong r;memcpy(&r,d,8);return r;}}
            \\    return 0;}
            \\static jfloat _nf(JNIEnv *e,jclass c,jlong key,jlong dk){(void)e;(void)c;
            \\    int64_t dk64=key^dk^__runtime_master_key;uint8_t*dkb=(uint8_t*)&dk64;uint8_t*mk=(uint8_t*)&__runtime_master_key;
            \\    for(int i=0;_enc_nums[i].key!=0||_enc_nums[i].enc_val!=0;i++){
            \\        if(_enc_nums[i].key==key&&_enc_nums[i].kind==2){uint8_t*ev=(uint8_t*)&_enc_nums[i].enc_val;uint8_t d[4];for(int j=0;j<4;j++)d[j]=_db(ev[j],dkb,mk,j);jfloat r;memcpy(&r,d,4);return r;}}
            \\    return 0.0f;}
            \\static jdouble _nd(JNIEnv *e,jclass c,jlong key,jlong dk){(void)e;(void)c;
            \\    int64_t dk64=key^dk^__runtime_master_key;uint8_t*dkb=(uint8_t*)&dk64;uint8_t*mk=(uint8_t*)&__runtime_master_key;
            \\    for(int i=0;_enc_nums[i].key!=0||_enc_nums[i].enc_val!=0;i++){
            \\        if(_enc_nums[i].key==key&&_enc_nums[i].kind==3){uint8_t*ev=(uint8_t*)&_enc_nums[i].enc_val;uint8_t d[8];for(int j=0;j<8;j++)d[j]=_db(ev[j],dkb,mk,j);jdouble r;memcpy(&r,d,8);return r;}}
            \\    return 0.0;}
            \\
        );
    } else {
        try buf.appendSlice(allocator,
            \\static jobject _ns(JNIEnv *env, jclass c, jlong key) {
            \\    (void)c;
            \\    int64_t dk64 = key ^ __runtime_master_key;
            \\    uint8_t *dkb = (uint8_t*)&dk64;
            \\    uint8_t *mk = (uint8_t*)&__runtime_master_key;
            \\    for (int i = 0; _enc_strs[i].enc != NULL; i++) {
            \\        if (_enc_strs[i].key == key) {
            \\            if (i < 256 && _str_cached[i]) return _str_cache[i];
            \\            int32_t len = _enc_strs[i].len;
            \\            char *d = (char*)malloc(len+1);
            \\            for (int j=0;j<len;j++) d[j]=_db((uint8_t)_enc_strs[i].enc[j],dkb,mk,j);
            \\            d[len]=0;
            \\            jstring r=(*env)->NewStringUTF(env,d); free(d);
            \\            if(i<256){_str_cache[i]=(*env)->NewGlobalRef(env,r);_str_cached[i]=1;}
            \\            return r;
            \\        }
            \\    }
            \\    return (*env)->NewStringUTF(env,"");
            \\}
            \\static jint _ni(JNIEnv *e,jclass c,jlong key){(void)e;(void)c;
            \\    int64_t dk64=key^__runtime_master_key;uint8_t*dkb=(uint8_t*)&dk64;uint8_t*mk=(uint8_t*)&__runtime_master_key;
            \\    for(int i=0;_enc_nums[i].key!=0||_enc_nums[i].enc_val!=0;i++){
            \\        if(_enc_nums[i].key==key&&_enc_nums[i].kind==0){uint8_t*ev=(uint8_t*)&_enc_nums[i].enc_val;uint8_t d[8];for(int j=0;j<4;j++)d[j]=_db(ev[j],dkb,mk,j);jint r;memcpy(&r,d,4);return r;}}
            \\    return 0;}
            \\static jlong _nl(JNIEnv *e,jclass c,jlong key){(void)e;(void)c;
            \\    int64_t dk64=key^__runtime_master_key;uint8_t*dkb=(uint8_t*)&dk64;uint8_t*mk=(uint8_t*)&__runtime_master_key;
            \\    for(int i=0;_enc_nums[i].key!=0||_enc_nums[i].enc_val!=0;i++){
            \\        if(_enc_nums[i].key==key&&_enc_nums[i].kind==1){uint8_t*ev=(uint8_t*)&_enc_nums[i].enc_val;uint8_t d[8];for(int j=0;j<8;j++)d[j]=_db(ev[j],dkb,mk,j);jlong r;memcpy(&r,d,8);return r;}}
            \\    return 0;}
            \\static jfloat _nf(JNIEnv *e,jclass c,jlong key){(void)e;(void)c;
            \\    int64_t dk64=key^__runtime_master_key;uint8_t*dkb=(uint8_t*)&dk64;uint8_t*mk=(uint8_t*)&__runtime_master_key;
            \\    for(int i=0;_enc_nums[i].key!=0||_enc_nums[i].enc_val!=0;i++){
            \\        if(_enc_nums[i].key==key&&_enc_nums[i].kind==2){uint8_t*ev=(uint8_t*)&_enc_nums[i].enc_val;uint8_t d[4];for(int j=0;j<4;j++)d[j]=_db(ev[j],dkb,mk,j);jfloat r;memcpy(&r,d,4);return r;}}
            \\    return 0.0f;}
            \\static jdouble _nd(JNIEnv *e,jclass c,jlong key){(void)e;(void)c;
            \\    int64_t dk64=key^__runtime_master_key;uint8_t*dkb=(uint8_t*)&dk64;uint8_t*mk=(uint8_t*)&__runtime_master_key;
            \\    for(int i=0;_enc_nums[i].key!=0||_enc_nums[i].enc_val!=0;i++){
            \\        if(_enc_nums[i].key==key&&_enc_nums[i].kind==3){uint8_t*ev=(uint8_t*)&_enc_nums[i].enc_val;uint8_t d[8];for(int j=0;j<8;j++)d[j]=_db(ev[j],dkb,mk,j);jdouble r;memcpy(&r,d,8);return r;}}
            \\    return 0.0;}
            \\
        );
    }
}


fn appendJniMangled(allocator: std.mem.Allocator, out: *std.ArrayList(u8), s: []const u8, slash_as_underscore: bool) !void {
    for (s) |ch| {
        switch (ch) {
            '/' => if (slash_as_underscore) try out.append(allocator, '_') else try out.appendSlice(allocator, "_2"),
            '_' => try out.appendSlice(allocator, "_1"),
            ';' => try out.appendSlice(allocator, "_2"),
            '[' => try out.appendSlice(allocator, "_3"),
            'A'...'Z', 'a'...'z', '0'...'9' => try out.append(allocator, ch),
            else => try out.print(allocator, "_0{x:0>4}", .{ch}),
        }
    }
}

fn getReturnChar(desc: []const u8) u8 {
    for (desc, 0..) |c, i| {
        if (c == ')' and i + 1 < desc.len) return desc[i + 1];
    }
    return 'V';
}

fn retCharToJniType(c: u8) []const u8 {
    return switch (c) {
        'V' => "void",
        'Z', 'B', 'C', 'S', 'I' => "jint",
        'J' => "jlong",
        'F' => "jfloat",
        'D' => "jdouble",
        else => "jobject",
    };
}

fn retCharToEnum(c: u8) []const u8 {
    return switch (c) {
        'V' => "RET_VOID",
        'Z', 'B', 'C', 'S', 'I' => "RET_INT",
        'J' => "RET_LONG",
        'F' => "RET_FLOAT",
        'D' => "RET_DOUBLE",
        else => "RET_OBJECT",
    };
}

fn paramTypeToJni(c: u8) []const u8 {
    return switch (c) {
        'J' => "jlong",
        'D' => "jdouble",
        'F' => "jfloat",
        'L' => "jobject",
        else => "jint",
    };
}

const ParamInfo = struct {
    types: [256]u8 = undefined,
    count: u16 = 0,
};

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
            '[' => { info.types[info.count] = 'L'; info.count += 1; i += 1;
                while (i < desc.len and desc[i] == '[') i += 1;
                if (i < desc.len and desc[i] == 'L') { while (i < desc.len and desc[i] != ';') i += 1; i += 1; }
                else if (i < desc.len) i += 1;
            },
            else => { i += 1; },
        }
    }
    return info;
}

fn countSlots(desc: []const u8) u16 {
    var slots: u16 = 0;
    var i: usize = 0;
    if (i >= desc.len or desc[i] != '(') return 0;
    i += 1;
    while (i < desc.len and desc[i] != ')') {
        switch (desc[i]) {
            'J', 'D' => { slots += 1; i += 1; }, // args array uses 1 slot per param
            'L' => { slots += 1; while (i < desc.len and desc[i] != ';') i += 1; i += 1; },
            '[' => { slots += 1; i += 1;
                while (i < desc.len and desc[i] == '[') i += 1;
                if (i < desc.len and desc[i] == 'L') { while (i < desc.len and desc[i] != ';') i += 1; i += 1; }
                else if (i < desc.len) i += 1;
            },
            else => { slots += 1; i += 1; },
        }
    }
    return slots;
}

/// Superinstruction opcodes
const SUPER_IINC_GOTO: u8 = 0xfe; // iinc + goto backward: [0xfe, idx, inc, off_hi, off_lo]
const SUPER_ILOAD_CMP: u8 = 0xfd; // iload + iload + if_icmpXX: [0xfd, loc1, loc2, cmp, off_hi, off_lo]

/// Apply superinstruction optimization to code_attr (header + bytecode + rest)
fn applySuperInstructions(allocator: std.mem.Allocator, code_data: []const u8) ![]u8 {
    if (code_data.len < 8) return try allocator.dupe(u8, code_data);

    const code_len = (@as(u32, code_data[4]) << 24) | (@as(u32, code_data[5]) << 16) |
        (@as(u32, code_data[6]) << 8) | @as(u32, code_data[7]);
    if (8 + code_len > code_data.len) return try allocator.dupe(u8, code_data);

    const code = code_data[8 .. 8 + code_len];
    const rest = code_data[8 + code_len ..];

    // First pass: find all branch targets (can't merge across them)
    var targets = try allocator.alloc(bool, code_len);
    defer allocator.free(targets);
    @memset(targets, false);

    var pc: u32 = 0;
    while (pc < code_len) {
        const op = code[pc];
        switch (op) {
            0x99...0xa7, 0xc6, 0xc7 => { // short branches + goto
                const off = @as(i16, @bitCast((@as(u16, code[pc + 1]) << 8) | @as(u16, code[pc + 2])));
                const tgt: i32 = @as(i32, @intCast(pc)) + @as(i32, off);
                if (tgt >= 0 and tgt < @as(i32, @intCast(code_len))) targets[@intCast(tgt)] = true;
            },
            0xc8 => { // goto_w
                const off = @as(i32, @bitCast((@as(u32, code[pc + 1]) << 24) | (@as(u32, code[pc + 2]) << 16) | (@as(u32, code[pc + 3]) << 8) | @as(u32, code[pc + 4])));
                const tgt: i32 = @as(i32, @intCast(pc)) + off;
                if (tgt >= 0 and tgt < @as(i32, @intCast(code_len))) targets[@intCast(tgt)] = true;
            },
            else => {},
        }
        pc += opcodeLength(code, pc, code_len);
    }

    // Second pass: apply superinstruction rewrites (in-place, same size)
    var out = try allocator.alloc(u8, code_data.len);
    @memcpy(out[0..8], code_data[0..8]); // header
    @memcpy(out[8 .. 8 + code_len], code); // bytecode
    @memcpy(out[8 + code_len ..], rest); // rest
    const oc = out[8 .. 8 + code_len];

    pc = 0;
    while (pc < code_len) {
        const op = oc[pc];
        // Pattern 1: iinc(3) + goto(3) with backward offset → SUPER_IINC_GOTO(5) + nop(1)
        if (op == 0x84 and pc + 6 <= code_len) {
            const next_pc = pc + 3;
            if (!targets[next_pc] and oc[next_pc] == 0xa7) { // goto
                const goto_off = @as(i16, @bitCast((@as(u16, oc[next_pc + 1]) << 8) | @as(u16, oc[next_pc + 2])));
                if (goto_off < 0) { // backward jump (loop)
                    // target = (pc+3) + goto_off; super_off = target - pc = goto_off + 3
                    const combined_off: i16 = goto_off + 3;
                    oc[pc] = SUPER_IINC_GOTO;
                    // oc[pc+1] = idx (already there from iinc)
                    // oc[pc+2] = inc (already there from iinc)
                    oc[pc + 3] = @intCast(@as(u16, @bitCast(combined_off)) >> 8);
                    oc[pc + 4] = @intCast(@as(u16, @bitCast(combined_off)) & 0xff);
                    oc[pc + 5] = 0x00; // nop padding
                    pc += 6;
                    continue;
                }
            }
        }
        // Pattern 2: iload_X(1) + iload_Y(1) + if_icmpXX(3) → SUPER_ILOAD_CMP(6) (save size by NOP is not possible if 5→6)
        // Actually 1+1+3=5 bytes, super is 6 bytes — doesn't fit. Skip this pattern for same-size constraint.
        // Instead: iload(2) + iload(2) + if_icmpXX(3) = 7 → SUPER_ILOAD_CMP(6) + nop(1)
        if (op == 0x15 and pc + 7 <= code_len) { // iload
            const next_pc = pc + 2;
            if (!targets[next_pc] and oc[next_pc] == 0x15) { // iload
                const third_pc = next_pc + 2;
                if (!targets[third_pc] and oc[third_pc] >= 0x9f and oc[third_pc] <= 0xa4) { // if_icmpXX
                    const cmp_type: u8 = oc[third_pc] - 0x9f; // 0=eq,1=ne,2=lt,3=ge,4=gt,5=le
                    // Remap: if_icmpeq=0x9f→4(eq), ne=0xa0→5(ne), lt=0xa1→0(lt), ge=0xa2→1(ge), gt=0xa3→2(gt), le=0xa4→3(le)
                    const cmp_remap = [_]u8{ 4, 5, 0, 1, 2, 3 };
                    // Original offset relative to third_pc; adjust to be relative to pc
                    const raw_off = @as(i16, @bitCast((@as(u16, oc[third_pc + 1]) << 8) | @as(u16, oc[third_pc + 2])));
                    const adj_off: i16 = raw_off + 4; // target = (pc+4)+raw_off, super needs pc+adj_off
                    oc[pc] = SUPER_ILOAD_CMP;
                    oc[pc + 1] = oc[pc + 1]; // local1 (already there)
                    oc[pc + 2] = oc[next_pc + 1]; // local2
                    oc[pc + 3] = cmp_remap[cmp_type];
                    oc[pc + 4] = @intCast(@as(u16, @bitCast(adj_off)) >> 8);
                    oc[pc + 5] = @intCast(@as(u16, @bitCast(adj_off)) & 0xff);
                    oc[pc + 6] = 0x00; // nop
                    pc += 7;
                    continue;
                }
            }
        }
        pc += opcodeLength(oc, pc, code_len);
    }

    return out;
}

fn opcodeLength(code: []const u8, pc: u32, code_len: u32) u32 {
    if (pc >= code_len) return 1;
    const op = code[pc];
    return switch (op) {
        0x10 => 2, 0x11 => 3, 0x12 => 2, 0x13, 0x14 => 3,
        0x15...0x19 => 2, 0x36...0x3a => 2, 0x84 => 3,
        0x99...0xa7 => 3, 0xc6, 0xc7 => 3, 0xc8 => 5,
        0xb2...0xb8 => 3, 0xb9 => 5, 0xba => 5,
        0xbb, 0xbd, 0xc0, 0xc1 => 3, 0xbc => 2, 0xc5 => 4,
        SUPER_IINC_GOTO => 6, // our super: 0xfe
        SUPER_ILOAD_CMP => 7, // our super: 0xfd (6 + 1 nop)
        0xaa => blk: { // tableswitch
            const pp = (pc + 4) & ~@as(u32, 3);
            if (pp + 12 > code_len) break :blk 1;
            const lo: i32 = @bitCast((@as(u32, code[pp + 4]) << 24) | (@as(u32, code[pp + 5]) << 16) | (@as(u32, code[pp + 6]) << 8) | @as(u32, code[pp + 7]));
            const hi: i32 = @bitCast((@as(u32, code[pp + 8]) << 24) | (@as(u32, code[pp + 9]) << 16) | (@as(u32, code[pp + 10]) << 8) | @as(u32, code[pp + 11]));
            const cnt: u32 = @intCast(@as(i64, hi) - @as(i64, lo) + 1);
            break :blk pp + 12 + cnt * 4 - pc;
        },
        0xab => blk: { // lookupswitch
            const pp = (pc + 4) & ~@as(u32, 3);
            if (pp + 8 > code_len) break :blk 1;
            const np: u32 = @intCast(@as(i32, @bitCast((@as(u32, code[pp + 4]) << 24) | (@as(u32, code[pp + 5]) << 16) | (@as(u32, code[pp + 6]) << 8) | @as(u32, code[pp + 7]))));
            break :blk pp + 8 + np * 8 - pc;
        },
        0xc4 => if (pc + 1 < code_len and code[pc + 1] == 0x84) 6 else 4,
        else => 1,
    };
}
