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

pub fn generateJniSource(
    allocator: std.mem.Allocator,
    methods: []const nativize.ExtractedMethod,
    watermark: []const u8,
    anti_debug: bool,
    renamer: bool,
    enc_strings: []const encrypt_mod.EncryptedString,
    enc_numbers: []const encrypt_mod.EncryptedNumber,
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
    try buf.appendSlice(allocator, "\n\n");

    if (anti_debug) {
        try buf.appendSlice(allocator,
            \\#ifdef _WIN32
            \\#include <windows.h>
            \\static void __anti_debug_check(void) { if (IsDebuggerPresent()) ExitProcess(1); }
            \\#else
            \\#include <sys/ptrace.h>
            \\#include <signal.h>
            \\static void __anti_debug_check(void) { if (ptrace(PTRACE_TRACEME,0,0,0)==-1) raise(SIGKILL); }
            \\#endif
            \\
            \\
        );
    }

    try buf.print(allocator, "static const char __watermark[] = \"{s}\";\n\n", .{watermark});

    // Generate bytecode arrays and CP arrays for each method
    var cp_entries_sizes: std.ArrayList(u32) = .empty;
    defer cp_entries_sizes.deinit(allocator);

    for (methods, 0..) |method, idx| {
        var vbuf: [32]u8 = undefined;
        const vp = names.varPrefix(&vbuf, idx);

        // Bytecode array
        try buf.print(allocator, "static const uint8_t _b_{s}[] = {{", .{vp});
        for (method.code_data, 0..) |byte, i| {
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
        const vp = names.varPrefix(&vb, idx);
        try buf.print(allocator, "static JvmResolved _r_{s}[{d}];\n", .{ vp, cp_entries_sizes.items[idx] });
    }
    try buf.appendSlice(allocator, "\n");
    for (methods, 0..) |_, idx| {
        var vb: [32]u8 = undefined;
        const vp = names.varPrefix(&vb, idx);
        try buf.print(allocator, "static JvmMethodCtx _m_{s} = {{_b_{s}, sizeof(_b_{s}), _c_{s}, _n_{s}, _r_{s}}};\n", .{ vp, vp, vp, vp, vp, vp });
    }
    try buf.appendSlice(allocator, "\n");

    // Generate native stubs
    for (methods, 0..) |method, idx| {
        try generateStub(allocator, &buf, method, idx, &names);
    }

    // Generate encrypted constant lookup functions (always emit tables, even if empty)
    try generateEncryptedLookups(allocator, &buf, enc_strings, enc_numbers);

    // Generate JNI_OnLoad (including encrypted lookup registrations)
    try generateOnLoad(allocator, &buf, methods, &names, enc_strings, enc_numbers);

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
    var vbuf2: [32]u8 = undefined;
    const vp = names.varPrefix(&vbuf2, idx);

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

fn generateOnLoad(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), methods: []const nativize.ExtractedMethod, names: *Names, enc_strings: []const encrypt_mod.EncryptedString, enc_numbers: []const encrypt_mod.EncryptedNumber) !void {
    try buf.appendSlice(allocator,
        \\JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
        \\    JNIEnv *env;
        \\    (void)reserved;
        \\    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) return -1;
        \\
        \\
    );

    for (methods, 0..) |method, idx| {
        var fnb: [32]u8 = undefined;
        const fn_name = names.funcName(&fnb, idx);
        try buf.print(allocator,
            \\    {{
            \\        jclass cls = (*env)->FindClass(env, "{s}");
            \\        if (cls) {{
            \\            JNINativeMethod nm = {{"{s}", "{s}", (void*){s}}};
            \\            (*env)->RegisterNatives(env, cls, &nm, 1);
            \\        }}
            \\    }}
            \\
        , .{ method.class_name, method.method_name, method.descriptor, fn_name });
    }

    // Register encrypted constant lookup methods
    if (enc_strings.len > 0 or enc_numbers.len > 0) {
        // Collect unique class names that have encrypted constants
        try buf.appendSlice(allocator,
            \\    /* Register encrypted constant lookup methods */
            \\
        );
        // We register for each unique class
        var registered_classes: [64][]const u8 = undefined;
        var num_registered: usize = 0;

        for (enc_strings) |s| {
            if (!classAlreadyRegistered(&registered_classes, num_registered, s.class_name)) {
                if (num_registered < 64) { registered_classes[num_registered] = s.class_name; num_registered += 1; }
                try buf.print(allocator,
                    \\    {{
                    \\        jclass cls = (*env)->FindClass(env, "{s}");
                    \\        if (cls) {{
                    \\            JNINativeMethod nms[] = {{
                    \\                {{"yuri$native_string", "(J)Ljava/lang/String;", (void*)_enc_str_lookup}},
                    \\                {{"yuri$native_int", "(J)I", (void*)_enc_int_lookup}},
                    \\                {{"yuri$native_long", "(J)J", (void*)_enc_long_lookup}}
                    \\            }};
                    \\            (*env)->RegisterNatives(env, cls, nms, 3);
                    \\        }}
                    \\    }}
                    \\
                , .{s.class_name});
            }
        }
        for (enc_numbers) |n| {
            if (!classAlreadyRegistered(&registered_classes, num_registered, n.class_name)) {
                if (num_registered < 64) { registered_classes[num_registered] = n.class_name; num_registered += 1; }
                try buf.print(allocator,
                    \\    {{
                    \\        jclass cls = (*env)->FindClass(env, "{s}");
                    \\        if (cls) {{
                    \\            JNINativeMethod nms[] = {{
                    \\                {{"yuri$native_string", "(J)Ljava/lang/String;", (void*)_enc_str_lookup}},
                    \\                {{"yuri$native_int", "(J)I", (void*)_enc_int_lookup}},
                    \\                {{"yuri$native_long", "(J)J", (void*)_enc_long_lookup}}
                    \\            }};
                    \\            (*env)->RegisterNatives(env, cls, nms, 3);
                    \\        }}
                    \\    }}
                    \\
                , .{n.class_name});
            }
        }
    }

    try buf.appendSlice(allocator,
        \\    return JNI_VERSION_1_6;
        \\}
        \\
    );
}

// === Descriptor parsing helpers ===

fn classAlreadyRegistered(list: []const []const u8, count: usize, name: []const u8) bool {
    for (list[0..count]) |n| { if (std.mem.eql(u8, n, name)) return true; }
    return false;
}

fn generateEncryptedLookups(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), enc_strings: []const encrypt_mod.EncryptedString, enc_numbers: []const encrypt_mod.EncryptedNumber) !void {
    // Generate XOR-encrypted string table
    try buf.appendSlice(allocator, "\n/* === Encrypted constant tables === */\n");

    // String table: key -> XOR-encrypted bytes
    try buf.print(allocator, "EncStr _enc_strs[] = {{\n", .{});
    for (enc_strings) |s| {
        try buf.print(allocator, "    {{{d}LL, \"", .{s.key});
        // XOR encrypt string with key bytes
        const key_bytes: [8]u8 = @bitCast(s.key);
        for (s.value, 0..) |ch, i| {
            const enc = ch ^ key_bytes[i % 8];
            try buf.print(allocator, "\\x{x:0>2}", .{enc});
        }
        try buf.print(allocator, "\", {d}}},\n", .{s.value.len});
    }
    try buf.appendSlice(allocator, "    {0, NULL, 0}\n};\n\n");

    // Number table: key -> XOR-encrypted value
    try buf.print(allocator, "EncNum _enc_nums[] = {{\n", .{});
    for (enc_numbers) |n| {
        const enc_val = n.value ^ n.key;
        try buf.print(allocator, "    {{{d}LL, {d}LL, {d}}},\n", .{ n.key, enc_val, @as(i8, if (n.is_long) 1 else 0) });
    }
    try buf.appendSlice(allocator, "    {0, 0, 0}\n};\n\n");

    // String lookup cache
    try buf.print(allocator, "static jobject _str_cache[{d}];\n", .{@max(enc_strings.len, 1)});
    try buf.appendSlice(allocator, "static int8_t _str_cached[" ++ "256];\n\n");

    // Lookup function: yuri$native_string(long key) -> String
    try buf.appendSlice(allocator,
        \\JNIEXPORT jobject JNICALL _enc_str_lookup(JNIEnv *env, jclass clazz, jlong key) {
        \\    (void)clazz;
        \\    for (int i = 0; _enc_strs[i].enc != NULL; i++) {
        \\        if (_enc_strs[i].key == key) {
        \\            if (i < 256 && _str_cached[i]) return _str_cache[i];
        \\            /* Decrypt: XOR with key bytes */
        \\            int32_t len = _enc_strs[i].len;
        \\            char *dec = (char*)malloc(len + 1);
        \\            const char *enc = _enc_strs[i].enc;
        \\            int64_t k = key;
        \\            uint8_t *kb = (uint8_t*)&k;
        \\            for (int j = 0; j < len; j++) dec[j] = enc[j] ^ kb[j % 8];
        \\            dec[len] = 0;
        \\            jstring result = (*env)->NewStringUTF(env, dec);
        \\            free(dec);
        \\            if (i < 256) { _str_cache[i] = (*env)->NewGlobalRef(env, result); _str_cached[i] = 1; }
        \\            return result;
        \\        }
        \\    }
        \\    return (*env)->NewStringUTF(env, "");
        \\}
        \\
        \\
    );

    // Lookup function: yuri$native_int(long key) -> int
    try buf.appendSlice(allocator,
        \\JNIEXPORT jint JNICALL _enc_int_lookup(JNIEnv *env, jclass clazz, jlong key) {
        \\    (void)env; (void)clazz;
        \\    for (int i = 0; _enc_nums[i].key != 0 || _enc_nums[i].enc_val != 0; i++) {
        \\        if (_enc_nums[i].key == key && !_enc_nums[i].is_long) {
        \\            return (jint)(_enc_nums[i].enc_val ^ key);
        \\        }
        \\    }
        \\    return 0;
        \\}
        \\
        \\
    );

    // Lookup function: yuri$native_long(long key) -> long
    try buf.appendSlice(allocator,
        \\JNIEXPORT jlong JNICALL _enc_long_lookup(JNIEnv *env, jclass clazz, jlong key) {
        \\    (void)env; (void)clazz;
        \\    for (int i = 0; _enc_nums[i].key != 0 || _enc_nums[i].enc_val != 0; i++) {
        \\        if (_enc_nums[i].key == key && _enc_nums[i].is_long) {
        \\            return (jlong)(_enc_nums[i].enc_val ^ key);
        \\        }
        \\    }
        \\    return 0;
        \\}
        \\
        \\
    );
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
