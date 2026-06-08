const std = @import("std");
const types = @import("../classfile/types.zig");
const annotations = @import("../classfile/annotations.zig");

pub const ExtractedMethod = struct {
    class_name: []const u8,
    method_name: []const u8,
    descriptor: []const u8,
    is_static: bool,
    code_data: []const u8,
    access_flags: u16,
    class_cp: []const types.CpInfo,
    class_attrs: []const types.AttributeInfo,
};

pub const NativizeResult = struct {
    extracted_methods: []ExtractedMethod,
    modified: bool,
    class_cp: []const types.CpInfo,
};

pub fn nativize(allocator: std.mem.Allocator, cf: *types.ClassFile) !NativizeResult {
    const anno = try annotations.detectNativeAnnotation(allocator, cf);
    const class_name = cf.getThisClassName() orelse return NativizeResult{ .extracted_methods = &.{}, .modified = false, .class_cp = cf.constant_pool };

    var extracted: std.ArrayList(ExtractedMethod) = .empty;
    defer extracted.deinit(allocator);

    // Check if class has main method
    var has_main = false;
    if (anno.class_annotated) {
        for (cf.methods) |method| {
            const name = cf.getUtf8(method.name_index) orelse continue;
            if (std.mem.eql(u8, name, "main")) { has_main = true; break; }
        }
    }

    // If has main, do the main transformation
    if (has_main) {
        var main_code_data: ?[]const u8 = null;
        for (cf.methods) |method| {
            const name = cf.getUtf8(method.name_index) orelse continue;
            if (std.mem.eql(u8, name, "main")) {
                for (method.attributes) |attr| {
                    const aname = cf.getUtf8(attr.name_index) orelse continue;
                    if (std.mem.eql(u8, aname, "Code")) { main_code_data = attr.data; break; }
                }
                break;
            }
        }

        try transformMain(allocator, cf, class_name);

        if (main_code_data) |mcd| {
            try extracted.append(allocator, ExtractedMethod{
                .class_name = cf.getThisClassName() orelse class_name,
                .method_name = "jnic$main",
                .descriptor = "([Ljava/lang/String;)V",
                .is_static = true,
                .code_data = mcd,
                .access_flags = types.ACC_PUBLIC | types.ACC_STATIC | types.ACC_NATIVE,
                .class_cp = cf.constant_pool,
                .class_attrs = cf.attributes,
            });
        }
    } else if (anno.class_annotated) {
        // No main but has @Native — still inject loadLibrary into <clinit>
        try injectLoadLibrary(allocator, cf);
    }

    if (anno.class_annotated) {
        for (cf.methods) |*method| {
            const name = cf.getUtf8(method.name_index) orelse continue;
            // Skip constructors, clinit, main (main is now a stub), and runStr
            if (std.mem.eql(u8, name, "<init>") or std.mem.eql(u8, name, "<clinit>") or std.mem.eql(u8, name, "main") or std.mem.eql(u8, name, "jnic$main") or std.mem.eql(u8, name, "runStr")) continue;
            if (method.access_flags & types.ACC_NATIVE != 0) continue;
            if (method.access_flags & types.ACC_ABSTRACT != 0) continue;

            if (try extractAndNativize(allocator, cf, method, class_name)) |em| {
                try extracted.append(allocator, em);
            }
        }
    } else {
        for (anno.method_indices) |idx| {
            const method = &cf.methods[idx];
            const name = cf.getUtf8(method.name_index) orelse continue;
            if (std.mem.eql(u8, name, "<init>") or std.mem.eql(u8, name, "<clinit>") or std.mem.eql(u8, name, "main") or std.mem.eql(u8, name, "jnic$main") or std.mem.eql(u8, name, "runStr")) continue;
            if (method.access_flags & types.ACC_NATIVE != 0) continue;
            if (method.access_flags & types.ACC_ABSTRACT != 0) continue;

            if (try extractAndNativize(allocator, cf, method, class_name)) |em| {
                try extracted.append(allocator, em);
            }
        }
    }

    const result = try extracted.toOwnedSlice(allocator);
    return NativizeResult{
        .extracted_methods = result,
        .modified = result.len > 0 or has_main,
        .class_cp = cf.constant_pool,
    };
}

/// Inject System.loadLibrary("yurijvm_native") into <clinit> for classes without main
fn injectLoadLibrary(allocator: std.mem.Allocator, cf: *types.ClassFile) !void {
    const cp_system_name = try findOrAddUtf8(allocator, cf, "java/lang/System");
    const cp_loadlib_name = try findOrAddUtf8(allocator, cf, "loadLibrary");
    const cp_str_void_desc = try findOrAddUtf8(allocator, cf, "(Ljava/lang/String;)V");
    const cp_lib_name = try findOrAddUtf8(allocator, cf, "yurijvm_native");
    const cp_code_name = try findOrAddUtf8(allocator, cf, "Code");
    const cp_system_class = try addCpEntry(allocator, cf, types.CpInfo{ .class = cp_system_name });
    const cp_lib_string = try addCpEntry(allocator, cf, types.CpInfo{ .string = cp_lib_name });
    const cp_loadlib_nat = try addCpEntry(allocator, cf, types.CpInfo{ .name_and_type = .{ .name_index = cp_loadlib_name, .descriptor_index = cp_str_void_desc } });
    const cp_loadlib_ref = try addCpEntry(allocator, cf, types.CpInfo{ .methodref = .{ .class_index = cp_system_class, .name_and_type_index = cp_loadlib_nat } });
    try addOrModifyClinit(allocator, cf, cp_code_name, cp_lib_string, cp_loadlib_ref);
}

/// Transform main: extract body to jnic$main (native), rewrite main to load lib + call jnic$main
fn transformMain(allocator: std.mem.Allocator, cf: *types.ClassFile, class_name: []const u8) !void {
    _ = class_name;

    // Find main method
    var main_idx: ?usize = null;
    var main_code: ?[]const u8 = null;
    for (cf.methods, 0..) |method, idx| {
        const name = cf.getUtf8(method.name_index) orelse continue;
        if (std.mem.eql(u8, name, "main")) {
            main_idx = idx;
            for (method.attributes) |attr| {
                const aname = cf.getUtf8(attr.name_index) orelse continue;
                if (std.mem.eql(u8, aname, "Code")) { main_code = attr.data; break; }
            }
            break;
        }
    }
    if (main_idx == null or main_code == null) return;

    // Add constant pool entries we need:
    // - Utf8 "jnic$main"
    // - Utf8 "([Ljava/lang/String;)V"  (already exists for main)
    // - Utf8 "java/lang/System"
    // - Utf8 "loadLibrary"
    // - Utf8 "(Ljava/lang/String;)V"
    // - Utf8 "yurijvm_native"
    // - Utf8 "Code"
    // - Class java/lang/System
    // - String "yurijvm_native"
    // - NameAndType loadLibrary:(Ljava/lang/String;)V
    // - Methodref System.loadLibrary
    // - NameAndType jnic$main:([Ljava/lang/String;)V
    // - Methodref thisClass.jnic$main

    // Find or add UTF8 entries
    const cp_yuri_main = try findOrAddUtf8(allocator, cf, "jnic$main");
    const cp_main_desc = try findOrAddUtf8(allocator, cf, "([Ljava/lang/String;)V");
    const cp_system_name = try findOrAddUtf8(allocator, cf, "java/lang/System");
    const cp_loadlib_name = try findOrAddUtf8(allocator, cf, "loadLibrary");
    const cp_str_void_desc = try findOrAddUtf8(allocator, cf, "(Ljava/lang/String;)V");
    const cp_lib_name = try findOrAddUtf8(allocator, cf, "yurijvm_native");
    const cp_code_name = try findOrAddUtf8(allocator, cf, "Code");

    // Add Class entry for System
    const cp_system_class = try addCpEntry(allocator, cf, types.CpInfo{ .class = cp_system_name });
    // Add String entry for "yurijvm_native"
    const cp_lib_string = try addCpEntry(allocator, cf, types.CpInfo{ .string = cp_lib_name });
    // Add NameAndType for loadLibrary:(Ljava/lang/String;)V
    const cp_loadlib_nat = try addCpEntry(allocator, cf, types.CpInfo{ .name_and_type = .{ .name_index = cp_loadlib_name, .descriptor_index = cp_str_void_desc } });
    // Add Methodref for System.loadLibrary
    const cp_loadlib_ref = try addCpEntry(allocator, cf, types.CpInfo{ .methodref = .{ .class_index = cp_system_class, .name_and_type_index = cp_loadlib_nat } });
    // Add NameAndType for jnic$main:([Ljava/lang/String;)V
    const cp_yurimain_nat = try addCpEntry(allocator, cf, types.CpInfo{ .name_and_type = .{ .name_index = cp_yuri_main, .descriptor_index = cp_main_desc } });
    // Add Methodref for thisClass.jnic$main
    const cp_yurimain_ref = try addCpEntry(allocator, cf, types.CpInfo{ .methodref = .{ .class_index = cf.this_class, .name_and_type_index = cp_yurimain_nat } });

    // === Create jnic$main method (native, with main's original code extracted later) ===
    // jnic$main is public static native void jnic$main(String[] args)
    const yuri_method = types.MethodInfo{
        .access_flags = types.ACC_PUBLIC | types.ACC_STATIC | types.ACC_NATIVE,
        .name_index = cp_yuri_main,
        .descriptor_index = cp_main_desc,
        .attributes = &.{},
    };

    // === Rewrite main's Code to: invokestatic jnic$main(args); return ===
    // Bytecode: aload_0, invokestatic cp_yurimain_ref, return
    // Code attribute: max_stack=1, max_locals=1, code_length=5
    var main_bytecode: [13]u8 = undefined;
    // max_stack = 1
    main_bytecode[0] = 0; main_bytecode[1] = 1;
    // max_locals = 1
    main_bytecode[2] = 0; main_bytecode[3] = 1;
    // code_length = 5
    main_bytecode[4] = 0; main_bytecode[5] = 0; main_bytecode[6] = 0; main_bytecode[7] = 5;
    // aload_0
    main_bytecode[8] = 0x2a;
    // invokestatic cp_yurimain_ref
    main_bytecode[9] = 0xb8;
    main_bytecode[10] = @intCast(cp_yurimain_ref >> 8);
    main_bytecode[11] = @intCast(cp_yurimain_ref & 0xff);
    // return
    main_bytecode[12] = 0xb1;

    // Full code attribute: bytecode + exception_table_count(0) + attributes_count(0)
    const main_code_full = try allocator.alloc(u8, 13 + 2 + 2); // bytecode + exc_count + attr_count
    @memcpy(main_code_full[0..13], &main_bytecode);
    main_code_full[13] = 0; main_code_full[14] = 0; // exception_table_count = 0
    main_code_full[15] = 0; main_code_full[16] = 0; // attributes_count = 0

    const main_code_attr = types.AttributeInfo{ .name_index = cp_code_name, .data = main_code_full };
    const main_attrs = try allocator.alloc(types.AttributeInfo, 1);
    main_attrs[0] = main_code_attr;
    cf.methods[main_idx.?].attributes = main_attrs;

    // === Add or modify <clinit> to call System.loadLibrary("yurijvm_native") ===
    // Bytecode: ldc cp_lib_string, invokestatic cp_loadlib_ref, return
    try addOrModifyClinit(allocator, cf, cp_code_name, cp_lib_string, cp_loadlib_ref);

    // === Add jnic$main to methods array ===
    var new_methods = try allocator.alloc(types.MethodInfo, cf.methods.len + 1);
    @memcpy(new_methods[0..cf.methods.len], cf.methods);
    new_methods[cf.methods.len] = yuri_method;
    cf.methods = new_methods;
}

fn addOrModifyClinit(allocator: std.mem.Allocator, cf: *types.ClassFile, cp_code_name: u16, cp_lib_string: u16, cp_loadlib_ref: u16) !void {
    // Check if <clinit> exists
    var clinit_idx: ?usize = null;
    for (cf.methods, 0..) |method, idx| {
        const name = cf.getUtf8(method.name_index) orelse continue;
        if (std.mem.eql(u8, name, "<clinit>")) { clinit_idx = idx; break; }
    }

    // loadLibrary bytecode: ldc string_idx, invokestatic methodref_idx, return (or pop existing return)
    // ldc (1 or 2 bytes depending on index), invokestatic (3 bytes)
    const load_lib_code = [_]u8{
        0x12, @intCast(cp_lib_string & 0xff), // ldc
        0xb8, @intCast(cp_loadlib_ref >> 8), @intCast(cp_loadlib_ref & 0xff), // invokestatic
    };

    if (clinit_idx) |ci| {
        // Prepend loadLibrary call to existing clinit code
        var existing_code: ?[]const u8 = null;
        for (cf.methods[ci].attributes) |attr| {
            const aname = cf.getUtf8(attr.name_index) orelse continue;
            if (std.mem.eql(u8, aname, "Code")) { existing_code = attr.data; break; }
        }
        if (existing_code) |ec| {
            if (ec.len < 8) return;
            const old_max_stack = (@as(u16, ec[0]) << 8) | @as(u16, ec[1]);
            const old_max_locals = (@as(u16, ec[2]) << 8) | @as(u16, ec[3]);
            const old_code_len = (@as(u32, ec[4]) << 24) | (@as(u32, ec[5]) << 16) | (@as(u32, ec[6]) << 8) | @as(u32, ec[7]);
            const old_bytecode = ec[8..8 + old_code_len];
            const rest = ec[8 + old_code_len..]; // exception table + attributes

            const new_stack = @max(old_max_stack, 1);
            const new_code_len = @as(u32, load_lib_code.len) + old_code_len;

            const new_data = try allocator.alloc(u8, 8 + new_code_len + rest.len);
            new_data[0] = @intCast(new_stack >> 8); new_data[1] = @intCast(new_stack & 0xff);
            new_data[2] = @intCast(old_max_locals >> 8); new_data[3] = @intCast(old_max_locals & 0xff);
            new_data[4] = @intCast(new_code_len >> 24); new_data[5] = @intCast((new_code_len >> 16) & 0xff);
            new_data[6] = @intCast((new_code_len >> 8) & 0xff); new_data[7] = @intCast(new_code_len & 0xff);
            @memcpy(new_data[8..8 + load_lib_code.len], &load_lib_code);
            @memcpy(new_data[8 + load_lib_code.len .. 8 + new_code_len], old_bytecode);
            @memcpy(new_data[8 + new_code_len..], rest);

            // Replace Code attribute
            const new_attrs = try allocator.alloc(types.AttributeInfo, 1);
            new_attrs[0] = .{ .name_index = cp_code_name, .data = new_data };
            cf.methods[ci].attributes = new_attrs;
        }
    } else {
        // Create new <clinit>
        // Code: max_stack=1, max_locals=0, code_len=6 (ldc + invokestatic + return)
        const clinit_name = try findOrAddUtf8(allocator, cf, "<clinit>");
        const clinit_desc = try findOrAddUtf8(allocator, cf, "()V");

        var code_data: [8 + 6 + 4]u8 = undefined;
        code_data[0] = 0; code_data[1] = 1; // max_stack=1
        code_data[2] = 0; code_data[3] = 0; // max_locals=0
        code_data[4] = 0; code_data[5] = 0; code_data[6] = 0; code_data[7] = 6; // code_len=6
        @memcpy(code_data[8..13], &load_lib_code);
        code_data[13] = 0xb1; // return
        code_data[14] = 0; code_data[15] = 0; // exc_table_count=0
        code_data[16] = 0; code_data[17] = 0; // attrs_count=0

        const code_slice = try allocator.alloc(u8, code_data.len);
        @memcpy(code_slice, &code_data);

        const attrs = try allocator.alloc(types.AttributeInfo, 1);
        attrs[0] = .{ .name_index = cp_code_name, .data = code_slice };

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

fn findOrAddUtf8(allocator: std.mem.Allocator, cf: *types.ClassFile, value: []const u8) !u16 {
    // Search existing CP
    for (cf.constant_pool, 0..) |entry, idx| {
        switch (entry) {
            .utf8 => |s| if (std.mem.eql(u8, s, value)) return @intCast(idx),
            else => {},
        }
    }
    // Add new entry
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

fn extractAndNativize(
    allocator: std.mem.Allocator,
    cf: *const types.ClassFile,
    method: *types.MethodInfo,
    class_name: []const u8,
) !?ExtractedMethod {
    const method_name = cf.getUtf8(method.name_index) orelse return null;
    const descriptor = cf.getUtf8(method.descriptor_index) orelse return null;

    var code_data: ?[]const u8 = null;
    var new_attrs: std.ArrayList(types.AttributeInfo) = .empty;
    defer new_attrs.deinit(allocator);

    for (method.attributes) |attr| {
        const attr_name = cf.getUtf8(attr.name_index) orelse {
            try new_attrs.append(allocator, attr);
            continue;
        };
        if (std.mem.eql(u8, attr_name, "Code")) {
            code_data = attr.data;
        } else if (std.mem.eql(u8, attr_name, "RuntimeVisibleAnnotations") or
            std.mem.eql(u8, attr_name, "RuntimeInvisibleAnnotations"))
        {
            try new_attrs.append(allocator, attr);
        } else if (std.mem.eql(u8, attr_name, "Exceptions")) {
            try new_attrs.append(allocator, attr);
        } else {}
    }

    if (code_data == null) return null;

    method.attributes = try new_attrs.toOwnedSlice(allocator);
    method.access_flags |= types.ACC_NATIVE;
    method.access_flags &= ~types.ACC_STRICT;

    return ExtractedMethod{
        .class_name = class_name,
        .method_name = method_name,
        .descriptor = descriptor,
        .is_static = (method.access_flags & types.ACC_STATIC) != 0,
        .code_data = code_data.?,
        .access_flags = method.access_flags,
        .class_cp = cf.constant_pool,
        .class_attrs = cf.attributes,
    };
}
