const std = @import("std");
const config_mod = @import("config.zig");
const parser = @import("classfile/parser.zig");
const class_writer = @import("classfile/writer.zig");
const nativize_mod = @import("transform/nativize.zig");
const encrypt_mod = @import("transform/encrypt.zig");
const jni = @import("codegen/jni.zig");
const ffm = @import("codegen/ffm.zig");

const Dir = std.Io.Dir;
const Io = std.Io;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Parse arguments
    var args_iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_iter.deinit();
    _ = args_iter.next();
    var config_path: []const u8 = "config.toml";
    while (args_iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config")) {
            if (args_iter.next()) |val| config_path = val;
        }
    }

    // Load config
    const config_data = Dir.cwd().readFileAlloc(io, config_path, allocator, .limited(1024 * 1024)) catch |err| {
        std.debug.print("Error reading config '{s}': {}\n", .{ config_path, err });
        return;
    };
    const config = try config_mod.parseConfig(allocator, config_data);

    std.debug.print("JNIC-zig v0.1\n", .{});
    std.debug.print("  Watermark:   {s}\n", .{config.watermark});
    std.debug.print("  Use FFM:     {}\n", .{config.use_ffm});
    std.debug.print("  Anti-debug:  {}\n", .{config.anti_debug});
    std.debug.print("  Renamer:     {}\n", .{config.renamer});
    std.debug.print("  Remove anno: {}\n", .{config.remove_native_annotation});
    std.debug.print("  Input JAR:   {s}\n", .{config.input_jar});
    std.debug.print("  Output JAR:  {s}\n", .{config.output_jar});

    // Extract input JAR to temp directory
    const tmp_in = ".yurijvm_tmp_in";
    const tmp_out = ".yurijvm_tmp_out";

    // Clean and create temp dirs
    runCmd(allocator, io, &.{ "rm", "-rf", tmp_in, tmp_out });
    Dir.cwd().createDirPath(io, tmp_in) catch {};
    Dir.cwd().createDirPath(io, tmp_out) catch {};

    // Extract JAR — jar xf only extracts to CWD, so use cwd option
    std.debug.print("\nExtracting {s}...\n", .{config.input_jar});
    // We need absolute path since jar runs in tmp_in directory
    var abs_buf: [4096]u8 = undefined;
    const cwd_len = std.process.currentPath(io, &abs_buf) catch 0;
    const abs_input = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ abs_buf[0..cwd_len], config.input_jar });
    // Normalize path separators
    for (abs_input) |*ch| { if (ch.* == '\\') ch.* = '/'; }
    runCmdCwd(allocator, io, &.{ "jar", "xf", abs_input }, tmp_in);

    // Process .class files
    var all_extracted: std.ArrayList(nativize_mod.ExtractedMethod) = .empty;
    defer all_extracted.deinit(allocator);
    var all_enc_strings: std.ArrayList(encrypt_mod.EncryptedString) = .empty;
    defer all_enc_strings.deinit(allocator);
    var all_enc_numbers: std.ArrayList(encrypt_mod.EncryptedNumber) = .empty;
    defer all_enc_numbers.deinit(allocator);

    var dir = Dir.cwd().openDir(io, tmp_in, .{ .iterate = true }) catch |err| {
        std.debug.print("Error opening temp dir: {}\n", .{err});
        return;
    };
    defer dir.close(io);
    try processDirectory(allocator, io, dir, tmp_out, &all_extracted, &all_enc_strings, &all_enc_numbers, config.remove_native_annotation);

    // Copy non-class files (META-INF, resources) from input to output
    copyNonClassFiles(allocator, io, tmp_in, tmp_out);

    if (all_extracted.items.len == 0) {
        std.debug.print("\nNo methods with @Native annotation found.\n", .{});
        // Still produce output JAR with unmodified classes
    } else {
        std.debug.print("\nNative-ized {d} method(s). Generating native code...\n", .{all_extracted.items.len});
    }

    // Generate native source
    if (all_extracted.items.len > 0) {
        if (config.use_ffm) {
            const output = try ffm.generateFfmSource(allocator, all_extracted.items, config.watermark, config.anti_debug);
            Dir.cwd().writeFile(io, .{ .sub_path = "native_ffm.c", .data = output.c_source }) catch {};
            Dir.cwd().writeFile(io, .{ .sub_path = "NativeBindings.java", .data = output.java_source }) catch {};
            std.debug.print("Generated: native_ffm.c, NativeBindings.java\n", .{});
        } else {
            const c_source = try jni.generateJniSource(allocator, all_extracted.items, config.watermark, config.anti_debug, config.renamer, all_enc_strings.items, all_enc_numbers.items);
            Dir.cwd().writeFile(io, .{ .sub_path = "native_jni.c", .data = c_source }) catch {};
            std.debug.print("Generated: native_jni.c\n", .{});
        }
    }

    // Repack output JAR, preserving original MANIFEST.MF
    std.debug.print("Packing {s}...\n", .{config.output_jar});
    const manifest_path = try std.fmt.allocPrint(allocator, "{s}/META-INF/MANIFEST.MF", .{tmp_out});
    runCmd(allocator, io, &.{ "jar", "cfm", config.output_jar, manifest_path, "-C", tmp_out, "." });

    // Cleanup temp dirs
    runCmd(allocator, io, &.{ "rm", "-rf", tmp_in, tmp_out });

    // Generate launch script
    if (all_extracted.items.len > 0) {
        const lib_name = if (config.use_ffm) "yurijvm_native_ffm" else "yurijvm_native";
        const script = try std.fmt.allocPrint(allocator,
            \\@echo off
            \\java -Xss4m -Djava.library.path=. --enable-native-access=ALL-UNNAMED -jar {s} %*
            \\
        , .{config.output_jar});
        Dir.cwd().writeFile(io, .{ .sub_path = "run.bat", .data = script }) catch {};

        const sh_script = try std.fmt.allocPrint(allocator,
            \\#!/bin/sh
            \\java -Xss4m -Djava.library.path=. --enable-native-access=ALL-UNNAMED -jar {s} "$@"
            \\
        , .{config.output_jar});
        Dir.cwd().writeFile(io, .{ .sub_path = "run.sh", .data = sh_script }) catch {};

        std.debug.print("\nOutput:\n", .{});
        std.debug.print("  {s}          - Protected JAR\n", .{config.output_jar});
        std.debug.print("  native_jni.c        - Native source (compile with zig cc)\n", .{});
        std.debug.print("  run.bat / run.sh    - Launch scripts\n", .{});
        std.debug.print("\nCompile native library:\n", .{});
        std.debug.print("  zig cc -shared -o {s}.dll native_jni.c -I\"$JAVA_HOME/include\" -I\"$JAVA_HOME/include/win32\" -O2\n", .{lib_name});
        std.debug.print("\nIMPORTANT: Add System.loadLibrary(\"{s}\") to your main class,\n", .{lib_name});
        std.debug.print("           or use a java agent to load the native library.\n", .{});
    }

    std.debug.print("\nDone.\n", .{});
}

fn runCmd(allocator: std.mem.Allocator, io: Io, argv: []const []const u8) void {
    runCmdCwd(allocator, io, argv, null);
}

fn runCmdCwd(allocator: std.mem.Allocator, io: Io, argv: []const []const u8, cwd: ?[]const u8) void {
    const cwd_opt: std.process.Child.Cwd = if (cwd) |p| .{ .path = p } else .inherit;
    const result = std.process.run(allocator, io, .{ .argv = argv, .cwd = cwd_opt }) catch |err| {
        std.debug.print("  [cmd error] {s}: {}\n", .{ argv[0], err });
        return;
    };
    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.debug.print("  [cmd fail] {s} exit={d}\n", .{ argv[0], code });
                if (result.stderr.len > 0) std.debug.print("  {s}\n", .{result.stderr});
            }
        },
        else => {
            std.debug.print("  [cmd signal] {s}\n", .{argv[0]});
        },
    }
}

fn copyNonClassFiles(allocator: std.mem.Allocator, io: Io, src_base: []const u8, dst_base: []const u8) void {
    var src_dir = Dir.cwd().openDir(io, src_base, .{ .iterate = true }) catch return;
    defer src_dir.close(io);
    var walker = Dir.walk(src_dir, allocator) catch return;
    defer walker.deinit();

    while (walker.next(io) catch null) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.endsWith(u8, entry.basename, ".class")) continue;

        // Copy this non-class file to output
        const data = entry.dir.readFileAlloc(io, entry.basename, allocator, .limited(50 * 1024 * 1024)) catch continue;
        const out_path = std.fmt.allocPrint(allocator, "{s}/{s}", .{ dst_base, entry.path }) catch continue;

        // Normalize separators
        for (out_path) |*c| {
            if (c.* == '\\') c.* = '/';
        }
        if (std.mem.lastIndexOfScalar(u8, out_path, '/')) |slash| {
            Dir.cwd().createDirPath(io, out_path[0..slash]) catch {};
        }
        Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = data }) catch {};
    }
}

fn processDirectory(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Dir,
    output_base: []const u8,
    extracted: *std.ArrayList(nativize_mod.ExtractedMethod),
    enc_strings: *std.ArrayList(encrypt_mod.EncryptedString),
    enc_numbers: *std.ArrayList(encrypt_mod.EncryptedNumber),
    remove_annotation: bool,
) !void {
    var walker = try Dir.walk(dir, allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".class")) continue;

        try processClassEntry(allocator, io, entry, output_base, extracted, enc_strings, enc_numbers, remove_annotation);
    }
}

fn processClassEntry(
    allocator: std.mem.Allocator,
    io: Io,
    entry: Dir.Walker.Entry,
    output_base: []const u8,
    extracted: *std.ArrayList(nativize_mod.ExtractedMethod),
    enc_strings: *std.ArrayList(encrypt_mod.EncryptedString),
    enc_numbers: *std.ArrayList(encrypt_mod.EncryptedNumber),
    remove_annotation: bool,
) !void {
    const rel_path = entry.path;

    const data = entry.dir.readFileAlloc(io, entry.basename, allocator, .limited(10 * 1024 * 1024)) catch |err| {
        std.debug.print("  Skip {s}: {}\n", .{ rel_path, err });
        return;
    };

    var cf = parser.parse(allocator, data) catch |err| {
        std.debug.print("  Parse error {s}: {}\n", .{ rel_path, err });
        return;
    };

    // Apply string/number encryption (before nativize, so encrypted methods get native-ized too)
    const enc_result = try encrypt_mod.encryptConstants(allocator, &cf);
    for (enc_result.strings) |s| try enc_strings.append(allocator, s);
    for (enc_result.numbers) |n| try enc_numbers.append(allocator, n);

    const result = try nativize_mod.nativize(allocator, &cf);

    // Remove @Native annotation from class and methods if configured
    if (remove_annotation and result.modified) {
        removeNativeAnnotation(allocator, &cf);
    }

    // Write class file (modified or not) to output
    const raw_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ output_base, rel_path });
    for (raw_path) |*c| {
        if (c.* == '\\') c.* = '/';
    }
    if (std.mem.lastIndexOfScalar(u8, raw_path, '/')) |slash| {
        Dir.cwd().createDirPath(io, raw_path[0..slash]) catch {};
    }

    if (result.modified) {
        std.debug.print("  Processing: {s} ({d} methods)\n", .{ rel_path, result.extracted_methods.len });
        for (result.extracted_methods) |em| {
            try extracted.append(allocator, em);
        }
        const modified_data = try class_writer.write(allocator, &cf);
        Dir.cwd().writeFile(io, .{ .sub_path = raw_path, .data = modified_data }) catch |err| {
            std.debug.print("  Write error {s}: {}\n", .{ raw_path, err });
        };
    } else {
        // Copy unmodified class to output
        Dir.cwd().writeFile(io, .{ .sub_path = raw_path, .data = data }) catch {};
    }
}

const types = @import("classfile/types.zig");
const Reader = @import("util/reader.zig").Reader;

/// Remove @Native annotation from class-level and method-level attributes
fn removeNativeAnnotation(allocator: std.mem.Allocator, cf: *types.ClassFile) void {
    const target_desc = "Lmaster/koitoyuu/Native;";

    // Remove from class attributes
    cf.attributes = filterAnnotationAttrs(allocator, cf, cf.attributes, target_desc);

    // Remove from method attributes
    for (cf.methods) |*method| {
        method.attributes = filterAnnotationAttrs(allocator, cf, method.attributes, target_desc);
    }

    // Remove from field attributes (just in case)
    for (cf.fields) |*field| {
        field.attributes = filterAnnotationAttrs(allocator, cf, field.attributes, target_desc);
    }
}

fn filterAnnotationAttrs(
    allocator: std.mem.Allocator,
    cf: *const types.ClassFile,
    attrs: []const types.AttributeInfo,
    target_desc: []const u8,
) []types.AttributeInfo {
    var result: std.ArrayList(types.AttributeInfo) = .empty;
    for (attrs) |attr| {
        const attr_name = cf.getUtf8(attr.name_index) orelse {
            result.append(allocator, attr) catch {};
            continue;
        };
        if (std.mem.eql(u8, attr_name, "RuntimeVisibleAnnotations") or
            std.mem.eql(u8, attr_name, "RuntimeInvisibleAnnotations"))
        {
            // Check if this annotation attribute contains @Native
            if (containsTargetAnnotation(cf, attr.data, target_desc)) {
                // Try to rebuild without the target annotation
                if (rebuildAnnotationsWithout(allocator, cf, attr, target_desc)) |new_attr| {
                    result.append(allocator, new_attr) catch {};
                }
                // If rebuild returns null, the attribute had only @Native, drop entirely
            } else {
                result.append(allocator, attr) catch {};
            }
        } else {
            result.append(allocator, attr) catch {};
        }
    }
    return result.items;
}

fn containsTargetAnnotation(cf: *const types.ClassFile, data: []const u8, target: []const u8) bool {
    if (data.len < 2) return false;
    var reader = Reader.init(data);
    const num = reader.readU16() catch return false;
    for (0..num) |_| {
        const type_idx = reader.readU16() catch return false;
        const type_desc = cf.getUtf8(type_idx) orelse "";
        if (std.mem.eql(u8, type_desc, target)) return true;
        // Skip annotation body
        const npairs = reader.readU16() catch return false;
        for (0..npairs) |_| {
            _ = reader.readU16() catch return false;
            skipElementValue(&reader) catch return false;
        }
    }
    return false;
}

fn rebuildAnnotationsWithout(
    allocator: std.mem.Allocator,
    cf: *const types.ClassFile,
    attr: types.AttributeInfo,
    target: []const u8,
) ?types.AttributeInfo {
    if (attr.data.len < 2) return null;
    var reader = Reader.init(attr.data);
    const num = reader.readU16() catch return null;

    // Collect annotations that are NOT the target
    var kept_count: u16 = 0;
    var segments: [64]struct { start: usize, end: usize } = undefined;

    for (0..num) |_| {
        const anno_start = reader.pos;
        const type_idx = reader.readU16() catch return null;
        const npairs = reader.readU16() catch return null;
        for (0..npairs) |_| {
            _ = reader.readU16() catch return null;
            skipElementValue(&reader) catch return null;
        }
        const anno_end = reader.pos;

        const type_desc = cf.getUtf8(type_idx) orelse "";
        if (!std.mem.eql(u8, type_desc, target)) {
            if (kept_count < 64) {
                segments[kept_count] = .{ .start = anno_start, .end = anno_end };
                kept_count += 1;
            }
        }
    }

    if (kept_count == 0) return null; // All annotations were @Native, drop attribute

    // Rebuild attribute data
    var size: usize = 2; // num_annotations u16
    for (segments[0..kept_count]) |seg| size += seg.end - seg.start;

    const new_data = allocator.alloc(u8, size) catch return null;
    new_data[0] = @intCast(kept_count >> 8);
    new_data[1] = @intCast(kept_count & 0xff);
    var pos: usize = 2;
    for (segments[0..kept_count]) |seg| {
        const len = seg.end - seg.start;
        @memcpy(new_data[pos .. pos + len], attr.data[seg.start .. seg.end]);
        pos += len;
    }

    return .{ .name_index = attr.name_index, .data = new_data };
}

fn skipElementValue(reader: *Reader) !void {
    const tag = try reader.readU8();
    switch (tag) {
        'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z', 's' => _ = try reader.readU16(),
        'e' => { _ = try reader.readU16(); _ = try reader.readU16(); },
        'c' => _ = try reader.readU16(),
        '@' => {
            _ = try reader.readU16();
            const np = try reader.readU16();
            for (0..np) |_| { _ = try reader.readU16(); try skipElementValue(reader); }
        },
        '[' => {
            const count = try reader.readU16();
            for (0..count) |_| try skipElementValue(reader);
        },
        else => {},
    }
}

test {
    _ = @import("classfile/parser.zig");
    _ = @import("classfile/writer.zig");
    _ = @import("classfile/types.zig");
    _ = @import("classfile/annotations.zig");
    _ = @import("transform/nativize.zig");
    _ = @import("transform/encrypt.zig");
    _ = @import("codegen/jni.zig");
    _ = @import("codegen/ffm.zig");
    _ = @import("codegen/cp_extract.zig");
    _ = @import("config.zig");
}
