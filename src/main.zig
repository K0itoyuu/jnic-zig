const std = @import("std");
const config_mod = @import("config.zig");
const parser = @import("classfile/parser.zig");
const class_writer = @import("classfile/writer.zig");
const nativize_mod = @import("transform/nativize.zig");
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

    var dir = Dir.cwd().openDir(io, tmp_in, .{ .iterate = true }) catch |err| {
        std.debug.print("Error opening temp dir: {}\n", .{err});
        return;
    };
    defer dir.close(io);
    try processDirectory(allocator, io, dir, tmp_out, &all_extracted);

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
            const c_source = try jni.generateJniSource(allocator, all_extracted.items, config.watermark, config.anti_debug, config.renamer);
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
) !void {
    var walker = try Dir.walk(dir, allocator);
    defer walker.deinit();

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".class")) continue;

        try processClassEntry(allocator, io, entry, output_base, extracted);
    }
}

fn processClassEntry(
    allocator: std.mem.Allocator,
    io: Io,
    entry: Dir.Walker.Entry,
    output_base: []const u8,
    extracted: *std.ArrayList(nativize_mod.ExtractedMethod),
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

    const result = try nativize_mod.nativize(allocator, &cf);

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

test {
    _ = @import("classfile/parser.zig");
    _ = @import("classfile/writer.zig");
    _ = @import("classfile/types.zig");
    _ = @import("classfile/annotations.zig");
    _ = @import("transform/nativize.zig");
    _ = @import("codegen/jni.zig");
    _ = @import("codegen/ffm.zig");
    _ = @import("codegen/cp_extract.zig");
    _ = @import("config.zig");
}
