const std = @import("std");
const nativize = @import("../transform/nativize.zig");

pub const FfmOutput = struct {
    c_source: []u8,
    java_source: []u8,
};

pub fn generateFfmSource(
    allocator: std.mem.Allocator,
    methods: []const nativize.ExtractedMethod,
    watermark: []const u8,
    anti_debug: bool,
) !FfmOutput {
    const c_source = try generateCSource(allocator, methods, watermark, anti_debug);
    const java_source = try generateJavaBindings(allocator, methods);
    return .{ .c_source = c_source, .java_source = java_source };
}

fn generateCSource(
    allocator: std.mem.Allocator,
    methods: []const nativize.ExtractedMethod,
    watermark: []const u8,
    anti_debug: bool,
) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator,
        \\#include <stdint.h>
        \\#include <stdlib.h>
        \\
        \\#ifdef _WIN32
        \\#define EXPORT __declspec(dllexport)
        \\#else
        \\#define EXPORT __attribute__((visibility("default")))
        \\#endif
        \\
        \\
    );

    if (anti_debug) {
        try buf.appendSlice(allocator,
            \\#ifdef _WIN32
            \\#include <windows.h>
            \\static void __anti_debug(void) { if (IsDebuggerPresent()) ExitProcess(1); }
            \\#else
            \\#include <sys/ptrace.h>
            \\#include <signal.h>
            \\static void __anti_debug(void) { if (ptrace(PTRACE_TRACEME,0,0,0)==-1) raise(SIGKILL); }
            \\#endif
            \\
            \\
        );
    }

    try buf.print(allocator, "static const char __wm[] = \"{s}\";\n\n", .{watermark});

    for (methods, 0..) |method, idx| {
        try buf.print(allocator, "static const uint8_t __bc_{d}[] = {{", .{idx});
        for (method.code_data, 0..) |byte, i| {
            if (i % 16 == 0) try buf.appendSlice(allocator, "\n    ");
            try buf.print(allocator, "0x{x:0>2},", .{byte});
        }
        try buf.appendSlice(allocator, "\n};\n\n");

        try buf.print(allocator,
            \\EXPORT int64_t ffm_native_{d}(int64_t* args, int32_t argc) {{
            \\    (void)args; (void)argc; (void)__bc_{d}; (void)__wm;
            \\    /* TODO: bytecode interpreter */
            \\    return 0;
            \\}}
            \\
            \\
        , .{ idx, idx });
    }

    return buf.toOwnedSlice(allocator);
}

fn generateJavaBindings(
    allocator: std.mem.Allocator,
    methods: []const nativize.ExtractedMethod,
) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator,
        \\import java.lang.foreign.*;
        \\import java.lang.invoke.MethodHandle;
        \\
        \\/**
        \\ * Generated FFM bindings for native-ized methods.
        \\ * Requires Java 22+.
        \\ */
        \\public class NativeBindings {
        \\    private static final Linker LINKER = Linker.nativeLinker();
        \\    private static final SymbolLookup LIB;
        \\
        \\    static {
        \\        System.loadLibrary("yurijvm_native");
        \\        LIB = SymbolLookup.loaderLookup();
        \\    }
        \\
        \\
    );

    for (methods, 0..) |method, idx| {
        try buf.print(allocator,
            \\    // {s}.{s}{s}
            \\    public static final MethodHandle MH_{d} = LINKER.downcallHandle(
            \\        LIB.find("ffm_native_{d}").orElseThrow(),
            \\        FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_INT)
            \\    );
            \\
            \\
        , .{ method.class_name, method.method_name, method.descriptor, idx, idx });
    }

    try buf.appendSlice(allocator, "}\n");
    return buf.toOwnedSlice(allocator);
}
