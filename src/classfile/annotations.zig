const std = @import("std");
const types = @import("types.zig");
const Reader = @import("../util/reader.zig").Reader;

const TARGET_ANNOTATION = "Lmaster/koitoyuu/jnic/Native;";

pub const AnnotationResult = struct {
    class_annotated: bool,
    method_indices: []u16,
};

/// Check if the class or its methods have the @Native annotation
pub fn detectNativeAnnotation(allocator: std.mem.Allocator, cf: *const types.ClassFile) !AnnotationResult {
    // Check class-level annotations
    const class_annotated = hasTargetAnnotation(cf, cf.attributes);

    // Check method-level annotations
    var method_list: std.ArrayList(u16) = .empty;
    defer method_list.deinit(allocator);

    if (!class_annotated) {
        for (cf.methods, 0..) |method, idx| {
            if (hasTargetAnnotation(cf, method.attributes)) {
                try method_list.append(allocator, @intCast(idx));
            }
        }
    }

    return AnnotationResult{
        .class_annotated = class_annotated,
        .method_indices = try method_list.toOwnedSlice(allocator),
    };
}

fn hasTargetAnnotation(cf: *const types.ClassFile, attrs: []const types.AttributeInfo) bool {
    for (attrs) |attr| {
        const attr_name = cf.getUtf8(attr.name_index) orelse continue;
        if (std.mem.eql(u8, attr_name, "RuntimeVisibleAnnotations") or
            std.mem.eql(u8, attr_name, "RuntimeInvisibleAnnotations"))
        {
            if (containsAnnotation(cf, attr.data)) return true;
        }
    }
    return false;
}

fn containsAnnotation(cf: *const types.ClassFile, data: []const u8) bool {
    if (data.len < 2) return false;
    var reader = Reader.init(data);
    const num_annotations = reader.readU16() catch return false;

    for (0..num_annotations) |_| {
        const type_index = reader.readU16() catch return false;
        const type_desc = cf.getUtf8(type_index) orelse {
            // Skip this annotation
            skipAnnotationBody(&reader) catch return false;
            continue;
        };

        if (std.mem.eql(u8, type_desc, TARGET_ANNOTATION)) return true;
        skipAnnotationBody(&reader) catch return false;
    }
    return false;
}

fn skipAnnotationBody(reader: *Reader) error{UnexpectedEof}!void {
    const num_pairs = reader.readU16() catch return error.UnexpectedEof;
    for (0..num_pairs) |_| {
        _ = reader.readU16() catch return error.UnexpectedEof; // element_name_index
        try skipElementValue(reader);
    }
}

fn skipElementValue(reader: *Reader) error{UnexpectedEof}!void {
    const tag = reader.readU8() catch return error.UnexpectedEof;
    switch (tag) {
        'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z', 's' => {
            _ = reader.readU16() catch return error.UnexpectedEof;
        },
        'e' => {
            _ = reader.readU16() catch return error.UnexpectedEof;
            _ = reader.readU16() catch return error.UnexpectedEof;
        },
        'c' => {
            _ = reader.readU16() catch return error.UnexpectedEof;
        },
        '@' => {
            _ = reader.readU16() catch return error.UnexpectedEof;
            try skipAnnotationBody(reader);
        },
        '[' => {
            const count = reader.readU16() catch return error.UnexpectedEof;
            for (0..count) |_| {
                try skipElementValue(reader);
            }
        },
        else => {},
    }
}
