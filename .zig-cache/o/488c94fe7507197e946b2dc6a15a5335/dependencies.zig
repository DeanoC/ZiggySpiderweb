pub const packages = struct {
    pub const @"system_sdk-0.3.0-dev-alwUNnYaaAJAtIdE2fg4NQfDqEKs7QCXy_qYukAOBfmF" = struct {
        pub const available = true;
        pub const build_root = "/home/deano/.cache/zig/p/system_sdk-0.3.0-dev-alwUNnYaaAJAtIdE2fg4NQfDqEKs7QCXy_qYukAOBfmF";
        pub const build_zig = @import("system_sdk-0.3.0-dev-alwUNnYaaAJAtIdE2fg4NQfDqEKs7QCXy_qYukAOBfmF");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
        };
    };
    pub const @"ziggy_core-0.1.0-q2d-rGiFAAA8ZiSbvWysW_gbVUJMoh-fGGn8PINTljE6" = struct {
        pub const build_root = "/home/deano/.cache/zig/p/ziggy_core-0.1.0-q2d-rGiFAAA8ZiSbvWysW_gbVUJMoh-fGGn8PINTljE6";
        pub const build_zig = @import("ziggy_core-0.1.0-q2d-rGiFAAA8ZiSbvWysW_gbVUJMoh-fGGn8PINTljE6");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "ztracy", "ztracy-0.14.0-dev-zHJSqzUHGQAmhJybhlwtl1QKevUBw4M5YKZqPfWx2y99" },
        };
    };
    pub const @"ztracy-0.14.0-dev-zHJSqzUHGQAmhJybhlwtl1QKevUBw4M5YKZqPfWx2y99" = struct {
        pub const available = true;
        pub const build_root = "/home/deano/.cache/zig/p/ztracy-0.14.0-dev-zHJSqzUHGQAmhJybhlwtl1QKevUBw4M5YKZqPfWx2y99";
        pub const build_zig = @import("ztracy-0.14.0-dev-zHJSqzUHGQAmhJybhlwtl1QKevUBw4M5YKZqPfWx2y99");
        pub const deps: []const struct { []const u8, []const u8 } = &.{
            .{ "system_sdk", "system_sdk-0.3.0-dev-alwUNnYaaAJAtIdE2fg4NQfDqEKs7QCXy_qYukAOBfmF" },
        };
    };
};

pub const root_deps: []const struct { []const u8, []const u8 } = &.{
    .{ "ziggy_core", "ziggy_core-0.1.0-q2d-rGiFAAA8ZiSbvWysW_gbVUJMoh-fGGn8PINTljE6" },
};
