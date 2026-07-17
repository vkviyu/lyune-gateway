const std = @import("std");

const source_flags = &.{
    "-std=c++17",
    "-DOPENSSL_NO_ASM",
    "-Wno-error",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const source = b.dependency("source", .{});

    const generated = loadGeneratedSources(b, source.path("gen/sources.json"));
    const library = b.addLibrary(.{
        .name = "boringssl",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        }),
    });
    library.root_module.addIncludePath(source.path("include"));
    addGroup(library.root_module, source, generated.value.object.get("bcm").?);
    addGroup(library.root_module, source, generated.value.object.get("crypto").?);
    addGroup(library.root_module, source, generated.value.object.get("ssl").?);
    library.root_module.addCSourceFiles(.{
        .root = source.path(""),
        .files = &.{"decrepit/blowfish/blowfish.cc"},
        .flags = source_flags,
        .language = .cpp,
    });
    library.installHeadersDirectory(source.path("include"), "", .{});

    b.installArtifact(library);
}

fn loadGeneratedSources(b: *std.Build, path: std.Build.LazyPath) std.json.Parsed(std.json.Value) {
    const absolute_path = path.getPath3(b, null);
    const data = absolute_path.root_dir.handle.readFileAlloc(
        b.graph.io,
        absolute_path.sub_path,
        b.allocator,
        .limited(16 * 1024 * 1024),
    ) catch @panic("unable to read BoringSSL source manifest");
    return std.json.parseFromSlice(std.json.Value, b.allocator, data, .{}) catch
        @panic("unable to parse BoringSSL source manifest");
}

fn addGroup(module: *std.Build.Module, source: *std.Build.Dependency, group: std.json.Value) void {
    const entries = group.object.get("srcs").?.array.items;
    var files = std.ArrayList([]const u8).empty;
    for (entries) |entry| {
        files.append(module.owner.allocator, entry.string) catch @panic("OOM");
    }
    module.addCSourceFiles(.{
        .root = source.path(""),
        .files = files.items,
        .flags = source_flags,
        .language = .cpp,
    });
}
