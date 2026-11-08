//! Runs zig with every @response-file flattened to a single level, and with
//! zig's caches confined to the action's scratch space.
//!
//! buck2's prelude nests argsfiles (@a containing @b); `zig cc` rejects that.
//! Nothing is read from or written to $HOME: sandboxed and remote actions have
//! no usable one. Built by the seed zig itself, so the toolchain needs no shell.
//!
//! Usage: zig-wrap <zig> <args...>
//!
//! Uses raw Linux syscalls rather than std.Io, which is still changing between
//! zig releases; only the allocator and deleteTree come from std.

const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

fn die(comptime fmt: []const u8, args: anytype) noreturn {
    var buf: [4096]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "zig-wrap: " ++ fmt ++ "\n", args) catch "zig-wrap: error\n";
    _ = linux.write(2, msg.ptr, msg.len);
    linux.exit_group(127);
}

fn failed(rc: usize) bool {
    return linux.errno(rc) != .SUCCESS;
}

fn z(gpa: Allocator, s: []const u8) [:0]u8 {
    return gpa.dupeSentinel(u8, s, 0) catch die("out of memory", .{});
}

fn isFile(path: [:0]const u8) bool {
    const rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (failed(rc)) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

fn readFile(gpa: Allocator, path: [:0]const u8) []u8 {
    const rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (failed(rc)) die("cannot open {s}: {t}", .{ path, linux.errno(rc) });
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var out: std.ArrayList(u8) = .empty;
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = linux.read(fd, &buf, buf.len);
        if (failed(n)) die("cannot read {s}: {t}", .{ path, linux.errno(n) });
        if (n == 0) break;
        out.appendSlice(gpa, buf[0..n]) catch die("out of memory", .{});
    }
    return out.items;
}

fn writeFile(path: [:0]const u8, data: []const u8) void {
    const rc = linux.open(path.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o644);
    if (failed(rc)) die("cannot create {s}: {t}", .{ path, linux.errno(rc) });
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var off: usize = 0;
    while (off < data.len) {
        const n = linux.write(fd, data[off..].ptr, data.len - off);
        if (failed(n)) die("cannot write {s}: {t}", .{ path, linux.errno(n) });
        off += n;
    }
}

fn mkdir(path: [:0]const u8) void {
    const rc = linux.mkdir(path.ptr, 0o755);
    if (failed(rc) and linux.errno(rc) != .EXIST) die("cannot mkdir {s}: {t}", .{ path, linux.errno(rc) });
}

/// Appends the lines of `path` to `out`, recursing into lines that name an
/// existing @file. Matches `while IFS= read -r line` semantics, including a
/// final line with no trailing newline.
fn expand(gpa: Allocator, path: [:0]const u8, out: *std.ArrayList(u8), depth: u32) void {
    if (depth > 64) die("argsfile nesting too deep at {s}", .{path});
    const data = readFile(gpa, path);
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        if (line.len == 0 and it.index == null) break; // trailing newline
        if (line.len > 1 and line[0] == '@') {
            const inner = z(gpa, line[1..]);
            if (isFile(inner)) {
                expand(gpa, inner, out, depth + 1);
                continue;
            }
        }
        out.appendSlice(gpa, line) catch die("out of memory", .{});
        out.append(gpa, '\n') catch die("out of memory", .{});
    }
}

fn getenv(envp: []const ?[*:0]const u8, key: []const u8) ?[]const u8 {
    for (envp) |e| {
        const s = std.mem.span(e.?);
        if (s.len > key.len and s[key.len] == '=' and std.mem.eql(u8, s[0..key.len], key)) return s[key.len + 1 ..];
    }
    return null;
}

fn absolute(gpa: Allocator, path: []const u8) []const u8 {
    if (path.len > 0 and path[0] == '/') return path;
    var buf: [4096]u8 = undefined;
    const rc = linux.getcwd(&buf, buf.len);
    if (failed(rc)) die("getcwd failed: {t}", .{linux.errno(rc)});
    const cwd = std.mem.sliceTo(&buf, 0);
    return std.fmt.allocPrint(gpa, "{s}/{s}", .{ cwd, path }) catch die("out of memory", .{});
}

pub fn main(init: std.process.Init) u8 {
    const gpa = init.arena.allocator();
    const argv = init.minimal.args.vector;
    const envp = init.minimal.environ.block.slice;
    if (argv.len < 2) die("usage: zig-wrap <zig> <args...>", .{});

    const scratch = getenv(envp, "BUCK_SCRATCH_PATH") orelse getenv(envp, "TMPDIR") orelse "/tmp";
    const base = absolute(gpa, scratch);
    mkdir(z(gpa, base));
    const pid = linux.getpid();
    const tmpdir = std.fmt.allocPrint(gpa, "{s}/zig.{d}", .{ base, pid }) catch die("out of memory", .{});
    mkdir(z(gpa, tmpdir));

    // Arguments: the zig binary, then each arg with @files flattened.
    var args: std.ArrayList(?[*:0]const u8) = .empty;
    args.append(gpa, argv[1]) catch die("out of memory", .{});
    var n: u32 = 0;
    for (argv[2..]) |a| {
        const s = std.mem.span(a);
        if (s.len > 1 and s[0] == '@') {
            const file = z(gpa, s[1..]);
            if (isFile(file)) {
                n += 1;
                var flat: std.ArrayList(u8) = .empty;
                expand(gpa, file, &flat, 0);
                const rsp = std.fmt.allocPrint(gpa, "{s}/{d}.rsp", .{ tmpdir, n }) catch die("out of memory", .{});
                writeFile(z(gpa, rsp), flat.items);
                args.append(gpa, z(gpa, std.fmt.allocPrint(gpa, "@{s}", .{rsp}) catch die("out of memory", .{}))) catch die("out of memory", .{});
                continue;
            }
        }
        args.append(gpa, a) catch die("out of memory", .{});
    }
    args.append(gpa, null) catch die("out of memory", .{});

    // Environment: inherited, with zig's caches pointed into tmpdir.
    var env: std.ArrayList(?[*:0]const u8) = .empty;
    for (envp) |e| {
        const s = std.mem.span(e.?);
        if (std.mem.startsWith(u8, s, "ZIG_GLOBAL_CACHE_DIR=") or std.mem.startsWith(u8, s, "ZIG_LOCAL_CACHE_DIR=")) continue;
        env.append(gpa, e) catch die("out of memory", .{});
    }
    env.append(gpa, z(gpa, std.fmt.allocPrint(gpa, "ZIG_GLOBAL_CACHE_DIR={s}/global-cache", .{tmpdir}) catch die("out of memory", .{}))) catch die("out of memory", .{});
    env.append(gpa, z(gpa, std.fmt.allocPrint(gpa, "ZIG_LOCAL_CACHE_DIR={s}/local-cache", .{tmpdir}) catch die("out of memory", .{}))) catch die("out of memory", .{});
    env.append(gpa, null) catch die("out of memory", .{});

    const argv_z: [*:null]const ?[*:0]const u8 = @ptrCast(args.items.ptr);
    const envp_z: [*:null]const ?[*:0]const u8 = @ptrCast(env.items.ptr);

    const child = linux.fork();
    if (failed(child)) die("fork failed: {t}", .{linux.errno(child)});
    if (child == 0) {
        const rc = linux.execve(argv[1], argv_z, envp_z);
        die("cannot exec {s}: {t}", .{ argv[1], linux.errno(rc) });
    }

    var status: u32 = 0;
    while (true) {
        const rc = linux.wait4(@intCast(child), @ptrCast(&status), 0, null);
        if (!failed(rc)) break;
        if (linux.errno(rc) != .INTR) die("wait failed: {t}", .{linux.errno(rc)});
    }

    std.Io.Dir.cwd().deleteTree(init.io, tmpdir) catch {};

    if (linux.W.IFEXITED(status)) return @intCast(linux.W.EXITSTATUS(status));
    return 128 +% @as(u8, @truncate(@intFromEnum(linux.W.TERMSIG(status))));
}
