// NTFSDIAG: runtime probe for the read-only NTFS data volume (0.60.4).
//
// Finds the first mounted NTFS drive and verifies it against the known
// content of the Windows-formatted fixture volume NTFS4K: deterministic
// pattern files (same xorshift32 generator as New-NtfsFixtures0603.ps1),
// the fragmented 2 MB file, sparse structure, the 320-entry B+ tree
// directory, long/mixed-case name resolution, visible rejection of
// compressed content and of every write on the read-only volume.

const r4os = @import("r4os");

const drive_kind_ntfs: u8 = 3;
const bigdir_expected: u32 = 320;

var chunk_buf: [65536]u8 = undefined;
var expect_buf: [65536]u8 = undefined;
var small_buf: [16384]u8 = undefined;
var path_buf: [128]u8 = undefined;
// PathZ borrows the parsed path storage; keep it module-owned so the
// pointer stays valid after pathOn returns.
var path_storage: r4os.FilePath = undefined;

const Pattern = struct {
    state: u32,

    fn init(seed: u32) Pattern {
        return .{ .state = seed | 1 };
    }

    fn next(self: *Pattern) u8 {
        var s = self.state;
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        self.state = s;
        return @truncate(s);
    }

    fn fill(self: *Pattern, out: []u8) void {
        for (out) |*b| b.* = self.next();
    }
};

var failures: u32 = 0;

fn report(ctx: *const r4os.r4sys.Context, label: []const u8, ok: bool) bool {
    ctx.write("NTFSDIAG ");
    ctx.write(label);
    ctx.println(if (ok) ": ok" else ": FAILED");
    if (!ok) failures += 1;
    return ok;
}

fn pathOn(letter: u8, rest: []const u8) ?r4os.path.PathZ {
    if (3 + rest.len >= path_buf.len) return null;
    path_buf[0] = letter;
    path_buf[1] = ':';
    path_buf[2] = '\\';
    @memcpy(path_buf[3 .. 3 + rest.len], rest);
    path_storage = r4os.FilePath.parse(path_buf[0 .. 3 + rest.len]) catch return null;
    return path_storage.asZ();
}

fn transferLen(transfer: r4os.app_storage.Transfer) ?usize {
    return switch (transfer) {
        .bytes => |count| count,
        .end => 0,
        .failure => null,
    };
}

fn infoSize(files: *const r4os.Files, path: r4os.path.PathZ) ?u64 {
    return switch (files.info(path)) {
        .value => |value| value.size,
        else => null,
    };
}

fn checkPatternFile(ctx: *const r4os.r4sys.Context, files: *const r4os.Files, letter: u8, rest: []const u8, size: usize, seed: u32, label: []const u8) bool {
    const path = pathOn(letter, rest) orelse return report(ctx, label, false);
    var pattern = Pattern.init(seed);
    var offset: usize = 0;
    while (offset < size) {
        const want = @min(chunk_buf.len, size - offset);
        const got = transferLen(files.readAt(path, @intCast(offset), chunk_buf[0..want])) orelse return report(ctx, label, false);
        if (got != want) return report(ctx, label, false);
        pattern.fill(expect_buf[0..want]);
        var i: usize = 0;
        while (i < want) : (i += 1) {
            if (chunk_buf[i] != expect_buf[i]) return report(ctx, label, false);
        }
        offset += want;
    }
    // Reading past the end must return zero bytes, never an error.
    const beyond = transferLen(files.readAt(path, @intCast(size), chunk_buf[0..16]));
    if (beyond == null or beyond.? != 0) return report(ctx, label, false);
    return report(ctx, label, true);
}

fn expectZeros(bytes: []const u8) bool {
    for (bytes) |b| {
        if (b != 0) return false;
    }
    return true;
}

fn expectRamp(bytes: []const u8) bool {
    for (bytes, 0..) |b, i| {
        if (b != @as(u8, @truncate((i * 7) & 0xFF))) return false;
    }
    return true;
}

fn checkSparse(ctx: *const r4os.r4sys.Context, files: *const r4os.Files, letter: u8) bool {
    const path = pathOn(letter, "SPARSE.BIN") orelse return report(ctx, "sparse", false);
    const size = infoSize(files, path) orelse return report(ctx, "sparse", false);
    if (size != 2 * 1024 * 1024) return report(ctx, "sparse", false);

    const checks = [_]struct { offset: u32, ramp: bool }{
        .{ .offset = 0, .ramp = true },
        .{ .offset = 512 * 1024, .ramp = false },
        .{ .offset = 1024 * 1024, .ramp = true },
        .{ .offset = 2 * 1024 * 1024 - 4096, .ramp = false },
    };
    for (checks) |check| {
        const got = transferLen(files.readAt(path, check.offset, chunk_buf[0..4096])) orelse return report(ctx, "sparse", false);
        if (got != 4096) return report(ctx, "sparse", false);
        const ok = if (check.ramp) expectRamp(chunk_buf[0..4096]) else expectZeros(chunk_buf[0..4096]);
        if (!ok) return report(ctx, "sparse", false);
    }
    return report(ctx, "sparse", true);
}

fn checkText(ctx: *const r4os.r4sys.Context, files: *const r4os.Files, letter: u8, rest: []const u8, expected: []const u8, label: []const u8) bool {
    const path = pathOn(letter, rest) orelse return report(ctx, label, false);
    const got = transferLen(files.read(path, small_buf[0..256])) orelse return report(ctx, label, false);
    return report(ctx, label, got == expected.len and eql(small_buf[0..expected.len], expected));
}

pub fn r4_app_main(app: *r4os.App) i32 {
    const ctx = app.system();
    const files = app.files() orelse return r4os.abi.err_no_fn;

    ctx.println("NTFSDIAG");

    // Locate the first NTFS drive BESIDES the system volume: since 0.60.9
    // C: itself is NTFS, but the diagnostic volumes arrive as second disks.
    var letter: u8 = 0;
    var index: u32 = 0;
    while (index < 26) : (index += 1) {
        const info = ctx.driveInfo(index) orelse continue;
        if (info.mounted != 0 and info.kind == drive_kind_ntfs and info.letter != 'C') {
            letter = info.letter;
            break;
        }
    }
    if (letter == 0) {
        ctx.println("NTFSDIAG no NTFS drive found");
        ctx.println("NTFSDIAG result: FAILED");
        return 1;
    }
    ctx.write("NTFSDIAG drive: ");
    ctx.putc(letter);
    ctx.println(":");

    if (hasFlag(app.args(), "/WRITE")) {
        return runWriteTests(&ctx, &files, letter);
    }
    if (hasFlag(app.args(), "/TREE")) {
        return runTreeTests(&ctx, &files, letter);
    }

    // 1. Known text file, directory info, empty file.
    _ = checkText(&ctx, &files, letter, "BASIC\\HELLO.TXT", "Hello from Windows NTFS.", "hello");
    {
        const path = pathOn(letter, "BASIC");
        const info = if (path) |p| ctx.fileInfo(p.ptr) else null;
        _ = report(&ctx, "dirinfo", info != null and info.?.is_dir != 0);
    }
    {
        const path = pathOn(letter, "BASIC\\EMPTY.DAT");
        const size = if (path) |p| infoSize(&files, p) else null;
        _ = report(&ctx, "empty", size != null and size.? == 0);
    }

    // 2. Deterministic pattern files including the resident one.
    _ = checkPatternFile(&ctx, &files, letter, "BASIC\\SUB1\\DATA1.BIN", 4096, 11, "data1");
    _ = checkPatternFile(&ctx, &files, letter, "BASIC\\SUB1\\SUB2\\DATA2.BIN", 12345, 22, "data2");
    _ = checkPatternFile(&ctx, &files, letter, "BASIC\\RESIDENT.DAT", 400, 33, "resident");

    // 3. Fragmented 2 MB file over many runs.
    _ = checkPatternFile(&ctx, &files, letter, "FRAG\\BIGFRAG.BIN", 2 * 1024 * 1024, 777, "bigfrag");

    // 4. Sparse structure.
    _ = checkSparse(&ctx, &files, letter);

    // 5. 320-entry directory forces INDEX_ALLOCATION B+ tree enumeration.
    {
        var count: u32 = 0;
        var ok = true;
        const dir_path = pathOn(letter, "BIGDIR") orelse blk: {
            ok = false;
            break :blk undefined;
        };
        if (ok) {
            var entry_index: u32 = 0;
            while (entry_index < 1024) : (entry_index += 1) {
                // dir_entry ABI: 1 = directory, 0 = file, negative = end.
                const rc = ctx.dirEntry(dir_path.ptr, entry_index, small_buf[0..128]);
                if (rc < 0) break;
                count += 1;
            }
        }
        ctx.write("NTFSDIAG bigdir-count: ");
        writeDec(&ctx, count);
        ctx.println("");
        // "." and ".." are synthetic entries 0 and 1.
        _ = report(&ctx, "bigdir", ok and count == bigdir_expected + 2);
    }

    // 6. Long and mixed-case names resolve case-insensitively.  Since the
    // 0.60.19 Windows-parity limits (255 characters per component) the real
    // 64-character Windows name resolves and reads; the old 63-byte
    // contract rejected it.
    _ = checkText(&ctx, &files, letter, "BIGDIR\\Entry-0123-with-a-reasonably-long-name.txt", "entry 123", "longname");
    _ = checkText(&ctx, &files, letter, "names with long components\\MIXEDCASE.KEEPSCASE", "case preserved", "caseless");
    {
        var long_ok = false;
        if (pathOn(letter, "Names With Long Components\\A rather long file name that certainly needs Win32 namespace.txt")) |p| {
            const got = transferLen(files.read(p, small_buf[0..1024]));
            long_ok = got != null and got.? > 0;
        }
        _ = report(&ctx, "longcomponent", long_ok);
    }

    // 6b. Windows metadata records stay hidden (0.60.13): the root listing
    // carries no $-record and $MFT is not reachable by path.
    {
        var hidden_ok = true;
        if (pathOn(letter, "")) |root_path| {
            var entry_index: u32 = 2;
            while (entry_index < 1024) : (entry_index += 1) {
                const rc = ctx.dirEntry(root_path.ptr, entry_index, small_buf[0..128]);
                if (rc < 0) break;
                const full = small_buf[0..nameLenZ(small_buf[0..128])];
                var name_start: usize = 0;
                for (full, 0..) |ch, i| {
                    if (ch == '\\' or ch == '/') name_start = i + 1;
                }
                if (name_start < full.len and full[name_start] == '$') hidden_ok = false;
            }
        } else hidden_ok = false;
        const mft_path = pathOn(letter, "$MFT");
        if (mft_path) |p| {
            if (ctx.fileInfo(p.ptr) != null) hidden_ok = false;
        }
        _ = report(&ctx, "metahidden", hidden_ok);
    }

    // 7. LZNT1-compressed content reads byte-exactly (since 0.60.10).
    {
        const path = pathOn(letter, "COMP\\COMPRESS.TXT");
        var content_ok = false;
        if (path) |p| {
            const got = transferLen(files.readAt(p, 0, chunk_buf[0..4096]));
            if (got != null and got.? == 4096) {
                const line = "R4OS NTFS compression test line. ";
                content_ok = true;
                var i: usize = 0;
                while (i < 4096) : (i += 1) {
                    if (chunk_buf[i] != line[i % line.len]) {
                        content_ok = false;
                        break;
                    }
                }
                const size = infoSize(&files, p);
                if (size == null or size.? != line.len * 8192) content_ok = false;
            }
        }
        _ = report(&ctx, "compressed-content", content_ok);
    }

    // 7b. The UTF-8 (umlaut) name is visible with its real bytes in the
    //     enumeration; the ASCII-only path CONTRACT keeps rejecting it
    //     visibly (the shared core reads it, proven by the host model).
    {
        var seen = false;
        const dir_path = pathOn(letter, "Names With Long Components");
        if (dir_path) |dp| {
            // dirEntry returns full drive paths; match the name as suffix.
            const expected = "\\Umlaute-\xc3\xa4\xc3\xb6\xc3\xbc.txt";
            var entry_index: u32 = 0;
            while (entry_index < 64) : (entry_index += 1) {
                const rc = ctx.dirEntry(dp.ptr, entry_index, small_buf[0..256]);
                if (rc < 0) break;
                const path_len = nameLenZ(small_buf[0..256]);
                if (path_len >= expected.len and eql(small_buf[path_len - expected.len .. path_len], expected)) {
                    seen = true;
                    break;
                }
            }
        }
        // Since 0.60.18 the path contract accepts UTF-8 (BMP): the umlaut
        // path must parse, TYPE-read real bytes, survive a COPY and allow
        // deleting the copy.  Malformed UTF-8 stays a visible parse error.
        // pathOn reuses one static buffer, so the source path is copied into
        // a local zero-terminated buffer before the copy target is built.
        var path_works = false;
        var copy_works = false;
        var src_z: [280]u8 = undefined;
        var original: [256]u8 = undefined;
        var original_len: usize = 0;
        if (pathOn(letter, "Names With Long Components\\Umlaute-\xc3\xa4\xc3\xb6\xc3\xbc.txt")) |p| {
            const got = transferLen(files.read(p, small_buf[0..256]));
            path_works = got != null and got.? > 0;
            if (path_works) {
                original_len = got.?;
                @memcpy(original[0..original_len], small_buf[0..original_len]);
                @memcpy(src_z[0..p.len], p.bytes());
                src_z[p.len] = 0;
            }
        }
        if (path_works) {
            if (pathOn(letter, "UMLKOPIE-\xc3\xa4.txt")) |copy_path| {
                if (ctx.fileCopy(@ptrCast(&src_z), copy_path.ptr) > 0) {
                    const copy_got = transferLen(files.read(copy_path, small_buf[0..256]));
                    copy_works = copy_got != null and copy_got.? == original_len and
                        eql(small_buf[0..original_len], original[0..original_len]) and
                        ctx.fileDelete(copy_path.ptr) > 0;
                }
            }
        }
        const malformed_rejected = pathOn(letter, "Names With Long Components\\Kaputt-\xc3\x28.txt") == null;
        if (!seen or !path_works or !copy_works or !malformed_rejected) {
            ctx.write("NTFSDIAG utf8name detail: seen=");
            ctx.write(if (seen) "yes" else "no");
            ctx.write(" read=");
            ctx.write(if (path_works) "yes" else "no");
            ctx.write(" copy=");
            ctx.write(if (copy_works) "yes" else "no");
            ctx.write(" badreject=");
            ctx.println(if (malformed_rejected) "yes" else "no");
        }
        _ = report(&ctx, "utf8name", seen and path_works and copy_works and malformed_rejected);
    }

    // 8. Hard link content is readable through both names.
    _ = checkPatternFile(&ctx, &files, letter, "LINKTGT.BIN", 8192, 55, "hardlink-a");
    _ = checkPatternFile(&ctx, &files, letter, "LINKALT.BIN", 8192, 55, "hardlink-b");

    // 9. The Windows-authored volume is writable since 0.60.6: a write
    //    round-trip works, and deleting ONE hard-link name keeps the other
    //    name and its content alive (0.60.10).
    {
        const path = pathOn(letter, "WRITE.TST");
        var roundtrip = false;
        if (path) |p| {
            roundtrip = switch (files.write(p, "foreign write roundtrip")) {
                .bytes => blk: {
                    const got = transferLen(files.read(p, small_buf[0..64]));
                    const read_ok = got != null and got.? == "foreign write roundtrip".len and
                        eql(small_buf[0..got.?], "foreign write roundtrip");
                    break :blk read_ok and ctx.fileDelete(p.ptr) > 0;
                },
                else => false,
            };
        }
        _ = report(&ctx, "write-roundtrip", roundtrip);
    }
    {
        const alt = pathOn(letter, "LINKALT.BIN");
        var hardlink_ok = false;
        if (alt) |p| {
            if (ctx.fileDelete(p.ptr) > 0) {
                const gone = ctx.fileInfo(p.ptr) == null or ctx.fileInfo(p.ptr).?.exists == 0;
                hardlink_ok = gone and checkPatternFile(&ctx, &files, letter, "LINKTGT.BIN", 8192, 55, "hardlinkdel-target");
            }
        }
        _ = report(&ctx, "hardlinkdel", hardlink_ok);
    }

    if (failures == 0) {
        ctx.println("NTFSDIAG result: OK");
        return 0;
    }
    ctx.println("NTFSDIAG result: FAILED");
    return 1;
}

fn writeDec(ctx: *const r4os.r4sys.Context, value: u32) void {
    var digits: [10]u8 = undefined;
    if (value == 0) {
        ctx.write("0");
        return;
    }
    var n = value;
    var i: usize = digits.len;
    while (n > 0) : (n /= 10) {
        i -= 1;
        digits[i] = '0' + @as(u8, @intCast(n % 10));
    }
    ctx.write(digits[i..]);
}

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

fn nameLenZ(buf: []const u8) usize {
    var i: usize = 0;
    while (i < buf.len and buf[i] != 0) : (i += 1) {}
    return i;
}

fn hasFlag(args: []const u8, flag: []const u8) bool {
    if (args.len < flag.len) return false;
    var i: usize = 0;
    while (i + flag.len <= args.len) : (i += 1) {
        var m = true;
        var j: usize = 0;
        while (j < flag.len) : (j += 1) {
            const a = args[i + j];
            const b = flag[j];
            const au = if (a >= 'a' and a <= 'z') a - 32 else a;
            const bu = if (b >= 'a' and b <= 'z') b - 32 else b;
            if (au != bu) {
                m = false;
                break;
            }
        }
        if (m) return true;
    }
    return false;
}

/// Write phase 1 acceptance against a writable R4OS-formatted NTFS volume.
fn runWriteTests(ctx: *const r4os.r4sys.Context, files: *const r4os.Files, letter: u8) i32 {
    ctx.println("NTFSDIAG write mode");
    failures = 0;

    // 1. Create + read back a resident file at root.
    {
        const path = pathOn(letter, "WTEST.TXT") orelse return writeResult(ctx);
        const payload = "R4OS NTFS write phase 1";
        const w = files.write(path, payload);
        _ = report(ctx, "create", switch (w) {
            .bytes => true,
            else => false,
        });
        _ = report(ctx, "create-read", checkExact(files, path, payload));
    }

    // 2. Overwrite with different content.
    {
        const path = pathOn(letter, "WTEST.TXT") orelse return writeResult(ctx);
        const payload = "overwritten shorter";
        _ = switch (files.write(path, payload)) {
            .bytes => report(ctx, "overwrite", true),
            else => report(ctx, "overwrite", false),
        };
        _ = report(ctx, "overwrite-read", checkExact(files, path, payload));
    }

    // 3. Non-resident file (multi-cluster) create + read back.
    {
        const path = pathOn(letter, "WBIG.BIN") orelse return writeResult(ctx);
        var pattern = Pattern.init(4242);
        pattern.fill(chunk_buf[0..16384]);
        _ = switch (files.write(path, chunk_buf[0..16384])) {
            .bytes => report(ctx, "bignew", true),
            else => report(ctx, "bignew", false),
        };
        var pat2 = Pattern.init(4242);
        pat2.fill(expect_buf[0..16384]);
        const got = files.read(path, small_buf[0..0]);
        _ = got;
        _ = report(ctx, "bigread", checkRangeMatch(files, path, 16384, expect_buf[0..16384]));
    }

    // 4. Append.
    {
        const path = pathOn(letter, "WLOG.TXT") orelse return writeResult(ctx);
        _ = files.write(path, "first\n");
        const a = files.append(path, "second\n");
        _ = report(ctx, "append", switch (a) {
            .bytes => true,
            else => false,
        });
        _ = report(ctx, "append-read", checkExact(files, path, "first\nsecond\n"));
    }

    // 5. Delete.
    {
        const path = pathOn(letter, "WTEST.TXT") orelse return writeResult(ctx);
        const rc = ctx.fileDelete(path.ptr);
        _ = report(ctx, "delete", rc > 0);
        const info = ctx.fileInfo(path.ptr);
        _ = report(ctx, "delete-gone", info == null or info.?.exists == 0);
    }

    return writeResult(ctx);
}

fn writeResult(ctx: *const r4os.r4sys.Context) i32 {
    if (failures == 0) {
        ctx.println("NTFSDIAG result: OK");
        return 0;
    }
    ctx.println("NTFSDIAG result: FAILED");
    return 1;
}

/// Write phase 2 acceptance: directory tree operations through the kernel
/// VFS/NTFS path (mkdir/rmdir/rename plus a directory large enough for real
/// B+ tree push-down and splits).
fn runTreeTests(ctx: *const r4os.r4sys.Context, files: *const r4os.Files, letter: u8) i32 {
    ctx.println("NTFSDIAG tree mode");
    failures = 0;
    const tree_files: usize = 90;

    // 1. mkdir + nested mkdir.
    {
        const p = pathOn(letter, "TREE") orelse return writeResult(ctx);
        _ = report(ctx, "mkdir", ctx.dirCreate(p.ptr) > 0);
        const p2 = pathOn(letter, "TREE\\SUB") orelse return writeResult(ctx);
        _ = report(ctx, "mkdir-nested", ctx.dirCreate(p2.ptr) > 0);
        const p3 = pathOn(letter, "TREE") orelse return writeResult(ctx);
        _ = report(ctx, "mkdir-dup-reject", ctx.dirCreate(p3.ptr) <= 0);
    }

    // 2. Enough files for a push-down and leaf splits.
    {
        var ok = true;
        var i: usize = 0;
        var name: [40]u8 = undefined;
        while (i < tree_files) : (i += 1) {
            const n = fmtName(name[0..], "TREE\\T", i, ".DAT");
            const p = pathOn(letter, n) orelse {
                ok = false;
                break;
            };
            var pat = Pattern.init(@intCast(i + 301));
            pat.fill(small_buf[0..96]);
            switch (files.write(p, small_buf[0..96])) {
                .bytes => {},
                else => ok = false,
            }
        }
        _ = report(ctx, "bigtree-create", ok);

        // Count via dirEntry: files + SUB + "." + "..".
        var count: u32 = 0;
        const dir_path = pathOn(letter, "TREE") orelse return writeResult(ctx);
        var entry_index: u32 = 0;
        while (entry_index < 1024) : (entry_index += 1) {
            const rc = ctx.dirEntry(dir_path.ptr, entry_index, small_buf[0..128]);
            if (rc < 0) break;
            count += 1;
        }
        _ = report(ctx, "bigtree-count", count == tree_files + 3);

        // Spot readback across the tree.
        var read_ok = true;
        i = 0;
        while (i < tree_files) : (i += 17) {
            const n = fmtName(name[0..], "TREE\\T", i, ".DAT");
            const p = pathOn(letter, n) orelse {
                read_ok = false;
                break;
            };
            var pat = Pattern.init(@intCast(i + 301));
            pat.fill(expect_buf[0..96]);
            const got = transferLen(files.read(p, small_buf[0..256])) orelse {
                read_ok = false;
                break;
            };
            if (got != 96 or !eql(small_buf[0..96], expect_buf[0..96])) {
                read_ok = false;
                break;
            }
        }
        _ = report(ctx, "bigtree-read", read_ok);
    }

    // 3. Rename inside the tree (same parent per r4sys contract).
    {
        const old = pathOn(letter, "TREE\\T0000.DAT") orelse return writeResult(ctx);
        var old_z: [64]u8 = undefined;
        const old_len = copyPath(old, old_z[0..]);
        const new = pathOn(letter, "TREE\\RENAMED0.DAT") orelse return writeResult(ctx);
        _ = report(ctx, "rename", ctx.fileRename(old_z[0..old_len :0].ptr, new.ptr) > 0);
        const gone = pathOn(letter, "TREE\\T0000.DAT") orelse return writeResult(ctx);
        const info = ctx.fileInfo(gone.ptr);
        _ = report(ctx, "rename-old-gone", info == null or info.?.exists == 0);
        const back = pathOn(letter, "TREE\\RENAMED0.DAT") orelse return writeResult(ctx);
        var pat = Pattern.init(301);
        pat.fill(expect_buf[0..96]);
        const got = transferLen(files.read(back, small_buf[0..256]));
        _ = report(ctx, "rename-read", got != null and got.? == 96 and eql(small_buf[0..96], expect_buf[0..96]));
    }

    // 4. rmdir constraints and cleanup down to an empty tree.
    {
        const tree = pathOn(letter, "TREE") orelse return writeResult(ctx);
        var tree_z: [64]u8 = undefined;
        const tree_len = copyPath(tree, tree_z[0..]);
        _ = report(ctx, "rmdir-nonempty-reject", ctx.dirDelete(tree_z[0..tree_len :0].ptr) <= 0);

        var ok = true;
        var name: [40]u8 = undefined;
        var i: usize = 1;
        while (i < tree_files) : (i += 1) {
            const n = fmtName(name[0..], "TREE\\T", i, ".DAT");
            const p = pathOn(letter, n) orelse {
                ok = false;
                break;
            };
            if (ctx.fileDelete(p.ptr) <= 0) {
                ok = false;
                break;
            }
        }
        const ren = pathOn(letter, "TREE\\RENAMED0.DAT") orelse return writeResult(ctx);
        if (ctx.fileDelete(ren.ptr) <= 0) ok = false;
        _ = report(ctx, "bigtree-delete", ok);

        const sub = pathOn(letter, "TREE\\SUB") orelse return writeResult(ctx);
        _ = report(ctx, "rmdir-sub", ctx.dirDelete(sub.ptr) > 0);
        const tree2 = pathOn(letter, "TREE") orelse return writeResult(ctx);
        _ = report(ctx, "rmdir", ctx.dirDelete(tree2.ptr) > 0);
        const tree3 = pathOn(letter, "TREE") orelse return writeResult(ctx);
        const info = ctx.fileInfo(tree3.ptr);
        _ = report(ctx, "rmdir-gone", info == null or info.?.exists == 0);
    }

    return writeResult(ctx);
}

fn fmtName(buf: []u8, prefix: []const u8, index: usize, suffix: []const u8) []const u8 {
    var pos: usize = 0;
    @memcpy(buf[0..prefix.len], prefix);
    pos += prefix.len;
    buf[pos] = @intCast('0' + (index / 1000) % 10);
    buf[pos + 1] = @intCast('0' + (index / 100) % 10);
    buf[pos + 2] = @intCast('0' + (index / 10) % 10);
    buf[pos + 3] = @intCast('0' + index % 10);
    pos += 4;
    @memcpy(buf[pos .. pos + suffix.len], suffix);
    return buf[0 .. pos + suffix.len];
}

/// Copies a PathZ into a caller buffer so a second pathOn call cannot alias
/// the module-owned path storage.
fn copyPath(path: r4os.path.PathZ, out: []u8) usize {
    var len: usize = 0;
    while (path.ptr[len] != 0 and len + 1 < out.len) : (len += 1) out[len] = path.ptr[len];
    out[len] = 0;
    return len;
}

fn checkExact(files: *const r4os.Files, path: r4os.path.PathZ, expected: []const u8) bool {
    const got = transferLen(files.read(path, small_buf[0 .. expected.len + 16])) orelse return false;
    return got == expected.len and eql(small_buf[0..expected.len], expected);
}

fn checkRangeMatch(files: *const r4os.Files, path: r4os.path.PathZ, size: usize, expected: []const u8) bool {
    var offset: usize = 0;
    while (offset < size) {
        const want = @min(chunk_buf.len, size - offset);
        const got = transferLen(files.readAt(path, @intCast(offset), chunk_buf[0..want])) orelse return false;
        if (got != want) return false;
        var i: usize = 0;
        while (i < want) : (i += 1) {
            if (chunk_buf[i] != expected[offset + i]) return false;
        }
        offset += want;
    }
    return true;
}
