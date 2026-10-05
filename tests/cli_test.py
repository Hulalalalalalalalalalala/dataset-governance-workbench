#!/usr/bin/env python3
"""branchaudit 命令行 SHA-256 摘要的端到端回归测试。

判定依据独立于本项目：预期摘要全部由 Python hashlib（底层为系统
OpenSSL 的 SHA-256 实现）计算，不读取、不信任 branchaudit 自身代码，
因此能与 C++ 层测试共同防止“共用计算代码同时出错”。

用法:
    python3 cli_test.py <branchaudit 可执行文件路径>

成功退出 0；任一检查失败退出非零。
"""

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

FAILURES = []
CHECKS = 0


def check(condition, message):
    global CHECKS
    CHECKS += 1
    if not condition:
        FAILURES.append(message)
        print(f"FAIL: {message}", file=sys.stderr)


def reference(data: bytes) -> str:
    """独立标准实现给出的参考摘要。"""
    return hashlib.sha256(data).hexdigest()


def merkle_leaf(data: bytes) -> bytes:
    """文件叶子：SHA-256(0x00 || 文件全部原始字节)，返回 32 原始字节。"""
    return hashlib.sha256(b"\x00" + data).digest()


def merkle_parent(left: bytes, right: bytes) -> bytes:
    """父节点：SHA-256(0x01 || 左摘要原始字节 || 右摘要原始字节)。"""
    return hashlib.sha256(b"\x01" + left + right).digest()


def reference_root(datas: list[bytes]) -> str:
    """按公开字节规则独立计算有序批次的 Merkle 根（十六进制文本）。"""
    level = [merkle_leaf(d) for d in datas]
    if not level:
        return hashlib.sha256(b"").hexdigest()
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(merkle_parent(level[i], level[i + 1]))
            else:
                # 落单节点原样上浮：不复制、不补零。
                nxt.append(level[i])
        level = nxt
    return level[0].hex()


def fill_a(n: int) -> bytes:
    return b"a" * n


def pattern(n: int) -> bytes:
    return bytes((i * 31 + 7) % 256 for i in range(n))


def run_cli(exe: str, *args: str, cwd: str | None = None):
    return subprocess.run(
        [exe, "hash", *args],
        capture_output=True,
        cwd=cwd,
    )


def run_root(exe: str, *args: str, cwd: str | None = None):
    return subprocess.run(
        [exe, "root", *args],
        capture_output=True,
        cwd=cwd,
    )


def expect_root_success(exe: str, paths: list[Path], datas: list[bytes],
                        label: str, cwd: str | None = None):
    proc = run_root(exe, *(str(p) for p in paths), cwd=cwd)
    expected = (reference_root(datas) + "\n").encode("ascii")
    check(proc.returncode == 0, f"{label}: exit code 0 (got {proc.returncode})")
    check(proc.stdout == expected,
          f"{label}: stdout must be the reference root + newline "
          f"(got {proc.stdout!r})")
    check(len(proc.stdout) == 65, f"{label}: stdout length is 65")
    check(proc.stderr == b"", f"{label}: stderr must be empty (got {proc.stderr!r})")


def expect_file_success(exe: str, path: Path, data: bytes, label: str):
    proc = run_cli(exe, str(path))
    expected_hex = reference(data)
    expected_stdout = (expected_hex + "\n").encode("ascii")
    check(proc.returncode == 0, f"{label}: exit code 0 (got {proc.returncode})")
    check(proc.stdout == expected_stdout,
          f"{label}: stdout must be exactly 64 lowercase hex chars + newline "
          f"(got {proc.stdout!r})")
    check(len(proc.stdout) == 65, f"{label}: stdout length is 65")
    check(proc.stderr == b"", f"{label}: stderr must be empty (got {proc.stderr!r})")


def write_fixture(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    exe = sys.argv[1]
    check(os.path.isfile(exe) and os.access(exe, os.X_OK),
          f"executable exists and is runnable: {exe}")
    if FAILURES:
        return 1

    with tempfile.TemporaryDirectory(prefix="branchaudit_cli_") as tmp:
        tmp = Path(tmp)

        # ---- 空文件、文本、含零字节/高位字节的二进制 --------------------
        basic_cases = [
            ("empty", b""),
            ("text", b"hello world\n"),
            ("binary", b"a\x00b\xff c\nd"),
            ("ramp", bytes(range(256))),
            ("spaces matter", b"a b c  d"),
            ("lf only", b"abc\n"),
            ("cr only", b"abc\r"),
            ("two lf", b"abc\n\n"),
        ]
        for name, data in basic_cases:
            p = tmp / f"{name}.bin"
            write_fixture(p, data)
            expect_file_success(exe, p, data, name)

        # ---- 仅在换行字节上不同的样本，各自匹配独立标准结果 -------------
        newline_pairs = [
            (b"line1\nline2\n", b"line1\rline2\r"),
            (b"abc\n", b"abc\r"),
        ]
        for i, (lf_data, cr_data) in enumerate(newline_pairs):
            p_lf = tmp / f"nl{i}_lf.bin"
            p_cr = tmp / f"nl{i}_cr.bin"
            write_fixture(p_lf, lf_data)
            write_fixture(p_cr, cr_data)
            expect_file_success(exe, p_lf, lf_data, f"newline LF pair {i}")
            expect_file_success(exe, p_cr, cr_data, f"newline CR pair {i}")
            r1 = run_cli(exe, str(p_lf))
            r2 = run_cli(exe, str(p_cr))
            check(r1.stdout != r2.stdout,
                  f"newline-only difference must change digest (pair {i})")

        # ---- 仅在单个内容字节上不同 ------------------------------------
        for i, (a, b) in enumerate([(b"abc", b"abd"),
                                    (b"\x00", b"\x01"),
                                    (b"\xff", b"\xfe")]):
            pa = tmp / f"byte_a_{i}.bin"
            pb = tmp / f"byte_b_{i}.bin"
            write_fixture(pa, a)
            write_fixture(pb, b)
            expect_file_success(exe, pa, a, f"single byte A {i}")
            expect_file_success(exe, pb, b, f"single byte B {i}")

        # ---- 分组/填充边界长度 55/56/63/64/65 与跨多分组 ---------------
        for n in (55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 200, 1000):
            data = fill_a(n)
            p = tmp / f"len{n}.bin"
            write_fixture(p, data)
            expect_file_success(exe, p, data, f"boundary length {n}")

        # ---- 超过 64KiB 且非 64KiB 整数倍，尾部不得遗漏 ----------------
        for n in (64 * 1024 + 1, 64 * 1024 - 1, 128 * 1024 + 1, 200000):
            data = fill_a(n)
            p = tmp / f"large{n}.bin"
            write_fixture(p, data)
            expect_file_success(exe, p, data, f"large file {n}")
        # 大文件尾部敏感性：仅最后一个字节不同，摘要必须随之改变。
        n = 128 * 1024 + 1
        d1 = bytearray(fill_a(n))
        d2 = bytearray(d1)
        d2[-1] = ord("b")
        p1 = tmp / "tail1.bin"
        p2 = tmp / "tail2.bin"
        write_fixture(p1, bytes(d1))
        write_fixture(p2, bytes(d2))
        r1 = run_cli(exe, str(p1))
        r2 = run_cli(exe, str(p2))
        check(r1.stdout != r2.stdout, "large file: changing last byte changes digest")
        check(r1.stdout == (reference(bytes(d1)) + "\n").encode(),
              "large file: reference digest d1")
        check(r2.stdout == (reference(bytes(d2)) + "\n").encode(),
              "large file: reference digest d2")

        # 非可打印确定性大内容
        big_pattern = pattern(200000)
        pp = tmp / "pattern200000.bin"
        write_fixture(pp, big_pattern)
        expect_file_success(exe, pp, big_pattern, "large binary pattern")

        # ---- 相同字节、不同文件名/目录：摘要一致且不含路径文字 ----------
        shared = b"a\x00b\xff c\nd"
        shared_hex = reference(shared)
        locations = [
            tmp / "same1.bin",
            tmp / "sub dir" / "another name.dat",
            tmp / "目录 一" / "文件 二.bin",
        ]
        for p in locations:
            write_fixture(p, shared)
            proc = run_cli(exe, str(p))
            check(proc.returncode == 0 and
                      proc.stdout == (shared_hex + "\n").encode() and
                      proc.stderr == b"",
                  f"same bytes under different path give same digest: {p}")

        # ---- 路径含空格 / 中文：完整路径定位，不把路径混入摘要 ----------
        spaced = tmp / "spa ce dir" / "na me.bin"
        write_fixture(spaced, shared)
        expect_file_success(exe, spaced, shared, "path with spaces")

        chinese = tmp / "中文目录" / "摘要文件 数据.bin"
        write_fixture(chinese, fill_a(65))
        expect_file_success(exe, chinese, fill_a(65), "Chinese path")

        # 路径文字不参与摘要的直接保证：相同字节、不同路径，stdout 全等。
        outs = set()
        for p in locations + [spaced]:
            outs.add(run_cli(exe, str(p)).stdout)
        check(outs == {(shared_hex + "\n").encode()},
              "path text is never mixed into the digest")

        # ---- 相对路径按当前工作目录解释 -------------------------------
        rel_dir = tmp / "rel 目录"
        rel_dir.mkdir(parents=True)
        (rel_dir / "r.bin").write_bytes(shared)
        proc = run_cli(exe, "r.bin", cwd=str(rel_dir))
        check(proc.returncode == 0 and
                  proc.stdout == (shared_hex + "\n").encode() and
                  proc.stderr == b"",
              "relative path resolved from current working directory")

        # ---- 失败：路径不存在 ------------------------------------------
        missing = tmp / "does not exist 缺失.bin"
        proc = run_cli(exe, str(missing))
        check(proc.returncode == 1, "missing path: exit code 1")
        check(proc.stdout == b"", "missing path: stdout empty")
        check(proc.stderr != b"", "missing path: stderr explains failure")
        check(str(missing).encode() in proc.stderr,
              f"missing path: stderr names failed path (got {proc.stderr!r})")
        check(len(proc.stderr) > len(str(missing)) + 2,
              "missing path: stderr gives a reason beyond the path")

        # ---- 失败：路径指向目录 ----------------------------------------
        directory = tmp / "a dir 目录"
        directory.mkdir()
        proc = run_cli(exe, str(directory))
        check(proc.returncode == 1, "directory path: exit code 1")
        check(proc.stdout == b"", "directory path: stdout empty")
        check(proc.stderr != b"", "directory path: stderr explains failure")
        check(str(directory).encode() in proc.stderr,
              f"directory path: stderr names failed path (got {proc.stderr!r})")
        check(b"directory" in proc.stderr,
              f"directory path: stderr states directory reason "
              f"(got {proc.stderr!r})")

        # ================================================================
        # root：有序文件批次的 Merkle 根
        # ================================================================

        root_datas = {
            "r_empty.bin": b"",
            "r_text.bin": b"abc",
            "r_binary.bin": b"a\x00b\xff c\nd",
            "r_65.bin": fill_a(65),
            "r_pattern.bin": pattern(100),
            "r_xyz.bin": b"xyz",
        }
        for name, data in root_datas.items():
            write_fixture(tmp / name, data)
        rp = {name: tmp / name for name in root_datas}

        # ---- 空批次：SHA-256(空字节序列)，exit 0 ------------------------
        proc = run_root(exe)
        check(proc.returncode == 0, f"root empty batch: exit 0 (got {proc.returncode})")
        check(proc.stdout == (hashlib.sha256(b"").hexdigest() + "\n").encode(),
              f"root empty batch: sha256 of empty byte sequence "
              f"(got {proc.stdout!r})")
        check(proc.stderr == b"", "root empty batch: stderr empty")

        # ---- 单文件：根是叶子 sha256(0x00||bytes)，不是 hash 结果 -------
        for name, data in root_datas.items():
            expect_root_success(exe, [rp[name]], [data], f"root single {name}")
        proc_leaf = run_root(exe, str(rp["r_empty.bin"]))
        proc_hash = run_cli(exe, str(rp["r_empty.bin"]))
        check(proc_leaf.stdout != proc_hash.stdout,
              "root of one empty file differs from hash of empty file")
        check(proc_leaf.stdout ==
              (hashlib.sha256(b"\x00").hexdigest() + "\n").encode(),
              "root one empty file is sha256(single 0x00 byte)")
        proc_leaf_text = run_root(exe, str(rp["r_text.bin"]))
        proc_hash_text = run_cli(exe, str(rp["r_text.bin"]))
        check(proc_leaf_text.stdout != proc_hash_text.stdout,
              "root single file must not equal plain hash output")

        # ---- 多文件批次：2/3/4/5/7 个位置，覆盖落单逐层上浮 ------------
        batches = [
            ["r_text.bin", "r_binary.bin"],
            ["r_text.bin", "r_binary.bin", "r_65.bin"],
            ["r_text.bin", "r_binary.bin", "r_65.bin", "r_pattern.bin"],
            ["r_text.bin", "r_binary.bin", "r_65.bin",
             "r_pattern.bin", "r_xyz.bin"],
            ["r_text.bin", "r_binary.bin", "r_65.bin", "r_pattern.bin",
             "r_xyz.bin", "r_empty.bin", "r_binary.bin"],
        ]
        for batch in batches:
            expect_root_success(
                exe, [rp[n] for n in batch],
                [root_datas[n] for n in batch],
                f"root batch of {len(batch)}")

        # ---- 顺序只来自命令行：交换位置结果必须不同 --------------------
        ab = run_root(exe, str(rp["r_text.bin"]), str(rp["r_binary.bin"]))
        ba = run_root(exe, str(rp["r_binary.bin"]), str(rp["r_text.bin"]))
        check(ab.stdout != ba.stdout, "root order: swapped files differ")
        check(ab.stdout == (reference_root(
            [root_datas["r_text.bin"], root_datas["r_binary.bin"]]) + "\n").encode(),
            "root order: [text,binary] matches reference")
        check(ba.stdout == (reference_root(
            [root_datas["r_binary.bin"], root_datas["r_text.bin"]]) + "\n").encode(),
            "root order: [binary,text] matches reference")

        # 不以文件名/摘要排序：故意让参数顺序与字典序相反。
        unsorted_names = ["r_xyz.bin", "r_pattern.bin", "r_65.bin"]
        proc_sorted_like = run_root(
            exe, *(str(tmp / n) for n in sorted(unsorted_names)))
        proc_given = run_root(
            exe, *(str(tmp / n) for n in unsorted_names))
        check(proc_sorted_like.stdout != proc_given.stdout,
              "root must not reorder arguments by file name")
        check(proc_given.stdout == (reference_root(
            [root_datas[n] for n in unsorted_names]) + "\n").encode(),
              "root honors CLI order against lexicographic order")

        # ---- 不去重：重复路径与相同内容文件各自占位 --------------------
        dup_two = run_root(exe, str(rp["r_text.bin"]), str(rp["r_text.bin"]))
        dup_three = run_root(exe, str(rp["r_text.bin"]),
                             str(rp["r_text.bin"]), str(rp["r_text.bin"]))
        single = run_root(exe, str(rp["r_text.bin"]))
        check(dup_two.stdout != single.stdout,
              "root repeated path keeps two positions")
        check(dup_three.stdout != dup_two.stdout,
              "root repeated path three times keeps three positions")
        check(dup_two.stdout == (reference_root(
            [root_datas["r_text.bin"], root_datas["r_text.bin"]]) + "\n").encode(),
              "root repeated path matches independent reference")
        copy_path = tmp / "别处 副本" / "same content 复制.bin"
        write_fixture(copy_path, root_datas["r_text.bin"])
        distinct_same = run_root(exe, str(rp["r_text.bin"]), str(copy_path))
        check(distinct_same.stdout == dup_two.stdout,
              "root identical contents at different paths keep both positions")
        check(distinct_same.returncode == 0 and distinct_same.stderr == b"",
              "root identical-content batch succeeds silently on stderr")

        # ---- 根不含路径文字：移动/改名后同序传入结果一致 ---------------
        moved_dir = tmp / "新目录 一"
        moved_dir.mkdir()
        moved_text = moved_dir / "改 名.dat"
        moved_bin = moved_dir / "数据 二.bin"
        write_fixture(moved_text, root_datas["r_text.bin"])
        write_fixture(moved_bin, root_datas["r_binary.bin"])
        before = run_root(exe, str(rp["r_text.bin"]), str(rp["r_binary.bin"]))
        after = run_root(exe, str(moved_text), str(moved_bin))
        check(before.stdout == after.stdout,
              "root unchanged when files move, given same order")
        check(before.stdout == (reference_root(
            [root_datas["r_text.bin"], root_datas["r_binary.bin"]]) + "\n").encode(),
              "root path-independence matches reference")

        # ---- 相对路径与含空格/中文路径沿用现有定位规则 -----------------
        rel_root_dir = tmp / "root rel 目录"
        rel_root_dir.mkdir()
        write_fixture(rel_root_dir / "r.bin", root_datas["r_text.bin"])
        proc_rel = run_root(exe, "r.bin", cwd=str(rel_root_dir))
        check(proc_rel.returncode == 0 and
                  proc_rel.stdout == (reference_root(
                      [root_datas["r_text.bin"]]) + "\n").encode() and
                  proc_rel.stderr == b"",
              "root relative path resolved from current working directory")

        # ---- 大文件流式参与批次，尾部敏感 ------------------------------
        big1 = bytearray(fill_a(128 * 1024 + 1))
        big2 = bytearray(big1)
        big2[-1] = ord("b")
        pb1 = tmp / "root_big1.bin"
        pb2 = tmp / "root_big2.bin"
        write_fixture(pb1, bytes(big1))
        write_fixture(pb2, bytes(big2))
        expect_root_success(exe, [pb1, rp["r_xyz.bin"]],
                            [bytes(big1), root_datas["r_xyz.bin"]],
                            "root batch with large file")
        rb1 = run_root(exe, str(pb1), str(pb1), str(rp["r_xyz.bin"]))
        rb2 = run_root(exe, str(pb2), str(pb2), str(rp["r_xyz.bin"]))
        check(rb1.stdout != rb2.stdout,
              "root changes when a large file's last byte changes")

        # ---- 失败契约：任一文件失败则整批失败，stdout 必须为空 ----------
        root_missing = tmp / "root missing 缺失.bin"
        root_dir = tmp / "root dir 目录"
        root_dir.mkdir()
        root_failure_cases = [
            ([root_missing, rp["r_text.bin"]], root_missing, "missing first"),
            ([rp["r_text.bin"], root_missing, rp["r_binary.bin"]],
             root_missing, "missing middle"),
            ([rp["r_text.bin"], root_dir], root_dir, "directory last"),
            ([root_dir], root_dir, "directory only"),
        ]
        for paths, failed_path, label in root_failure_cases:
            proc = run_root(exe, *(str(p) for p in paths))
            check(proc.returncode == 1, f"root {label}: exit code 1")
            check(proc.stdout == b"", f"root {label}: stdout empty")
            check(proc.stderr != b"", f"root {label}: stderr explains failure")
            check(str(failed_path).encode() in proc.stderr,
                  f"root {label}: stderr names failed path "
                  f"(got {proc.stderr!r})")
            check(len(proc.stderr) > len(str(failed_path)) + 2,
                  f"root {label}: stderr gives a reason beyond the path")

    if FAILURES:
        print(f"{len(FAILURES)} of {CHECKS} CLI checks failed", file=sys.stderr)
        return 1
    print(f"all {CHECKS} cli regression checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
