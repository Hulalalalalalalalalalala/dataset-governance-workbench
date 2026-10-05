#!/usr/bin/env python3
"""branchaudit 命令行文件摘要（hash）与有序批次 Merkle 根（root）的端到端测试。

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


# ---- Merkle 根的独立参考实现（hashlib / OpenSSL） --------------------------

def leaf_hash(data: bytes) -> bytes:
    """文件叶子：SHA-256(0x00 || 原始字节)，0x00 是单个原始前缀字节。"""
    return hashlib.sha256(b"\x00" + data).digest()


def parent_hash(left: bytes, right: bytes) -> bytes:
    """父摘要：SHA-256(0x01 || 左32字节 || 右32字节)，用原始字节而非十六进制。"""
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(contents) -> bytes:
    """按公开配对规则计算有序批次的根；空批次为 SHA-256(空字节序列)。"""
    if not contents:
        return hashlib.sha256(b"").digest()
    level = [leaf_hash(d) for d in contents]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - (len(level) & 1), 2):
            nxt.append(parent_hash(level[i], level[i + 1]))
        if len(level) & 1:  # 奇数：末节点原样提升，不复制、不补零
            nxt.append(level[-1])
        level = nxt
    return level[0]


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


def expect_root(exe: str, args, contents, label: str):
    """root 成功契约：退出码 0；stdout 恰为 64 位小写十六进制加换行；stderr 空。"""
    proc = run_root(exe, *args)
    expected = (merkle_root(contents).hex() + "\n").encode("ascii")
    check(proc.returncode == 0, f"{label}: exit code 0 (got {proc.returncode})")
    check(proc.stdout == expected,
          f"{label}: stdout must be the 64-hex root + newline "
          f"(got {proc.stdout!r}, want {expected!r})")
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

        # ==================================================================
        # root：有序文件批次的 Merkle 根（预期值全部由上方 hashlib 参考
        # 实现独立计算）
        # ==================================================================
        rdir = tmp / "root fixtures"
        r_empty = rdir / "empty.bin"
        r_a = rdir / "a.bin"
        r_abc = rdir / "abc.bin"
        r_hello = rdir / "hello.bin"
        write_fixture(r_empty, b"")
        write_fixture(r_a, b"a")
        write_fixture(r_abc, b"abc")
        write_fixture(r_hello, b"hello\n")

        empty_batch_hex = hashlib.sha256(b"").hexdigest()
        leaf_empty_hex = hashlib.sha256(b"\x00").hexdigest()

        # ---- 零文件：空字节序列的 SHA-256，成功退出 0 -------------------
        proc = run_root(exe)
        check(proc.returncode == 0, f"root no files: exit 0 (got {proc.returncode})")
        check(proc.stdout == (empty_batch_hex + "\n").encode("ascii"),
              f"root no files: SHA-256 of empty sequence (got {proc.stdout!r})")
        check(proc.stderr == b"", "root no files: stderr empty")

        # ---- 单个空文件 ≠ 空批次根 --------------------------------------
        proc = run_root(exe, str(r_empty))
        check(proc.returncode == 0, "root single empty file: exit 0")
        check(proc.stdout == (leaf_empty_hex + "\n").encode("ascii"),
              f"root single empty file is leaf 0x00 (got {proc.stdout!r})")
        check(proc.stdout != (empty_batch_hex + "\n").encode("ascii"),
              "single empty file root differs from empty batch root")
        check(proc.stderr == b"", "root single empty file: stderr empty")

        # ---- 单文件根是叶子，绝不是现有 hash 的结果 ---------------------
        proc = run_root(exe, str(r_a))
        hash_a = run_cli(exe, str(r_a)).stdout
        expect_root(exe, [str(r_a)], [b"a"], "root single file 'a'")
        check(proc.stdout != hash_a,
              "root of one file must not equal plain hash of that file")

        # ---- 顺序来自参数：交换顺序根不同 -------------------------------
        expect_root(exe, [str(r_a), str(r_abc)], [b"a", b"abc"],
                    "root [a, abc]")
        expect_root(exe, [str(r_abc), str(r_a)], [b"abc", b"a"],
                    "root [abc, a]")
        check(run_root(exe, str(r_a), str(r_abc)).stdout !=
                  run_root(exe, str(r_abc), str(r_a)).stdout,
              "root is order-sensitive")

        # ---- 奇数末节点原样提升；重复位置保留 ---------------------------
        expect_root(exe,
                    [str(r_a), str(r_abc), str(r_empty)],
                    [b"a", b"abc", b""],
                    "root [a, abc, empty] odd promotion")
        expect_root(exe,
                    [str(r_a), str(r_abc), str(r_empty), str(r_hello), str(r_a)],
                    [b"a", b"abc", b"", b"hello\n", b"a"],
                    "root of 5 files")
        expect_root(exe, [str(r_a), str(r_a)], [b"a", b"a"],
                    "same path repeated keeps two positions")
        r_a_copy = rdir / "copy of a.bin"
        write_fixture(r_a_copy, b"a")
        check(run_root(exe, str(r_a), str(r_a_copy)).stdout ==
                  run_root(exe, str(r_a), str(r_a)).stdout,
              "equal contents in distinct files equal repeated positions")
        check(run_root(exe, str(r_a), str(r_a_copy)).stdout !=
                  run_root(exe, str(r_a)).stdout,
              "two equal files do not collapse to one position")

        # ---- 路径无关：同序内容移到别处（含空格/中文目录）根一致 --------
        moved = tmp / "搬到 别处" / "批 次"
        m_empty = moved / "空.bin"
        m_a = moved / "a file.dat"
        m_abc = tmp / "深 路径" / "摘 要.bin"
        write_fixture(m_empty, b"")
        write_fixture(m_a, b"a")
        write_fixture(m_abc, b"abc")
        check(run_root(exe, str(m_empty), str(m_a), str(m_abc)).stdout ==
                  run_root(exe, str(r_empty), str(r_a), str(r_abc)).stdout,
              "moving files elsewhere keeps root for same ordered contents")

        # ---- 含空格/中文路径与相对路径 ----------------------------------
        spaced_root = run_root(exe, str(m_empty), str(m_a), str(m_abc))
        check(spaced_root.returncode == 0 and spaced_root.stderr == b"",
              "root handles paths with spaces and Chinese characters")
        rel_dir = tmp / "root rel 目录"
        rel_dir.mkdir(parents=True, exist_ok=True)
        write_fixture(rel_dir / "r1.bin", b"a")
        write_fixture(rel_dir / "r2.bin", b"abc")
        proc = run_root(exe, "r1.bin", "r2.bin", cwd=str(rel_dir))
        check(proc.returncode == 0 and
                  proc.stdout ==
                  (merkle_root([b"a", b"abc"]).hex() + "\n").encode("ascii") and
                  proc.stderr == b"",
              "root relative paths resolved from current working directory")

        # ---- 大文件流式 + 尾部敏感 --------------------------------------
        big1 = fill_a(200000)
        big2 = pattern(200000)
        rb1 = rdir / "big1.bin"
        rb2 = rdir / "big2.bin"
        write_fixture(rb1, big1)
        write_fixture(rb2, big2)
        expect_root(exe, [str(rb1)], [big1], "root single large file")
        expect_root(exe, [str(rb1), str(rb2)], [big1, big2],
                    "root two large files")
        big_tail = bytearray(big1)
        big_tail[-1] = ord("b")
        rb_tail = rdir / "big1tail.bin"
        write_fixture(rb_tail, bytes(big_tail))
        check(run_root(exe, str(rb_tail)).stdout !=
                  run_root(exe, str(rb1)).stdout,
              "root large file: changing last byte changes root")

        # ---- 失败即整次失败：退出 1、stdout 空、stderr 指明路径与原因 ---
        r_missing = rdir / "root missing 缺失.bin"
        for label, args in (
            ("only missing", [str(r_missing)]),
            ("missing first", [str(r_missing), str(r_a)]),
            ("missing middle", [str(r_a), str(r_missing), str(r_abc)]),
            ("missing last", [str(r_a), str(r_missing)]),
        ):
            proc = run_root(exe, *args)
            check(proc.returncode == 1, f"root {label}: exit code 1")
            check(proc.stdout == b"", f"root {label}: stdout empty")
            check(proc.stderr != b"", f"root {label}: stderr nonempty")
            check(str(r_missing).encode() in proc.stderr,
                  f"root {label}: stderr names failed path "
                  f"(got {proc.stderr!r})")

        r_dir = rdir / "a root dir 目录"
        r_dir.mkdir()
        proc = run_root(exe, str(r_a), str(r_dir))
        check(proc.returncode == 1, "root directory: exit code 1")
        check(proc.stdout == b"", "root directory: stdout empty")
        check(str(r_dir).encode() in proc.stderr and b"directory" in proc.stderr,
              f"root directory: stderr names path and directory reason "
              f"(got {proc.stderr!r})")

        # ---- 保留 hash / --version 及用法错误行为 -----------------------
        check(subprocess.run([exe, "--version"], capture_output=True).stdout ==
                  b"branchaudit 0.1.0\n",
              "--version output preserved")
        proc = subprocess.run([exe, "hash"], capture_output=True)
        check(proc.returncode == 2 and proc.stdout == b"",
              "hash with no path remains usage error (exit 2)")
        proc = subprocess.run([exe, "hash", str(r_a), str(r_abc)],
                              capture_output=True)
        check(proc.returncode == 2 and proc.stdout == b"",
              "hash with extra paths remains usage error (exit 2)")
        proc = subprocess.run([exe, "bogus"], capture_output=True)
        check(proc.returncode == 2, "unknown subcommand remains usage error")

    if FAILURES:
        print(f"{len(FAILURES)} of {CHECKS} CLI checks failed", file=sys.stderr)
        return 1
    print(f"all {CHECKS} cli regression checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
