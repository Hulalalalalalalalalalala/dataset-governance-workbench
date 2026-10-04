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

    if FAILURES:
        print(f"{len(FAILURES)} of {CHECKS} CLI checks failed", file=sys.stderr)
        return 1
    print(f"all {CHECKS} cli regression checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
