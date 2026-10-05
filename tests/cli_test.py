#!/usr/bin/env python3
"""branchaudit 命令行文件摘要（hash）与有序批次 Merkle 根（root）的端到端测试。

判定依据独立于本项目：预期摘要全部由 Python hashlib（底层为系统
OpenSSL 的 SHA-256 实现）计算，不读取、不信任 branchaudit 自身代码，
因此能与 C++ 层测试共同防止“共用计算代码同时出错”。

用法:
    python3 cli_test.py <branchaudit 可执行文件路径>

成功退出 0；任一检查失败退出非零。
"""

import fcntl
import hashlib
import os
import pty
import socket
import subprocess
import sys
import tempfile
import termios
import time
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


# ---- 真实文件访问故障注入（测试自身安排，不依赖偶发磁盘故障） --------------
#
# 两种机制仅在 Linux 风格系统上可用；其他平台显式跳过，绝不能把“无法触发
# 目标错误”算作通过。

FAULT_SUPPORTED = sys.platform.startswith("linux")

# 阻塞写阶段强制读取方至少消费的字节数（“确实读到过内容”的内核级证明）。
_FORCED_BYTES = 8192
# 预置载荷上限：足以填满常见 tty 输入缓冲并仍留下 _FORCED_BYTES 可写。
_PAYLOAD_SIZE = 96 * 1024


def fault_payload() -> bytes:
    """确定性字节序列，覆盖 0x00/0xff；与 C++ 层 pattern 构造一致。"""
    return bytes((i * 31 + 7) % 256 for i in range(_PAYLOAD_SIZE))


def _raw_termios(fd: int) -> None:
    """raw 模式：关闭回显/规范/信号/加工，字节原样到达。"""
    attrs = termios.tcgetattr(fd)
    attrs[0] = 0                                   # iflag
    attrs[1] = 0                                   # oflag
    attrs[2] = termios.CS8 | termios.CREAD         # cflag
    attrs[3] = 0                                   # lflag（无 ICANON/ECHO/ISIG）
    attrs[6][termios.VMIN] = 1
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def make_unopenable_socket(directory: Path, name: str) -> Path:
    """创建真实存在、却无法以普通文件方式打开的 AF_UNIX 套接字节点。

    用于“文件确实存在但打开失败”：它不是缺失路径，也不是目录。"""
    path = directory / name
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    # 保持套接字存活到测试结束；进程结束后由 OS/临时目录清理。
    sock.listen(1)
    globals().setdefault("_fault_sockets", []).append(sock)
    assert path.exists() and not path.is_file()
    return path


def _force_write_nonblock(fd: int, view: memoryview, n: int, timeout: float) -> int:
    """在 fd 已为非阻塞、缓冲已填满到 EAGAIN 的前提下，再写入至多 n 字节。

    对端不读时一直 EAGAIN；对端每读走一段、腾出缓冲，下一次非阻塞写才会
    成功。因此“在 EAGAIN 之后又成功写入 n 字节”由内核证明对端确实消费了
    n 字节。超时返回已写量，绝不阻塞（用于识别伪造读取的对端）。"""
    total = 0
    deadline = time.monotonic() + timeout
    while total < n:
        try:
            w = os.write(fd, view[total:total + (n - total)])
        except BlockingIOError:
            if time.monotonic() >= deadline:
                break
            time.sleep(0.001)
            continue
        except InterruptedError:
            continue
        except OSError:
            break
        if w <= 0:
            break
        total += w
    return total


def run_with_read_fault(exe: str, prefix_args):
    """对伪终端从端执行 [exe, *prefix_args, slave_path]，制造“读到真实内容后
    读取出错”。

    采用内核级“填满缓冲 + 非阻塞写重试”握手（与 C++ 故障设施一致）：
      1) raw 模式下非阻塞写满从端缓冲到 EAGAIN（读取方尚未启动）；
      2) 启动读取方；
      3) 保持非阻塞再写 _FORCED_BYTES 字节：对端不读时一直 EAGAIN，对端每读走
         一段腾出缓冲，写才成功——由内核证明读取方已读到这么多真实字节；
      4) 关闭写端与主端，使其下一次 read(2) 以 EIO 失败。

    全程非阻塞：若被测程序根本不读文件（仅伪造一个带错误文字的返回值），
    步骤 3 会超时、forced 不足并显式判失败，而不会把测试挂死。

    prefix_args 位于从端路径之前（root 可在此放正常文件，它们按顺序必先于
    故障叶子被处理）。返回 (proc, slave_name, forced)。
    """
    payload = fault_payload()
    master, slave = pty.openpty()
    _raw_termios(slave)
    _raw_termios(master)
    slave_name = os.ttyname(slave)
    os.close(slave)
    writer = os.open(slave_name, os.O_WRONLY | os.O_NOCTTY)
    forced = 0
    try:
        # 1) 非阻塞写直到 EAGAIN：填满从端缓冲。
        flags = fcntl.fcntl(master, fcntl.F_GETFL)
        fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        off = 0
        hit_eagain = False
        view = memoryview(payload)
        while off < len(payload):
            try:
                n = os.write(master, view[off:])
            except BlockingIOError:
                hit_eagain = True
                break
            except InterruptedError:
                continue
            off += n
        if not hit_eagain:
            raise RuntimeError("pty buffer could not be filled to EAGAIN")

        # 2) 启动读取方。
        proc = subprocess.Popen(
            [exe, *prefix_args, slave_name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # 3) 主端保持非阻塞，重试写 _FORCED_BYTES 字节。若被测程序不真正读
        # 文件（仅伪造错误），缓冲一直满、持续 EAGAIN，超时后 forced 不足，
        # 下面显式判失败而不是挂死。
        want = min(_FORCED_BYTES, len(payload) - off)
        forced = _force_write_nonblock(master, view[off:], want, timeout=3.0)
        if forced != want:
            proc.kill()
            raise RuntimeError("reader never consumed the forced bytes")

        # 留出窗口确保读取方已进入下一次阻塞读取。
        time.sleep(0.05)
        return proc, slave_name, forced
    finally:
        try:
            os.close(writer)
        except OSError:
            pass
        try:
            os.close(master)
        except OSError:
            pass


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

        # ---- 失败：文件确实存在却不能打开（AF_UNIX 套接字）-------------
        # 与缺失路径、目录都不同：节点真实存在，但以普通文件方式打开必失败。
        if FAULT_SUPPORTED:
            unopenable = make_unopenable_socket(tmp, "exists but unopenable.sock")
            proc = run_cli(exe, str(unopenable))
            check(proc.returncode == 1, "unopenable existing file: exit code 1")
            check(proc.stdout == b"", "unopenable existing file: stdout empty")
            check(proc.stderr != b"",
                  "unopenable existing file: stderr explains failure")
            check(str(unopenable).encode() in proc.stderr,
                  f"unopenable existing file: stderr names failed path "
                  f"(got {proc.stderr!r})")
            check(b"read error" not in proc.stderr,
                  f"unopenable existing file: fails at open, not read "
                  f"(got {proc.stderr!r})")
            # 错误来自真实打开失败：stderr 必须在路径之外给出原因文字。
            check(len(proc.stderr) > len(str(unopenable)) + 2,
                  "unopenable existing file: stderr gives a reason beyond the path")
        else:
            print("SKIP: open-failure fault injection unsupported", file=sys.stderr)

        # ---- 失败：文件已打开、读到真实内容后继续读出错（EIO）----------
        # 已读到的真实内容绝不能成为成功摘要，也不能被当作正常 EOF。
        if FAULT_SUPPORTED:
            proc, fault_path, forced = run_with_read_fault(exe, ["hash"])
            out, err = proc.communicate(timeout=5)
            # 前提：内核握手证明读取方至少消费了 8192 字节真实内容。
            check(forced == _FORCED_BYTES,
                  f"read failure premise: {_FORCED_BYTES} real bytes consumed")
            check(proc.returncode == 1, "read failure after real bytes: exit 1")
            check(out == b"", "read failure after real bytes: stdout empty")
            check(err != b"", "read failure after real bytes: stderr nonempty")
            check(fault_path.encode() in err,
                  f"read failure: stderr names the failed path (got {err!r})")
            check(b"read error" in err,
                  f"read failure: stderr states read failure (got {err!r})")
        else:
            print("SKIP: read-failure fault injection unsupported", file=sys.stderr)

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

        if FAULT_SUPPORTED:
            # ---- root 失败：叶子真实存在却打不开（套接字）---------------
            r_sock = make_unopenable_socket(rdir, "root leaf unopenable.sock")
            for label, args in (
                ("only unopenable", [str(r_sock)]),
                ("unopenable after good", [str(r_a), str(r_sock)]),
            ):
                proc = run_root(exe, *args)
                check(proc.returncode == 1, f"root {label}: exit code 1")
                check(proc.stdout == b"", f"root {label}: stdout empty")
                check(str(r_sock).encode() in proc.stderr,
                      f"root {label}: stderr names the real failing path "
                      f"(got {proc.stderr!r})")
                check(b"read error" not in proc.stderr,
                      f"root {label}: failure is at open, not read "
                      f"(got {proc.stderr!r})")

            # ---- root 失败：出错前已处理过正常文件，随后叶子读出错 -------
            # 有序批次 [正常文件, 读出错文件]：正常文件必先按序处理；内核握手
            # 又证明故障叶子确实读到真实字节。整次仍必须失败且 stdout 全空
            # （这本身排除了：已处理文件的根、故障文件部分内容的根、跳过出错
            # 位置后的根），stderr 指向真正出错的文件。
            proc, fault_path, forced = run_with_read_fault(
                exe, ["root", str(r_a)])
            out, err = proc.communicate(timeout=5)
            check(forced == _FORCED_BYTES,
                  f"root read failure premise: failing leaf consumed "
                  f"{_FORCED_BYTES} real bytes")
            check(proc.returncode == 1,
                  "root read failure after good file: exit code 1")
            check(out == b"",
                  "root read failure: stdout empty (no partial root of any kind)")
            # 反证：若错误地只输出“已处理正常文件的根/跳过出错位置的根”，
            # 它会等于单文件批次 [r_a] 的成功根；stdout 必须与之不同。
            good_only_root = run_root(exe, str(r_a)).stdout
            check(good_only_root.endswith(b"\n") and len(good_only_root) == 65,
                  "sanity: single good-file root is produced when asked")
            check(out != good_only_root,
                  "root read failure: no root of already-processed / skipped files")
            check(fault_path.encode() in err,
                  f"root read failure: stderr points at the real failing file "
                  f"(got {err!r})")
            check(b"read error" in err,
                  f"root read failure: stderr states read failure "
                  f"(got {err!r})")

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
