// branchaudit 有序文件批次 Merkle 根回归测试（无第三方依赖，链接 branchaudit_core）。
//
// 预期摘要的独立依据：全部常量由 Python hashlib（底层系统 OpenSSL 的
// SHA-256）按公开字节规则（叶子 SHA-256(0x00||data)、父节点
// SHA-256(0x01||left||right)、奇数末节点原样提升、空批次为 SHA-256("")）
// 独立计算，不使用本项目代码生成期望值。
//
// 运行成功返回 0；任一断言失败返回非零。

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fault_fixture.h"
#include "filehash.h"
#include "merkle.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, std::string_view what) {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::cerr << "FAIL: " << what << '\n';
    }
}

namespace fs = std::filesystem;

using branchaudit::Digest;

std::string hex_of(const Digest& d) {
    return branchaudit::to_hex(d);
}

Digest leaf_bytes(const std::vector<unsigned char>& data) {
    return branchaudit::merkle_leaf(data.data(), data.size());
}

std::vector<unsigned char> bytes_of(std::string_view s) {
    return std::vector<unsigned char>(s.begin(), s.end());
}

std::vector<unsigned char> fill_a(std::size_t n) {
    return std::vector<unsigned char>(n, static_cast<unsigned char>('a'));
}

std::vector<unsigned char> pattern(std::size_t n) {
    std::vector<unsigned char> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<unsigned char>((i * 31 + 7) % 256);
    }
    return v;
}

struct TempArea {
    fs::path root;
    explicit TempArea(const std::string& tag) {
        const auto cwd_hash = std::hash<fs::path>{}(fs::current_path());
        root = fs::temp_directory_path() /
               ("branchaudit_merkle_test_" + tag + "_" +
                std::to_string(static_cast<std::uint64_t>(cwd_hash)));
        fs::remove_all(root);
        fs::create_directories(root);
    }
    ~TempArea() { std::error_code ec; fs::remove_all(root, ec); }
};

void write_file(const fs::path& p, const std::vector<unsigned char>& bytes) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    check(static_cast<bool>(out), std::string("write fixture ") + p.string());
}

Digest root_of(const std::vector<fs::path>& paths) {
    const branchaudit::FileHashResult r = branchaudit::merkle_root_files(paths);
    check(r.ok(), std::string("merkle_root_files succeeds: ") + r.error);
    return r.digest;
}

// 调用库接口期间截获标准输出/错误：库只返回结果，不自行打印、不退出进程。
std::pair<std::string, std::string> silent_root(
    const std::vector<fs::path>& paths, branchaudit::FileHashResult* out) {
    std::stringstream cap_out, cap_err;
    auto* old_out = std::cout.rdbuf(cap_out.rdbuf());
    auto* old_err = std::cerr.rdbuf(cap_err.rdbuf());
    *out = branchaudit::merkle_root_files(paths);
    std::cout.rdbuf(old_out);
    std::cerr.rdbuf(old_err);
    return {cap_out.str(), cap_err.str()};
}

// ---- 空批次根 -------------------------------------------------------------

void test_empty_batch() {
    const Digest empty_root = branchaudit::merkle_empty_root();
    check(hex_of(empty_root) ==
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "empty batch root is SHA-256 of empty byte sequence");

    const branchaudit::FileHashResult r =
        branchaudit::merkle_root_files({});
    check(r.ok(), "zero files: succeeds");
    check(r.digest == empty_root, "zero files: root equals merkle_empty_root()");

    // 空批次根必须与“单个空文件”的叶子摘要不同。
    const Digest leaf_empty = leaf_bytes({});
    check(hex_of(leaf_empty) ==
              "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
          "leaf of empty file is SHA-256(0x00)");
    check(leaf_empty != empty_root,
          "empty batch root differs from single empty-file leaf");
}

// ---- 叶子：0x00 前缀与原始字节 --------------------------------------------

void test_leaf_rule() {
    check(hex_of(leaf_bytes(bytes_of("a"))) ==
              "022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c",
          "leaf('a') = SHA-256(0x00 || 'a')");
    check(hex_of(leaf_bytes(bytes_of("abc"))) ==
              "609f6e36d2405585188d5cfd761f407c7cc46a7d3f314c88270469dde315fcd1",
          "leaf('abc') = SHA-256(0x00 || 'abc')");
    check(hex_of(leaf_bytes(bytes_of("hello\n"))) ==
              "54a6dc1bfc990ced3f5757264f357ad708a9ee54ce3d117299641b234f6d5800",
          "leaf('hello\\n') includes raw newline byte");

    // 叶子不是普通 hash：0x00 前缀必须改变结果。
    branchaudit::Sha256 plain;
    const unsigned char a_byte = 'a';
    plain.update(&a_byte, 1);
    const Digest plain_a = plain.final();
    check(hex_of(plain_a) ==
              "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
          "plain SHA-256('a') reference (no prefix)");
    check(leaf_bytes(bytes_of("a")) != plain_a,
          "leaf('a') must not equal plain hash('a')");

    // 分组/填充边界长度的叶子（前缀使总长度 +1，覆盖各边界）。
    struct BCase { std::size_t n; const char* hex; };
    const BCase cases[] = {
        {55,  "2f96780fb415b287dd95897a04ef96fde6a5f5b0c771d0a1175543bc3250718e"},
        {56,  "4632d4b47c0932896996fe232ae65a5af500608fabd0bdbfbb6856795eaf9d85"},
        {63,  "5ec0fdb427bf003f71ceb018dfedc0028590a422eaf9f15a69dd1e5a6aa03d5e"},
        {64,  "88df0645999a1bc9dec19086e862403750a069436d7ecf7775256f78279b3fcb"},
        {65,  "3f104f71a21ddad6e23bac5b43967f5eed6675a5adf0c4050de374fff8055af7"},
        {128, "6023f14a3b7582c7e389f4ef3313bc3c6cbf69623e12a7d19485553d02d1f635"},
    };
    for (const BCase& c : cases) {
        check(hex_of(leaf_bytes(fill_a(c.n))) == c.hex,
              "leaf of 'a'*" + std::to_string(c.n) + " matches independent value");
    }
}

// ---- 父节点：0x01 前缀、原始 32 字节、先左后右 -----------------------------

void test_parent_rule() {
    const Digest la = leaf_bytes(bytes_of("a"));
    const Digest lbc = leaf_bytes(bytes_of("abc"));

    check(hex_of(branchaudit::merkle_parent(la, lbc)) ==
              "6a5c0676c6dd1efd519348f49315879d99549029726d5dd1a5dedbf700720761",
          "parent(leaf('a'), leaf('abc')) = SHA-256(0x01||left||right)");

    // 左右顺序不可交换。
    check(branchaudit::merkle_parent(la, lbc) != branchaudit::merkle_parent(lbc, la),
          "parent is ordered: parent(a,abc) != parent(abc,a)");
    check(hex_of(branchaudit::merkle_parent(lbc, la)) ==
              "ece02d1ac6ea17f528a19562aea6b77f7e7d1d8224a7583d3fbfc9f6e3d426ab",
          "parent(leaf('abc'), leaf('a')) independent value");
}

// ---- 逐文件批次：顺序、重复、奇数提升、路径无关 ---------------------------

void test_file_batches() {
    TempArea tmp("batches");

    const auto empty = bytes_of("");
    const auto a = bytes_of("a");
    const auto abc = bytes_of("abc");
    const auto hello = bytes_of("hello\n");

    const fs::path f_empty = tmp.root / "empty.bin";
    const fs::path f_a = tmp.root / "a.bin";
    const fs::path f_abc = tmp.root / "abc.bin";
    const fs::path f_hello = tmp.root / "hello.bin";
    write_file(f_empty, empty);
    write_file(f_a, a);
    write_file(f_abc, abc);
    write_file(f_hello, hello);

    // 单文件批次：根即叶子摘要。
    check(hex_of(root_of({f_a})) == hex_of(leaf_bytes(a)),
          "single file: root equals its leaf digest");
    check(hex_of(root_of({f_a})) ==
              "022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c",
          "single file root('a') is leaf, not plain hash");
    check(hex_of(root_of({f_empty})) ==
              "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
          "single empty file root differs from empty batch root");

    // 两文件、顺序敏感。
    check(hex_of(root_of({f_a, f_abc})) ==
              "6a5c0676c6dd1efd519348f49315879d99549029726d5dd1a5dedbf700720761",
          "root [a, abc]");
    check(hex_of(root_of({f_abc, f_a})) ==
              "ece02d1ac6ea17f528a19562aea6b77f7e7d1d8224a7583d3fbfc9f6e3d426ab",
          "root [abc, a] differs when order is reversed");

    // 三文件：末节点原样提升。结构 = parent(parent(La,Lbc), Lempty)。
    const Digest p = branchaudit::merkle_parent(leaf_bytes(a), leaf_bytes(abc));
    const Digest three = branchaudit::merkle_parent(p, leaf_bytes(empty));
    check(hex_of(three) ==
              "b3beb69a3342155ac93f8fb124f5b39ec5955cdcbff261495547e03361f9c99a",
          "structural 3-file root with odd promotion (independent value)");
    check(root_of({f_a, f_abc, f_empty}) == three,
          "root [a, abc, empty] matches promoted (not duplicated) structure");

    // 明确排除“复制末节点”与“补零”两种错误配对。
    const Digest dup_last = branchaudit::merkle_parent(
        p, branchaudit::merkle_parent(leaf_bytes(empty), leaf_bytes(empty)));
    check(dup_last != three,
          "odd node is never duplicated to make a pair");
    const Digest zeros{};
    check(branchaudit::merkle_parent(p, zeros) != three,
          "odd node is never zero-padded to make a pair");

    // 不同位置的重复排列给出不同根（不按摘要重排、不去重）。
    check(hex_of(root_of({f_a, f_a, f_abc})) ==
              "d2b37c5ec897ce0504f95ec7a060d88c38664164a4614b5ca18e5dd3df527702",
          "root [a, a, abc] keeps both positions");
    check(hex_of(root_of({f_a, f_abc, f_a})) ==
              "588340eb2a7896e08c25b9af5be4538358eadeb56e0c685910ac0cc6fb12e006",
          "root [a, abc, a] differs from [a, a, abc]");

    // 同一路径重复传入，保留两个位置。
    check(hex_of(root_of({f_a, f_a})) ==
              "8025de747bafe2560d6b991bdb17ca89efe1b6fedda1be209c0ee015338861ea",
          "same path twice keeps two positions");
    // 两个不同文件、内容相同，结果与重复同一路径一致。
    const fs::path f_a_copy = tmp.root / "copy of a.bin";
    write_file(f_a_copy, a);
    check(root_of({f_a, f_a_copy}) == root_of({f_a, f_a}),
          "identical content in distinct files behaves like repeated positions");

    // 偶数四文件与奇数五文件（末节点先提升，再与其左侧在上层配对）。
    check(hex_of(root_of({f_a, f_abc, f_empty, f_hello})) ==
              "ae395b1592efa07192377a24fc187eba186da891a39c12d3dfae9df84f0c9a93",
          "root of 4 files");
    check(hex_of(root_of({f_a, f_abc, f_empty, f_hello, f_a})) ==
              "685686ca622026c4537dfdb49e8f9dac110c553f1d21aee96633e12fa47a7c47",
          "root of 5 files (odd promotion across levels)");

    // 七文件树：跨层多次奇数提升。
    const std::array<std::vector<unsigned char>, 7> seven_data = {
        empty, a, bytes_of("bb"), bytes_of("ccc"), bytes_of("dddd"),
        bytes_of("eeeee"), bytes_of("ffffff")};
    std::array<fs::path, 7> seven;
    for (std::size_t i = 0; i < seven.size(); ++i) {
        seven[i] = tmp.root / ("seven" + std::to_string(i) + ".bin");
        write_file(seven[i], seven_data[i]);
    }
    check(hex_of(root_of({seven.begin(), seven.end()})) ==
              "80bea6847da15bd2a145bbce5c01fb61672c4ad0f91da2e282075758d2610de2",
          "root of 7 files (independent multi-level value)");

    // 根只反映各位置内容：相同有序内容放在不同路径（含空格/中文目录），
    // 根相同。
    const fs::path alt_dir = tmp.root / "子 目录" / "另一批";
    std::array<fs::path, 3> alt;
    alt[0] = alt_dir / "空.bin";
    alt[1] = alt_dir / "a file.dat";
    alt[2] = tmp.root / "深 路径" / "文 件.bin";
    write_file(alt[0], empty);
    write_file(alt[1], a);
    write_file(alt[2], abc);
    const Digest r1 = root_of({f_empty, f_a, f_abc});
    const Digest r2 = root_of({alt[0], alt[1], alt[2]});
    check(r1 == r2, "root is path-independent: same ordered contents, other paths");
    // 顺序不同则根不同，确认不是按路径或摘要排序。
    check(root_of({alt[2], alt[1], alt[0]}) != r2,
          "different position order yields different root even with same files");
}

// ---- 相对路径按当前工作目录解释 -------------------------------------------

void test_relative_paths() {
    TempArea tmp("relative");
    write_file(tmp.root / "r1.bin", bytes_of("a"));
    write_file(tmp.root / "r2.bin", bytes_of("a"));

    const fs::path prev = fs::current_path();
    fs::current_path(tmp.root);
    const branchaudit::FileHashResult r =
        branchaudit::merkle_root_files({"r1.bin", "r2.bin"});
    fs::current_path(prev);

    check(r.ok(), "relative paths resolved from current working directory");
    check(hex_of(r.digest) ==
              "8025de747bafe2560d6b991bdb17ca89efe1b6fedda1be209c0ee015338861ea",
          "relative-path batch root matches independent value");
}

// ---- 失败：缺失、目录、任一失败即整次失败 ---------------------------------

void test_failures() {
    TempArea tmp("fail");
    const fs::path good1 = tmp.root / "good1.bin";
    const fs::path good2 = tmp.root / "good2.bin";
    write_file(good1, bytes_of("a"));
    write_file(good2, bytes_of("abc"));

    const fs::path missing = tmp.root / "does not exist 缺失.bin";
    auto names_path = [&](const branchaudit::FileHashResult& r) {
        return r.error.find(missing.string()) != std::string::npos;
    };

    branchaudit::FileHashResult r = branchaudit::merkle_root_files({missing});
    check(!r.ok(), "only missing file: batch fails");
    check(names_path(r), "missing file: error names the failed path");
    check(r.error.size() > missing.string().size() + 2,
          "missing file: error gives a reason beyond the path");

    // 缺失位于中间：报错指出该路径，而非用其余文件算出结果。
    r = branchaudit::merkle_root_files({good1, missing, good2});
    check(!r.ok(), "missing file in middle: whole batch fails");
    check(names_path(r), "middle failure names the middle path");

    // 缺失位于最前。
    r = branchaudit::merkle_root_files({missing, good1});
    check(!r.ok() && names_path(r), "missing file first: fails on that path");

    // 目录不是文件。
    const fs::path dir = tmp.root / "a dir 目录";
    fs::create_directories(dir);
    r = branchaudit::merkle_root_files({good1, dir, good2});
    check(!r.ok(), "directory among files: batch fails");
    check(r.error.find(dir.string()) != std::string::npos,
          "directory: error names the failed path");
    check(r.error.find("directory") != std::string::npos,
          "directory: error states directory reason");
}

// ---- 故障：存在却无法打开 / 部分读取后读出错 -------------------------------
//
// 这两种错误都必须从真实文件访问传导到最终批次结果；已处理文件与出错文件
// 的部分内容都不能成为任何根。这里用测试自身安排的故障节点稳定触发，
// 不依赖偶发磁盘故障。
void test_file_access_faults() {
    if (!fault_fixture::supported()) {
        std::cerr << "SKIP: open/read fault injection unsupported on this platform\n";
        return;
    }

    TempArea tmp("fault");
    const fs::path good1 = tmp.root / "good1.bin";
    const fs::path good2 = tmp.root / "good2.bin";
    write_file(good1, bytes_of("a"));
    write_file(good2, bytes_of("abc"));

    // 对照：空普通文件读到零字节是正常 EOF，仍然成功——不能把“没读到
    // 内容”一概当作读错误。
    const fs::path empty_regular = tmp.root / "empty-regular.bin";
    write_file(empty_regular, {});
    {
        branchaudit::FileHashResult r;
        auto captured = silent_root({empty_regular}, &r);
        check(r.ok() && hex_of(r.digest) ==
                  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
              "empty regular file read to EOF is still a success");
        check(captured.first.empty() && captured.second.empty(),
              "empty regular file: library does not print");
    }

    // 故障一：叶子路径是真实存在却无法打开的套接字。
    {
        fault_fixture::UnopenableSocket sock(tmp.root, "leaf-unopenable.sock");
        check(sock.ready, "unopenable leaf: fixture node exists as a socket");
        if (sock.ready) {
            // 单独作为一个叶子。
            {
                branchaudit::FileHashResult r;
                auto captured = silent_root({sock.path}, &r);
                check(!r.ok(), "unopenable leaf: batch fails");
                check(r.error.find(sock.path.string()) != std::string::npos,
                      "unopenable leaf: error names the failed path");
                check(r.error.find("read error") == std::string::npos,
                      "unopenable leaf: failure is at open, not read");
                check(captured.first.empty() && captured.second.empty(),
                      "unopenable leaf: library does not print");
            }
            // 有序批次：前面的正常文件已处理，仍须整次失败，错误指向套接字；
            // 库只以 !ok 表达失败（调用方仅在 ok 时才应使用 digest），因此
            // “不产出已处理文件的根 / 跳过出错位置后的根”在这里即由 !ok 保证；
            // 对外的 stdout 契约在 CLI 层另外精确断言。
            {
                branchaudit::FileHashResult r;
                auto captured = silent_root({good1, sock.path, good2}, &r);
                check(!r.ok(), "unopenable leaf after a good file: whole batch fails");
                check(r.error.find(sock.path.string()) != std::string::npos,
                      "unopenable leaf mid-batch: error points at the real file");
                check(captured.first.empty() && captured.second.empty(),
                      "unopenable leaf mid-batch: library does not print");
            }
        }
    }

    // 故障二：叶子已打开并读到真实内容，随后 read 出错（EIO）。
    // 每个读取场景使用独立的伪终端：故障节点在一次挂断后即失效。

    // 场景 A：单叶子。确认已读内容不会被当作正常 EOF 而成功。
    {
        fault_fixture::PartiallyReadablePty pty;
        branchaudit::FileHashResult single;
        std::pair<std::string, std::string> cap_single;
        pty.start_then_fail_after_real_bytes(
            [&](const std::string& p) {
                cap_single = silent_root({fs::path(p)}, &single);
            });

        check(pty.ready(), "read-fault leaf: fixture opens a pty");
        check(pty.forced_consumed(),
              "read-fault leaf premise: kernel proved bytes were read");
        check(pty.delivered_bytes() > fault_fixture::kForcedBytes,
              "read-fault leaf premise: substantial content was read first");
        check(!single.ok(), "read-failing leaf: batch fails");
        check(single.error.find(pty.path()) != std::string::npos,
              "read-failing leaf: error names the failed path");
        check(single.error.find("read error") != std::string::npos,
              "read-failing leaf: error is a read failure");
        // forced_consumed 保证读取方真的消费了确定数量的字节；在此前提下仍
        // !ok，即“已读到的真实内容没有成为成功叶子”。若仅构造一个带错误
        // 文字的结果而不真正读文件，非阻塞写始终 EAGAIN、forced 不足，前提
        // 为假，无法蒙混。“不产出部分根”的对外保证在 CLI 层以 stdout 为空
        // 精确断言。
        check(cap_single.first.empty() && cap_single.second.empty(),
              "read-failing leaf: library does not print");
    }

    // 场景 B：有序批次 [正常文件, 读出错文件]。第一个位置的正常文件已先
    // 处理完，随后第二个叶子读到真实内容后读出错；整次仍须失败，错误指向
    // 真正出错的文件（不是笼统的“无法计算”）。
    {
        fault_fixture::PartiallyReadablePty pty;
        branchaudit::FileHashResult batched;
        std::pair<std::string, std::string> cap_batch;
        pty.start_then_fail_after_real_bytes(
            [&](const std::string& p) {
                cap_batch = silent_root({good1, fs::path(p)}, &batched);
            });

        check(pty.ready(), "read-fault mid-batch: fixture opens a pty");
        check(pty.forced_consumed(),
              "read-fault mid-batch premise: kernel proved bytes were read");
        check(pty.delivered_bytes() > fault_fixture::kForcedBytes,
              "read-fault mid-batch premise: substantial content was read first");
        check(!batched.ok(),
              "read failure after good file: whole ordered batch fails");
        check(batched.error.find(pty.path()) != std::string::npos,
              "read failure mid-batch: error points at the real failing file");
        check(batched.error.find("read error") != std::string::npos,
              "read failure mid-batch: error states a read failure");
        // 在 forced_consumed 已证明故障叶子读到真实字节、且其前的正常文件已按
        // 顺序处理之后，结果仍必须 !ok：不产出“已处理文件的根 / 跳过出错位置
        // 的根 / 部分内容根”。对外层面由 CLI 测试以 stdout 为空精确断言。
        check(cap_batch.first.empty() && cap_batch.second.empty(),
              "read failure mid-batch: library does not print");
    }
}

// ---- 大文件：流式读取、尾部敏感 -------------------------------------------

void test_large_files() {
    TempArea tmp("large");
    const std::vector<unsigned char> big = fill_a(200000);
    const std::vector<unsigned char> pat = pattern(200000);
    const fs::path f_big = tmp.root / "a200000.bin";
    const fs::path f_pat = tmp.root / "pattern200000.bin";
    write_file(f_big, big);
    write_file(f_pat, pat);

    check(hex_of(root_of({f_big})) ==
              "0ce74c178a2d90235341a8a2e17539e34aad75dfead1f361b5bec500c1eff93e",
          "single large file leaf (streaming)");
    check(hex_of(root_of({f_big, f_pat})) ==
              "a801ef6c29a4ee3e4e2bc339c7437fe24a2bc10b86571825062a80f6a374daa0",
          "root [big, pattern]");
    check(hex_of(root_of({f_pat, f_big})) ==
              "892596758489f559ec8778ed1d271cd52b18a340926ef47cd16481a432bf2494",
          "root [pattern, big] differs under reversal");

    // 仅最后一个字节不同：叶子必须随之改变（流式尾部不遗漏）。
    std::vector<unsigned char> tail = big;
    tail.back() = static_cast<unsigned char>('b');
    const fs::path f_tail = tmp.root / "a200000tail.bin";
    write_file(f_tail, tail);
    check(hex_of(root_of({f_tail})) ==
              "e705589769e167619ac6a979e5e06f245ff1ff34a65f34e261b728abc4698a75",
          "large file: changing last byte changes leaf/root");
    check(root_of({f_tail}) != root_of({f_big}),
          "large file: tail change is detected");
}

}  // namespace

int main() {
    test_empty_batch();
    test_leaf_rule();
    test_parent_rule();
    test_file_batches();
    test_relative_paths();
    test_failures();
    test_file_access_faults();
    test_large_files();

    if (g_failures == 0) {
        std::cout << "all " << g_checks << " merkle regression checks passed\n";
        return 0;
    }
    std::cerr << g_failures << " of " << g_checks << " checks failed\n";
    return 1;
}
