// branchaudit 有序文件批次 Merkle 根与单文件成员证明回归测试
//（无第三方依赖，链接 branchaudit_core）。
//
// 预期摘要的独立依据：全部常量由 Python hashlib（底层系统 OpenSSL 的
// SHA-256）按公开字节规则（叶子 SHA-256(0x00||data)、父节点
// SHA-256(0x01||left||right)、奇数末节点原样提升、空批次为 SHA-256("")）
// 独立计算，不使用本项目代码生成期望值。
//
// 运行成功返回 0；任一断言失败返回非零。

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "filehash.h"
#include "merkle.h"
#include "test_fault.h"

namespace {

int g_failures = 0;
int g_checks = 0;
int g_skipped = 0;

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

// 调用库接口期间截获标准输出/错误：库只返回结果，不自行打印、不退出。
std::pair<std::string, std::string> silent_merkle(
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

// ---- 失败：文件存在却打不开 / 叶子读到一半出错 ----------------------------
//
// 与“缺失/目录”不同，这两类错误发生在文件真实存在、且读取已经（部分）
// 开始之后。经随测试预载的故障注入库在 libc 打开/读取接口确定性触发，
// 覆盖普通摘要与文件叶子共用的同一条文件计算路径。

void test_io_failures() {
    TempArea tmp("iofail");

    const fs::path good1 = tmp.root / "good1.bin";
    const fs::path good2 = tmp.root / "good2.bin";
    const fs::path bad = tmp.root / "present 出错.bin";
    const fs::path empty = tmp.root / "empty 空.bin";
    constexpr long kPartial = 40;
    const auto good_bytes1 = bytes_of("normal-file-one");
    const auto good_bytes2 = bytes_of("normal-file-two");
    const auto bad_bytes = pattern(200);
    write_file(good1, good_bytes1);
    write_file(good2, good_bytes2);
    write_file(bad, bad_bytes);
    write_file(empty, {});

    const Digest good_leaf1 = leaf_bytes(good_bytes1);
    const Digest good_leaf2 = leaf_bytes(good_bytes2);
    const Digest bad_partial_leaf =
        branchaudit::merkle_leaf(bad_bytes.data(),
                                 static_cast<std::size_t>(kPartial));

    // 夹具在无注入时必须成功，排除“写死错误结果”的可能。
    check(hex_of(root_of({good1, bad, good2})).size() == 64,
          "iofail fixtures: batch succeeds without injected fault");

    // ---- 打开失败：唯一位置 --------------------------------------------
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_OPEN_FAIL", bad.string());
        branchaudit::FileHashResult r;
        auto captured = silent_merkle({bad}, &r);
        check(!r.ok(), "unopenable leaf: batch fails");
        check(r.error.find(bad.string()) != std::string::npos,
              "unopenable leaf: error names the failed file");
        check(r.error.find("ermission") != std::string::npos ||
                  r.error.find("denied") != std::string::npos ||
                  r.error.find("cces") != std::string::npos,
              "unopenable leaf: error states open/permission reason");
        check(captured.first.empty() && captured.second.empty(),
              "unopenable leaf: library prints nothing, does not exit");
    }

    // ---- 打开失败：有序批次中出错前已经处理过正常文件 ------------------
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_OPEN_FAIL", bad.string());
        branchaudit::FileHashResult r;
        auto captured = silent_merkle({good1, good2, bad}, &r);
        check(!r.ok(),
              "open failure after processed good files: whole batch fails");
        check(r.error.find(bad.string()) != std::string::npos,
              "open failure in batch: error points at the real failing file");
        check(r.error.find(good1.string()) == std::string::npos &&
                  r.error.find(good2.string()) == std::string::npos,
              "open failure in batch: already-processed files are not blamed");
        check(captured.first.empty(),
              "open failure in batch: no root of the processed prefix is printed");
        check(captured.second.empty(),
              "open failure in batch: library prints nothing");
        // 不得给出“仅前两个正常文件”的根。
        check(r.digest != branchaudit::merkle_parent(good_leaf1, good_leaf2),
              "open failure: root skipping the failing position is not returned");
        check(r.digest != good_leaf1,
              "open failure: a processed leaf is not returned as the root");
    }

    // ---- 读取失败：叶子取得部分内容后继续读出错 ------------------------
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_READ_FAIL",
            bad.string() + ":" + std::to_string(kPartial));
        branchaudit::FileHashResult r;
        auto captured = silent_merkle({bad}, &r);
        check(!r.ok(), "read error mid-leaf: batch fails");
        check(r.error.find(bad.string()) != std::string::npos,
              "read failure: error names the failed file");
        check(r.error.find("read") != std::string::npos,
              "read failure: error says read failed rather than normal EOF");
        check(captured.first.empty() && captured.second.empty(),
              "read failure: library prints nothing");
        // 已读到的部分内容不能成为成功叶子摘要。
        check(r.digest != bad_partial_leaf,
              "read failure: partial leaf digest is not returned as success");
        check(r.digest != leaf_bytes(bad_bytes),
              "read failure: full-content leaf is not fabricated either");
    }

    // ---- 读取失败：出错前正常文件已处理，仍整次失败且指向真正出错文件 --
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_READ_FAIL",
            bad.string() + ":" + std::to_string(kPartial));
        branchaudit::FileHashResult r;
        auto captured = silent_merkle({good1, bad, good2}, &r);
        check(!r.ok(),
              "read error after a good file: whole ordered batch fails");
        check(r.error.find(bad.string()) != std::string::npos,
              "batch read failure: error names the truly failing file");
        check(r.error.find(good1.string()) == std::string::npos &&
                  r.error.find(good2.string()) == std::string::npos,
              "batch read failure: good files are not named as the cause");
        check(captured.first.empty(),
              "batch read failure: no partial/skipped-position root is emitted");
        check(captured.second.empty(),
              "batch read failure: library prints nothing");
        check(r.digest != good_leaf1,
              "batch read failure: processed-prefix leaf is not a result");
    }

    // ---- 空文件叶子在读取故障武装下仍正常读完 --------------------------
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_READ_FAIL",
            empty.string() + ":" + std::to_string(kPartial));
        branchaudit::FileHashResult r;
        auto captured = silent_merkle({empty}, &r);
        check(r.ok(),
              "empty file leaf reads to completion successfully (no content != error)");
        check(hex_of(r.digest) ==
                  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
              "empty file leaf remains SHA-256(0x00)");
        check(captured.first.empty() && captured.second.empty(),
              "empty file leaf: library prints nothing");
    }

    // ---- 故障只作用于指定路径：批次中其他文件不受影响 ------------------
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_READ_FAIL",
            bad.string() + ":" + std::to_string(kPartial));
        branchaudit::FileHashResult r;
        silent_merkle({good1, good2}, &r);
        check(r.ok() && r.digest == branchaudit::merkle_parent(good_leaf1, good_leaf2),
              "fault is path-scoped: batch without the named path is unaffected");
    }
}

// ---- 成员证明：结构、兄弟侧向、奇数提升、失败 ------------------------------

// 用证明中的兄弟从叶子向根折叠，应回到证明给出的根。
Digest fold_proof(const branchaudit::MerkleProof& p) {
    Digest d = p.leaf;
    for (const branchaudit::MerkleSibling& s : p.siblings) {
        d = (s.side == branchaudit::MerkleSibling::Side::left)
                ? branchaudit::merkle_parent(s.digest, d)
                : branchaudit::merkle_parent(d, s.digest);
    }
    return d;
}

void test_proofs() {
    TempArea tmp("proofs");

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

    const Digest la = leaf_bytes(a);
    const Digest labc = leaf_bytes(abc);
    const Digest lempty = leaf_bytes(empty);

    // 单文件批次：siblings 为空，root 等于 leaf。
    {
        const branchaudit::MerkleProofResult r =
            branchaudit::merkle_proof_file({f_a}, 0);
        check(r.ok(), "proof single file: succeeds");
        check(r.proof.leaf_count == 1 && r.proof.leaf_index == 0,
              "proof single file: count/index");
        check(r.proof.siblings.empty(), "proof single file: no siblings");
        check(r.proof.root == r.proof.leaf && r.proof.leaf == la,
              "proof single file: root equals leaf");
    }
    // 单个空文件同样如此。
    {
        const branchaudit::MerkleProofResult r =
            branchaudit::merkle_proof_file({f_empty}, 0);
        check(r.ok() && r.proof.siblings.empty() &&
                  r.proof.root == r.proof.leaf && r.proof.leaf == lempty,
              "proof single empty file: root equals leaf SHA-256(0x00)");
    }

    // 两文件：兄弟侧向正确。
    {
        const branchaudit::MerkleProofResult r0 =
            branchaudit::merkle_proof_file({f_a, f_abc}, 0);
        check(r0.ok() && r0.proof.siblings.size() == 1,
              "proof [a, abc] index 0: one sibling");
        check(r0.proof.siblings[0].side == branchaudit::MerkleSibling::Side::right &&
                  r0.proof.siblings[0].digest == labc,
              "proof [a, abc] index 0: sibling on the right");
        check(r0.proof.root == branchaudit::merkle_parent(la, labc),
              "proof [a, abc] index 0: root matches pairing");
        const branchaudit::MerkleProofResult r1 =
            branchaudit::merkle_proof_file({f_a, f_abc}, 1);
        check(r1.ok() && r1.proof.siblings.size() == 1 &&
                  r1.proof.siblings[0].side == branchaudit::MerkleSibling::Side::left &&
                  r1.proof.siblings[0].digest == la,
              "proof [a, abc] index 1: sibling on the left");
        check(r1.proof.root == r0.proof.root,
              "proof root is identical for every position of the batch");
    }

    // 三文件（奇数提升）：末位置的第一层没有兄弟记录。
    {
        const std::vector<fs::path> batch{f_a, f_abc, f_empty};
        const Digest p = branchaudit::merkle_parent(la, labc);
        const Digest expected_root = branchaudit::merkle_parent(p, lempty);
        check(root_of(batch) == expected_root, "proof fixture: 3-file root");

        const branchaudit::MerkleProofResult r2 =
            branchaudit::merkle_proof_file(batch, 2);
        check(r2.ok() && r2.proof.leaf_count == 3 && r2.proof.leaf_index == 2,
              "proof [a, abc, empty] index 2: count/index");
        check(r2.proof.leaf == lempty, "proof index 2: leaf is SHA-256(0x00)");
        // 奇数末节点原样提升的层不添加记录：只有上层一个左侧兄弟。
        check(r2.proof.siblings.size() == 1 &&
                  r2.proof.siblings[0].side == branchaudit::MerkleSibling::Side::left &&
                  r2.proof.siblings[0].digest == p,
              "proof index 2: promoted level records no sibling");
        check(r2.proof.root == expected_root &&
                  fold_proof(r2.proof) == expected_root,
              "proof index 2: siblings fold back to the root");

        const branchaudit::MerkleProofResult r0 =
            branchaudit::merkle_proof_file(batch, 0);
        check(r0.ok() && r0.proof.siblings.size() == 2 &&
                  r0.proof.siblings[0].side == branchaudit::MerkleSibling::Side::right &&
                  r0.proof.siblings[0].digest == labc &&
                  r0.proof.siblings[1].side == branchaudit::MerkleSibling::Side::right &&
                  r0.proof.siblings[1].digest == lempty,
              "proof index 0: siblings ordered from leaf to root");
        check(fold_proof(r0.proof) == r0.proof.root &&
                  r0.proof.root == expected_root,
              "proof index 0: folds to the same root");
    }

    // 五文件（跨层奇数提升）：每个位置的证明都折回同一根，且根与
    // merkle_root_files 一致；中间被提升的层不记录兄弟。
    {
        const std::vector<fs::path> batch{f_a, f_abc, f_empty, f_hello, f_a};
        const Digest root = root_of(batch);
        check(hex_of(root) ==
                  "685686ca622026c4537dfdb49e8f9dac110c553f1d21aee96633e12fa47a7c47",
              "proof fixture: 5-file root matches independent value");
        // 各层节点数 5 -> 3 -> 2 -> 1：位置 4 连续两次原样提升，
        // 只在最后一层记录一个左侧兄弟。
        const std::size_t expected_siblings[5] = {3, 3, 3, 3, 1};
        for (std::uint64_t i = 0; i < 5; ++i) {
            const branchaudit::MerkleProofResult r =
                branchaudit::merkle_proof_file(batch, i);
            check(r.ok(), "proof 5-file index " + std::to_string(i) + ": ok");
            check(r.proof.leaf_count == 5 && r.proof.leaf_index == i,
                  "proof 5-file: count/index echoed");
            check(r.proof.root == root,
                  "proof 5-file: root equals merkle_root_files result");
            check(r.proof.siblings.size() == expected_siblings[i],
                  "proof 5-file index " + std::to_string(i) +
                      ": sibling count matches tree shape");
            check(fold_proof(r.proof) == r.proof.root,
                  "proof 5-file index " + std::to_string(i) +
                      ": siblings fold back to root");
        }
        // 位置 4 的唯一兄弟是左侧的 parent(parent(La,Labc), parent(Lempty,Lhello))。
        const branchaudit::MerkleProofResult r4 =
            branchaudit::merkle_proof_file(batch, 4);
        const Digest left_subtree = branchaudit::merkle_parent(
            branchaudit::merkle_parent(la, labc),
            branchaudit::merkle_parent(lempty, leaf_bytes(hello)));
        check(r4.proof.siblings.size() == 1 &&
                  r4.proof.siblings[0].side == branchaudit::MerkleSibling::Side::left &&
                  r4.proof.siblings[0].digest == left_subtree,
              "proof index 4: promoted twice, single left sibling at the top");
    }

    // 重复路径与相同内容各占独立位置，证明按位置区分。
    {
        const std::vector<fs::path> batch{f_a, f_a};
        const branchaudit::MerkleProofResult r0 =
            branchaudit::merkle_proof_file(batch, 0);
        const branchaudit::MerkleProofResult r1 =
            branchaudit::merkle_proof_file(batch, 1);
        check(r0.ok() && r1.ok() && r0.proof.root == r1.proof.root &&
                  r0.proof.leaf == r1.proof.leaf &&
                  r0.proof.siblings[0].side == branchaudit::MerkleSibling::Side::right &&
                  r1.proof.siblings[0].side == branchaudit::MerkleSibling::Side::left,
              "proof repeated path: two positions, mirrored sibling sides");
        check(r0.proof.root == root_of(batch),
              "proof repeated path: root matches root command semantics");
    }

    // 库接口失败：位置越界（含空批次）、文件失败；不打印、不退出。
    {
        branchaudit::MerkleProofResult r =
            branchaudit::merkle_proof_file({f_a}, 1);
        check(!r.ok(), "proof index out of range: fails");
        r = branchaudit::merkle_proof_file({}, 0);
        check(!r.ok(), "proof empty batch: no valid position");
        const fs::path missing = tmp.root / "missing 缺失.bin";
        std::stringstream cap_out, cap_err;
        auto* old_out = std::cout.rdbuf(cap_out.rdbuf());
        auto* old_err = std::cerr.rdbuf(cap_err.rdbuf());
        r = branchaudit::merkle_proof_file({f_a, missing, f_abc}, 0);
        std::cout.rdbuf(old_out);
        std::cerr.rdbuf(old_err);
        check(!r.ok(), "proof with a failing file: whole operation fails");
        check(r.error.find(missing.string()) != std::string::npos,
              "proof file failure: error names the failed path");
        check(cap_out.str().empty() && cap_err.str().empty(),
              "proof library: prints nothing, does not exit");
    }
}

// ---- 成员证明校验：三项输入、结构约束、信任锚 ------------------------------

using branchaudit::MerkleProof;
using branchaudit::MerkleProofResult;
using branchaudit::MerkleSibling;
using branchaudit::MerkleVerifyResult;

// 直接调用校验：真实批次由 merkle_proof_file 产出，可信根由独立入口
// merkle_root_files 取得（绝不拿 proof.root 当信任锚喂回去）。
MerkleVerifyResult verify_real(const std::vector<fs::path>& batch,
                               std::uint64_t index, const Digest& content_leaf,
                               const Digest* trusted_override = nullptr) {
    const MerkleProofResult pr = branchaudit::merkle_proof_file(batch, index);
    check(pr.ok(), std::string("fixture proof succeeds: ") + pr.error);
    const Digest trusted = trusted_override
                               ? *trusted_override
                               : root_of(batch);
    return branchaudit::merkle_verify_proof(pr.proof, trusted, content_leaf);
}

void test_verify_success() {
    TempArea tmp("verify_ok");
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

    // 单文件：位置 0、空兄弟列表；内容叶子必须是带 0x00 前缀的叶子。
    {
        const MerkleVerifyResult v = verify_real({f_a}, 0, leaf_bytes(a));
        check(v.ok(), "verify single file: passes with the 0x00-prefixed leaf");
        check(v.valid && v.error.empty(),
              "verify success: valid is true and error is empty");
    }
    // 单个空文件：叶子 SHA-256(0x00)，与空批次根不同，仍正常通过。
    {
        const MerkleVerifyResult v =
            verify_real({f_empty}, 0, leaf_bytes(empty));
        check(v.ok(), "verify single empty file: passes with SHA-256(0x00)");
        check(branchaudit::merkle_verify_proof(
                  branchaudit::merkle_proof_file({f_empty}, 0).proof,
                  branchaudit::merkle_empty_root(), leaf_bytes(empty)).ok() ==
                      false,
              "verify: single empty-file proof fails against the empty batch "
              "root");
    }

    // 两文件：两个位置互为镜像兄弟，各自通过。
    {
        check(verify_real({f_a, f_abc}, 0, leaf_bytes(a)).ok(),
              "verify two files: index 0 passes");
        check(verify_real({f_a, f_abc}, 1, leaf_bytes(abc)).ok(),
              "verify two files: index 1 passes");
    }

    // 三文件（奇数末节点提升，末位置缺第一层兄弟记录）必须正常通过。
    {
        const std::vector<fs::path> batch{f_a, f_abc, f_empty};
        check(verify_real(batch, 2, leaf_bytes(empty)).ok(),
              "verify 3 files index 2: proof with a promoted level omitted "
              "passes without padding records");
        check(verify_real(batch, 0, leaf_bytes(a)).ok(),
              "verify 3 files index 0: passes");
    }

    // 五文件（5->3->2->1，位置 4 连续两次提升）与七文件（多次奇数提升）
    // 的每个位置都通过——生成端省略的提升层不要求补齐。
    {
        const std::vector<fs::path> batch{f_a, f_abc, f_empty, f_hello, f_a};
        const std::vector<std::vector<unsigned char>> five_data{
            a, abc, empty, hello, a};
        for (std::uint64_t i = 0; i < 5; ++i) {
            check(verify_real(batch, i, leaf_bytes(five_data[i])).ok(),
                  "verify 5-file index " + std::to_string(i) + " passes");
        }
    }
    {
        const std::array<std::vector<unsigned char>, 7> data = {
            empty, a, bytes_of("bb"), bytes_of("ccc"), bytes_of("dddd"),
            bytes_of("eeeee"), bytes_of("ffffff")};
        std::array<fs::path, 7> seven;
        for (std::size_t i = 0; i < seven.size(); ++i) {
            seven[i] = tmp.root / ("seven" + std::to_string(i) + ".bin");
            write_file(seven[i], data[i]);
        }
        for (std::uint64_t i = 0; i < 7; ++i) {
            check(verify_real({seven.begin(), seven.end()}, i,
                              leaf_bytes(data[static_cast<std::size_t>(i)])).ok(),
                  "verify 7-file index " + std::to_string(i) + " passes");
        }
    }

    // 重复内容各占独立位置：按位置结构核对，不按摘要去重。
    {
        const std::vector<fs::path> batch{f_a, f_a};
        check(verify_real(batch, 0, leaf_bytes(a)).ok(),
              "verify repeated content index 0 passes");
        check(verify_real(batch, 1, leaf_bytes(a)).ok(),
              "verify repeated content index 1 passes");
    }

    // 成功路径同样不打印、不退出。
    {
        const MerkleProofResult pr =
            branchaudit::merkle_proof_file({f_a, f_abc}, 0);
        const Digest trusted = root_of({f_a, f_abc});
        std::stringstream cap_out, cap_err;
        auto* old_out = std::cout.rdbuf(cap_out.rdbuf());
        auto* old_err = std::cerr.rdbuf(cap_err.rdbuf());
        const MerkleVerifyResult v =
            branchaudit::merkle_verify_proof(pr.proof, trusted, leaf_bytes(a));
        std::cout.rdbuf(old_out);
        std::cerr.rdbuf(old_err);
        check(v.ok(), "verify silent fixture passes");
        check(cap_out.str().empty() && cap_err.str().empty(),
              "verify library: prints nothing on success");
    }
}

void test_verify_failures() {
    TempArea tmp("verify_bad");
    const auto a = bytes_of("a");
    const auto abc = bytes_of("abc");
    const auto empty = bytes_of("");
    const fs::path f_a = tmp.root / "a.bin";
    const fs::path f_abc = tmp.root / "abc.bin";
    const fs::path f_empty = tmp.root / "empty.bin";
    write_file(f_a, a);
    write_file(f_abc, abc);
    write_file(f_empty, empty);

    const std::vector<fs::path> batch{f_a, f_abc, f_empty};
    const Digest trusted = root_of(batch);
    const Digest other_root = root_of({f_a, f_abc});

    auto reject = [&](const MerkleProof& p, const Digest& root,
                      const Digest& leaf, std::string_view what) {
        const MerkleVerifyResult v =
            branchaudit::merkle_verify_proof(p, root, leaf);
        check(!v.ok() && !v.valid && !v.error.empty(), what);
    };

    // 条件 1：内容叶子与证明叶子不符。
    {
        const MerkleProof p =
            branchaudit::merkle_proof_file(batch, 0).proof;
        reject(p, trusted, leaf_bytes(abc),
               "wrong content leaf (different file content) is rejected");
        // 普通文件摘要（无 0x00 前缀）不能替代叶子摘要。
        branchaudit::Sha256 plain;
        plain.update(reinterpret_cast<const unsigned char*>(a.data()),
                     a.size());
        reject(p, trusted, plain.final(),
               "plain hash digest without the 0x00 leaf prefix is rejected");
    }

    // 条件 2：证明自报的根与可信根不符——即使证明内部自洽，换另一批次的
    // 可信根也必须失败，不能拿 proof.root 充当信任依据。
    {
        const MerkleProof p =
            branchaudit::merkle_proof_file(batch, 0).proof;
        reject(p, other_root, leaf_bytes(a),
               "internally consistent proof fails against another batch's "
               "trusted root");
        Digest fake_trusted = trusted;
        fake_trusted[0] ^= 0x01;
        reject(p, fake_trusted, leaf_bytes(a),
               "proof fails when the trusted root differs by one bit");
    }

    // 结构：空批次没有成员。
    {
        MerkleProof p;
        p.leaf_count = 0;
        p.leaf_index = 0;
        p.leaf = leaf_bytes(a);
        p.root = trusted;
        reject(p, trusted, leaf_bytes(a),
               "leaf_count 0 (empty batch) has no members");
    }

    // 结构：位置越界。
    {
        MerkleProof p =
            branchaudit::merkle_proof_file(batch, 0).proof;
        p.leaf_index = 3;
        reject(p, trusted, leaf_bytes(a),
               "leaf_index equal to leaf_count is rejected");
        p.leaf_index = 100;
        reject(p, trusted, leaf_bytes(a),
               "leaf_index beyond leaf_count is rejected");
        p = branchaudit::merkle_proof_file({f_a}, 0).proof;
        p.leaf_index = 1;
        reject(p, root_of({f_a}), leaf_bytes(a),
               "single-file batch rejects index other than 0");
    }

    // 结构：单文件批次带多余兄弟、空兄弟却是多文件计数。
    {
        MerkleProof p =
            branchaudit::merkle_proof_file({f_a}, 0).proof;
        p.siblings.push_back({MerkleSibling::Side::left, leaf_bytes(abc)});
        reject(p, root_of({f_a}), leaf_bytes(a),
               "single-file batch accepts only an empty sibling list");
    }

    // 结构：兄弟方向错误（即使换成“折叠能得到某个摘要”的内容也不行）。
    {
        MerkleProof p =
            branchaudit::merkle_proof_file(batch, 0).proof;
        // 位置 0 第一层要求 right 兄弟：翻成 left 必须失败。
        p.siblings[0].side = MerkleSibling::Side::left;
        reject(p, trusted, leaf_bytes(a),
               "wrong sibling side is rejected regardless of digest values");
    }

    // 结构：缺少一个必要兄弟。
    {
        MerkleProof p =
            branchaudit::merkle_proof_file(batch, 0).proof;
        p.siblings.pop_back();
        reject(p, trusted, leaf_bytes(a),
               "a missing required sibling is rejected");
    }

    // 结构：多出一个兄弟。
    {
        MerkleProof p =
            branchaudit::merkle_proof_file(batch, 0).proof;
        p.siblings.push_back({MerkleSibling::Side::left, leaf_bytes(empty)});
        reject(p, trusted, leaf_bytes(a),
               "an extra sibling beyond the root is rejected");
    }

    // 结构：兄弟从叶子向根的次序被调换（两者侧向恰好与另一层相同，
    // 数量不变、每一项单独看都是 left/right，仍必须失败）。
    {
        MerkleProof p =
            branchaudit::merkle_proof_file(batch, 0).proof;
        // 位置 0、三文件：两层都要求 right，交换两项只错次序。
        check(p.siblings.size() == 2 &&
                      p.siblings[0].side == MerkleSibling::Side::right &&
                      p.siblings[1].side == MerkleSibling::Side::right,
              "fixture: 3-file index 0 has two right-side siblings");
        std::swap(p.siblings[0], p.siblings[1]);
        reject(p, trusted, leaf_bytes(a),
               "siblings in the wrong leaf-to-root order are rejected");
    }

    // 结构：兄弟摘要被篡改——方向/数量/次序都对，但折叠不到可信根。
    {
        MerkleProof p =
            branchaudit::merkle_proof_file(batch, 0).proof;
        p.siblings[0].digest = leaf_bytes(bytes_of("totally different"));
        reject(p, trusted, leaf_bytes(a),
               "tampered sibling digest fails the fold into the root");
    }

    // 条件 3 的独立攻击：把 proof.root 改成可信根，叶子与根字段都对，
    // 但兄弟链属于另一结构——折叠结果不等于可信根。
    {
        MerkleProof p =
            branchaudit::merkle_proof_file(batch, 0).proof;
        p.siblings.clear();
        // 声称 3 个叶子却不给兄弟，同时 root 伪装成可信根。
        p.root = trusted;
        reject(p, trusted, leaf_bytes(a),
               "missing siblings with a forged root field are rejected");
    }

    // 提升层不得要求补记录：删掉的若是“有兄弟的层”才失败；而把一个
    // 本应省略的提升层补一条记录，同样属于多出项，必须失败。
    {
        // 三文件、位置 2：第一层提升（无记录），第二层一个 left 兄弟。
        const MerkleProof real =
            branchaudit::merkle_proof_file(batch, 2).proof;
        check(real.siblings.size() == 1,
              "fixture: promoted index carries one sibling");
        MerkleProof padded = real;
        padded.siblings.insert(
            padded.siblings.begin(),
            MerkleSibling{MerkleSibling::Side::right, leaf_bytes(abc)});
        reject(padded, trusted, leaf_bytes(empty),
               "padding an omitted promotion level with a record is rejected");
    }

    // 非法 side 枚举值（调用方自行构造结构时可能出现）。
    {
        MerkleProof p =
            branchaudit::merkle_proof_file(batch, 0).proof;
        p.siblings[0].side = static_cast<MerkleSibling::Side>(99);
        reject(p, trusted, leaf_bytes(a),
               "an invalid sibling side value is rejected");
    }

    // 失败时同样不打印、不退出，并给出非空原因。
    {
        const MerkleProof p =
            branchaudit::merkle_proof_file(batch, 0).proof;
        std::stringstream cap_out, cap_err;
        auto* old_out = std::cout.rdbuf(cap_out.rdbuf());
        auto* old_err = std::cerr.rdbuf(cap_err.rdbuf());
        const MerkleVerifyResult v =
            branchaudit::merkle_verify_proof(p, other_root, leaf_bytes(a));
        std::cout.rdbuf(old_out);
        std::cerr.rdbuf(old_err);
        check(!v.ok() && !v.error.empty(),
              "cross-branch verify fails with a reason");
        check(cap_out.str().empty() && cap_err.str().empty(),
              "verify library: prints nothing on failure");
    }
}

// ---- 通过结论的边界：声明数字可被等价改写，内容与可信根仍被强制核对 --------
//
// 固定 README“通过结论的边界”一节公开的结论：三份不同内容按固定顺序组成
// 批次，为从 0 开始的位置 2 生成证明；可信根由对同一批次另行的一次根计算
// 取得（绝不拿 proof.root 回喂），内容叶子按现有单个 0x00 前缀规则计算。
// 仅把证明自报的 leaf_count/leaf_index 3/2 改成 2/1，根、叶子、兄弟摘要与
// 兄弟方向原样保留，校验仍必须通过——通过只说明内容受可信根支持、兄弟记录
// 与新的声明自洽，绝不认证这两个数字（不能据此断言原批次少了一个文件，或
// 第三个文件被认证为位置 1）。相邻的拒绝边界在此一并固定：声明位置与保留
// 兄弟方向冲突、可信根不符、内容叶子不符，都必须 valid 为假并给出非空原因。
void test_verify_claimed_numbers() {
    TempArea tmp("verify_claims");
    const auto jan = bytes_of("january");
    const auto feb = bytes_of("february");
    const auto mar = bytes_of("march");
    const fs::path f_jan = tmp.root / "report-jan.bin";
    const fs::path f_feb = tmp.root / "report-feb.bin";
    const fs::path f_mar = tmp.root / "report-mar.bin";
    write_file(f_jan, jan);
    write_file(f_feb, feb);
    write_file(f_mar, mar);

    const std::vector<fs::path> batch{f_jan, f_feb, f_mar};

    // 可信根独立于证明保存：对同一批次另行计算，而不是取 proof.root。
    const Digest trusted = root_of(batch);
    // 第三个文件（位置 2）按现有规则计算的内容叶子 SHA-256(0x00 || content)。
    const Digest mar_leaf = leaf_bytes(mar);

    const MerkleProofResult pr =
        branchaudit::merkle_proof_file(batch, /*leaf_index=*/2);
    check(pr.ok(), std::string("claimed-numbers fixture proof: ") + pr.error);
    const MerkleProof proof = pr.proof;

    // 夹具形状：位置 2 在三条目批次首层是奇数末节点，原样提升、不补兄弟
    // 记录；只在上层记录一个 left 兄弟，摘要为前两份内容叶子的父节点。
    check(proof.leaf_count == 3 && proof.leaf_index == 2,
          "claimed-numbers fixture: proof self-reports count 3, index 2");
    check(proof.leaf == mar_leaf,
          "claimed-numbers fixture: proof leaf is the third file's 0x00 leaf");
    check(proof.root == trusted,
          "claimed-numbers fixture: generated root equals the independently "
          "computed trusted root");
    check(proof.siblings.size() == 1 &&
                  proof.siblings[0].side == MerkleSibling::Side::left &&
                  proof.siblings[0].digest ==
                      branchaudit::merkle_parent(leaf_bytes(jan), leaf_bytes(feb)),
          "claimed-numbers fixture: odd last node promoted without a sibling; "
          "a single left sibling remains at the upper level");

    // 原证明在独立可信根与第三文件内容叶子下通过：valid 为真、error 为空。
    {
        const MerkleVerifyResult v =
            branchaudit::merkle_verify_proof(proof, trusted, mar_leaf);
        check(v.ok() && v.valid && v.error.empty(),
              "original proof (count=3, index=2) verifies: valid is true and "
              "error is empty");
    }

    // 只改证明自报的两个数字：leaf_count 3→2、leaf_index 2→1；根、叶子、
    // 兄弟摘要与兄弟方向全部保持原样。
    MerkleProof altered = proof;
    altered.leaf_count = 2;
    altered.leaf_index = 1;
    check(altered.root == proof.root && altered.leaf == proof.leaf &&
                  altered.siblings.size() == proof.siblings.size() &&
                  altered.siblings[0].side == proof.siblings[0].side &&
                  altered.siblings[0].digest == proof.siblings[0].digest,
          "altered proof differs from the original only in the two claimed "
          "numbers");

    // 位置 2 在三条目批次的首层被原样提升（无兄弟记录），其兄弟路径形状与
    // “两条目批次的位置 1”完全相同：同一份根、叶子与兄弟记录对两组声明都
    // 自洽。这种“声明数字改变、证明仍成立”的输入不能被误判为损坏。
    {
        const MerkleVerifyResult v =
            branchaudit::merkle_verify_proof(altered, trusted, mar_leaf);
        check(v.ok() && v.valid && v.error.empty(),
              "altered claims (count=2, index=1) still verify against the same "
              "trusted root and content leaf: valid is true, error is empty");
    }

    // 通过不认证这两个数字：随可信根独立保存的批次事实仍是 3 个条目、
    // 位置 2。真正要确认批次大小/位置的调用方必须另行比对证明自报数字，
    // 校验通过代替不了它——原证明的声明与独立事实相符，改写后的不符。
    const auto claims_match_independent_fact = [](const MerkleProof& p) {
        return p.leaf_count == 3 && p.leaf_index == 2;
    };
    check(claims_match_independent_fact(proof),
          "the genuine proof's claims match the independently stored batch "
          "fact (count 3, index 2)");
    check(!claims_match_independent_fact(altered),
          "the altered claims differ from the independent fact even though "
          "verify passes: success is not a certification of count or position");

    auto reject = [&](const MerkleProof& p, const Digest& root,
                      const Digest& leaf, std::string_view what) {
        const MerkleVerifyResult v =
            branchaudit::merkle_verify_proof(p, root, leaf);
        check(!v.ok() && !v.valid && !v.error.empty(), what);
    };

    // 拒绝边界 1：在改写后的证明上只把位置 1→0，其余输入不动。两条目批次
    // 的位置 0 在首层需要 right 兄弟，而保留下来的唯一兄弟是 left——声明
    // 位置与保留兄弟方向不符，必须失败。这守住位置结构检查，防止为了让
    // “等价改写”通过而放松方向核对。
    {
        MerkleProof wrong_pos = altered;
        wrong_pos.leaf_index = 0;
        reject(wrong_pos, trusted, mar_leaf,
               "altered proof with only the position changed to 0 is rejected: "
               "a 2-leaf position 0 requires a right sibling, conflicting with "
               "the retained left sibling");
    }

    // 拒绝边界 2：仍然自洽的改写证明换用不匹配的可信根也必须失败；声明
    // 数字的等价性不能绕过可信根核对。
    {
        // 顺序不同的另一份批次（内容相同、排列改变）产生另一个根。
        const Digest reordered_root = root_of({f_jan, f_mar, f_feb});
        check(reordered_root != trusted,
              "fixture: reordered batch yields a different root");
        reject(altered, reordered_root, mar_leaf,
               "altered proof fails against another batch's trusted root");
        Digest flipped = trusted;
        flipped[0] ^= 0x01;
        reject(altered, flipped, mar_leaf,
               "altered proof fails against a trusted root differing by one "
               "bit");
    }

    // 拒绝边界 3：同一份改写证明配另一份内容的叶子（同样带单个 0x00
    // 前缀）也必须失败；声明数字的等价性不能绕过内容核对。
    {
        reject(altered, trusted, leaf_bytes(jan),
               "altered proof fails with another content's 0x00-prefixed leaf");
        // 普通文件摘要（无 0x00 前缀）同样不能借等价改写混入。
        branchaudit::Sha256 plain;
        plain.update(reinterpret_cast<const unsigned char*>(mar.data()),
                     mar.size());
        reject(altered, trusted, plain.final(),
               "altered proof rejects a plain file digest without the 0x00 "
               "leaf prefix");
    }
}

// ---- 64 位计数边界：纯结构推导，不按 leaf_count 分配内存 --------------------

// 沿 (leaf_count, leaf_index) 计算生成端会记录的兄弟数与各层期望侧向，
// 用独立的一份循环模拟证明形状（不调用生成接口，也不需要真实文件）。
struct ShapeStep {
    MerkleSibling::Side side;
};
std::vector<ShapeStep> expected_shape(std::uint64_t leaf_count,
                                      std::uint64_t leaf_index) {
    std::vector<ShapeStep> steps;
    std::uint64_t n = leaf_count;
    std::uint64_t pos = leaf_index;
    while (n > 1) {
        const bool promoted = (pos % 2 == 0) && (pos == n - 1);
        if (!promoted) {
            steps.push_back({(pos % 2 == 0) ? MerkleSibling::Side::right
                                            : MerkleSibling::Side::left});
        }
        pos /= 2;
        n -= n / 2;
    }
    return steps;
}

void test_verify_uint64_limits() {
    // 沿 (leaf_count, leaf_index) 按形状构造一份结构自洽的证明：兄弟摘要
    // 全部取零，折叠结果与 root 字段、可信根保持一致，因此通过与否只取
    // 决于结构推导是否无回绕、必定终止（不依赖真实文件或巨大内存）。
    auto build_shaped_proof = [](std::uint64_t leaf_count,
                                 std::uint64_t leaf_index,
                                 const std::vector<ShapeStep>& shape) {
        MerkleProof p;
        p.leaf_count = leaf_count;
        p.leaf_index = leaf_index;
        Digest leaf{};
        leaf[31] = 0x7f;
        p.leaf = leaf;
        Digest node = leaf;
        for (const ShapeStep& st : shape) {
            const Digest sib{};
            if (st.side == MerkleSibling::Side::right) {
                p.siblings.push_back({MerkleSibling::Side::right, sib});
                node = branchaudit::merkle_parent(node, sib);
            } else {
                p.siblings.push_back({MerkleSibling::Side::left, sib});
                node = branchaudit::merkle_parent(sib, node);
            }
        }
        p.root = node;
        return std::pair<MerkleProof, Digest>{p, node};
    };

    // leaf_count = UINT64_MAX（最大可表示的合法计数，奇数），位置 0：
    // 位置 0 每层都是偶数下标且永不等于本层末下标，因此每层都有 right
    // 兄弟。层数恰为 64：反复 ceil(n/2) 把 2^64-1 经 63 次提升变为 2，
    // 第 64 层变为 1。结构循环必须走完 64 层、消费 64 项后终止。
    constexpr std::uint64_t kMax = ~std::uint64_t{0};
    {
        const std::vector<ShapeStep> shape = expected_shape(kMax, 0);
        check(shape.size() == 64,
              "UINT64_MAX leaves index 0: exactly 64 right-sibling levels");
        for (const ShapeStep& st : shape) {
            check(st.side == MerkleSibling::Side::right,
                  "UINT64_MAX leaves index 0: every sibling is on the right");
        }

        const auto [p, folded] = build_shaped_proof(kMax, 0, shape);
        check(branchaudit::merkle_verify_proof(p, folded, p.leaf).ok(),
              "UINT64_MAX leaves: structurally exact proof verifies "
              "deterministically without wraparound");

        // 可信根差一位：必须在完整走完 64 层结构核对后才失败于根比对。
        Digest other = folded;
        other[0] ^= 0x80;
        check(!branchaudit::merkle_verify_proof(p, other, p.leaf).ok(),
              "UINT64_MAX leaves: wrong trusted root rejected after the full "
              "64-level traversal");

        // 少最后一个兄弟：第 64 层缺项必须被发现，不能误判通过。
        MerkleProof short_proof = p;
        short_proof.siblings.pop_back();
        check(!branchaudit::merkle_verify_proof(short_proof, folded, p.leaf).ok(),
              "UINT64_MAX leaves: a missing sibling at the final level is "
              "detected");

        // 多一个兄弟：按形状只该有 64 项。
        MerkleProof long_proof = p;
        long_proof.siblings.push_back({MerkleSibling::Side::left, Digest{}});
        check(!branchaudit::merkle_verify_proof(long_proof, folded, p.leaf).ok(),
              "UINT64_MAX leaves: a trailing extra sibling is rejected");
    }

    // 位置取最大合法值 UINT64_MAX-1（偶数，恰为奇数层的末下标）：第 0 层
    // 原样提升、不产生兄弟记录；之后每层节点数均为偶数、该位置都是奇数
    // 下标，故共 63 条 left 兄弟。重点验证：首层省略提升记录不会被误判为
    // 缺项，且奇数下标分支在极限值上不回绕。
    {
        const std::uint64_t last = kMax - 1;
        const std::vector<ShapeStep> shape = expected_shape(kMax, last);
        check(shape.size() == 63,
              "UINT64_MAX leaves index UINT64_MAX-1: 63 records (level 0 "
              "promoted without a sibling)");
        for (const ShapeStep& st : shape) {
            check(st.side == MerkleSibling::Side::left,
                  "UINT64_MAX leaves index UINT64_MAX-1: every recorded "
                  "sibling is on the left");
        }

        const auto [p, folded] = build_shaped_proof(kMax, last, shape);
        check(branchaudit::merkle_verify_proof(p, folded, p.leaf).ok(),
              "UINT64_MAX leaves at the last even position verifies without "
              "integer wraparound and without a padded promotion record");
    }

    // leaf_index == leaf_count 是越界（即使两者都是最大可表示值）。
    {
        MerkleProof p;
        p.leaf_count = kMax;
        p.leaf_index = kMax;
        p.leaf = Digest{};
        check(!branchaudit::merkle_verify_proof(p, Digest{}, Digest{}).ok(),
              "UINT64_MAX: leaf_index equal to leaf_count is out of range");
    }

    // 2 的幂边界 leaf_count = 2^63，末位置 2^63-1（奇数）：每层都有 left
    // 兄弟、没有任何提升省略，共 63 条；这是“全左、无省略”的极限形状，
    // 与前一块“首层省略”互为对照，两条路径上的下标推导都不得回绕。
    {
        constexpr std::uint64_t kPow2 = UINT64_C(1) << 63;
        const std::uint64_t last = kPow2 - 1;
        const std::vector<ShapeStep> shape = expected_shape(kPow2, last);
        check(shape.size() == 63,
              "2^63 leaves at the last position: 63 levels, none omitted");
        for (const ShapeStep& st : shape) {
            check(st.side == MerkleSibling::Side::left,
                  "2^63 leaves last position: every sibling is on the left");
        }
        const auto [p, folded] = build_shaped_proof(kPow2, last, shape);
        check(branchaudit::merkle_verify_proof(p, folded, p.leaf).ok(),
              "2^63 leaves: structurally exact proof verifies deterministically");
    }
}

// ---- prove JSON 的读取：版本 1 格式严格校验、读入后接校验 -----------------

using branchaudit::MerkleProofParseResult;

// 把摘要数组拼成 prove 版本 1 的 JSON 文本；可用 write_json 做小范围改写。
std::string proof_json(const Digest& root, std::uint64_t leaf_count,
                       std::uint64_t leaf_index, const Digest& leaf,
                       const std::vector<std::pair<MerkleSibling::Side, Digest>>&
                           siblings) {
    std::string s = "{\"version\":1,\"root\":\"" + hex_of(root) +
                    "\",\"leaf_count\":" + std::to_string(leaf_count) +
                    ",\"leaf_index\":" + std::to_string(leaf_index) +
                    ",\"leaf\":\"" + hex_of(leaf) + "\",\"siblings\":[";
    for (std::size_t i = 0; i < siblings.size(); ++i) {
        if (i != 0) {
            s += ',';
        }
        s += "{\"side\":\"";
        s += siblings[i].first == MerkleSibling::Side::left ? "left" : "right";
        s += "\",\"digest\":\"" + hex_of(siblings[i].second) + "\"}";
    }
    s += "]}";
    return s;
}

// 读取成功路径并返回结果；what 描述该用例。
MerkleProofParseResult expect_parse_ok(const std::string& text,
                                       std::string_view what) {
    // 截获输出：库读取不得打印。
    std::stringstream cap_out, cap_err;
    auto* old_out = std::cout.rdbuf(cap_out.rdbuf());
    auto* old_err = std::cerr.rdbuf(cap_err.rdbuf());
    MerkleProofParseResult r = branchaudit::merkle_proof_from_json(text);
    std::cout.rdbuf(old_out);
    std::cerr.rdbuf(old_err);
    check(r.ok(), std::string("parse ok: ") + std::string(what) +
                      " — " + r.error);
    check(cap_out.str().empty() && cap_err.str().empty(),
          std::string("parse prints nothing: ") + std::string(what));
    return r;
}

// 读取失败路径：必须失败、给出非空可展示原因且不打印。
void expect_parse_fail(const std::string& text, std::string_view what) {
    std::stringstream cap_out, cap_err;
    auto* old_out = std::cout.rdbuf(cap_out.rdbuf());
    auto* old_err = std::cerr.rdbuf(cap_err.rdbuf());
    MerkleProofParseResult r = branchaudit::merkle_proof_from_json(text);
    std::cout.rdbuf(old_out);
    std::cerr.rdbuf(old_err);
    check(!r.ok(), std::string("parse rejected: ") + std::string(what));
    check(!r.error.empty(),
          std::string("parse failure gives a displayable reason: ") +
              std::string(what));
    check(cap_out.str().empty() && cap_err.str().empty(),
          std::string("parse failure prints nothing: ") + std::string(what));
    // 失败不提供可用的部分证明：结构保持默认构造（零计数、空兄弟）。
    check(r.proof.leaf_count == 0 && r.proof.leaf_index == 0 &&
              r.proof.siblings.empty(),
          std::string("parse failure yields no usable partial proof: ") +
              std::string(what));
}

void test_proof_json() {
    TempArea tmp("proof_json");
    const auto a = bytes_of("a");
    const auto abc = bytes_of("abc");
    const auto empty = bytes_of("");
    const fs::path f_a = tmp.root / "a.bin";
    const fs::path f_abc = tmp.root / "abc.bin";
    const fs::path f_empty = tmp.root / "empty.bin";
    write_file(f_a, a);
    write_file(f_abc, abc);
    write_file(f_empty, empty);

    const Digest la = leaf_bytes(a);
    const Digest labc = leaf_bytes(abc);
    const Digest lempty = leaf_bytes(empty);

    // ---- 成功：真实证明经 JSON 往返，字段准确保留 ------------------------
    const std::vector<fs::path> batch{f_a, f_abc, f_empty};
    const Digest trusted_root = root_of(batch);
    const MerkleProofResult generated =
        branchaudit::merkle_proof_file(batch, 2);
    check(generated.ok(),
          std::string("json fixture proof generated: ") + generated.error);
    const MerkleProof& gp = generated.proof;

    std::string text;
    {
        // 与命令行完全相同的序列化（含末尾换行），避免测试只经过自造格式。
        text = "{\"version\":1,\"root\":\"" + hex_of(gp.root) +
               "\",\"leaf_count\":" + std::to_string(gp.leaf_count) +
               ",\"leaf_index\":" + std::to_string(gp.leaf_index) +
               ",\"leaf\":\"" + hex_of(gp.leaf) + "\",\"siblings\":[";
        for (std::size_t i = 0; i < gp.siblings.size(); ++i) {
            if (i != 0) text += ',';
            text += "{\"side\":\"";
            text += gp.siblings[i].side == MerkleSibling::Side::left
                        ? "left"
                        : "right";
            text += "\",\"digest\":\"" + hex_of(gp.siblings[i].digest) + "\"}";
        }
        text += "]}\n";  // 完整接受命令输出，包括末尾换行。
    }

    MerkleProofParseResult parsed =
        expect_parse_ok(text, "prove command output including trailing newline");
    if (parsed.ok()) {
        const MerkleProof& p = parsed.proof;
        check(p.root == gp.root, "json round trip: root bytes preserved");
        check(p.leaf == gp.leaf, "json round trip: leaf bytes preserved");
        check(p.leaf_count == gp.leaf_count && p.leaf_index == gp.leaf_index,
              "json round trip: count/index preserved exactly");
        check(p.siblings.size() == gp.siblings.size(),
              "json round trip: sibling count preserved");
        for (std::size_t i = 0; i < p.siblings.size(); ++i) {
            check(p.siblings[i].side == gp.siblings[i].side &&
                      p.siblings[i].digest == gp.siblings[i].digest,
                  "json round trip: sibling side/digest/order preserved at " +
                      std::to_string(i));
        }

        // 读取成功只表示格式正确；成员判断仍由现有校验接口完成。
        MerkleVerifyResult v =
            branchaudit::merkle_verify_proof(p, trusted_root, lempty);
        check(v.ok(), std::string("parsed proof verifies against the "
                                  "independently obtained trusted root: ") +
                          v.error);

        // 可信根来自独立渠道：把 proof.root 误当可信根、同时换一份内容时
        // 仍按既有规则失败（读取层不替调用方选择可信根）。
        Digest wrong_leaf = la;  // 证明选的是空文件，不是 a。
        check(!merkle_verify_proof(p, trusted_root, wrong_leaf).ok(),
              "parse does not imply membership: mismatched content leaf is "
              "rejected by merkle_verify_proof");
    }

    // 单文件证明：空兄弟数组正常读入，root 等于 leaf。
    {
        const std::string one =
            proof_json(lempty, 1, 0, lempty, {});
        MerkleProofParseResult r =
            expect_parse_ok(one + "\n", "single-file proof with empty siblings");
        if (r.ok()) {
            check(r.proof.siblings.empty() && r.proof.root == lempty &&
                      r.proof.leaf == lempty && r.proof.leaf_count == 1 &&
                      r.proof.leaf_index == 0,
                  "single-file proof: empty siblings, root equals leaf");
            check(merkle_verify_proof(r.proof, lempty, lempty).ok(),
                  "single-file parsed proof verifies");
        }
    }

    // 两文件、左右各一：兄弟方向按输入保留。
    {
        const Digest pair_root = branchaudit::merkle_parent(la, labc);
        const std::string j_right =
            proof_json(pair_root, 2, 0, la,
                       {{MerkleSibling::Side::right, labc}});
        const std::string j_left =
            proof_json(pair_root, 2, 1, labc,
                       {{MerkleSibling::Side::left, la}});
        MerkleProofParseResult rr = expect_parse_ok(j_right, "right sibling");
        MerkleProofParseResult rl = expect_parse_ok(j_left, "left sibling");
        if (rr.ok() && rl.ok()) {
            check(rr.proof.siblings[0].side == MerkleSibling::Side::right &&
                      rr.proof.siblings[0].digest == labc,
                  "right sibling kept as given");
            check(rl.proof.siblings[0].side == MerkleSibling::Side::left &&
                      rl.proof.siblings[0].digest == la,
                  "left sibling kept as given");
            check(merkle_verify_proof(rr.proof, pair_root, la).ok() &&
                      merkle_verify_proof(rl.proof, pair_root, labc).ok(),
                  "both parsed two-file proofs verify");
        }
    }

    // 兄弟数组严格按输入保留：不为奇数提升层补记录、不排序、不去重。
    {
        // 三文件位置 2 的形状只允许一个 left 兄弟；文本里就只给一个，
        // 读取端不得“补出”被提升层的记录。
        const Digest p = branchaudit::merkle_parent(la, labc);
        const Digest root3 = branchaudit::merkle_parent(p, lempty);
        const std::string j =
            proof_json(root3, 3, 2, lempty,
                       {{MerkleSibling::Side::left, p}});
        MerkleProofParseResult r = expect_parse_ok(
            j, "promoted level stays unrecorded (no padding on read)");
        if (r.ok()) {
            check(r.proof.siblings.size() == 1,
                  "reader does not invent siblings for promoted levels");
        }

        // 重复/次序奇怪的兄弟也原样保留——读取不重排、不去重；是否合法
        // 是校验接口按 leaf_count/leaf_index 判断的事。
        const std::string dup =
            proof_json(root3, 7, 0, la,
                       {{MerkleSibling::Side::right, labc},
                        {MerkleSibling::Side::right, labc},
                        {MerkleSibling::Side::left, lempty}});
        MerkleProofParseResult rd =
            expect_parse_ok(dup, "duplicated siblings preserved verbatim");
        if (rd.ok()) {
            check(rd.proof.siblings.size() == 3 &&
                      rd.proof.siblings[0].digest == labc &&
                      rd.proof.siblings[1].digest == labc &&
                      rd.proof.siblings[2].digest == lempty,
                  "siblings are neither reordered nor deduplicated");
        }
    }

    // ---- 合法 JSON 空白与字段次序不影响读取 ------------------------------
    {
        // 兄弟对象内部字段次序也可交换（digest 在前、side 在后）。
        const std::string reversed_sibling =
            "{\"version\":1,\"leaf_count\":2,\"leaf_index\":0,\"root\":\"" +
            hex_of(branchaudit::merkle_parent(la, labc)) + "\",\"leaf\":\"" +
            hex_of(la) + "\",\"siblings\":[{\"digest\":\"" + hex_of(labc) +
            "\",\"side\":\"right\"}]}";
        MerkleProofParseResult rr = expect_parse_ok(
            reversed_sibling, "sibling entry with digest before side");
        if (rr.ok()) {
            check(rr.proof.siblings.size() == 1 &&
                      rr.proof.siblings[0].side == MerkleSibling::Side::right &&
                      rr.proof.siblings[0].digest == labc,
                  "reversed sibling field order reads the same record");
        }

        const std::string pretty =
            "{\n\t\"version\" : 1,\r\n"
            "  \"siblings\" : [ { \"side\" : \"right\" , \"digest\" : \"" +
            hex_of(labc) + "\" } ] ,\n"
            "  \"leaf_count\" : 2,\n"
            "  \"leaf_index\" : 0,\n"
            "  \"root\" : \"" + hex_of(branchaudit::merkle_parent(la, labc)) +
            "\",\n"
            "  \"leaf\" : \"" + hex_of(la) + "\"\n}\n   \t\r\n";
        MerkleProofParseResult r = expect_parse_ok(
            pretty, "arbitrary JSON whitespace and reordered fields");
        if (r.ok()) {
            check(r.proof.leaf_count == 2 && r.proof.leaf_index == 0 &&
                      r.proof.siblings.size() == 1 &&
                      r.proof.siblings[0].side == MerkleSibling::Side::right,
                  "pretty-printed/reordered proof reads to the same values");
        }
    }

    // ---- 无符号 64 位整数边界：准确保留 ----------------------------------
    {
        const std::string max_text =
            proof_json(la, UINT64_C(18446744073709551615),
                       UINT64_C(18446744073709551615), la, {});
        MerkleProofParseResult r = expect_parse_ok(
            max_text, "leaf_count/leaf_index at UINT64_MAX");
        if (r.ok()) {
            constexpr std::uint64_t kMax = ~std::uint64_t{0};
            check(r.proof.leaf_count == kMax && r.proof.leaf_index == kMax,
                  "UINT64_MAX values retained exactly");
        }
        // 0 也合法（读取接受；空批次没有成员是校验阶段的事）。
        const std::string zero_text =
            proof_json(la, 0, 0, la, {});
        MerkleProofParseResult rz =
            expect_parse_ok(zero_text, "zero count/index accepted on read");
        if (rz.ok()) {
            check(rz.proof.leaf_count == 0 && rz.proof.leaf_index == 0,
                  "zero values retained");
            check(!merkle_verify_proof(rz.proof, la, la).ok(),
                  "empty-batch claim remains for merkle_verify_proof to "
                  "reject (parse success is not membership)");
        }
    }

    // ---- 失败：空文本、语法损坏、顶层类型 --------------------------------
    expect_parse_fail("", "empty text");
    expect_parse_fail("   \t\r\n  ", "whitespace only");
    expect_parse_fail("[]", "top-level array");
    expect_parse_fail("\"x\"", "top-level string");
    expect_parse_fail("123", "top-level number");
    expect_parse_fail("true", "top-level boolean");
    expect_parse_fail("null", "top-level null");
    expect_parse_fail("{,}", "object starting with comma");
    expect_parse_fail("{\"version\" 1}", "missing colon");
    expect_parse_fail("{\"version\":1", "unterminated object");
    expect_parse_fail("{\"version\":1,", "trailing comma in object");
    expect_parse_fail("{\"version\":1} {\"x\":2}", "second object after the "
                                                  "proof object");
    expect_parse_fail(proof_json(la, 1, 0, la, {}) + "x",
                      "non-whitespace trailing byte");
    expect_parse_fail(proof_json(la, 1, 0, la, {}) + " ,",
                      "comma after the object");

    // ---- 失败：必填字段缺失 ----------------------------------------------
    {
        const std::string full = proof_json(la, 1, 0, la, {});
        // 每个字段在 compact JSON 中的确切序列化；删除时连同相邻逗号。
        const std::string serialized[] = {
            "\"version\":1",
            "\"root\":\"" + hex_of(la) + "\"",
            "\"leaf_count\":1",
            "\"leaf_index\":0",
            "\"leaf\":\"" + hex_of(la) + "\"",
            "\"siblings\":[]",
        };
        const std::string field_names[] = {"version", "root", "leaf_count",
                                           "leaf_index", "leaf", "siblings"};
        for (std::size_t f = 0; f < 6; ++f) {
            std::string t = full;
            std::size_t at = t.find(serialized[f]);
            check(at != std::string::npos,
                  "fixture serialization contains field " + field_names[f]);
            std::size_t end = at + serialized[f].size();
            if (end < t.size() && t[end] == ',') {
                ++end;  // 连后置逗号一起删
            } else if (at > 0 && t[at - 1] == ',') {
                --at;  // 或删前置逗号
            }
            t.erase(at, end - at);
            expect_parse_fail(t, "missing required field: " + field_names[f]);
        }
        expect_parse_fail("{}", "empty object");
    }

    // ---- 失败：版本 -------------------------------------------------------
    {
        const std::string good = proof_json(la, 1, 0, la, {});
        auto replace = [&](const std::string& from, const std::string& to) {
            std::string t = good;
            const auto at = t.find(from);
            check(at != std::string::npos,
                  std::string("test fixture contains ") + from);
            t.replace(at, from.size(), to);
            return t;
        };
        expect_parse_fail(replace("\"version\":1", "\"version\":2"),
                          "unsupported version 2");
        expect_parse_fail(replace("\"version\":1", "\"version\":0"),
                          "version 0");
        expect_parse_fail(replace("\"version\":1", "\"version\":-1"),
                          "negative version");
        expect_parse_fail(replace("\"version\":1", "\"version\":1.0"),
                          "version as decimal");
        expect_parse_fail(replace("\"version\":1", "\"version\":1e0"),
                          "version in exponent notation");
        expect_parse_fail(replace("\"version\":1", "\"version\":\"1\""),
                          "version as numeric string");
        expect_parse_fail(replace("\"version\":1", "\"version\":true"),
                          "version as boolean");
        expect_parse_fail(replace("\"version\":1", "\"version\":null"),
                          "version as null");
        expect_parse_fail(replace("\"version\":1", "\"version\":[]"),
                          "version as array");
        expect_parse_fail(replace("\"version\":1", "\"version\":{}"),
                          "version as object");
        expect_parse_fail(replace("\"version\":1", "\"version\":01"),
                          "version with leading zero");
    }

    // ---- 失败：计数/位置整数规则与范围 -----------------------------------
    {
        const std::string good = proof_json(la, 1, 0, la, {});
        auto bad_count = [&](const std::string& literal,
                             const std::string& label) {
            std::string t = good;
            const std::string from = "\"leaf_count\":1";
            const auto at = t.find(from);
            t.replace(at, from.size(), "\"leaf_count\":" + literal);
            expect_parse_fail(t, label);
        };
        bad_count("-0", "leaf_count negative zero");
        bad_count("-1", "leaf_count negative");
        bad_count("1.0", "leaf_count decimal");
        bad_count("0.5", "leaf_count fraction");
        bad_count("1e3", "leaf_count exponent");
        bad_count("1E3", "leaf_count capital exponent");
        bad_count("\"1\"", "leaf_count numeric string");
        bad_count("true", "leaf_count boolean");
        bad_count("false", "leaf_count false");
        bad_count("null", "leaf_count null");
        bad_count("[]", "leaf_count array");
        bad_count("{}", "leaf_count object");
        bad_count("18446744073709551616", "leaf_count UINT64_MAX+1");
        bad_count("99999999999999999999999999", "leaf_count far out of range");
        bad_count("01", "leaf_count leading zero");
        bad_count("+1", "leaf_count with leading plus sign");

        const std::string max_bad =
            proof_json(la, 1, UINT64_C(18446744073709551615), la, {});
        // leaf_index 越界 1。
        std::string t = max_bad;
        const std::string from =
            "\"leaf_index\":18446744073709551615";
        const auto at = t.find(from);
        t.replace(at, from.size(),
                  "\"leaf_index\":18446744073709551616");
        expect_parse_fail(t, "leaf_index UINT64_MAX+1");
    }

    // ---- 失败：摘要规则 ---------------------------------------------------
    {
        const std::string good = proof_json(la, 1, 0, la, {});
        auto corrupt = [&](char replacement, std::size_t char_index,
                           const std::string& label) {
            std::string t = good;
            // 第一个摘要是 root（64 个十六进制字符）。
            const std::string marker = "\"root\":\"";
            const auto at = t.find(marker) + marker.size() + char_index;
            t[at] = replacement;
            expect_parse_fail(t, label);
        };
        corrupt('A', 0, "uppercase hex digest");
        corrupt('g', 1, "non-hex letter in digest");
        corrupt('z', 10, "non-hex z in digest");
        corrupt('-', 2, "dash in digest");
        corrupt(' ', 3, "space inside digest");

        auto replace_field = [&](const std::string& field,
                                 const std::string& value,
                                 const std::string& label) {
            std::string t = good;
            const std::string from =
                "\"" + field + "\":\"" + hex_of(la) + "\"";
            const auto at = t.find(from);
            check(at != std::string::npos,
                  std::string("digest fixture contains field ") + field);
            t.replace(at, from.size(), "\"" + field + "\":" + value);
            expect_parse_fail(t, label);
        };
        const std::string hex63 = hex_of(la).substr(1);       // 63 字符
        const std::string hex65 = hex_of(la) + "a";           // 65 字符
        replace_field("root", "\"" + hex63 + "\"", "63-char digest");
        replace_field("leaf", "\"" + hex65 + "\"", "65-char digest");
        replace_field("root", "\"\"", "empty digest string");
        replace_field("root", "123", "digest as number");
        replace_field("root", "null", "digest as null");
        replace_field("root", "[]", "digest as array");
        replace_field("leaf", "true", "leaf digest as boolean");
        replace_field("leaf", "{}", "leaf digest as object");

        // 兄弟摘要同样受约束。
        {
            const std::string with_sib =
                proof_json(branchaudit::merkle_parent(la, labc), 2, 0, la,
                           {{MerkleSibling::Side::right, labc}});
            std::string t = with_sib;
            const std::string needle =
                "\"digest\":\"" + hex_of(labc) + "\"";
            const auto at = t.find(needle);
            t.replace(at, needle.size(),
                      "\"digest\":\"" + hex_of(labc).substr(0, 63) + "\"");
            expect_parse_fail(t, "63-char sibling digest");

            std::string t2 = with_sib;
            const auto at2 =
                t2.find(needle) + std::string("\"digest\":\"").size();
            t2[at2] = 'F';  // 大写。
            expect_parse_fail(t2, "uppercase sibling digest");
        }
    }

    // ---- 失败：兄弟结构与 side --------------------------------------------
    {
        const Digest pair_root = branchaudit::merkle_parent(la, labc);
        const std::string good =
            proof_json(pair_root, 2, 0, la,
                       {{MerkleSibling::Side::right, labc}});
        auto replace_once = [&](const std::string& from,
                                const std::string& to,
                                const std::string& label) {
            std::string t = good;
            const auto at = t.find(from);
            check(at != std::string::npos,
                  std::string("sibling fixture contains: ") + from);
            t.replace(at, from.size(), to);
            expect_parse_fail(t, label);
        };
        replace_once("\"side\":\"right\"", "\"side\":\"LEFT\"",
                     "uppercase side");
        replace_once("\"side\":\"right\"", "\"side\":\"up\"",
                     "unknown side value");
        replace_once("\"side\":\"right\"", "\"side\":null",
                     "side as null");
        replace_once("\"side\":\"right\"", "\"side\":1",
                     "side as number");
        replace_once("\"side\":\"right\"",
                     "\"side\":\"right\",\"side\":\"left\"",
                     "duplicate side field");
        replace_once("\"digest\":\"" + hex_of(labc) + "\"",
                     "\"digest\":\"" + hex_of(labc) + "\",\"digest\":\"" +
                         hex_of(la) + "\"",
                     "duplicate digest field");
        replace_once("{\"side\":\"right\",\"digest\":\"" + hex_of(labc) +
                         "\"}",
                     "{\"side\":\"right\",\"digest\":\"" + hex_of(labc) +
                         "\",\"extra\":1}",
                     "unknown field in sibling entry");
        replace_once("{\"side\":\"right\",\"digest\":\"" + hex_of(labc) +
                         "\"}",
                     "{\"side\":\"right\"}",
                     "sibling entry missing digest");
        replace_once("{\"side\":\"right\",\"digest\":\"" + hex_of(labc) +
                         "\"}",
                     "{\"digest\":\"" + hex_of(labc) + "\"}",
                     "sibling entry missing side");
        replace_once("\"siblings\":[", "\"siblings\":[1",
                     "numeric sibling entry");
        // 顶层 siblings 类型错误。
        {
            std::string t = good;
            const std::string from =
                "\"siblings\":[{\"side\":\"right\",\"digest\":\"" +
                hex_of(labc) + "\"}]";
            const auto at = t.find(from);
            t.replace(at, from.size(), "\"siblings\":{}");
            expect_parse_fail(t, "siblings as object");
        }
    }

    // ---- 失败：重复与未知顶层字段、各种语法尾巴 ---------------------------
    {
        const std::string good = proof_json(la, 1, 0, la, {});
        expect_parse_fail(good.substr(0, good.size() - 1) +
                              ",\"root\":\"" + hex_of(la) + "\"}",
                          "duplicate root field");
        expect_parse_fail(good.substr(0, good.size() - 1) +
                              ",\"leaf\":\"" + hex_of(labc) + "\"}",
                          "duplicate leaf field");
        // 在对象闭合前插入未知字段。
        expect_parse_fail(good.substr(0, good.size() - 1) + ",\"x\":1}",
                          "unknown top-level field x");
        // 兄弟数组未闭合。
        const std::string with_sib =
            proof_json(branchaudit::merkle_parent(la, labc), 2, 0, la,
                       {{MerkleSibling::Side::right, labc}});
        expect_parse_fail(with_sib.substr(0, with_sib.size() - 2),
                          "unterminated siblings array");
        // 字符串里的转义必须按 JSON 识别；非法转义失败。
        expect_parse_fail(
            "{\"version\":1,\"root\":\"" + hex_of(la) +
                "\",\"leaf_count\":1,\"leaf_index\":0,\"leaf\":\"" +
                hex_of(la) + "\",\"siblings\\q\":[]}",
            "invalid escape in field name");
    }
}

// ---- Unicode 转义：写法不同但解码后等价的证明 JSON --------------------------

// 把 ASCII 字符 c 写成 JSON \u00XX 转义形式（小写十六进制）。
std::string json_unicode_escape(char c) {
    const char* hex = "0123456789abcdef";
    const unsigned char u = static_cast<unsigned char>(c);
    std::string e = "\\u00";
    e += hex[u >> 4];
    e += hex[u & 0xF];
    return e;
}

// 字段名第 i 个字符改用 \u00XX 转义，其余字符保持普通写法（两种写法混用）。
std::string escape_name_char(const std::string& name, std::size_t i) {
    return name.substr(0, i) + json_unicode_escape(name[i]) +
           name.substr(i + 1);
}

// 十六进制文本中的字母全部改写成 \u00XX 转义，数字保持原样：解码后与原
// 字符串完全相同，但字面写法与长度都不同。
std::string escape_hex_letters(const std::string& hex_text) {
    std::string out;
    for (char c : hex_text) {
        if (c >= 'a' && c <= 'f') {
            out += json_unicode_escape(c);
        } else {
            out += c;
        }
    }
    return out;
}

void test_proof_json_unicode_escapes() {
    TempArea tmp("proof_json_escape");
    const auto a = bytes_of("a");
    const auto abc = bytes_of("abc");
    const auto empty = bytes_of("");
    const fs::path f_a = tmp.root / "a.bin";
    const fs::path f_abc = tmp.root / "abc.bin";
    const fs::path f_empty = tmp.root / "empty.bin";
    write_file(f_a, a);
    write_file(f_abc, abc);
    write_file(f_empty, empty);

    const Digest la = leaf_bytes(a);
    const Digest labc = leaf_bytes(abc);
    const Digest lempty = leaf_bytes(empty);

    // 三文件批次位置 1 的证明：两个兄弟，左右各一，两种方向值都被覆盖。
    const std::vector<fs::path> batch{f_a, f_abc, f_empty};
    const Digest trusted_root = root_of(batch);
    const MerkleProofResult generated = branchaudit::merkle_proof_file(batch, 1);
    check(generated.ok(),
          std::string("escape fixture proof generated: ") + generated.error);
    const MerkleProof& gp = generated.proof;
    check(gp.siblings.size() == 2 &&
              gp.siblings[0].side == MerkleSibling::Side::left &&
              gp.siblings[1].side == MerkleSibling::Side::right,
          "escape fixture proof has one left and one right sibling");

    // ---- 成功：字段名、方向值与摘要中的部分字符写成 \u00XX 转义 -----------
    // 顶层字段名、兄弟记录字段名、left/right 与根/叶子/兄弟摘要都混用普通
    // 字符与转义写法；两条兄弟记录各自出现 side/digest 属于正常格式（即使
    // 一条用转义名、另一条也用转义名，跨记录不算重复）。末尾换行一并接受。
    const std::string escaped =
        "{\"" + escape_name_char("version", 1) + "\":1,"
        "\"" + escape_name_char("root", 2) + "\":\"" +
            escape_hex_letters(hex_of(gp.root)) + "\","
        "\"" + escape_name_char("leaf_count", 5) + "\":" +
            std::to_string(gp.leaf_count) + ","
        "\"" + escape_name_char("leaf_index", 9) + "\":" +
            std::to_string(gp.leaf_index) + ","
        "\"" + escape_name_char("leaf", 0) + "\":\"" +
            escape_hex_letters(hex_of(gp.leaf)) + "\","
        "\"" + escape_name_char("siblings", 7) + "\":["
        "{\"" + escape_name_char("side", 3) + "\":\"lef" +
            json_unicode_escape('t') + "\","
        "\"" + escape_name_char("digest", 0) + "\":\"" +
            escape_hex_letters(hex_of(gp.siblings[0].digest)) + "\"},"
        "{\"" + escape_name_char("side", 0) + "\":\"" +
            json_unicode_escape('r') + "ight\","
        "\"" + escape_name_char("digest", 5) + "\":\"" +
            escape_hex_letters(hex_of(gp.siblings[1].digest)) + "\"}]}\n";

    MerkleProofParseResult r = expect_parse_ok(
        escaped, "unicode escapes in field names, side values and digests");
    if (r.ok()) {
        const MerkleProof& p = r.proof;
        check(p.root == gp.root && p.leaf == gp.leaf,
              "escaped form decodes to the same 32-byte root and leaf");
        check(p.leaf_count == gp.leaf_count && p.leaf_index == gp.leaf_index,
              "escaped form keeps batch size and position");
        check(p.siblings.size() == gp.siblings.size(),
              "escaped form keeps sibling count");
        for (std::size_t i = 0; i < p.siblings.size(); ++i) {
            check(p.siblings[i].side == gp.siblings[i].side &&
                      p.siblings[i].digest == gp.siblings[i].digest,
                  "escaped form keeps sibling side/digest/order at " +
                      std::to_string(i));
        }
        // 用同一份独立保存的可信根与内容叶子校验：与普通写法结果相同。
        MerkleVerifyResult v =
            branchaudit::merkle_verify_proof(p, trusted_root, labc);
        check(v.ok(), std::string("escaped-form proof verifies against the "
                                  "trusted root like the plain form: ") +
                          v.error);
        // 读取成功仍只代表格式正确：换一份内容叶子照样被校验拒绝。
        check(!branchaudit::merkle_verify_proof(p, trusted_root, la).ok(),
              "escaped-form parse is not membership: wrong content leaf "
              "rejected by merkle_verify_proof");
    }

    // ---- 摘要规则按解码后的内容判断，不按转义文字的长度 ---------------------
    {
        const std::string good = proof_json(la, 1, 0, la, {});
        const std::string marker = "\"root\":\"";
        const auto at = good.find(marker) + marker.size();
        const std::string root_hex = hex_of(la);
        auto replace_root = [&](const std::string& replacement,
                                const std::string& label) {
            std::string t = good;
            t.replace(at, root_hex.size(), replacement);
            expect_parse_fail(t, label);
        };
        // 解码后 63 个字符：转义写法字面长达 68 字符，仍按解码长度判失败。
        replace_root(json_unicode_escape(root_hex[1]) + root_hex.substr(2),
                     "digest decoding to 63 chars rejected despite a "
                     "longer escaped literal");
        // 解码后 65 个字符。
        replace_root(root_hex + "\\u0061",
                     "digest decoding to 65 chars rejected");
        // 解码后出现大写字符：不能因使用转义而被接受。
        replace_root("\\u0041" + root_hex.substr(1),
                     "escaped uppercase hex letter in digest rejected");
        // 解码后出现非十六进制字符。
        replace_root("\\u0067" + root_hex.substr(1),
                     "escaped non-hex letter in digest rejected");

        // 兄弟摘要同样按解码内容判断。
        const std::string with_sib = proof_json(
            branchaudit::merkle_parent(la, labc), 2, 0, la,
            {{MerkleSibling::Side::right, labc}});
        std::string sib_upper = with_sib;
        const std::string needle = "\"digest\":\"";
        const auto sib_digest_at = sib_upper.find(needle);
        check(sib_digest_at != std::string::npos,
              "sibling digest fixture contains digest field");
        sib_upper.replace(sib_digest_at + needle.size(), 1,
                          "\\u0046");  // 首字符解码为大写 'F'
        expect_parse_fail(sib_upper,
                          "escaped uppercase letter in sibling digest");
    }

    // ---- 重复字段按解码后的名字识别 -----------------------------------------
    {
        const std::string good = proof_json(la, 1, 0, la, {});
        const std::string root_hex = hex_of(la);
        // 顶层：普通 "root" 与转义写法的等价名字同现，值完全相同也失败。
        expect_parse_fail(good.substr(0, good.size() - 1) +
                              ",\"r\\u006fot\":\"" + root_hex + "\"}",
                          "top-level duplicate root via escaped field name "
                          "(identical value)");
        expect_parse_fail(good.substr(0, good.size() - 1) +
                              ",\"l\\u0065af\":\"" + root_hex + "\"}",
                          "top-level duplicate leaf via escaped field name");

        // 单条兄弟记录内同样按解码后的名字判重。
        const std::string sib = proof_json(
            branchaudit::merkle_parent(la, labc), 2, 0, la,
            {{MerkleSibling::Side::right, labc}});
        std::string t = sib;
        const std::string side_field = "\"side\":\"right\"";
        const auto at2 = t.find(side_field);
        check(at2 != std::string::npos, "sibling fixture contains side field");
        t.replace(at2, side_field.size(),
                  side_field + ",\"sid\\u0065\":\"right\"");
        expect_parse_fail(t, "sibling entry duplicate side via escaped name "
                             "(identical value)");

        std::string t2 = sib;
        const std::string digest_field = "\"digest\":\"" + hex_of(labc) + "\"";
        const auto at3 = t2.find(digest_field);
        check(at3 != std::string::npos,
              "sibling fixture contains digest field");
        t2.replace(at3, digest_field.size(),
                   digest_field + ",\"d\\u0069gest\":\"" + hex_of(labc) +
                       "\"");
        expect_parse_fail(t2, "sibling entry duplicate digest via escaped "
                              "name");
    }

    // ---- 损坏的 Unicode 转义：明确失败，不丢弃片段、不替换字符 --------------
    {
        const std::string good = proof_json(la, 1, 0, la, {});
        auto replace_once = [&](const std::string& from, const std::string& to,
                                const std::string& label) {
            std::string t = good;
            const auto at = t.find(from);
            check(at != std::string::npos,
                  std::string("escape fixture contains: ") + from);
            t.replace(at, from.size(), to);
            expect_parse_fail(t, label);
        };
        // 字段名中 \u 后的四位十六进制不完整（第三位就是结束引号）。
        replace_once("\"root\"", "\"r\\u00\"",
                     "truncated \\u escape in field name");
        // \u 后含非法十六进制字符。
        replace_once("\"root\"", "\"\\u00g0ot\"",
                     "non-hex character in \\u escape");

        // 摘要值中的代理项未正确配对。
        const std::string marker = "\"root\":\"";
        const auto at = good.find(marker) + marker.size();
        const std::string root_hex = hex_of(la);
        auto corrupt_root = [&](const std::string& replacement,
                                const std::string& label) {
            std::string t = good;
            t.replace(at, root_hex.size(), replacement);
            expect_parse_fail(t, label);
        };
        corrupt_root("\\uD800" + root_hex.substr(1),
                     "lone high surrogate in digest");
        corrupt_root("\\uDC00" + root_hex.substr(1),
                     "lone low surrogate in digest");
        corrupt_root("\\uD800\\u0041" + root_hex.substr(2),
                     "high surrogate followed by a non-surrogate escape");
        // 转义序列在输入末尾被截断。
        expect_parse_fail(good.substr(0, at) + "\\u12",
                          "\\u escape cut off at end of input");
    }
}

// ---- 命令行 prove 原文 -> 库读取 -> 成员校验 的直接回归 -------------------
//
// 上面的 JSON 用例只能由测试自行拼出证明文本，无法防止“库读取的格式”与
// “prove 命令真正写到标准输出的字节”之间发生漂移。这里补上这一环：经
// fork+execvp 实际运行命令行程序，从管道逐字节取得 prove 的完整标准输出
// （保留原文与唯一的末尾换行，不经 shell、不做任何转换），原样交给
// merkle_proof_from_json，再只用 (证明, 另行获得的可信根, 按 0x00 叶子规则
// 计算的待验证内容) 调 merkle_verify_proof——校验一侧不提供整批文件。

#if defined(__unix__)

struct CliResult {
    bool launched = false;   // 成功启动并正常收尸
    int exit_code = -1;
    std::string out;         // stdout 逐字节原样保留
    std::string err;         // stderr 逐字节原样保留
};

// 命令行路径：CMake 以编译定义注入构建出的 branchaudit；手工运行可用
// BRANCHAUDIT_EXE 覆盖，找不到时该组检查明确跳过而非误判通过。
fs::path branchaudit_exe_path() {
    if (const char* from_env = std::getenv("BRANCHAUDIT_EXE");
        from_env != nullptr && *from_env != '\0') {
        return fs::path{from_env};
    }
#ifdef BRANCHAUDIT_EXE
    return fs::path{BRANCHAUDIT_EXE};
#else
    return {};
#endif
}

bool read_fd_all(int fd, std::string& into) {
    char buf[4096];
    while (true) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n > 0) {
            into.append(buf, static_cast<std::size_t>(n));
            continue;
        }
        if (n == 0) {
            return true;
        }
        if (errno == EINTR) {
            continue;
        }
        return false;
    }
}

// 实际运行 <exe> args...，stdout/stderr 分别经管道收集。证明体只有一行、
// 成功时 stderr 为空、失败时也只有一行用法/错误文字，均远小于管道容量，
// 故顺序读完 stdout 再读 stderr 不会死锁。
CliResult run_cli_capture(const fs::path& exe,
                          const std::vector<std::string>& args) {
    CliResult result;
    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0) {
        return result;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(out_pipe[0]);
        ::close(out_pipe[1]);
        ::close(err_pipe[0]);
        ::close(err_pipe[1]);
        return result;
    }

    if (pid == 0) {
        // 子进程：把两个管道接到 stdout/stderr 后执行真正的命令行程序。
        ::dup2(out_pipe[1], STDOUT_FILENO);
        ::dup2(err_pipe[1], STDERR_FILENO);
        ::close(out_pipe[0]);
        ::close(out_pipe[1]);
        ::close(err_pipe[0]);
        ::close(err_pipe[1]);

        std::string exe_str = exe.string();
        std::vector<std::string> storage = args;
        std::vector<char*> argv;
        argv.push_back(exe_str.data());
        for (std::string& a : storage) {
            argv.push_back(a.data());
        }
        argv.push_back(nullptr);
        ::execvp(exe_str.c_str(), argv.data());
        ::_exit(127);
    }

    ::close(out_pipe[1]);
    ::close(err_pipe[1]);
    const bool out_ok = read_fd_all(out_pipe[0], result.out);
    const bool err_ok = read_fd_all(err_pipe[0], result.err);
    ::close(out_pipe[0]);
    ::close(err_pipe[0]);

    int status = 0;
    pid_t waited = -1;
    do {
        waited = ::waitpid(pid, &status, 0);
    } while (waited == -1 && errno == EINTR);
    result.launched =
        out_ok && err_ok && waited == pid && WIFEXITED(status);
    if (result.launched) {
        result.exit_code = WEXITSTATUS(status);
    }
    return result;
}

CliResult run_prove_cli(const fs::path& exe, std::uint64_t index,
                        const std::vector<fs::path>& files) {
    std::vector<std::string> args{"prove", std::to_string(index)};
    for (const fs::path& f : files) {
        args.push_back(f.string());
    }
    return run_cli_capture(exe, args);
}

CliResult run_root_cli(const fs::path& exe,
                       const std::vector<fs::path>& files) {
    std::vector<std::string> args{"root"};
    for (const fs::path& f : files) {
        args.push_back(f.string());
    }
    return run_cli_capture(exe, args);
}

// 仅测试使用：把独立依据（Python hashlib/OpenSSL）固化的 64 个小写十六进制
// 字符还原为 32 字节，绝不取自被测库的输出。
Digest digest_from_literal(std::string_view hex) {
    Digest d{};
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < 32; ++i) {
        d[i] = static_cast<std::uint8_t>(
            (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
    return d;
}

// 调库校验期间截获标准输出/错误：校验接口只返回结果，不打印、不退出。
MerkleVerifyResult verify_quietly(const MerkleProof& proof,
                                  const Digest& trusted_root,
                                  const Digest& content_leaf,
                                  std::string_view what) {
    std::stringstream cap_out, cap_err;
    auto* old_out = std::cout.rdbuf(cap_out.rdbuf());
    auto* old_err = std::cerr.rdbuf(cap_err.rdbuf());
    MerkleVerifyResult v =
        branchaudit::merkle_verify_proof(proof, trusted_root, content_leaf);
    std::cout.rdbuf(old_out);
    std::cerr.rdbuf(old_err);
    check(cap_out.str().empty() && cap_err.str().empty(),
          std::string("verify prints nothing: ") + std::string(what));
    return v;
}

void test_cli_proof_roundtrip() {
    const fs::path exe = branchaudit_exe_path();
    if (exe.empty() || !fs::exists(exe)) {
        ++g_skipped;
        std::cout << "SKIP: real prove output -> library read/verify "
                     "round-trip (branchaudit executable not locatable)\n";
        return;
    }

    TempArea tmp("cli_proof_roundtrip");

    // 独立依据（Python hashlib/OpenSSL，SHA-256(0x00||data) 叶子、
    // SHA-256(0x01||l||r) 父节点、奇数末节点原样提升）。
    const Digest indep_empty_batch_root = digest_from_literal(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const Digest indep_leaf_empty = digest_from_literal(
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
    const Digest indep_leaf_a = digest_from_literal(
        "022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c");
    const Digest indep_leaf_abc = digest_from_literal(
        "609f6e36d2405585188d5cfd761f407c7cc46a7d3f314c88270469dde315fcd1");
    const Digest indep_leaf_hello = digest_from_literal(
        "54a6dc1bfc990ced3f5757264f357ad708a9ee54ce3d117299641b234f6d5800");
    const Digest indep_plain_abc = digest_from_literal(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // 五文件批次 [a, abc, 空, hello\n, abc] 的独立中间摘要与根。
    const Digest indep_p01 = digest_from_literal(
        "6a5c0676c6dd1efd519348f49315879d99549029726d5dd1a5dedbf700720761");
    const Digest indep_p23 = digest_from_literal(
        "bda74a974b773365b399173caa53ddca21a5192f093803e787bf774d21ed6651");
    const Digest indep_q = digest_from_literal(
        "ae395b1592efa07192377a24fc187eba186da891a39c12d3dfae9df84f0c9a93");
    const Digest indep_five_root = digest_from_literal(
        "d4abac6c1b56d60f14de10178f0b27880072f5ee1165de749b2ec1089259aebd");

    // ---- 场景 1：单个空文件 ----------------------------------------------
    const fs::path f_empty = tmp.root / "empty.bin";
    write_file(f_empty, bytes_of(""));
    const std::vector<fs::path> one{f_empty};

    const CliResult one_prove = run_prove_cli(exe, 0, one);
    check(one_prove.launched && one_prove.exit_code == 0,
          "real prove on a single empty file exits 0");
    check(one_prove.err.empty(),
          "real prove on a single empty file writes nothing to stderr");
    const std::string& one_raw = one_prove.out;
    check(!one_raw.empty() && one_raw.back() == '\n' &&
              one_raw.find('\n') == one_raw.size() - 1,
          "real proof stdout is one JSON line kept verbatim with its trailing "
          "newline");
    check(one_raw.find("\"siblings\":[]") != std::string::npos,
          "real single-empty-file proof text carries an empty siblings array");

    // 原文（含末尾换行）直接交给库读取。
    MerkleProofParseResult one_parsed = expect_parse_ok(
        one_raw, "real single-empty-file prove stdout read verbatim");
    if (one_parsed.ok()) {
        const MerkleProof& p = one_parsed.proof;
        check(p.leaf_count == 1 && p.leaf_index == 0,
              "single empty file: batch count 1, zero-based position 0");
        check(p.leaf == indep_leaf_empty && p.root == indep_leaf_empty,
              "single empty file: root equals the SHA-256(0x00) leaf");
        check(p.siblings.empty(),
              "single empty file: sibling table is empty");
        check(p.root != indep_empty_batch_root &&
                  p.root != branchaudit::merkle_empty_root(),
              "single empty file: root differs from the empty batch root");

        // 可信根来自对同一有序批次另行运行 root 取得，而不是 proof.root。
        const CliResult one_root = run_root_cli(exe, one);
        check(one_root.launched && one_root.exit_code == 0 &&
                  one_root.err.empty(),
              "independent root command for the single file succeeds");
        std::string one_root_hex = one_root.out;
        check(!one_root_hex.empty() && one_root_hex.back() == '\n',
              "independent root stdout is hex plus newline");
        one_root_hex.pop_back();
        check(one_root_hex.size() == 64,
              "independent root stdout decodes as one digest line");
        const Digest one_trusted = digest_from_literal(one_root_hex);
        check(one_trusted == indep_leaf_empty,
              "independently obtained root matches the hashlib leaf");

        // 校验只消费证明、可信根与内存中按 0x00 叶子规则计算的内容，不给
        // 整批文件。
        const Digest content_leaf = leaf_bytes(bytes_of(""));
        const MerkleVerifyResult v =
            verify_quietly(p, one_trusted, content_leaf,
                           "single empty file with the 0x00 leaf");
        check(v.ok() && v.valid && v.error.empty(),
              std::string("single empty file: real proof verifies: ") +
                  v.error);

        // 普通无 0x00 前缀的 hash 摘要不能充当待验证内容。
        const MerkleVerifyResult plain =
            verify_quietly(p, one_trusted, indep_empty_batch_root,
                           "single empty file with a plain hash digest");
        check(!plain.ok() && !plain.error.empty(),
              "single empty file: a plain SHA-256 (empty) digest is rejected "
              "with a non-empty reason");
    }

    // ---- 场景 2：五文件批次的最后一个位置（含连续奇数末节点提升）---------
    // 内容在位置 1 与 4 相同（都是 "abc"），位置必须按传入顺序保留、不去重。
    const fs::path f0 = tmp.root / "f0";
    const fs::path f1 = tmp.root / "f1";
    const fs::path f2 = tmp.root / "f2";
    const fs::path f3 = tmp.root / "f3";
    const fs::path f4 = tmp.root / "f4";
    const std::vector<unsigned char> c0 = bytes_of("a");
    const std::vector<unsigned char> c1 = bytes_of("abc");
    const std::vector<unsigned char> c2 = bytes_of("");
    const std::vector<unsigned char> c3 = bytes_of("hello\n");
    const std::vector<unsigned char> c4 = bytes_of("abc");  // 与位置 1 相同
    write_file(f0, c0);
    write_file(f1, c1);
    write_file(f2, c2);
    write_file(f3, c3);
    write_file(f4, c4);
    const std::vector<fs::path> five{f0, f1, f2, f3, f4};

    // 对同一有序批次另行获得可信根（独立 root 命令 + hashlib 双重核对）。
    const CliResult five_root_run = run_root_cli(exe, five);
    check(five_root_run.launched && five_root_run.exit_code == 0 &&
              five_root_run.err.empty(),
          "independent root command for the five-file batch succeeds");
    std::string five_root_hex = five_root_run.out;
    check(!five_root_hex.empty() && five_root_hex.back() == '\n',
          "independent five-file root keeps its trailing newline");
    five_root_hex.pop_back();
    check(five_root_hex.size() == 64, "independent root is one digest line");
    const Digest five_trusted = digest_from_literal(five_root_hex);
    check(five_trusted == indep_five_root,
          "independently obtained five-file root matches the hashlib value");

    const CliResult last_prove = run_prove_cli(exe, 4, five);
    check(last_prove.launched && last_prove.exit_code == 0 &&
              last_prove.err.empty(),
          "real prove at the five-file batch last position exits 0 silently");
    const std::string& last_raw = last_prove.out;
    check(!last_raw.empty() && last_raw.back() == '\n' &&
              last_raw.find('\n') == last_raw.size() - 1,
          "real last-position proof kept verbatim with trailing newline");
    check(last_raw.find("\"leaf_count\":5") != std::string::npos &&
              last_raw.find("\"leaf_index\":4") != std::string::npos,
          "real last-position proof text states count 5 and zero-based index 4");

    MerkleProofParseResult last_parsed = expect_parse_ok(
        last_raw, "real five-file last-position prove stdout read verbatim");
    if (last_parsed.ok()) {
        const MerkleProof& p = last_parsed.proof;
        check(p.leaf_count == 5 && p.leaf_index == 4,
              "last position: count 5 and zero-based position 4 preserved");
        check(p.root == indep_five_root,
              "last position: root matches the independent batch root");
        check(p.leaf == indep_leaf_abc,
              "last position: leaf is the 0x00-prefixed leaf of its content");
        // 5 -> 3 -> 2 -> 1：该位置在节点数为 5 和 3 的两层都是奇数末节点，
        // 原样提升、不补记录；只剩节点数为 2 的层上一个 left 兄弟。
        check(p.siblings.size() == 1,
              "last position: promoted levels add no records (one sibling)");
        check(p.siblings[0].side == MerkleSibling::Side::left &&
                  p.siblings[0].digest == indep_q,
              "last position: sole sibling is the left subtree digest in "
              "leaf-to-root order");

        const Digest content_leaf = leaf_bytes(c4);  // 内存内容，带 0x00 前缀
        const MerkleVerifyResult v =
            verify_quietly(p, five_trusted, content_leaf,
                           "five-file last position with the 0x00 leaf");
        check(v.ok() && v.valid && v.error.empty(),
              std::string("last position: verbatim real proof verifies: ") +
                  v.error);

        // proof.root 自报值不充当信任来源：可信根换成空批次根即拒绝。
        const MerkleVerifyResult wrong_anchor =
            verify_quietly(p, indep_empty_batch_root, content_leaf,
                           "last position against an untrusted root");
        check(!wrong_anchor.ok() && !wrong_anchor.error.empty(),
              "last position: proof.root cannot serve as the trust anchor");

        // 普通无 0x00 前缀摘要不能替代待验证内容。
        check(indep_plain_abc != indep_leaf_abc,
              "plain SHA-256(abc) differs from the 0x00-prefixed leaf");
        const MerkleVerifyResult plain =
            verify_quietly(p, five_trusted, indep_plain_abc,
                           "last position with a plain hash digest");
        check(!plain.ok() && !plain.error.empty(),
              "last position: plain SHA-256(abc) is rejected with a reason");
    }

    // ---- 相同内容各占独立位置：读取后均可校验，形状随位置不同 -------------
    {
        const CliResult first_dup = run_prove_cli(exe, 1, five);
        check(first_dup.launched && first_dup.exit_code == 0 &&
                  first_dup.err.empty(),
              "real prove at position 1 (duplicate content) succeeds");
        MerkleProofParseResult p1 = expect_parse_ok(
            first_dup.out, "real position-1 proof read verbatim");
        MerkleProofParseResult p4 = expect_parse_ok(
            last_raw, "real position-4 proof re-read for duplicate check");
        if (p1.ok() && p4.ok()) {
            check(p1.proof.leaf == p4.proof.leaf &&
                      p1.proof.leaf == indep_leaf_abc,
                  "duplicate-content entries keep the same leaf digest");
            check(p1.proof.leaf_index == 1 && p4.proof.leaf_index == 4,
                  "positions are preserved by input order, not deduplicated");
            check(p1.proof.siblings.size() == 3 &&
                      p4.proof.siblings.size() == 1,
                  "the two duplicate-content positions keep distinct paths");
            // 位置 1 从叶子向根：left=L0、right=P23、right=L4。
            check(p1.proof.siblings[0].side == MerkleSibling::Side::left &&
                      p1.proof.siblings[0].digest == indep_leaf_a &&
                      p1.proof.siblings[1].side == MerkleSibling::Side::right &&
                      p1.proof.siblings[1].digest == indep_p23 &&
                      p1.proof.siblings[2].side == MerkleSibling::Side::right &&
                      p1.proof.siblings[2].digest == indep_leaf_abc,
                  "position 1 keeps left/right/right siblings in leaf-to-root "
                  "order");
            // 两个位置用同一份内容叶子与同一可信根都能通过。
            const Digest dup_leaf = leaf_bytes(c1);
            check(verify_quietly(p1.proof, five_trusted, dup_leaf,
                                 "duplicate content at position 1").ok(),
                  "position-1 proof verifies with the shared content leaf");
            check(verify_quietly(p4.proof, five_trusted, dup_leaf,
                                 "duplicate content at position 4").ok(),
                  "position-4 proof verifies with the same shared content leaf");
        }
    }

    // ---- 失败 1：完整真实证明 + 改变过的待验证内容 ------------------------
    // 读取仍然成功；成员校验明确拒绝并给出非空原因。
    {
        MerkleProofParseResult parsed = expect_parse_ok(
            last_raw, "re-read real proof before altered-content verification");
        if (parsed.ok()) {
            const Digest altered_leaf = leaf_bytes(bytes_of("abc!"));
            check(altered_leaf != indep_leaf_abc,
                  "altered content yields a different leaf");
            const MerkleVerifyResult v =
                verify_quietly(parsed.proof, five_trusted, altered_leaf,
                               "real proof with altered content");
            check(!v.ok() && !v.valid && !v.error.empty(),
                  "altered content: proof still parses, but membership is "
                  "rejected with a non-empty reason");
        }
    }

    // ---- 失败 2：把真实证明文本截断到对象或字符串未闭合 -------------------
    // 读取失败、原因非空，且不留下可当作输入的部分证明。
    {
        check(last_raw.size() >= 3 &&
                  last_raw[last_raw.size() - 1] == '\n' &&
                  last_raw[last_raw.size() - 2] == '}' &&
                  last_raw[last_raw.size() - 3] == ']',
              "real proof ends with the siblings array close, object close "
              "and newline");

        // 去掉对象闭合 '}' 与换行：兄弟数组已闭合、证明对象未闭合。
        std::string object_unclosed = last_raw;
        object_unclosed.resize(object_unclosed.size() - 2);
        check(!object_unclosed.empty() && object_unclosed.back() == ']',
              "truncation leaves the array closed but the object open");
        expect_parse_fail(object_unclosed,
                          "real proof truncated so the JSON object is "
                          "unterminated");

        // 在 leaf 摘要字符串中间截断：字符串引号未闭合。
        const std::string marker = "\"leaf\":\"";
        const std::size_t at = last_raw.find(marker);
        check(at != std::string::npos,
              "real proof contains the leaf digest string");
        const std::size_t cut = at + marker.size() + 8;  // 64 个摘要字符只留 8 个
        check(cut < last_raw.size(), "truncation point lies inside the string");
        const std::string string_unclosed = last_raw.substr(0, cut);
        expect_parse_fail(string_unclosed,
                          "real proof truncated so a JSON string is "
                          "unterminated");

        // 失败结果没有可用的部分证明，不能再拿去校验。
        MerkleProofParseResult failed =
            branchaudit::merkle_proof_from_json(object_unclosed);
        check(!failed.ok() && !failed.error.empty(),
              "truncated real proof: read fails with a non-empty reason");
        check(failed.proof.leaf_count == 0 && failed.proof.leaf_index == 0 &&
                  failed.proof.siblings.empty(),
              "truncated real proof: no usable partial proof is returned");
    }
}

#else  // !__unix__

// 非 POSIX 平台无 fork/exec：明确跳过这组“命令行原文 -> 库”回归，
// 其余 merkle 检查照常执行（与故障注入检查的跳过处理一致）。
void test_cli_proof_roundtrip() {
    ++g_skipped;
    std::cout << "SKIP: real prove output -> library read/verify round-trip "
                 "(fork/exec is not available on this platform)\n";
}

#endif  // __unix__

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

int main(int argc, char** argv) {
    fault_test::ensure_fault_preloaded(argc, argv);

    test_empty_batch();
    test_leaf_rule();
    test_parent_rule();
    test_file_batches();
    test_relative_paths();
    test_failures();
    if (fault_test::kFaultInjectionAvailable) {
        test_io_failures();
    } else {
        // 平台无 LD_PRELOAD//proc 故障注入支持（如 macOS）：明确报告
        // 跳过，不计入已通过检查。
        ++g_skipped;
        std::cout << "SKIP: unopenable-leaf and mid-read-error checks "
                     "(fault injection not supported on this platform)\n";
    }
    test_large_files();
    test_proofs();
    test_verify_success();
    test_verify_failures();
    test_verify_claimed_numbers();
    test_verify_uint64_limits();
    test_proof_json();
    test_proof_json_unicode_escapes();
    test_cli_proof_roundtrip();

    if (g_failures == 0) {
        std::cout << "all " << g_checks << " merkle regression checks passed";
        if (g_skipped > 0) {
            std::cout << " (" << g_skipped << " platform-specific check group"
                         " skipped, not verified)";
        }
        std::cout << '\n';
        return 0;
    }
    std::cerr << g_failures << " of " << g_checks << " checks failed\n";
    return 1;
}
