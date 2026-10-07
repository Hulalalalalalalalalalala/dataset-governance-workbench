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
