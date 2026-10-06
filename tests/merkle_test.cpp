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

// 用证明中从叶子向根的兄弟逐层配对，重建根：
// side == left 表示兄弟在当前节点左侧 -> parent(sibling, current)，反之亦然。
Digest reconstruct(const branchaudit::MerkleProof& proof) {
    Digest current = proof.leaf;
    for (const branchaudit::ProofSibling& sibling : proof.siblings) {
        current = (sibling.side == branchaudit::ProofSide::kLeft)
                      ? branchaudit::merkle_parent(sibling.digest, current)
                      : branchaudit::merkle_parent(current, sibling.digest);
    }
    return current;
}

branchaudit::MerkleProof proof_of(const std::vector<fs::path>& paths,
                                  std::size_t index) {
    const branchaudit::MerkleProofResult r =
        branchaudit::merkle_proof_files(paths, index);
    check(r.ok(), std::string("merkle_proof_files succeeds: ") + r.error);
    return r.proof;
}

// 对一批大小逐一检查每个位置：证明自洽（重建得到 root）且与 root 接口一致。
void check_all_indices(const std::vector<fs::path>& paths,
                       std::string_view label) {
    const Digest root = root_of(paths);
    for (std::size_t idx = 0; idx < paths.size(); ++idx) {
        const branchaudit::MerkleProof proof = proof_of(paths, idx);
        check(proof.leaf_count == paths.size(),
              std::string(label) + ": leaf_count equals batch size");
        check(proof.leaf_index == idx,
              std::string(label) + ": leaf_index echoed");
        check(proof.root == root,
              std::string(label) + ": proof root equals root-of-same-batch");
        check(reconstruct(proof) == root,
              std::string(label) + ": proof reconstructs to root");
    }
}

std::pair<std::string, std::string> silent_proof(
        const std::vector<fs::path>& paths, std::size_t index,
        branchaudit::MerkleProofResult* out) {
    std::stringstream cap_out, cap_err;
    auto* old_out = std::cout.rdbuf(cap_out.rdbuf());
    auto* old_err = std::cerr.rdbuf(cap_err.rdbuf());
    *out = branchaudit::merkle_proof_files(paths, index);
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

// ---- 单文件成员证明 -------------------------------------------------------

void test_proof() {
    TempArea tmp("proof");

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

    // 单文件批次：siblings 为空，root 即叶子（单个空文件也如此）。
    {
        const branchaudit::MerkleProof proof = proof_of({f_a}, 0);
        check(proof.leaf_count == 1 && proof.leaf_index == 0,
              "single-file proof counts/index");
        check(proof.leaf == leaf_bytes(a), "single-file proof leaf");
        check(proof.root == leaf_bytes(a), "single-file proof root equals leaf");
        check(proof.siblings.empty(), "single-file proof has no siblings");
    }
    {
        const branchaudit::MerkleProof proof = proof_of({f_empty}, 0);
        check(proof.leaf == leaf_bytes(empty) && proof.root == leaf_bytes(empty),
              "single empty file proof: root equals its 0x00-prefixed leaf");
        check(proof.siblings.empty(),
              "single empty file proof has no siblings");
        check(proof.root != branchaudit::merkle_empty_root(),
              "single empty file proof root differs from empty batch root");
    }

    // 两文件：一个右兄弟；被选位置在右侧时兄弟在左。
    {
        const branchaudit::MerkleProof p0 = proof_of({f_a, f_abc}, 0);
        check(p0.siblings.size() == 1, "2-file idx0: one sibling");
        check(p0.siblings[0].side == branchaudit::ProofSide::kRight,
              "2-file idx0: sibling on the right");
        check(p0.siblings[0].digest == leaf_bytes(abc),
              "2-file idx0: sibling is the other leaf");
        check(reconstruct(p0) == p0.root, "2-file idx0 reconstructs");

        const branchaudit::MerkleProof p1 = proof_of({f_a, f_abc}, 1);
        check(p1.siblings.size() == 1 &&
                  p1.siblings[0].side == branchaudit::ProofSide::kLeft &&
                  p1.siblings[0].digest == leaf_bytes(a),
              "2-file idx1: one sibling on the left");
        check(reconstruct(p1) == p1.root, "2-file idx1 reconstructs");
        check(p0.root == p1.root &&
                  p0.root == branchaudit::merkle_parent(
                                  leaf_bytes(a), leaf_bytes(abc)),
              "both proofs share the independently-defined root");
    }

    // 三文件（末节点在叶子层原样提升）：
    //   idx0：右兄弟 Lbc，再右兄弟 Lempty（提升上来的同一摘要）；
    //   idx2（末位置）：叶子层无兄弟（原样提升），上一层有左兄弟
    //         parent(La,Lbc)——提升层不得产生记录。
    {
        const Digest la = leaf_bytes(a);
        const Digest lbc = leaf_bytes(abc);
        const Digest le = leaf_bytes(empty);
        const Digest pair = branchaudit::merkle_parent(la, lbc);

        const branchaudit::MerkleProof p0 =
            proof_of({f_a, f_abc, f_empty}, 0);
        check(p0.siblings.size() == 2, "3-file idx0: two siblings");
        check(p0.siblings[0].side == branchaudit::ProofSide::kRight &&
                  p0.siblings[0].digest == lbc,
              "3-file idx0 sibling 0 is right leaf('abc')");
        check(p0.siblings[1].side == branchaudit::ProofSide::kRight &&
                  p0.siblings[1].digest == le,
              "3-file idx0 sibling 1 is the promoted leaf('')");
        check(reconstruct(p0) == p0.root, "3-file idx0 reconstructs");

        const branchaudit::MerkleProof p2 =
            proof_of({f_a, f_abc, f_empty}, 2);
        check(p2.siblings.size() == 1,
              "3-file idx2: promoted level adds no sibling record");
        check(p2.siblings[0].side == branchaudit::ProofSide::kLeft &&
                  p2.siblings[0].digest == pair,
              "3-file idx2: sole sibling is the left pair at the upper level");
        check(reconstruct(p2) == p2.root, "3-file idx2 reconstructs");
        check(p0.root == p2.root, "3-file: proofs for both indices share root");
    }

    // 多种规模（含 4~8 与重复路径/相同内容）：每个位置逐一重建并核对根。
    const std::vector<fs::path> batch5 = {
        f_a, f_abc, f_empty, f_hello, f_a};
    check_all_indices(batch5, "5-file batch");
    check_all_indices({f_a, f_abc, f_empty, f_hello}, "4-file batch");

    std::array<fs::path, 8> eight;
    for (std::size_t i = 0; i < eight.size(); ++i) {
        eight[i] = tmp.root / ("eight" + std::to_string(i) + ".bin");
        write_file(eight[i], pattern(1 + i * 13));
    }
    check_all_indices({eight.begin(), eight.end()}, "8-file batch");
    // 七文件：跨多层奇数提升；末位置的提升层必须全部跳过。
    check_all_indices({eight.begin(), eight.begin() + 7}, "7-file batch");
    // 六文件：不同位置在中间层成为奇数末节点。
    check_all_indices({eight.begin(), eight.begin() + 6}, "6-file batch");

    // 重复路径、相同内容各占独立位置：证明按位置区分，不去重。
    check_all_indices({f_a, f_a}, "repeated same path");
    {
        const fs::path f_a_copy = tmp.root / "copy of a.bin";
        write_file(f_a_copy, a);
        const branchaudit::MerkleProof p0 = proof_of({f_a, f_a_copy}, 0);
        const branchaudit::MerkleProof p1 = proof_of({f_a, f_a_copy}, 1);
        check(p0.leaf == p1.leaf && p0.siblings[0].digest == p1.leaf,
              "identical contents: proof still carries a real sibling position");
        check(reconstruct(p0) == root_of({f_a, f_a}),
              "equal-content batch root matches repeated-path root");
    }

    // 证明不含路径文字：无法直接检查摘要内容，但同序内容换路径后证明
    // （leaf/root/siblings）完全一致。
    {
        const fs::path alt_dir = tmp.root / "子 目录";
        const fs::path g0 = alt_dir / "空.bin";
        const fs::path g1 = alt_dir / "a file.dat";
        const fs::path g2 = tmp.root / "深 路径" / "文 件.bin";
        write_file(g0, empty);
        write_file(g1, a);
        write_file(g2, abc);
        for (std::size_t idx = 0; idx < 3; ++idx) {
            const branchaudit::MerkleProof p1 =
                proof_of({f_empty, f_a, f_abc}, idx);
            const branchaudit::MerkleProof p2 = proof_of({g0, g1, g2}, idx);
            check(p1.leaf == p2.leaf && p1.root == p2.root &&
                      p1.siblings.size() == p2.siblings.size(),
                  "proof is path-independent: same ordered contents, other paths");
            for (std::size_t s = 0; s < p1.siblings.size(); ++s) {
                check(p1.siblings[s].side == p2.siblings[s].side &&
                          p1.siblings[s].digest == p2.siblings[s].digest,
                      "proof siblings are path-independent");
            }
        }
    }
}

// ---- 证明：空批次、越界位置 -----------------------------------------------

void test_proof_bad_index() {
    TempArea tmp("proofidx");
    const fs::path f_a = tmp.root / "a.bin";
    write_file(f_a, bytes_of("a"));

    branchaudit::MerkleProofResult r =
        branchaudit::merkle_proof_files({}, 0);
    check(!r.ok(), "empty batch: no valid position, proof fails");
    check(r.proof.siblings.empty(), "empty batch failure: no partial proof");

    r = branchaudit::merkle_proof_files({f_a}, 1);
    check(!r.ok(), "index == batch size is out of range");
    r = branchaudit::merkle_proof_files({f_a}, 128);
    check(!r.ok(), "index beyond batch size is out of range");

    // 成功路径仍然正常（错误返回不污染）。
    r = branchaudit::merkle_proof_files({f_a}, 0);
    check(r.ok(), "in-range index succeeds");
}

// ---- 证明：文件失败即整次失败、不输出部分证明、库保持静默 -----------------

void test_proof_failures() {
    TempArea tmp("prooffail");
    const fs::path good1 = tmp.root / "good1.bin";
    const fs::path good2 = tmp.root / "good2.bin";
    write_file(good1, bytes_of("a"));
    write_file(good2, bytes_of("abc"));

    const fs::path missing = tmp.root / "does not exist 缺失.bin";
    const fs::path dir = tmp.root / "a dir 目录";
    fs::create_directories(dir);

    for (std::size_t chosen : {0u, 1u}) {
        // 被选位置是正常文件，但批次中另有缺失：仍整次失败。
        branchaudit::MerkleProofResult r =
            branchaudit::merkle_proof_files({good1, missing}, chosen);
        check(!r.ok(), "missing file among batch: proof fails");
        check(r.error.find(missing.string()) != std::string::npos,
              "missing file: error names the failed path");
        check(r.proof.siblings.empty() &&
                  r.proof.leaf_count == 0 && r.proof.leaf_index == 0,
              "missing file: no partial proof fields are populated");

        r = branchaudit::merkle_proof_files({good1, dir, good2}, chosen);
        check(!r.ok() && r.error.find(dir.string()) != std::string::npos,
              "directory among files: proof fails and names the directory");
    }

    // 库接口不打印、不退出：即使失败也没有任何 stdout/stderr。
    {
        branchaudit::MerkleProofResult r;
        auto captured = silent_proof({good1, missing}, 0, &r);
        check(!r.ok() && captured.first.empty() && captured.second.empty(),
              "proof failure: library prints nothing, does not exit");
    }
    {
        branchaudit::MerkleProofResult r;
        auto captured = silent_proof({good1, good2}, 0, &r);
        check(r.ok() && captured.first.empty() && captured.second.empty(),
              "proof success: library prints nothing");
    }
}

// ---- 证明：打开失败 / 读取中途失败的故障注入 ------------------------------

void test_proof_io_failures() {
    TempArea tmp("proofio");
    const fs::path good1 = tmp.root / "good1.bin";
    const fs::path good2 = tmp.root / "good2.bin";
    const fs::path bad = tmp.root / "present 出错.bin";
    constexpr long kPartial = 40;
    write_file(good1, bytes_of("normal-file-one"));
    write_file(good2, bytes_of("normal-file-two"));
    write_file(bad, pattern(200));

    // 无注入时基线成功。
    check(proof_of({good1, bad, good2}, 0).siblings.size() == 2,
          "proof iofail fixtures succeed without injected fault");

    // 打开失败：被选位置正常、坏文件在其后，仍整次失败且无部分证明。
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_OPEN_FAIL", bad.string());
        branchaudit::MerkleProofResult r;
        auto captured = silent_proof({good1, good2, bad}, 0, &r);
        check(!r.ok(), "proof: open failure makes whole batch fail");
        check(r.error.find(bad.string()) != std::string::npos,
              "proof open failure names the real failing file");
        check(r.proof.siblings.empty(),
              "proof open failure returns no partial proof");
        check(captured.first.empty() && captured.second.empty(),
              "proof open failure: library prints nothing");
    }

    // 读取中途失败：被选叶子本身读到一半出错，部分叶子不得成为结果。
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_READ_FAIL",
            bad.string() + ":" + std::to_string(kPartial));
        branchaudit::MerkleProofResult r;
        auto captured = silent_proof({good1, bad}, 1, &r);
        check(!r.ok(), "proof: mid-read failure on selected leaf fails");
        check(r.error.find(bad.string()) != std::string::npos &&
                  r.error.find("read") != std::string::npos,
              "proof read failure names file and states read error");
        const Digest partial = branchaudit::merkle_leaf(
            pattern(200).data(), static_cast<std::size_t>(kPartial));
        check(r.proof.leaf != partial && r.proof.siblings.empty(),
              "proof read failure: partial leaf is not returned");
        check(captured.first.empty() && captured.second.empty(),
              "proof read failure: library prints nothing");
    }
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
    test_proof();
    test_proof_bad_index();
    test_proof_failures();
    if (fault_test::kFaultInjectionAvailable) {
        test_io_failures();
        test_proof_io_failures();
    } else {
        // 平台无 LD_PRELOAD//proc 故障注入支持（如 macOS）：明确报告
        // 跳过，不计入已通过检查。
        ++g_skipped;
        std::cout << "SKIP: unopenable-leaf and mid-read-error checks "
                     "(fault injection not supported on this platform)\n";
    }
    test_large_files();

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
