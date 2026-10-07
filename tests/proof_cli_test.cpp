// branchaudit “命令行 prove 输出 → 库读取 → 库校验”端到端回归测试
//（无第三方依赖，链接 branchaudit_core，经 BRANCHAUDIT_CLI 取得真实
// branchaudit 可执行文件路径）。
//
// 与 merkle_unit 的区别：那里的 JSON 文本由测试自行拼接；本套件里的证明
// 文本逐字节来自真实 `prove` 命令的标准输出（保持原文及末尾换行），可信根
// 来自对同一有序批次另行执行的 `root` 命令——绝不拿证明里的 root 字段充当
// 可信来源。读取（merkle_proof_from_json）与校验（merkle_verify_proof）
// 都只返回结构化结果，不向标准输出/标准错误写内容，本套件对此一并截获检查。
//
// 运行成功返回 0；任一断言失败返回非零。

#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "merkle.h"

#ifndef BRANCHAUDIT_CLI
#error "BRANCHAUDIT_CLI must name the built branchaudit executable"
#endif

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
using branchaudit::MerkleProof;
using branchaudit::MerkleProofParseResult;
using branchaudit::MerkleSibling;
using branchaudit::MerkleVerifyResult;

const fs::path g_cli = BRANCHAUDIT_CLI;

std::string hex_of(const Digest& d) { return branchaudit::to_hex(d); }

// 待验证内容的内容叶子：现有规则 SHA-256(0x00 || content)，带单个 0x00
// 前缀字节——绝不能用 hash/sha256_file 的普通摘要代替。
Digest leaf_of(std::string_view content) {
    return branchaudit::merkle_leaf(
        reinterpret_cast<const unsigned char*>(content.data()), content.size());
}

// 独立的小写十六进制解码（测试本地实现，只接受恰好 64 个小写十六进制
// 字符），用于把 root 命令输出的可信根还原为 32 个原始字节。
bool hex_to_digest(std::string_view hex, Digest& out) {
    if (hex.size() != 64) {
        return false;
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = nibble(hex[2 * i]);
        const int lo = nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

struct TempArea {
    fs::path root;
    explicit TempArea(const std::string& tag) {
        const auto cwd_hash = std::hash<fs::path>{}(fs::current_path());
        root = fs::temp_directory_path() /
               ("branchaudit_proof_cli_test_" + tag + "_" +
                std::to_string(static_cast<std::uint64_t>(cwd_hash)));
        fs::remove_all(root);
        fs::create_directories(root);
    }
    ~TempArea() { std::error_code ec; fs::remove_all(root, ec); }
};

void write_file(const fs::path& p, std::string_view content) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    check(static_cast<bool>(out), std::string("write fixture ") + p.string());
}

// ---- 真实命令行执行 ---------------------------------------------------------

struct CliResult {
    int code = -1;
    std::string out;
    std::string err;
};

std::string read_all(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in),
                       std::istreambuf_iterator<char>());
}

// 以真实子进程执行 branchaudit，把标准输出/标准错误分别重定向到文件后
// 逐字节读回：证明文本保持命令实际输出的原文（含末尾换行），不经测试
// 重新拼接。
CliResult run_cli(const fs::path& work, const std::vector<std::string>& args) {
    const fs::path out_path = work / "cli-stdout.bin";
    const fs::path err_path = work / "cli-stderr.bin";
    fs::remove(out_path);
    fs::remove(err_path);
    std::string cmd = "\"" + g_cli.string() + "\"";
    for (const std::string& a : args) {
        cmd += " \"" + a + "\"";
    }
    cmd += " >\"" + out_path.string() + "\" 2>\"" + err_path.string() + "\"";
    CliResult r;
    r.code = std::system(cmd.c_str());
    r.out = read_all(out_path);
    r.err = read_all(err_path);
    return r;
}

// 真实 prove 命令的标准输出原文（含末尾换行）。
std::string cli_prove(const fs::path& work, std::uint64_t index,
                      const std::vector<fs::path>& batch) {
    std::vector<std::string> args{"prove", std::to_string(index)};
    for (const fs::path& p : batch) {
        args.push_back(p.string());
    }
    const CliResult r = run_cli(work, args);
    check(r.code == 0, "prove exits 0");
    check(r.err.empty(), "prove writes nothing to stderr");
    check(r.out.size() > 1 && r.out.back() == '\n',
          "prove stdout is a JSON object plus a trailing newline");
    check(r.out.rfind("{\"version\":1,", 0) == 0,
          "prove stdout starts with the version 1 object");
    return r.out;
}

// 可信根：对同一有序批次另行执行 root 命令取得（独立获得，不取自证明）。
Digest cli_root(const fs::path& work, const std::vector<fs::path>& batch) {
    std::vector<std::string> args{"root"};
    for (const fs::path& p : batch) {
        args.push_back(p.string());
    }
    const CliResult r = run_cli(work, args);
    check(r.code == 0, "root exits 0");
    check(r.err.empty(), "root writes nothing to stderr");
    check(r.out.size() == 65 && r.out.back() == '\n',
          "root stdout is 64 lowercase hex chars plus a newline");
    Digest d{};
    check(hex_to_digest(r.out.substr(0, 64), d),
          "root stdout parses as lowercase hex");
    return d;
}

// ---- 库调用的输出截获：读取/校验接口只返回结果，不打印 ----------------------

template <typename F>
std::pair<std::string, std::string> capture_stdio(F&& f) {
    std::stringstream cap_out, cap_err;
    auto* old_out = std::cout.rdbuf(cap_out.rdbuf());
    auto* old_err = std::cerr.rdbuf(cap_err.rdbuf());
    f();
    std::cout.rdbuf(old_out);
    std::cerr.rdbuf(old_err);
    return {cap_out.str(), cap_err.str()};
}

MerkleProofParseResult parse_silent(const std::string& text,
                                    std::string_view what) {
    MerkleProofParseResult r;
    const auto cap = capture_stdio(
        [&] { r = branchaudit::merkle_proof_from_json(text); });
    check(cap.first.empty() && cap.second.empty(),
          std::string("parse prints nothing to stdout/stderr: ") +
              std::string(what));
    return r;
}

MerkleVerifyResult verify_silent(const MerkleProof& proof,
                                 const Digest& trusted_root,
                                 const Digest& content_leaf,
                                 std::string_view what) {
    MerkleVerifyResult v;
    const auto cap = capture_stdio([&] {
        v = branchaudit::merkle_verify_proof(proof, trusted_root, content_leaf);
    });
    check(cap.first.empty() && cap.second.empty(),
          std::string("verify prints nothing to stdout/stderr: ") +
              std::string(what));
    return v;
}

// ---- 正常：单个空文件 -------------------------------------------------------
//
// 兄弟表为空、根等于空文件叶子 SHA-256(0x00)，并区别于空批次根
// SHA-256("")。（两个十六进制常量均为 hashlib/OpenSSL 独立计算的公开值。）
void test_single_empty_file() {
    TempArea tmp("single_empty");
    const fs::path f_empty = tmp.root / "empty.bin";
    write_file(f_empty, "");

    const std::string proof_text = cli_prove(tmp.root, 0, {f_empty});
    const Digest trusted = cli_root(tmp.root, {f_empty});
    const Digest empty_batch_root = cli_root(tmp.root, {});

    check(hex_of(trusted) ==
              "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
          "single empty file: trusted root is the leaf SHA-256(0x00)");
    check(hex_of(empty_batch_root) ==
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "empty batch root is SHA-256 of the empty byte sequence");
    check(trusted != empty_batch_root,
          "single empty file root differs from the empty batch root");

    const MerkleProofParseResult parsed =
        parse_silent(proof_text, "single empty file proof");
    check(parsed.ok(), std::string("single empty file proof parses: ") +
                           parsed.error);
    if (!parsed.ok()) {
        return;
    }
    const MerkleProof& p = parsed.proof;
    check(p.leaf_count == 1 && p.leaf_index == 0,
          "single empty file: count 1, zero-based index 0");
    check(p.siblings.empty(), "single empty file: sibling list is empty");
    check(p.root == p.leaf, "single empty file: root equals the leaf");
    check(p.root == trusted,
          "single empty file: proof root matches the independently "
          "obtained trusted root");
    check(p.root != empty_batch_root,
          "single empty file: proof root is not the empty batch root");

    // 待验证内容为空字节序列，按 0x00 前缀叶子规则计算内容叶子。
    const MerkleVerifyResult v =
        verify_silent(p, trusted, leaf_of(""), "single empty file");
    check(v.ok() && v.valid && v.error.empty(),
          std::string("single empty file proof verifies against the "
                      "trusted root: ") +
              v.error);
}

// ---- 正常：五文件批次（含重复内容）的最后一个位置 ----------------------------
//
// 树形 5 -> 3 -> 2 -> 1：位置 4 在首两层都是奇数末节点，连续两次原样
// 提升，省略的层不补记录，只剩顶层一个 left 兄弟。批次中位置 0/2 内容
// 相同、位置 1/4 内容相同：位置仍按传入顺序保留（leaf_count 为 5），
// 不按内容去重。可信根由另行执行的 root 命令取得；取得证明文本与可信
// 根后删除全部批次文件——读取与校验只需要证明、可信根与待验证内容。
void test_five_files_last_position() {
    TempArea tmp("five_files");
    const std::array<std::string, 5> contents = {"alpha", "beta", "alpha",
                                                 "gamma", "beta"};
    std::vector<fs::path> batch;
    for (std::size_t i = 0; i < contents.size(); ++i) {
        batch.push_back(tmp.root / ("f" + std::to_string(i) + ".bin"));
        write_file(batch.back(), contents[i]);
    }

    const std::string proof_text = cli_prove(tmp.root, 4, batch);
    // 相同内容的另一个位置（位置 1，内容与位置 4 相同）也取一份真实证明，
    // 用来确认重复内容各占独立位置。
    const std::string dup_proof_text = cli_prove(tmp.root, 1, batch);
    const Digest trusted = cli_root(tmp.root, batch);

    // 校验一侧不依赖整批文件：拿到证明与可信根后即删除批次文件。
    for (const fs::path& p : batch) {
        fs::remove(p);
    }

    const Digest l_alpha = leaf_of("alpha");
    const Digest l_beta = leaf_of("beta");
    const Digest l_gamma = leaf_of("gamma");
    // 位置 4 唯一兄弟：左子树 parent(parent(L0,L1), parent(L2,L3))。
    const Digest left_subtree = branchaudit::merkle_parent(
        branchaudit::merkle_parent(l_alpha, l_beta),
        branchaudit::merkle_parent(l_alpha, l_gamma));

    const MerkleProofParseResult parsed =
        parse_silent(proof_text, "five-file last position proof");
    check(parsed.ok(), std::string("five-file last position proof parses: ") +
                           parsed.error);
    if (!parsed.ok()) {
        return;
    }
    const MerkleProof& p = parsed.proof;
    check(p.leaf_count == 5,
          "five files with duplicate contents: count stays 5, no "
          "content-based deduplication");
    check(p.leaf_index == 4, "five files: zero-based last position 4");
    check(p.leaf == l_beta,
          "five files: leaf is the 0x00-prefixed leaf of the last file");
    check(p.root == trusted,
          "five files: proof root matches the independently obtained "
          "trusted root");
    check(p.siblings.size() == 1,
          "five files index 4: promoted levels are omitted, not padded "
          "(a single record for three levels)");
    check(p.siblings.size() == 1 &&
              p.siblings[0].side == MerkleSibling::Side::left &&
              p.siblings[0].digest == left_subtree,
          "five files index 4: the only sibling is the left subtree at "
          "the top level");

    const MerkleVerifyResult v =
        verify_silent(p, trusted, leaf_of("beta"), "five-file last position");
    check(v.ok() && v.valid && v.error.empty(),
          std::string("five-file last position proof verifies after the "
                      "batch files are gone: ") +
              v.error);

    // 重复内容按传入顺序保留位置：位置 1 与位置 4 内容相同，但兄弟记录
    // 不同；位置 1 的证明读入后也用同一份内容叶子通过校验。
    const MerkleProofParseResult dup =
        parse_silent(dup_proof_text, "duplicate content at position 1");
    check(dup.ok(), std::string("duplicate-content proof parses: ") +
                        dup.error);
    if (dup.ok()) {
        check(dup.proof.leaf_count == 5 && dup.proof.leaf_index == 1,
              "duplicate content: position 1 kept as its own position");
        check(dup.proof.leaf == l_beta && p.leaf == dup.proof.leaf,
              "duplicate content: positions 1 and 4 share the same leaf");
        check(dup.proof.siblings.size() == 3 &&
                  dup.proof.siblings[0].side == MerkleSibling::Side::left &&
                  dup.proof.siblings[0].digest == l_alpha &&
                  dup.proof.siblings[1].side == MerkleSibling::Side::right &&
                  dup.proof.siblings[1].digest ==
                      branchaudit::merkle_parent(l_alpha, l_gamma) &&
                  dup.proof.siblings[2].side == MerkleSibling::Side::right &&
                  dup.proof.siblings[2].digest == l_beta,
              "duplicate content: position 1 keeps its own sibling path "
              "(side, digest, leaf-to-root order preserved)");
        const MerkleVerifyResult dv = verify_silent(
            dup.proof, trusted, leaf_of("beta"), "duplicate position 1");
        check(dv.ok(),
              std::string("duplicate content at position 1 verifies with "
                          "the same content leaf: ") +
                  dv.error);
    }

    // 失败一：完整证明配上改变过的待验证内容——读取仍然成功，成员校验
    // 必须明确拒绝并返回非空原因。
    const MerkleProofParseResult reparsed =
        parse_silent(proof_text, "proof re-read before altered content");
    check(reparsed.ok(),
          "full proof still parses when the content is later altered");
    const MerkleVerifyResult bad = verify_silent(
        reparsed.proof, trusted, leaf_of("betb"), "altered content");
    check(!bad.ok() && !bad.valid,
          "altered content (betb instead of beta) is rejected");
    check(!bad.error.empty(),
          "altered content rejection returns a non-empty displayable "
          "reason");
}

// ---- 失败：截断的真实证明文本 ------------------------------------------------
//
// 把真实 prove 输出截断到 JSON 对象未闭合、字符串未闭合两种形态：读取
// 必须失败、返回非空可展示原因，且失败结果没有可用的部分证明（保持
// 默认构造状态），不再当作可校验的输入。
void test_truncated_proof() {
    TempArea tmp("truncated");
    const fs::path f0 = tmp.root / "t0.bin";
    const fs::path f1 = tmp.root / "t1.bin";
    write_file(f0, "truncate-me-one");
    write_file(f1, "truncate-me-two");

    const std::string proof_text = cli_prove(tmp.root, 1, {f0, f1});
    check(proof_text.size() > 80, "truncation fixture proof is long enough");

    auto expect_truncated_failure = [&](const std::string& text,
                                        std::string_view what) {
        const MerkleProofParseResult r = parse_silent(text, what);
        check(!r.ok(),
              std::string("truncated proof is rejected: ") +
                  std::string(what));
        check(!r.error.empty(),
              std::string("truncated proof failure gives a non-empty "
                          "displayable reason: ") +
                  std::string(what));
        check(r.proof.leaf_count == 0 && r.proof.leaf_index == 0 &&
                  r.proof.siblings.empty(),
              std::string("truncated proof failure yields no usable "
                          "partial proof: ") +
                  std::string(what));
    };

    // JSON 对象未闭合：去掉末尾的 "}\n"，兄弟数组已闭合但对象没有。
    expect_truncated_failure(proof_text.substr(0, proof_text.size() - 2),
                             "object left unclosed");

    // 字符串未闭合：在 root 摘要的十六进制文本中间截断。
    const std::string marker = "\"root\":\"";
    const std::size_t at = proof_text.find(marker);
    check(at != std::string::npos, "fixture proof contains the root field");
    expect_truncated_failure(proof_text.substr(0, at + marker.size() + 20),
                             "digest string left unclosed");
}

}  // namespace

int main() {
    check(fs::exists(g_cli),
          std::string("branchaudit executable exists: ") + g_cli.string());

    test_single_empty_file();
    test_five_files_last_position();
    test_truncated_proof();

    if (g_failures == 0) {
        std::cout << "all " << g_checks
                  << " proof cli-to-library regression checks passed\n";
        return 0;
    }
    std::cerr << g_failures << " of " << g_checks << " checks failed\n";
    return 1;
}
