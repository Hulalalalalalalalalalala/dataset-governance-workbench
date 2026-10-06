// branchaudit SHA-256 回归测试（无第三方依赖，链接 branchaudit_core）。
//
// 预期摘要的独立依据：
//   - 空串、"abc"、56 字节 NIST 向量、1,000,000 个 'a'：FIPS 180-4 附录 B
//     公布的标准测试向量。
//   - 其余常量：由系统独立实现 sha256sum（coreutils）与 Python hashlib
//     （OpenSSL）分别计算并交叉核对一致，不使用本项目代码生成期望值。
//
// 运行成功返回 0；任一断言失败返回非零。

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
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
#include "sha256.h"
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

std::string hex_of(const std::array<std::uint8_t, branchaudit::Sha256::kDigestSize>& d) {
    return branchaudit::to_hex(d);
}

// 一次性提交全部字节。
std::string hash_whole(const std::vector<unsigned char>& data) {
    branchaudit::Sha256 sha;
    sha.update(data.data(), data.size());
    return hex_of(sha.final());
}

// 按给定偏移分段提交（偏移为相对起点的累计切分点，0 与 data.size() 可省略）。
std::string hash_parts(const std::vector<unsigned char>& data,
                       const std::vector<std::size_t>& cuts) {
    branchaudit::Sha256 sha;
    std::size_t prev = 0;
    for (std::size_t cut : cuts) {
        sha.update(data.data() + prev, cut - prev);
        prev = cut;
    }
    sha.update(data.data() + prev, data.size() - prev);
    return hex_of(sha.final());
}

std::vector<unsigned char> fill_a(std::size_t n) {
    return std::vector<unsigned char>(n, static_cast<unsigned char>('a'));
}

// 确定性字节序列，覆盖 0x00 与 0xff。
std::vector<unsigned char> pattern(std::size_t n) {
    std::vector<unsigned char> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<unsigned char>((i * 31 + 7) % 256);
    }
    return v;
}

void expect_digest(std::string_view label, const std::vector<unsigned char>& data,
                   std::string_view expected) {
    check(hash_whole(data) == expected, label);
}

// ---- 超长消息：2^32 比特长度编码边界（512 MiB） ---------------------------
//
// SHA-256 在最后一个分组里以 8 字节大端写入消息的【比特】长度。输入字节数
// 越过 2^32/8 = 536870912（512 MiB）后，该长度字段的高 32 位不再为零。
// 若实现只保留长度的低 32 位、让总长度回绕、或把字节数直接当作比特数，
// 越过边界后的摘要都会改变：
//   - 长度按 32 位回绕时，2^29 字节（恰 2^32 比特）的编码与空消息相同，
//     2^29+1 字节的编码与 1 字节相同；
//   - 字节数误当比特数时，2^29 字节的编码相当于 64 MiB 消息。
// 下面的标准答案能区分这些错误。
//
// 期望值的独立依据：均由系统 coreutils sha256sum 与 Python hashlib
// （OpenSSL）对同一份真实字节分别计算、交叉核对一致，不使用本项目代码
// 生成；两者与被测实现互不共用代码。
//
// 内存有界：最长输入也只反复复用小块缓冲喂入增量接口，绝不把整份消息
// 一次装入内存；消息总长度只来自实际 update() 的全部字节。

constexpr std::uint64_t kLargeBoundaryBytes = 1uLL << 29;  // 2^29 字节 = 2^32 比特

// 用固定大小缓冲把 n 个 fill 字节流式追加进 sha；内存占用与 n 无关。
void feed_fill(branchaudit::Sha256& sha, std::uint64_t n,
               unsigned char fill, std::size_t chunk) {
    std::vector<unsigned char> block(chunk, fill);
    while (n > 0) {
        const std::size_t take =
            static_cast<std::size_t>(std::min<std::uint64_t>(chunk, n));
        sha.update(block.data(), take);
        n -= take;
    }
}

// 全 'a' 消息按指定块大小逐段提交的摘要。
std::string hash_fill_stream(std::uint64_t n, std::size_t chunk) {
    branchaudit::Sha256 sha;
    feed_fill(sha, n, 'a', chunk);
    return hex_of(sha.final());
}

void test_large_length_encoding() {
    struct LongCase {
        std::uint64_t n;
        const char* hex;
        const char* meaning;
    };
    const LongCase long_cases[] = {
        {kLargeBoundaryBytes - 1,
         "1f97811a3a059e582b3753e94d8852bd89740248c5f35911f8e70afdd57f9842",
         "boundary minus one: bit length still fits in low 32 bits"},
        {kLargeBoundaryBytes,
         "b9045a713caed5dff3d3b783e98d1ce5778d8bc331ee4119d707072312af06a7",
         "exactly 2^32 bits: length high word is 1, low word is 0"},
        {kLargeBoundaryBytes + 1,
         "bf6084769b780af4396e058ef0eaf9ca59366db146ca86ebfcaf58cbf7a35669",
         "boundary plus one: bits above the low 32 must affect digest"},
    };

    // 三种长度各自经增量接口（1 MiB 分段）匹配独立标准摘要；摘要对象
    // 各只完整扫描一次并复用于后续比较。
    std::string before_digest, exact_digest, over_digest;
    for (const auto& c : long_cases) {
        const std::string got = hash_fill_stream(c.n, 1u << 20);
        check(got == c.hex,
              std::string("long message n=") + std::to_string(c.n) +
              " bytes via incremental API (1 MiB chunks): " + c.meaning);
        if (c.n == kLargeBoundaryBytes - 1) before_digest = got;
        if (c.n == kLargeBoundaryBytes) exact_digest = got;
        if (c.n == kLargeBoundaryBytes + 1) over_digest = got;
    }

    // 三个长度的摘要必须两两不同：长度字段的高、低 32 位都真实参与了
    // 最终摘要（回绕到空消息/1 字节长度的错误会被这里和上面的精确匹配抓住）。
    check(before_digest != exact_digest && exact_digest != over_digest &&
              before_digest != over_digest,
          "long messages n=536870911/536870912/536870913 have distinct digests "
          "(length word, including its high 32 bits, affects the digest)");
    check(exact_digest !=
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "n=536870912 must not wrap to the empty-message length encoding");
    {
        branchaudit::Sha256 one;
        const unsigned char a = 'a';
        one.update(&a, 1);
        check(over_digest != hex_of(one.final()),
              "n=536870913 must not wrap to the 1-byte length encoding");
    }

    // 越过边界的同一份消息：在边界附近采用不同分段，必须得到同一个标准
    // 摘要。边界点 2^29 相对 64 字节分组余 0（2^29 = 64*2^23），其前后
    // 一字节分别落在相邻分组，故切分点选在 2^29-1、2^29 会把跨边界分组
    // 逐字节拆开。
    const std::string expected_over =
        "bf6084769b780af4396e058ef0eaf9ca59366db146ca86ebfcaf58cbf7a35669";

    // 变体 A：(2^29-1) + 1 + 1 —— 边界前后两个字节各自单独提交。
    {
        branchaudit::Sha256 sha;
        feed_fill(sha, kLargeBoundaryBytes - 1, 'a', 1u << 20);
        const unsigned char b1 = 'a', b2 = 'a';
        sha.update(&b1, 1);
        sha.update(&b2, 1);
        check(hex_of(sha.final()) == expected_over,
              "over-boundary n=536870913 split (2^29-1)+1+1 via incremental API");
    }

    // 变体 B：边界前后共 193 字节全部逐字节提交，跨边界的分组被拆成
    // 多次 1 字节 update；前面的海量字节仍以 1 MiB 分段提交。
    {
        constexpr std::uint64_t kTail = 193;  // 3*64+1，覆盖字节 2^29
        branchaudit::Sha256 sha;
        feed_fill(sha, kLargeBoundaryBytes + 1 - kTail, 'a', 1u << 20);
        for (std::uint64_t i = 0; i < kTail; ++i) {
            const unsigned char b = 'a';
            sha.update(&b, 1);
        }
        check(hex_of(sha.final()) == expected_over,
              "over-boundary n=536870913 with last 193 bytes fed one at a time");
    }

    // 变体 C：从边界前 4096 字节起（含边界字节 2^29，共 4097 字节）按
    // 63 字节错位块提交（每次 update 都横跨 64 字节分组边界，最后一块
    // 恰好把字节 2^29-1、2^29 一起交付，跨过边界所在分组），其余字节
    // 仍 1 MiB 流式；缓冲只分配一次。
    {
        constexpr std::uint64_t kStraddle = 4096;
        constexpr std::uint64_t kRegion = kStraddle + 1;  // 字节 2^29-4096 .. 2^29
        branchaudit::Sha256 sha;
        feed_fill(sha, kLargeBoundaryBytes - kStraddle, 'a', 1u << 20);
        const std::vector<unsigned char> mis(63, 'a');
        std::uint64_t remaining = kRegion;
        while (remaining >= mis.size()) {
            sha.update(mis.data(), mis.size());
            remaining -= mis.size();
        }
        if (remaining > 0) {
            sha.update(mis.data(), static_cast<std::size_t>(remaining));
        }
        check(hex_of(sha.final()) == expected_over,
              "over-boundary n=536870913 with 63-byte misaligned chunks "
              "straddling the boundary");
    }

    // 最后一段属于输入：越过边界的消息把末字节改为 'b'，必须得到另一个
    // 独立标准摘要；它既不同于全 'a' 结果，也不是前 2^29 字节（恰好
    // 2^32 比特）的摘要。
    {
        branchaudit::Sha256 sha;
        feed_fill(sha, kLargeBoundaryBytes, 'a', 1u << 20);
        const unsigned char tail = 'b';
        sha.update(&tail, 1);
        const std::string tail_digest = hex_of(sha.final());
        check(tail_digest ==
                  "91d4098afec4bb6731e4dba873b3c9a9c581cd4800086ac2fbb4175c21992375",
              "over-boundary n=536870913 last byte 'b' matches independent standard");
        check(tail_digest != expected_over,
              "over-boundary: last segment is part of the input, not omitted "
              "(digest differs from all-'a')");
        check(tail_digest != exact_digest,
              "over-boundary: digest is not that of the first 2^29 bytes only");
    }
}

// ---- 标准已知答案向量 -----------------------------------------------------

void test_standard_vectors() {
    // FIPS 180-4 附录 B.1：空串
    expect_digest("empty (FIPS 180-4)", {},
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // FIPS 180-4 附录 B.2："abc"
    expect_digest("abc (FIPS 180-4)",
                  {'a', 'b', 'c'},
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // FIPS 180-4 附录 B.3：56 字节双块向量
    const std::string nist56 =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    expect_digest("FIPS 180-4 56-byte vector",
                  std::vector<unsigned char>(nist56.begin(), nist56.end()),
                  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // FIPS 180-4 附录 B.4：1,000,000 个 'a'（跨多个分组）
    expect_digest("FIPS 180-4 one million 'a'", fill_a(1'000'000),
                  "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// ---- 原始字节语义：空格、换行、零字节、高位字节 ---------------------------

void test_byte_semantics() {
    // 普通文本
    expect_digest("plain text 'hello world'",
                  std::vector<unsigned char>{'h', 'e', 'l', 'l', 'o', ' ',
                                             'w', 'o', 'r', 'l', 'd'},
                  "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");

    // 含零字节与高位字节（0xff）以及空格、换行的二进制内容
    expect_digest("binary with NUL/high/space/newline",
                  std::vector<unsigned char>{'a', 0x00, 'b', 0xff, ' ', 'c', '\n', 'd'},
                  "ae37f71921db5e6d58be22370d3f0cc73cd4fa8bcc327dccd8b881094bc03d7c");

    // 0..255 全字节循环
    std::vector<unsigned char> ramp(256);
    for (int i = 0; i < 256; ++i) ramp[i] = static_cast<unsigned char>(i);
    expect_digest("byte ramp 0..255", ramp,
                  "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880");

    // 空格属于输入："a b" 与 "ab" 必须不同
    expect_digest("space inside input",
                  std::vector<unsigned char>{'a', ' ', 'b'},
                  "c8687a08aa5d6ed2044328fa6a697ab8e96dc34291e8c2034ae8c38e6fcc6d65");

    // 只在换行字节上不同的样本：LF、CR、双 LF 各自匹配独立标准结果
    expect_digest("abc LF",
                  std::vector<unsigned char>{'a', 'b', 'c', '\n'},
                  "edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb");
    expect_digest("abc CR",
                  std::vector<unsigned char>{'a', 'b', 'c', '\r'},
                  "e2af64b38bbaf25b74d1e999d27370bde03f62b612f43a3f8f548287079ef77e");
    expect_digest("abc two LFs",
                  std::vector<unsigned char>{'a', 'b', 'c', '\n', '\n'},
                  "783701f7599830824fa73488f80eb79894f6f14203264b6a3ac3f0a14012c25f");

    // 只在单个内容字节上不同：c vs d
    expect_digest("single byte diff: abc",
                  std::vector<unsigned char>{'a', 'b', 'c'},
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect_digest("single byte diff: abd",
                  std::vector<unsigned char>{'a', 'b', 'd'},
                  "a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9");
}

// ---- 分组与填充边界长度 ---------------------------------------------------

void test_boundary_lengths() {
    struct Case { std::size_t n; const char* hex; };
    // 期望值由 sha256sum / OpenSSL 独立计算。
    const Case cases[] = {
        {55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"},
        {56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"},
        {63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"},
        {64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"},
        {65, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"},
        {200, "c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5"},
    };
    for (const auto& c : cases) {
        expect_digest("boundary length " + std::to_string(c.n), fill_a(c.n), c.hex);
    }
}

// ---- 增量接口：一次提交与任意分段必须一致 ---------------------------------

void test_incremental_splits() {
    const std::size_t sizes[] = {0, 1, 2, 3, 55, 56, 63, 64, 65, 66,
                                 127, 128, 129, 200, 255, 256, 257};
    for (std::size_t n : sizes) {
        const std::vector<unsigned char> data = pattern(n);
        const std::string whole = hash_whole(data);
        // 每个切分点都试：含空段、恰好在 64 字节边界上、把边界两侧拆开。
        for (std::size_t cut = 0; cut <= n; ++cut) {
            check(hash_parts(data, {cut}) == whole,
                  "2-way split n=" + std::to_string(n) + " cut=" + std::to_string(cut));
        }
    }

    // 较大输入上围绕分组边界的三分段组合。
    {
        const std::size_t n = 200;
        const std::vector<unsigned char> data = pattern(n);
        const std::string whole = hash_whole(data);
        const std::size_t points[] = {0, 1, 7, 55, 56, 63, 64, 65,
                                      127, 128, 129, 135, 199, 200};
        for (std::size_t c1 : points) {
            for (std::size_t c2 : points) {
                if (c1 > c2) continue;
                check(hash_parts(data, {c1, c2}) == whole,
                      "3-way split 200 @ " + std::to_string(c1) + "," +
                      std::to_string(c2));
            }
        }
    }

    // 手工构造的对抗性分段：边界两侧逐字节拆开，缓冲区跨多次 update 填满。
    {
        const std::vector<unsigned char> data = pattern(300);
        const std::string whole = hash_whole(data);
        const std::size_t plans[][5] = {
            {63, 64, 64, 65, 44},   // 300 = 63+64+64+65+44
            {1, 64, 64, 64, 107},   // 300 = 1+64*3+107
            {56, 8, 56, 8, 172},
            {55, 1, 55, 1, 188},
        };
        for (const auto& plan : plans) {
            branchaudit::Sha256 sha;
            std::size_t off = 0;
            for (std::size_t len : plan) {
                sha.update(data.data() + off, len);
                off += len;
            }
            check(off == 300 && hex_of(sha.final()) == whole,
                  "adversarial segmented update");
        }
    }
}

// ---- 文件摘要 -------------------------------------------------------------

namespace fs = std::filesystem;

struct TempArea {
    fs::path root;
    explicit TempArea(const std::string& tag) {
        const auto cwd_hash = std::hash<fs::path>{}(fs::current_path());
        root = fs::temp_directory_path() /
               ("branchaudit_test_" + tag + "_" +
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

// 调用库接口期间截获标准输出/错误：库只返回结果，不自行打印。
std::pair<std::string, std::string> silent_file_hash(const fs::path& p,
                                                     branchaudit::FileHashResult* out) {
    std::stringstream cap_out, cap_err;
    auto* old_out = std::cout.rdbuf(cap_out.rdbuf());
    auto* old_err = std::cerr.rdbuf(cap_err.rdbuf());
    *out = branchaudit::sha256_file(p);
    std::cout.rdbuf(old_out);
    std::cerr.rdbuf(old_err);
    return {cap_out.str(), cap_err.str()};
}

void test_file_hashing() {
    TempArea tmp("file");

    struct Case {
        std::string name;
        std::vector<unsigned char> bytes;
        std::string expected;  // sha256sum / OpenSSL 独立结果
    };
    const std::vector<unsigned char> binary = {'a', 0x00, 'b', 0xff, ' ',
                                               'c', '\n', 'd'};
    std::vector<Case> cases = {
        {"empty.bin", {},
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"text.txt",
         {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '\n'},
         ""},  // 下方用 sha256sum 风格常量填充
        {"binary.bin", binary,
         "ae37f71921db5e6d58be22370d3f0cc73cd4fa8bcc327dccd8b881094bc03d7c"},
        {"bound55.bin", fill_a(55),
         "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"},
        {"bound56.bin", fill_a(56),
         "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"},
        {"bound63.bin", fill_a(63),
         "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"},
        {"bound64.bin", fill_a(64),
         "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"},
        {"bound65.bin", fill_a(65),
         "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"},
        // 超过 64KiB 且不是 64KiB 整数倍：尾部不能被遗漏。
        {"large65537.bin", fill_a(64 * 1024 + 1),
         "008ffc88d3c96a9f307524eb361e47c5222a887fc45fa0c1fb8d429c5c23b430"},
        {"large131073.bin", fill_a(128 * 1024 + 1),
         "7e009ea4ef882e385b3c0bcbbfa8d009bb0a633bdd764415c09182ee0e75da73"},
        {"large200000.bin", fill_a(200000),
         "2287d207f24a941ff3b56c04c8a25ad56b63e3023207b3bb5b4ac0c9869d74be"},
    };
    // "hello world\n" 的独立标准结果。
    cases[1].expected =
        "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447";

    std::string same_bytes_digest;
    for (std::size_t i = 0; i < cases.size(); ++i) {
        const auto& c = cases[i];
        const fs::path p = tmp.root / c.name;
        write_file(p, c.bytes);

        branchaudit::FileHashResult r;
        auto [cout_text, cerr_text] = silent_file_hash(p, &r);
        check(r.ok(), std::string("file hash ok: ") + c.name);
        check(cout_text.empty() && cerr_text.empty(),
              std::string("library prints nothing: ") + c.name);
        check(r.digest.size() == 32, std::string("digest is 32 bytes: ") + c.name);
        check(hex_of(r.digest) == c.expected,
              std::string("file digest matches independent standard: ") + c.name);
        check(hex_of(r.digest) == hash_whole(c.bytes),
              std::string("file digest matches incremental API: ") + c.name);
        if (c.name == "binary.bin") same_bytes_digest = hex_of(r.digest);
    }

    // 同样字节放在不同文件名/目录下必须同一摘要，路径文字不混入。
    const std::vector<unsigned char>& shared_bytes = cases[2].bytes;
    const fs::path alt_paths[] = {
        tmp.root / "copy.bin",
        tmp.root / "sub dir" / "another name.dat",
        tmp.root / "目录 一" / "文件 二.bin",
    };
    for (const auto& p : alt_paths) {
        write_file(p, shared_bytes);
        branchaudit::FileHashResult r;
        auto captured = silent_file_hash(p, &r);
        check(r.ok() && hex_of(r.digest) == same_bytes_digest,
              std::string("same bytes same digest regardless of path: ") + p.string());
        check(captured.first.empty() && captured.second.empty(),
              std::string("no printing for path: ") + p.string());
    }

    // 路径含空格或中文：完整路径必须准确定位。
    const fs::path spaced = tmp.root / "spa ce dir" / "na me.bin";
    write_file(spaced, binary);
    {
        branchaudit::FileHashResult r;
        auto captured = silent_file_hash(spaced, &r);
        check(r.ok() && hex_of(r.digest) == same_bytes_digest,
              "path with spaces locates file");
        check(captured.first.empty() && captured.second.empty(),
              "path with spaces: no printing");
    }
    const fs::path chinese =
        tmp.root / "中文目录" / "摘要文件 数据.bin";
    write_file(chinese, fill_a(65));
    {
        branchaudit::FileHashResult r;
        auto captured = silent_file_hash(chinese, &r);
        check(r.ok() &&
                  hex_of(r.digest) ==
                      "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
              "Chinese path locates file; path text not mixed into digest");
        check(captured.first.empty() && captured.second.empty(),
              "Chinese path: no printing");
    }

    // 相对路径同样按完整路径定位。
    const fs::path rel_dir = tmp.root / "rel 目录";
    fs::create_directories(rel_dir);
    const fs::path rel_name = "r.bin";
    write_file(rel_dir / rel_name, binary);
    const fs::path old_cwd = fs::current_path();
    fs::current_path(rel_dir);
    branchaudit::FileHashResult rel_result;
    auto rel_captured = silent_file_hash(rel_name, &rel_result);
    fs::current_path(old_cwd);
    check(rel_result.ok() && hex_of(rel_result.digest) == same_bytes_digest,
          "relative path resolved from current directory");
    check(rel_captured.first.empty() && rel_captured.second.empty(),
          "relative path: no printing");
}

// ---- 文件失败行为 ---------------------------------------------------------

void test_file_failures() {
    TempArea tmp("fail");

    // 路径不存在
    const fs::path missing = tmp.root / "does not exist 缺失.bin";
    {
        branchaudit::FileHashResult r;
        auto captured = silent_file_hash(missing, &r);
        check(!r.ok(), "nonexistent path: failure result");
        check(!r.error.empty(), "nonexistent path: error states reason");
        check(r.error.find(missing.string()) != std::string::npos,
              "nonexistent path: error names failed path");
        check(r.error.size() > missing.string().size() + 2,
              "nonexistent path: error gives reason beyond the path");
        check(captured.first.empty() && captured.second.empty(),
              "nonexistent path: library does not print");
    }

    // 路径指向目录
    const fs::path dir = tmp.root / "a dir 目录";
    fs::create_directories(dir);
    {
        branchaudit::FileHashResult r;
        auto captured = silent_file_hash(dir, &r);
        check(!r.ok(), "directory path: failure result");
        check(!r.error.empty(), "directory path: error states reason");
        check(r.error.find(dir.string()) != std::string::npos,
              "directory path: error names failed path");
        check(r.error.find("directory") != std::string::npos,
              "directory path: error explains it is a directory");
        check(captured.first.empty() && captured.second.empty(),
              "directory path: library does not print");
    }
}

// ---- 文件失败行为：存在却打不开 / 部分读取后继续读出错 --------------------
//
// 这两类错误无法用“缺失路径/目录”夹具制造：文件真实存在、打开成功，
// 错误分别发生在 open 与后续 read 上。通过随测试预载的故障注入库在
// libc 文件访问接口处确定性触发（见 tests/fault_inject.c），因此被测
// 代码走的是与生产完全相同的“定位 -> 打开 -> 流式读取 -> 错误传播”
// 路径，而不是构造一个带错误文字的返回值。

void test_file_io_failures() {
    TempArea tmp("iofail");

    // 打开失败与读取失败共用的夹具：文件确定存在、内容确定。
    const fs::path existing = tmp.root / "present 存在.bin";
    constexpr long kPartial = 40;
    const std::vector<unsigned char> bytes = pattern(200);
    write_file(existing, bytes);

    // 同一文件不注入时必须成功，证明失败确由文件访问错误引起，而不是
    // 针对该路径写死的错误结果。
    {
        branchaudit::FileHashResult r;
        auto captured = silent_file_hash(existing, &r);
        check(r.ok() && hex_of(r.digest) == hash_whole(bytes),
              "iofail fixture: succeeds without injected fault");
        check(captured.first.empty() && captured.second.empty(),
              "iofail fixture: library stays silent on success");
    }

    // ---- 文件确实存在却不能打开 ----------------------------------------
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_OPEN_FAIL", existing.string());
        branchaudit::FileHashResult r;
        auto captured = silent_file_hash(existing, &r);
        check(!r.ok(), "existing-but-unopenable: failure result");
        check(r.error.find(existing.string()) != std::string::npos,
              "open failure: error names the failed path");
        check(r.error.find("ermission") != std::string::npos ||
                  r.error.find("denied") != std::string::npos ||
                  r.error.find("cces") != std::string::npos,
              "open failure: error states an open/permission reason");
        check(r.error.size() > existing.string().size() + 2,
              "open failure: error gives reason beyond the path");
        check(captured.first.empty() && captured.second.empty(),
              "open failure: library only returns result, prints nothing");
    }
    // 触发变量离开作用域后，同一文件恢复成功。
    {
        branchaudit::FileHashResult r;
        silent_file_hash(existing, &r);
        check(r.ok(), "open trigger scoped: later access succeeds again");
    }

    // ---- 文件已打开、取得部分内容后继续读取时出错 ----------------------
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_READ_FAIL",
            existing.string() + ":" + std::to_string(kPartial));
        branchaudit::FileHashResult r;
        auto captured = silent_file_hash(existing, &r);
        check(!r.ok(), "read error after partial content: failure result");
        check(r.error.find(existing.string()) != std::string::npos,
              "read failure: error names the failed path");
        check(r.error.find("read") != std::string::npos,
              "read failure: error states it is a read failure (not EOF)");
        check(r.error.size() > existing.string().size() + 2,
              "read failure: error gives reason beyond the path");
        check(captured.first.empty() && captured.second.empty(),
              "read failure: library only returns result, prints nothing");

        // 已读到的部分内容绝不能成为成功摘要：既不是完整文件摘要，也不
        // 是前 kPartial 字节的摘要。
        const std::string got = hex_of(r.digest);
        check(got != hash_whole(bytes),
              "read failure: digest is not the whole-file summary");
        check(got != hash_whole(std::vector<unsigned char>(
                      bytes.begin(), bytes.begin() + kPartial)),
              "read failure: already-read partial content is not a success digest");
    }

    // ---- 空文件正常读完仍然成功：没有读到内容不等于读错误 --------------
    const fs::path empty = tmp.root / "empty 空.bin";
    write_file(empty, {});
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_READ_FAIL",
            empty.string() + ":" + std::to_string(kPartial));
        branchaudit::FileHashResult r;
        auto captured = silent_file_hash(empty, &r);
        check(r.ok(), "empty file read to completion: still success under read-fault arm");
        check(hex_of(r.digest) ==
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
              "empty file still yields SHA-256 of empty sequence");
        check(captured.first.empty() && captured.second.empty(),
              "empty file: library stays silent");
    }

    // ---- 触发只作用于指定路径：其他文件不受影响 ------------------------
    const fs::path other = tmp.root / "other.bin";
    write_file(other, bytes);
    {
        fault_test::FaultTrigger trigger(
            "BRANCHAUDIT_TEST_READ_FAIL",
            existing.string() + ":" + std::to_string(kPartial));
        branchaudit::FileHashResult r;
        silent_file_hash(other, &r);
        check(r.ok() && hex_of(r.digest) == hash_whole(bytes),
              "fault is path-scoped: unrelated file still hashes correctly");
    }
}

// ---- to_hex 格式 ----------------------------------------------------------

void test_hex_format() {
    branchaudit::Sha256 sha;
    const auto digest = sha.final();  // 空输入摘要
    const std::string hex = branchaudit::to_hex(digest);
    check(hex.size() == 64, "to_hex returns 64 characters");
    bool lowercase = true;
    for (char ch : hex) {
        const bool ok_digit = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        if (!ok_digit) lowercase = false;
    }
    check(lowercase, "to_hex is lowercase hexadecimal");
    check(hex == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "to_hex of empty digest matches standard");
}

}  // namespace

int main(int argc, char** argv) {
    fault_test::ensure_fault_preloaded(argc, argv);

    test_standard_vectors();
    test_byte_semantics();
    test_boundary_lengths();
    test_incremental_splits();
    test_large_length_encoding();
    test_file_hashing();
    test_file_failures();
    if (fault_test::kFaultInjectionAvailable) {
        test_file_io_failures();
    } else {
        // 平台无 LD_PRELOAD//proc 故障注入支持（如 macOS）：明确报告
        // 跳过，不计入已通过检查。
        ++g_skipped;
        std::cout << "SKIP: existing-but-unopenable and mid-read-error "
                     "checks (fault injection not supported on this platform)\n";
    }
    test_hex_format();

    if (g_failures == 0) {
        std::cout << "all " << g_checks << " sha256 regression checks passed";
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
