// branchaudit SHA-256 摘要行为的回归测试。
//
// 所有预期摘要均为独立的标准已知答案（SHA-256 由 FIPS 180-4 定义；
// 本文件中的期望值用 Python hashlib 独立实现计算并硬编码），
// 不是把本项目库接口与命令行两个入口互相比对——两者共用计算代码，
// 互相比对无法发现共同的错误。库与命令行的一致性检查是在两者
// 各自匹配独立标准答案之外附加进行的。
//
// 用法：branchaudit_tests <branchaudit 可执行文件路径>
// 全部通过时退出码为 0，任一检查失败则退出码为 1。

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "filehash.h"
#include "sha256.h"

namespace fs = std::filesystem;

namespace {

int g_checks = 0;
int g_failures = 0;

void report_failure(const char* file, int line, const std::string& what) {
    ++g_failures;
    std::cerr << "FAIL " << file << ":" << line << ": " << what << "\n";
}

#define CHECK(cond)                                        \
    do {                                                   \
        ++g_checks;                                        \
        if (!(cond)) {                                     \
            report_failure(__FILE__, __LINE__, #cond);     \
        }                                                  \
    } while (0)

#define CHECK_EQ(actual, expected)                                        \
    do {                                                                  \
        ++g_checks;                                                       \
        const auto actual_val = (actual);                                 \
        const auto expected_val = (expected);                             \
        if (!(actual_val == expected_val)) {                              \
            std::ostringstream oss;                                       \
            oss << #actual " == " #expected "\n  actual:   ["             \
                << actual_val << "]\n  expected: [" << expected_val       \
                << "]";                                                   \
            report_failure(__FILE__, __LINE__, oss.str());                \
        }                                                                 \
    } while (0)

// ---------------------------------------------------------------------------
// 标准已知答案（独立实现计算，见文件头注释）
// ---------------------------------------------------------------------------

constexpr const char* kHexEmpty =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
constexpr const char* kHexAbc =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
constexpr const char* kHexAbc56 =
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
constexpr const char* kHexMillionA =
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
constexpr const char* kHexText =
    "1cf34cbeaca6f2ce821c4b6369c37c583b1cc10846122a8c77a4df77d0d5b7b8";
constexpr const char* kHexBinary00ToFF =
    "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880";
constexpr const char* kHexA55 =
    "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318";
constexpr const char* kHexA56 =
    "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a";
constexpr const char* kHexA63 =
    "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34";
constexpr const char* kHexA64 =
    "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb";
constexpr const char* kHexA65 =
    "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0";
constexpr const char* kHexMultiblock1000 =
    "a8af099bf2e878609558dbf69d8f88f4a31040a8cf84b549a0cfa912f12ffc3f";
constexpr const char* kHexLarge200000 =
    "ec0ebf98b6f2954bf0f7b839402b1ba245996c39d18e155414e91a2b4353c157";
constexpr const char* kHexPattern200 =
    "2c7e18c942ef065b526a2d4e5546283749cd3ddfb51d8fc71f42717363685f46";
constexpr const char* kHexAbcLf =
    "edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb";
constexpr const char* kHexAbcCrlf =
    "552bab6864c7a7b69a502ed1854b9245c0e1a30f008aaa0b281da62585fdb025";
constexpr const char* kHexAbd =
    "a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9";
constexpr const char* kHexHelloWorld =
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
constexpr const char* kHexHelloWorldNl =
    "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447";

// ---------------------------------------------------------------------------
// 样本内容
// ---------------------------------------------------------------------------

using Bytes = std::vector<unsigned char>;

Bytes to_bytes(const char* s) {
    return Bytes(s, s + std::char_traits<char>::length(s));
}

Bytes repeat_byte(unsigned char c, std::size_t n) {
    return Bytes(n, c);
}

Bytes range_00_to_ff() {
    Bytes v(256);
    for (std::size_t i = 0; i < v.size(); ++i) {
        v[i] = static_cast<unsigned char>(i);
    }
    return v;
}

// 确定性的伪随机模式：(i*7+3) mod 256，覆盖零字节与高位字节。
Bytes pattern(std::size_t n) {
    Bytes v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<unsigned char>((i * 7 + 3) % 256);
    }
    return v;
}

Bytes multiblock_1000() {
    Bytes v(1000);
    for (std::size_t i = 0; i < v.size(); ++i) {
        v[i] = static_cast<unsigned char>(i % 256);
    }
    return v;
}

// ---------------------------------------------------------------------------
// 摘要辅助
// ---------------------------------------------------------------------------

std::string hex_one_shot(const Bytes& data) {
    branchaudit::Sha256 sha;
    if (!data.empty()) {
        sha.update(data.data(), data.size());
    }
    return branchaudit::to_hex(sha.final());
}

// 在 cuts 指定的每个位置切开，分多次 update() 提交同一组字节。
std::string hex_split(const Bytes& data, const std::vector<std::size_t>& cuts) {
    branchaudit::Sha256 sha;
    std::size_t pos = 0;
    for (std::size_t cut : cuts) {
        sha.update(data.data() + pos, cut - pos);
        pos = cut;
    }
    sha.update(data.data() + pos, data.size() - pos);
    return branchaudit::to_hex(sha.final());
}

// 按固定块长分多次 update() 提交。
std::string hex_chunked(const Bytes& data, std::size_t chunk) {
    branchaudit::Sha256 sha;
    for (std::size_t pos = 0; pos < data.size(); pos += chunk) {
        const std::size_t n = std::min(chunk, data.size() - pos);
        sha.update(data.data() + pos, n);
    }
    return branchaudit::to_hex(sha.final());
}

// ---------------------------------------------------------------------------
// 文件系统辅助
// ---------------------------------------------------------------------------

void write_file(const fs::path& path, const Bytes& data) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    if (!out) {
        std::cerr << "FATAL: cannot write fixture " << path << "\n";
        std::exit(2);
    }
}

std::string read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string hex_of_file(const fs::path& path) {
    const branchaudit::FileHashResult result = branchaudit::sha256_file(path);
    CHECK(result.ok());
    if (!result.ok()) {
        std::cerr << "  (sha256_file failed for " << path << ": "
                  << result.error << ")\n";
        return {};
    }
    return branchaudit::to_hex(result.digest);
}

// ---------------------------------------------------------------------------
// 命令行辅助
// ---------------------------------------------------------------------------

struct CliResult {
    int exit_code = -1;
    std::string out;
    std::string err;
};

CliResult run_cli_hash(const std::string& exe, const std::string& arg,
                       const fs::path& tmp) {
    const fs::path out_path = tmp / "cli.stdout";
    const fs::path err_path = tmp / "cli.stderr";
    // 样本路径不含单引号，直接用单引号包裹即可安全传参（含空格、中文）。
    const std::string cmd = "'" + exe + "' hash '" + arg + "' >'" +
                            out_path.string() + "' 2>'" + err_path.string() +
                            "'";
    const int rc = std::system(cmd.c_str());
    CliResult result;
    result.exit_code = (rc != -1 && WIFEXITED(rc)) ? WEXITSTATUS(rc) : -1;
    result.out = read_file(out_path);
    result.err = read_file(err_path);
    return result;
}

bool is_lower_hex_64(const std::string& s) {
    return s.size() == 64 &&
           s.find_first_not_of("0123456789abcdef") == std::string::npos;
}

// 成功的命令行调用：退出 0，stdout 严格为 64 个小写十六进制加换行，
// stderr 为空，且摘要等于独立标准答案。
void check_cli_success(const std::string& exe, const fs::path& tmp,
                       const std::string& arg, const std::string& known_hex) {
    const CliResult r = run_cli_hash(exe, arg, tmp);
    CHECK_EQ(r.exit_code, 0);
    CHECK_EQ(r.err, std::string());
    CHECK_EQ(r.out, known_hex + "\n");
    CHECK(is_lower_hex_64(r.out.substr(0, 64)));
}

// ---------------------------------------------------------------------------
// 测试用例
// ---------------------------------------------------------------------------

// 增量接口：已知答案，覆盖空输入、文本、二进制、分组与填充边界。
void test_known_answers() {
    CHECK_EQ(hex_one_shot(Bytes{}), kHexEmpty);
    CHECK_EQ(hex_one_shot(to_bytes("abc")), kHexAbc);
    CHECK_EQ(hex_one_shot(to_bytes(
                 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
             kHexAbc56);
    CHECK_EQ(hex_one_shot(to_bytes("hello world\nsecond line\n")), kHexText);
    CHECK_EQ(hex_one_shot(range_00_to_ff()), kHexBinary00ToFF);

    // 55/56/63/64/65 字节：SHA-256 分组（64）与末尾填充（56）边界。
    CHECK_EQ(hex_one_shot(repeat_byte('a', 55)), kHexA55);
    CHECK_EQ(hex_one_shot(repeat_byte('a', 56)), kHexA56);
    CHECK_EQ(hex_one_shot(repeat_byte('a', 63)), kHexA63);
    CHECK_EQ(hex_one_shot(repeat_byte('a', 64)), kHexA64);
    CHECK_EQ(hex_one_shot(repeat_byte('a', 65)), kHexA65);

    // 跨多个分组的内容。
    CHECK_EQ(hex_one_shot(multiblock_1000()), kHexMultiblock1000);
    CHECK_EQ(hex_one_shot(repeat_byte('a', 1000000)), kHexMillionA);

    // 仅在换行字节或单个内容字节上不同的样本，分别匹配各自的标准结果。
    CHECK_EQ(hex_one_shot(to_bytes("abc\n")), kHexAbcLf);
    CHECK_EQ(hex_one_shot(to_bytes("abc\r\n")), kHexAbcCrlf);
    CHECK_EQ(hex_one_shot(to_bytes("abd")), kHexAbd);
    CHECK_EQ(hex_one_shot(to_bytes("hello world")), kHexHelloWorld);
    CHECK_EQ(hex_one_shot(to_bytes("hello world\n")), kHexHelloWorldNl);
}

// 增量接口：同一组字节一次提交与分多次提交，结果必须完全相同。
void test_incremental_splits() {
    const Bytes data = multiblock_1000();
    const std::string expected = kHexMultiblock1000;

    // 每一个可能的单切分点（含 0 与全长）。
    for (std::size_t cut = 0; cut <= data.size(); ++cut) {
        CHECK_EQ(hex_split(data, {cut}), expected);
    }

    // 恰好落在 64 字节分组边界上的切分，以及把边界两侧拆开的切分。
    for (std::size_t cut : {55, 56, 63, 64, 65, 127, 128, 129, 191, 192, 193}) {
        CHECK_EQ(hex_split(data, {cut}), expected);
        if (cut + 1 < data.size()) {
            CHECK_EQ(hex_split(data, {cut, cut + 1}), expected);
        }
    }

    // 多段切分与固定块长喂入（块长跨边界、等于边界、小于边界）。
    CHECK_EQ(hex_split(data, {55, 56, 63, 64, 65, 128, 500, 999}), expected);
    for (std::size_t chunk : {1, 7, 55, 63, 64, 65, 128, 1000}) {
        CHECK_EQ(hex_chunked(data, chunk), expected);
    }

    // 大块内容（超过 64KiB、非 64KiB 整数倍）的各种分块方式。
    const Bytes large = pattern(200000);
    for (std::size_t chunk : {1, 64, 65535, 65536, 65537, 200000}) {
        CHECK_EQ(hex_chunked(large, chunk), kHexLarge200000);
    }

    // 200 字节样本的全部切分点，对照该样本自己的标准答案。
    const Bytes p200 = pattern(200);
    for (std::size_t cut = 0; cut <= p200.size(); ++cut) {
        CHECK_EQ(hex_split(p200, {cut}), kHexPattern200);
    }

    // 空 update() 不改变结果。
    {
        branchaudit::Sha256 sha;
        const unsigned char dummy = 0;
        sha.update(&dummy, 0);
        sha.update(reinterpret_cast<const unsigned char*>("abc"), 3);
        sha.update(&dummy, 0);
        CHECK_EQ(branchaudit::to_hex(sha.final()), kHexAbc);
    }

    // final() 返回 32 字节摘要。
    {
        branchaudit::Sha256 sha;
        CHECK_EQ(sha.final().size(), std::size_t{32});
    }
}

// 文件接口：各类内容的文件摘要匹配独立标准答案。
void test_file_known_answers(const fs::path& tmp) {
    const struct {
        const char* name;
        Bytes content;
        const char* hex;
    } cases[] = {
        {"empty.bin", Bytes{}, kHexEmpty},
        {"text.txt", to_bytes("hello world\nsecond line\n"), kHexText},
        {"binary.bin", range_00_to_ff(), kHexBinary00ToFF},
        {"a55.bin", repeat_byte('a', 55), kHexA55},
        {"a56.bin", repeat_byte('a', 56), kHexA56},
        {"a63.bin", repeat_byte('a', 63), kHexA63},
        {"a64.bin", repeat_byte('a', 64), kHexA64},
        {"a65.bin", repeat_byte('a', 65), kHexA65},
        {"multiblock.bin", multiblock_1000(), kHexMultiblock1000},
        // 超过 64KiB 且长度不是 64KiB 整数倍：尾部不能被遗漏。
        {"large.bin", pattern(200000), kHexLarge200000},
        {"abc_lf.txt", to_bytes("abc\n"), kHexAbcLf},
        {"abc_crlf.txt", to_bytes("abc\r\n"), kHexAbcCrlf},
    };
    for (const auto& c : cases) {
        const fs::path path = tmp / "files" / c.name;
        write_file(path, c.content);
        CHECK_EQ(hex_of_file(path), c.hex);
    }
}

// 同样的字节放在不同文件名或目录下，应得到同一摘要；
// 路径含空格或中文时按完整路径定位，路径文字不混入摘要。
void test_file_path_independence(const fs::path& tmp) {
    const Bytes content = range_00_to_ff();
    const fs::path plain = tmp / "files" / "plain.bin";
    const fs::path spaced = tmp / "dir with space" / "sub dir" / "na me.bin";
    const fs::path chinese =
        tmp / "中文目录" / "子 目录" / "文件 名.bin";
    write_file(plain, content);
    write_file(spaced, content);
    write_file(chinese, content);

    CHECK_EQ(hex_of_file(plain), kHexBinary00ToFF);
    CHECK_EQ(hex_of_file(spaced), kHexBinary00ToFF);
    CHECK_EQ(hex_of_file(chinese), kHexBinary00ToFF);
}

// 文件接口失败行为：路径不存在、路径指向目录。
void test_file_failures(const fs::path& tmp) {
    const fs::path missing = tmp / "no-such-file.bin";
    const branchaudit::FileHashResult r1 = branchaudit::sha256_file(missing);
    CHECK(!r1.ok());
    CHECK(r1.error.find(missing.string()) != std::string::npos);

    const fs::path dir = tmp / "files";
    const branchaudit::FileHashResult r2 = branchaudit::sha256_file(dir);
    CHECK(!r2.ok());
    CHECK(r2.error.find(dir.string()) != std::string::npos);
    CHECK(r2.error.find("directory") != std::string::npos);
}

// 库接口只返回结果，不自行打印。
void test_library_does_not_print(const fs::path& tmp) {
    const fs::path path = tmp / "files" / "text.txt";
    std::ostringstream captured_out;
    std::ostringstream captured_err;
    std::streambuf* old_out = std::cout.rdbuf(captured_out.rdbuf());
    std::streambuf* old_err = std::cerr.rdbuf(captured_err.rdbuf());
    const branchaudit::FileHashResult result = branchaudit::sha256_file(path);
    const std::string hex = branchaudit::to_hex(result.digest);
    std::cout.rdbuf(old_out);
    std::cerr.rdbuf(old_err);

    CHECK(result.ok());
    CHECK_EQ(hex, kHexText);
    CHECK_EQ(captured_out.str(), std::string());
    CHECK_EQ(captured_err.str(), std::string());
}

// 命令行：成功调用的输出契约，以及与库接口结果一致。
void test_cli_success(const std::string& exe, const fs::path& tmp) {
    const struct {
        const char* arg_file;  // 相对 tmp 的路径
        const char* hex;
    } cases[] = {
        {"files/empty.bin", kHexEmpty},
        {"files/text.txt", kHexText},
        {"files/binary.bin", kHexBinary00ToFF},
        {"files/a55.bin", kHexA55},
        {"files/a56.bin", kHexA56},
        {"files/a63.bin", kHexA63},
        {"files/a64.bin", kHexA64},
        {"files/a65.bin", kHexA65},
        {"files/multiblock.bin", kHexMultiblock1000},
        {"files/large.bin", kHexLarge200000},
        {"files/abc_lf.txt", kHexAbcLf},
        {"files/abc_crlf.txt", kHexAbcCrlf},
        {"dir with space/sub dir/na me.bin", kHexBinary00ToFF},
        {"中文目录/子 目录/文件 名.bin", kHexBinary00ToFF},
    };
    for (const auto& c : cases) {
        const fs::path path = tmp / c.arg_file;
        check_cli_success(exe, tmp, path.string(), c.hex);

        // 一致性：命令行输出与库接口对同一文件的结果相同
        // （两者已分别对照独立标准答案，此处为附加保障）。
        const CliResult r = run_cli_hash(exe, path.string(), tmp);
        CHECK_EQ(r.out, hex_of_file(path) + "\n");
    }
}

// 命令行失败行为：退出 1、stdout 为空、stderr 指出失败路径和原因。
void test_cli_failures(const std::string& exe, const fs::path& tmp) {
    const fs::path missing = tmp / "no-such-file.bin";
    const CliResult r1 = run_cli_hash(exe, missing.string(), tmp);
    CHECK_EQ(r1.exit_code, 1);
    CHECK_EQ(r1.out, std::string());
    CHECK(!r1.err.empty());
    CHECK(r1.err.find(missing.string()) != std::string::npos);

    const fs::path dir = tmp / "files";
    const CliResult r2 = run_cli_hash(exe, dir.string(), tmp);
    CHECK_EQ(r2.exit_code, 1);
    CHECK_EQ(r2.out, std::string());
    CHECK(!r2.err.empty());
    CHECK(r2.err.find(dir.string()) != std::string::npos);
    CHECK(r2.err.find("directory") != std::string::npos);
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <path-to-branchaudit>\n";
        return 2;
    }
    const std::string exe = argv[1];

    const fs::path tmp =
        fs::temp_directory_path() /
        ("branchaudit_test_" + std::to_string(static_cast<long long>(getpid())));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    test_known_answers();
    test_incremental_splits();
    test_file_known_answers(tmp);
    test_file_path_independence(tmp);
    test_file_failures(tmp);
    test_library_does_not_print(tmp);
    test_cli_success(exe, tmp);
    test_cli_failures(exe, tmp);

    fs::remove_all(tmp);

    std::cout << (g_checks - g_failures) << "/" << g_checks
              << " checks passed\n";
    if (g_failures > 0) {
        std::cout << g_failures << " FAILURES\n";
        return 1;
    }
    return 0;
}
