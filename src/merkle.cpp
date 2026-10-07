#include "merkle.h"

#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "file_digest_internal.h"

namespace branchaudit {

Digest merkle_empty_root() {
    // SHA-256 对空字节序列（不追加任何 Merkle 前缀）。
    return Sha256{}.final();
}

Digest merkle_leaf(const unsigned char* data, std::size_t size) {
    Sha256 sha;
    const unsigned char prefix = 0x00;
    sha.update(&prefix, 1);
    sha.update(data, size);
    return sha.final();
}

Digest merkle_parent(const Digest& left, const Digest& right) {
    Sha256 sha;
    const unsigned char prefix = 0x01;
    sha.update(&prefix, 1);
    sha.update(left.data(), left.size());
    sha.update(right.data(), right.size());
    return sha.final();
}

namespace {

// 流式计算单个文件的叶子摘要 SHA-256(0x00 || file bytes)。
// 定位、打开、分块读取与失败处理与 sha256_file 共用同一实现：唯一区别是
// 在文件字节之前加入一次单个 0x00 前缀字节（空文件也存在，且不随分块重复）。
FileHashResult leaf_file(const std::filesystem::path& path) {
    static constexpr unsigned char kLeafPrefix = 0x00;
    return internal::sha256_file_digest(path, &kLeafPrefix);
}

// 计算有序批次的叶子层。严格按 paths 下标顺序：不排序、不去重。
// 任一文件失败立即返回该错误，不读取也不使用其后的任何文件。
std::string leaf_level(const std::vector<std::filesystem::path>& paths,
                       std::vector<Digest>& level) {
    level.clear();
    level.reserve(paths.size());
    for (const std::filesystem::path& path : paths) {
        FileHashResult leaf = leaf_file(path);
        if (!leaf.ok()) {
            return std::move(leaf.error);
        }
        level.push_back(leaf.digest);
    }
    return {};
}

// 批次合并规则（root 与 prove 共用的唯一一份实现）：对当前层做一次相邻
// 配对——相邻节点按先左后右两两用 merkle_parent 合并；若该层节点数为
// 奇数，最后一个没有伙伴的节点摘要原样进入上一层（不复制、不补零）。
// 输入层不被修改，返回合并后的上一层；输入只有一个节点时返回的层同样
// 只有该节点本身。
std::vector<Digest> combine_level(const std::vector<Digest>& level) {
    std::vector<Digest> next;
    const bool odd = (level.size() % 2) != 0;
    next.reserve(level.size() / 2 + (odd ? 1 : 0));
    for (std::size_t i = 0; i + 1 < level.size(); i += 2) {
        next.push_back(merkle_parent(level[i], level[i + 1]));
    }
    if (odd) {
        next.push_back(level.back());
    }
    return next;
}

// ---- prove 版本 1 JSON 的严格读取 -----------------------------------------
//
// 只实现 prove 已公开的格式所需的 JSON 子集：对象、数组、字符串、整数。
// 不接受小数、指数、null/true/false 作为字段值；空白与字段次序按 JSON
// 规则自由；重复字段、未知字段与对象之后的多余内容一律判错。解析器只
// 扫描传入文本，不做任何文件或内存映射 I/O。

struct JsonParser {
    std::string_view text;
    std::size_t pos = 0;
    std::string error;

    void ws() {
        while (pos < text.size()) {
            const char c = text[pos];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++pos;
            } else {
                break;
            }
        }
    }

    bool eof() const { return pos >= text.size(); }

    char peek() const { return text[pos]; }

    bool fail(std::string msg) {
        // 每个调用点只会在尚未出错时进入；保留第一条原因。
        if (error.empty()) {
            error = std::move(msg);
        }
        return false;
    }

    // 读取一个 JSON 字符串字面量（text[pos] 必须是 '"'），把解码后的
    // UTF-8 内容写入 out。prove 的摘要/字段名/side 都只含 ASCII，这里仍
    // 按 JSON 规则处理转义与 uXXXX（含代理对），以便对任意输入给出确定
    // 结果而非越界读取。
    bool read_string(std::string& out) {
        out.clear();
        ++pos;  // 跳过起始引号
        while (true) {
            if (eof()) {
                return fail("unterminated JSON string");
            }
            const char c = text[pos++];
            if (static_cast<unsigned char>(c) < 0x20) {
                return fail("unescaped control character in JSON string");
            }
            if (c == '"') {
                return true;
            }
            if (c == '\\') {
                if (eof()) {
                    return fail("unterminated escape in JSON string");
                }
                const char e = text[pos++];
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        std::uint32_t cp = 0;
                        if (!read_hex4(cp)) {
                            return fail("invalid \\u escape in JSON string");
                        }
                        // UTF-16 代理对：\uD800-\uDBFF 后必须紧跟
                        // \uDC00-\uDFFF。
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (pos + 1 < text.size() && text[pos] == '\\' &&
                                text[pos + 1] == 'u') {
                                pos += 2;
                                std::uint32_t lo = 0;
                                if (!read_hex4(lo) || lo < 0xDC00 ||
                                    lo > 0xDFFF) {
                                    return fail("invalid UTF-16 surrogate pair "
                                                "in JSON string");
                                }
                                cp = 0x10000 + ((cp - 0xD800) << 10) +
                                     (lo - 0xDC00);
                            } else {
                                return fail("lone UTF-16 high surrogate in JSON "
                                            "string");
                            }
                        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                            return fail("lone UTF-16 low surrogate in JSON "
                                        "string");
                        }
                        append_utf8(cp, out);
                        break;
                    }
                    default:
                        return fail("invalid escape sequence in JSON string");
                }
            } else {
                out.push_back(c);
            }
        }
    }

    // 从 text[pos..pos+4) 读取四个十六进制位；不足或非法返回 false。
    bool read_hex4(std::uint32_t& out) {
        if (pos + 4 > text.size()) {
            return false;
        }
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = text[pos++];
            v <<= 4;
            if (c >= '0' && c <= '9') {
                v |= static_cast<std::uint32_t>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                v |= static_cast<std::uint32_t>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                v |= static_cast<std::uint32_t>(c - 'A' + 10);
            } else {
                return false;
            }
        }
        out = v;
        return true;
    }

    static void append_utf8(std::uint32_t cp, std::string& out) {
        if (cp <= 0x7F) {
            out.push_back(static_cast<char>(cp));
        } else if (cp <= 0x7FF) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp <= 0xFFFF) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    // 扫描一个 JSON 数字的语法区间并在必须为无符号整数时拒绝非整数写法。
    // must_be_uint 为真时：不得有符号/小数/指数；成功时 [start,pos) 即
    // 一段 0..2^64-1 的十进制数字（是否超界由 read_uint64 用 from_chars
    // 判定）。返回 [start,pos) 长度便于调用方取出数字串。
    bool scan_number(bool must_be_uint, std::size_t& start, std::size_t& end) {
        start = pos;
        if (!eof() && peek() == '-') {
            ++pos;
            if (must_be_uint) {
                return fail("negative integer is not allowed");
            }
        }
        // 整数部分：JSON 不允许前导 0（"0" 之后不能再跟数字）。
        if (eof() || peek() < '0' || peek() > '9') {
            return fail("invalid JSON number");
        }
        if (peek() == '0') {
            ++pos;
            if (!eof() && peek() >= '0' && peek() <= '9') {
                return fail("leading zeros are not allowed in JSON numbers");
            }
        } else {
            while (!eof() && peek() >= '0' && peek() <= '9') {
                ++pos;
            }
        }
        bool fraction_or_exponent = false;
        if (!eof() && peek() == '.') {
            fraction_or_exponent = true;
            ++pos;
            if (eof() || peek() < '0' || peek() > '9') {
                return fail("invalid JSON fraction");
            }
            while (!eof() && peek() >= '0' && peek() <= '9') {
                ++pos;
            }
        }
        if (!eof() && (peek() == 'e' || peek() == 'E')) {
            fraction_or_exponent = true;
            ++pos;
            if (!eof() && (peek() == '+' || peek() == '-')) {
                ++pos;
            }
            if (eof() || peek() < '0' || peek() > '9') {
                return fail("invalid JSON exponent");
            }
            while (!eof() && peek() >= '0' && peek() <= '9') {
                ++pos;
            }
        }
        if (must_be_uint && fraction_or_exponent) {
            // 1.0、1e0 这类写法在 JSON 里是数字，但不是“JSON 整数”，
            // leaf_count/leaf_index/version 必须准确保留整数值。
            return fail("only JSON integers are accepted for this field");
        }
        end = pos;
        return true;
    }

    // 读取字段值位置上的无符号 64 位 JSON 整数。
    bool read_uint64(std::uint64_t& out, std::string_view field) {
        ws();
        if (eof()) {
            return fail(std::string("missing value for field \"") +
                        std::string(field) + "\"");
        }
        const char c = peek();
        if (c == '"') {
            return fail(std::string("field \"") + std::string(field) +
                        "\" must be a JSON integer, got a string");
        }
        if (c == 't' || c == 'f' || c == 'n') {
            return fail(std::string("field \"") + std::string(field) +
                        "\" must be a JSON integer, got a boolean or null");
        }
        if (c == '{' || c == '[') {
            return fail(std::string("field \"") + std::string(field) +
                        "\" must be a JSON integer, got a container");
        }
        if (c != '-' && (c < '0' || c > '9')) {
            return fail(std::string("field \"") + std::string(field) +
                        "\" has an invalid value");
        }
        std::size_t start = 0;
        std::size_t end = 0;
        if (!scan_number(/*must_be_uint=*/true, start, end)) {
            return false;
        }
        const std::string_view digits(text.data() + start, end - start);
        const auto res = std::from_chars(
            digits.data(), digits.data() + digits.size(), out);
        if (res.ec != std::errc{} ||
            res.ptr != digits.data() + digits.size()) {
            return fail(std::string("field \"") + std::string(field) +
                        "\" integer is out of unsigned 64-bit range");
        }
        return true;
    }

    // 读取字段值位置上的 JSON 字符串。
    bool read_string_value(std::string& out, std::string_view field) {
        ws();
        if (eof()) {
            return fail(std::string("missing value for field \"") +
                        std::string(field) + "\"");
        }
        const char c = peek();
        if (c != '"') {
            return fail(std::string("field \"") + std::string(field) +
                        "\" must be a JSON string");
        }
        return read_string(out);
    }
};

// 把恰好 64 个小写十六进制字符还原为 32 字节摘要。长度不符、含非十六
// 进制字符或使用大写字符都明确失败：不截断、不替换损坏内容。
bool parse_digest_hex(const std::string& hex, Digest& out) {
    if (hex.size() != 64) {
        return false;
    }
    auto nibble = [](char c, unsigned int& v) -> bool {
        if (c >= '0' && c <= '9') {
            v = static_cast<unsigned int>(c - '0');
            return true;
        }
        // 只接受小写：A-F 等大写字符在此失败，而不是被当作同一摘要。
        if (c >= 'a' && c <= 'f') {
            v = static_cast<unsigned int>(c - 'a' + 10);
            return true;
        }
        return false;
    };
    for (std::size_t i = 0; i < 32; ++i) {
        unsigned int hi = 0;
        unsigned int lo = 0;
        if (!nibble(hex[2 * i], hi) || !nibble(hex[2 * i + 1], lo)) {
            return false;
        }
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

// 读取字段值位置上的摘要字符串：恰好 64 个小写十六进制字符。
bool read_digest_value(JsonParser& p, Digest& out, std::string_view field) {
    std::string raw;
    if (!p.read_string_value(raw, field)) {
        return false;
    }
    if (!parse_digest_hex(raw, out)) {
        return p.fail(std::string("field \"") + std::string(field) +
                      "\" must be exactly 64 lowercase hexadecimal characters "
                      "decoding to 32 bytes");
    }
    return true;
}

// 解析一个兄弟对象：只允许 side 与 digest 两个字段，均必填、不得重复、
// 不得出现其他字段。调用时 p 已停在起始 '{' 之后的位置。
bool parse_sibling_object(JsonParser& p, MerkleSibling& sibling) {
    bool have_side = false;
    bool have_digest = false;
    p.ws();
    if (!p.eof() && p.peek() == '}') {
        ++p.pos;
        return p.fail("a siblings entry must contain \"side\" and \"digest\"");
    }
    while (true) {
        p.ws();
        if (p.eof() || p.peek() != '"') {
            return p.fail("expected string key in sibling object");
        }
        std::string key;
        if (!p.read_string(key)) {
            return false;
        }
        p.ws();
        if (p.eof() || p.peek() != ':') {
            return p.fail("expected ':' after sibling object key \"" + key +
                          "\"");
        }
        ++p.pos;

        if (key == "side") {
            if (have_side) {
                return p.fail("duplicate field \"side\" in a siblings entry");
            }
            std::string side;
            if (!p.read_string_value(side, "side")) {
                return false;
            }
            if (side == "left") {
                sibling.side = MerkleSibling::Side::left;
            } else if (side == "right") {
                sibling.side = MerkleSibling::Side::right;
            } else {
                return p.fail("sibling side must be \"left\" or \"right\"");
            }
            have_side = true;
        } else if (key == "digest") {
            if (have_digest) {
                return p.fail("duplicate field \"digest\" in a siblings entry");
            }
            if (!read_digest_value(p, sibling.digest, "digest")) {
                return false;
            }
            have_digest = true;
        } else {
            return p.fail("undefined field \"" + key +
                          "\" in a siblings entry (only \"side\" and "
                          "\"digest\" are allowed)");
        }

        p.ws();
        if (p.eof()) {
            return p.fail("unterminated sibling object");
        }
        if (p.peek() == '}') {
            ++p.pos;
            break;
        }
        if (p.peek() != ',') {
            return p.fail("expected ',' or '}' in sibling object");
        }
        ++p.pos;
    }
    if (!have_side || !have_digest) {
        return p.fail("a siblings entry must contain both \"side\" and "
                      "\"digest\"");
    }
    return true;
}

// 解析 siblings 数组：顺序、方向与摘要严格按输入保留，不排序、不去重、
// 不补记录。调用时 p 已确认当前字符为 '['。
bool parse_siblings_array(JsonParser& p,
                          std::vector<MerkleSibling>& siblings) {
    ++p.pos;  // 跳过 '['
    p.ws();
    if (!p.eof() && p.peek() == ']') {
        ++p.pos;
        return true;  // 单文件证明的空兄弟数组。
    }
    while (true) {
        p.ws();
        if (p.eof()) {
            return p.fail("unterminated siblings array");
        }
        if (p.peek() != '{') {
            return p.fail("each siblings entry must be a JSON object");
        }
        ++p.pos;  // 跳过 '{'
        MerkleSibling& sibling = siblings.emplace_back();
        if (!parse_sibling_object(p, sibling)) {
            return false;
        }
        p.ws();
        if (p.eof()) {
            return p.fail("unterminated siblings array");
        }
        if (p.peek() == ']') {
            ++p.pos;
            return true;
        }
        if (p.peek() != ',') {
            return p.fail("expected ',' or ']' in siblings array");
        }
        ++p.pos;
    }
}

}  // namespace

FileHashResult merkle_root_files(const std::vector<std::filesystem::path>& paths) {
    FileHashResult result;

    // 没有文件：空字节序列的 SHA-256。
    if (paths.empty()) {
        result.digest = merkle_empty_root();
        return result;
    }

    // 叶子层。
    std::vector<Digest> level;
    result.error = leaf_level(paths, level);
    if (!result.ok()) {
        return result;
    }

    // 逐层相邻配对直到只剩一个根；配对与奇数末节点原样提升的规则由
    // combine_level 唯一实现，prove 沿同一函数走，两条路径不会出现规则漂移。
    while (level.size() > 1) {
        level = combine_level(level);
    }

    result.digest = level.front();
    return result;
}

MerkleProofResult merkle_proof_file(
        const std::vector<std::filesystem::path>& paths,
        std::uint64_t leaf_index) {
    MerkleProofResult result;

    // 位置必须落在批次内；空批次没有任何合法位置。
    if (leaf_index >= paths.size()) {
        result.error = "leaf index " + std::to_string(leaf_index) +
                       " out of range for batch of " +
                       std::to_string(paths.size()) + " file(s)";
        return result;
    }

    // 叶子层：与 merkle_root_files 完全相同的文件与顺序规则。
    std::vector<Digest> level;
    result.error = leaf_level(paths, level);
    if (!result.ok()) {
        return result;
    }

    MerkleProof& proof = result.proof;
    proof.leaf_count = paths.size();
    proof.leaf_index = leaf_index;
    proof.leaf = level[static_cast<std::size_t>(leaf_index)];

    // 沿被选位置逐层向上：每层只记录实际存在的兄弟；奇数末节点原样
    // 提升的层没有兄弟，不添加记录（不复制末节点、不补零）。该层如何
    // 合并与 root 完全相同——两者都调用同一份 combine_level。
    std::size_t idx = static_cast<std::size_t>(leaf_index);
    while (level.size() > 1) {
        if (idx % 2 == 0) {
            if (idx + 1 < level.size()) {
                proof.siblings.push_back(
                    {MerkleSibling::Side::right, level[idx + 1]});
            }
            // idx 是奇数层的末节点：经 combine_level 原样提升，无兄弟记录。
        } else {
            proof.siblings.push_back(
                {MerkleSibling::Side::left, level[idx - 1]});
        }

        idx /= 2;
        level = combine_level(level);
    }

    proof.root = level.front();
    return result;
}

MerkleVerifyResult merkle_verify_proof(const MerkleProof& proof,
                                       const Digest& trusted_root,
                                       const Digest& content_leaf) {
    MerkleVerifyResult result;

    // 空批次没有任何成员；位置必须从 0 开始并落在批次内。
    if (proof.leaf_count == 0) {
        result.error =
            "proof rejected: empty batch (leaf_count is 0) has no members";
        return result;
    }
    if (proof.leaf_index >= proof.leaf_count) {
        result.error =
            "proof rejected: leaf_index " +
            std::to_string(proof.leaf_index) + " is out of range for leaf_count " +
            std::to_string(proof.leaf_count);
        return result;
    }

    // 条件 1：待验证内容的叶子摘要必须与证明中的叶子完全一致。
    // content_leaf 按叶子规则带单个 0x00 前缀；普通文件摘要（无此前缀）
    // 不可能与真实叶子相等，不能借此通过。
    if (content_leaf != proof.leaf) {
        result.error =
            "proof rejected: supplied content leaf digest does not match the "
            "leaf digest in the proof";
        return result;
    }

    // 条件 4 + 条件 3 的折叠：兄弟的方向、数量与从叶子向根的次序必须严格
    // 符合 (leaf_count, leaf_index) 描述的位置；在逐层核对的同时按
    // SHA-256(0x01||left||right) 折叠。不能只在最后比对摘要——结构不符
    // （侧向错、缺项、多项、次序错）即使凑出相等摘要也必须拒绝。
    //
    // 各层节点数只做纯 uint64 模拟，绝不按 leaf_count 分配内存；上一层
    // 大小为 ceil(n/2)，写成 n - n/2 —— n 为奇数时 (n+1)/2 在
    // n=UINT64_MAX 处会回绕，n - n/2 不会。层数关于 n 有界（至多 64 层），
    // 因此最大可表示的合法计数也立即得到确定结果。
    std::uint64_t level_size = proof.leaf_count;
    std::uint64_t pos = proof.leaf_index;
    std::uint64_t tree_level = 0;  // 叶子之上第一层为 0，仅用于错误信息
    std::size_t consumed = 0;
    Digest node = content_leaf;

    while (level_size > 1) {
        // 与 merkle_proof_file 的记录规则完全一致：偶数位置且该位置是
        // 奇数层末节点时，节点原样提升，本层没有兄弟、不消费记录；
        // 偶数且右侧仍有伙伴 -> 必须有 right 兄弟；奇数位置 -> 必须有
        // left 兄弟（pos>=1，左侧伙伴必然存在）。
        // 写成 pos == level_size - 1 而非 pos + 1 >= level_size：
        // level_size > 1 保证减法安全，而 pos+1 在 pos=UINT64_MAX 时会
        // 无符号回绕成 0，恰好把“末节点提升”误判成“右侧有兄弟”。
        const bool promoted_without_sibling =
            (pos % 2 == 0) && (pos == level_size - 1);

        if (!promoted_without_sibling) {
            if (consumed >= proof.siblings.size()) {
                result.error =
                    "proof rejected: missing required sibling at tree level " +
                    std::to_string(tree_level) + " for leaf_index " +
                    std::to_string(proof.leaf_index) + " of leaf_count " +
                    std::to_string(proof.leaf_count);
                return result;
            }

            const MerkleSibling& sibling = proof.siblings[consumed];

            // side 只能是 left 或 right：证明结构可能由调用方自行构造，
            // 非法枚举值也必须明确拒绝，不能落入任一分支碰运气。
            bool sibling_on_right;
            if (sibling.side == MerkleSibling::Side::right) {
                sibling_on_right = true;
            } else if (sibling.side == MerkleSibling::Side::left) {
                sibling_on_right = false;
            } else {
                result.error =
                    "proof rejected: sibling at tree level " +
                    std::to_string(tree_level) +
                    " has an invalid side (only left or right is allowed)";
                return result;
            }

            const bool expected_on_right = (pos % 2 == 0);
            if (sibling_on_right != expected_on_right) {
                result.error =
                    "proof rejected: sibling at tree level " +
                    std::to_string(tree_level) + " is on the " +
                    (sibling_on_right ? "right" : "left") +
                    " side, but the position in the batch requires it on the " +
                    (expected_on_right ? "right" : "left");
                return result;
            }

            node = sibling_on_right
                       ? merkle_parent(node, sibling.digest)
                       : merkle_parent(sibling.digest, node);
            ++consumed;
        }
        // 原样提升或正常配对后，被选位置在上一层的下标都是 floor(pos/2)；
        // pos 始终小于 level_size，不会触及 UINT64_MAX 回绕。
        pos /= 2;
        ++tree_level;
        const std::uint64_t half = level_size / 2;
        level_size -= half;  // ceil(level_size/2)，无回绕。
    }

    // 到达根后不得还有多余兄弟。
    if (consumed != proof.siblings.size()) {
        result.error =
            "proof rejected: proof carries " +
            std::to_string(proof.siblings.size()) +
            " sibling(s), but the batch position requires exactly " +
            std::to_string(consumed);
        return result;
    }

    // 条件 2：信任锚只来自调用方单独传入的可信根；证明自报的 root 不能
    // 充当信任依据——属于另一批次的证明即使内部自洽也在此被拒。
    if (proof.root != trusted_root) {
        result.error =
            "proof rejected: root claimed by the proof does not match the "
            "trusted batch root";
        return result;
    }

    // 条件 3：兄弟必须真的把内容叶子折叠到可信根（防止 root 字段被改成
    // 可信根、但兄弟链与叶子并不相容的证明）。
    if (node != trusted_root) {
        result.error =
            "proof rejected: the supplied siblings do not combine the content "
            "leaf into the trusted batch root";
        return result;
    }

    result.valid = true;
    return result;
}

MerkleProofParseResult merkle_proof_from_json(std::string_view text) {
    MerkleProofParseResult result;

    // 全程写入本地 proof：只有文本完整通过后才移入返回值，任何失败都不
    // 留下可用的部分证明（返回对象保持默认构造）。
    MerkleProof proof;
    JsonParser p;
    p.text = text;

    enum FieldBit : unsigned {
        kVersion = 1u << 0,
        kRoot = 1u << 1,
        kLeafCount = 1u << 2,
        kLeafIndex = 1u << 3,
        kLeaf = 1u << 4,
        kSiblings = 1u << 5,
    };
    constexpr unsigned kAllFields = kVersion | kRoot | kLeafCount |
                                    kLeafIndex | kLeaf | kSiblings;
    unsigned seen = 0;

    p.ws();
    if (p.eof()) {
        result.error =
            "proof text rejected: input is empty or whitespace only "
            "(expected a version 1 proof JSON object)";
        return result;
    }
    if (p.peek() != '{') {
        result.error =
            "proof text rejected: top-level value must be a single JSON object";
        return result;
    }
    ++p.pos;
    p.ws();

    // 空对象（"{}"）不进入字段循环，直接落到后面的必填字段检查。
    if (!p.eof() && p.peek() == '}') {
        ++p.pos;
    } else {
        while (p.error.empty()) {
        p.ws();
        if (p.eof() || p.peek() != '"') {
            p.fail("expected a string field name in proof object");
            break;
        }
        std::string key;
        if (!p.read_string(key)) {
            break;
        }
        p.ws();
        if (p.eof() || p.peek() != ':') {
            p.fail("expected ':' after proof object field \"" + key + "\"");
            break;
        }
        ++p.pos;

        unsigned bit = 0;
        if (key == "version") {
            bit = kVersion;
        } else if (key == "root") {
            bit = kRoot;
        } else if (key == "leaf_count") {
            bit = kLeafCount;
        } else if (key == "leaf_index") {
            bit = kLeafIndex;
        } else if (key == "leaf") {
            bit = kLeaf;
        } else if (key == "siblings") {
            bit = kSiblings;
        } else {
            p.fail("undefined field \"" + key + "\" in proof object (version 1 "
                   "defines only version, root, leaf_count, leaf_index, leaf "
                   "and siblings)");
            break;
        }
        if (seen & bit) {
            p.fail("duplicate field \"" + key + "\" in proof object");
            break;
        }

        if (bit == kVersion) {
            std::uint64_t version = 0;
            if (!p.read_uint64(version, "version")) {
                break;
            }
            if (version != 1) {
                p.fail("unsupported proof version " +
                       std::to_string(version) + " (only version 1 is "
                       "supported)");
                break;
            }
        } else if (bit == kRoot) {
            if (!read_digest_value(p, proof.root, "root")) {
                break;
            }
        } else if (bit == kLeafCount) {
            if (!p.read_uint64(proof.leaf_count, "leaf_count")) {
                break;
            }
        } else if (bit == kLeafIndex) {
            if (!p.read_uint64(proof.leaf_index, "leaf_index")) {
                break;
            }
        } else if (bit == kLeaf) {
            if (!read_digest_value(p, proof.leaf, "leaf")) {
                break;
            }
        } else {  // kSiblings
            p.ws();
            if (p.eof() || p.peek() != '[') {
                p.fail("field \"siblings\" must be a JSON array");
                break;
            }
            if (!parse_siblings_array(p, proof.siblings)) {
                break;
            }
        }
        seen |= bit;

        p.ws();
        if (p.eof()) {
            p.fail("unterminated proof object");
            break;
        }
        if (p.peek() == '}') {
            ++p.pos;
            break;
        }
        if (p.peek() != ',') {
            p.fail("expected ',' or '}' in proof object");
            break;
        }
        ++p.pos;
        // 逗号之后要求另一个字段名；循环回到顶部做该检查。
        }
    }

    if (p.error.empty()) {
        // 对象之后除 JSON 空白外不得再有任何内容：不能只取前半段当作成功。
        p.ws();
        if (!p.eof()) {
            p.fail("unexpected trailing content after the proof JSON object");
        }
    }
    if (p.error.empty() && seen != kAllFields) {
        std::string missing;
        auto add = [&](unsigned b, const char* name) {
            if (!(seen & b)) {
                if (!missing.empty()) {
                    missing += ", ";
                }
                missing += '"';
                missing += name;
                missing += '"';
            }
        };
        add(kVersion, "version");
        add(kRoot, "root");
        add(kLeafCount, "leaf_count");
        add(kLeafIndex, "leaf_index");
        add(kLeaf, "leaf");
        add(kSiblings, "siblings");
        p.fail("proof object is missing required field(s): " + missing);
    }

    if (!p.error.empty()) {
        result.error = "proof text rejected: " + p.error;
        return result;
    }

    result.proof = std::move(proof);
    return result;
}

}  // namespace branchaudit
