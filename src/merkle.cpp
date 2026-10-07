#include "merkle.h"

#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>
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

namespace {

// ---- 只读、严格的 JSON 语法读取器（仅服务于 merkle_proof_from_json）--------
//
// 不接受语法宽松：要求合法的 UTF-8 JSON（RFC 8259 语法），拒绝尾逗号、
// 裸标识符（true/false/null 除外）、单引号、注释、NaN/Infinity、+ 号等。
// 数字按“仅十进制整数”处理：小数与指数在词法层即可识别，由调用方按字段
// 决定是否接受。解析结果是一棵小的值树——一份证明文本很小（每兄弟约 90
// 字节、至多 64 项），不存在按外部计数分配内存的问题。
namespace json {

struct Value {
    enum class Type { null, boolean, integer, real, string, array, object };
    Type type = Type::null;
    bool boolean = false;
    std::uint64_t integer = 0;
    std::string string;  // string：已反转义；real：数字原文
    std::vector<Value> array;
    // object：保持输入字段次序；重复键在读取对象时直接判失败。
    std::vector<std::pair<std::string, Value>> object;
};

class Parser {
public:
    explicit Parser(std::string_view text) : text_(text) {}

    // 解析整段文本：一个 JSON 值，其后只允许 JSON 空白；空文本失败。
    bool parse_document(Value& out, std::string& error) {
        skip_ws();
        if (!parse_value(out)) {
            error = fail_message();
            return false;
        }
        skip_ws();
        if (pos_ != text_.size()) {
            error = "invalid proof JSON: trailing content after the proof "
                    "object";
            return false;
        }
        return true;
    }

private:
    // 合法证明的嵌套至多 3 层（对象 -> siblings 数组 -> 兄弟对象）；给足
    // 余量后把递归深度限制在一个很小的值，使恶意深嵌套输入得到普通失败
    // 而不是撑爆调用方进程的栈（读取绝不允许以崩溃结束调用方）。
    static constexpr unsigned kMaxDepth = 8;

    std::string_view text_;
    std::size_t pos_ = 0;
    unsigned depth_ = 0;
    std::string fail_;  // 非空即失败原因；优先于通用的位置信息

    // 进入一个容器（对象/数组）时占用一层深度；离开时自动归还。
    class DepthGuard {
    public:
        explicit DepthGuard(Parser& parser) : parser_(parser) {
            allowed = parser_.depth_ < Parser::kMaxDepth;
            if (allowed) {
                ++parser_.depth_;
            }
        }
        ~DepthGuard() {
            if (allowed) {
                --parser_.depth_;
            }
        }
        bool allowed = false;

    private:
        Parser& parser_;
    };

    char peek() const {
        return pos_ < text_.size() ? text_[pos_] : '\0';
    }

    bool eof() const { return pos_ >= text_.size(); }

    void fail(std::string message) {
        if (fail_.empty()) {
            fail_ = std::move(message);
        }
    }

    std::string fail_message() const {
        if (!fail_.empty()) {
            return fail_;
        }
        if (eof()) {
            return "invalid proof JSON: unexpected end of text";
        }
        return "invalid proof JSON: unexpected character at byte offset " +
               std::to_string(pos_);
    }

    void skip_ws() {
        while (pos_ < text_.size()) {
            const char c = text_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++pos_;
            } else {
                break;
            }
        }
    }

    bool consume_literal(const char* literal) {
        std::size_t n = 0;
        while (literal[n] != '\0') {
            if (pos_ + n >= text_.size() || text_[pos_ + n] != literal[n]) {
                return false;
            }
            ++n;
        }
        pos_ += n;
        return true;
    }

    bool parse_value(Value& out) {
        if (eof()) {
            fail("invalid proof JSON: expected a value but reached end of "
                 "text");
            return false;
        }
        switch (peek()) {
            case '{': return parse_object(out);
            case '[': return parse_array(out);
            case '"':
                out.type = Value::Type::string;
                return parse_string(out.string);
            case 't':
                if (!consume_literal("true")) {
                    fail("invalid proof JSON: malformed literal");
                    return false;
                }
                out.type = Value::Type::boolean;
                out.boolean = true;
                return true;
            case 'f':
                if (!consume_literal("false")) {
                    fail("invalid proof JSON: malformed literal");
                    return false;
                }
                out.type = Value::Type::boolean;
                out.boolean = false;
                return true;
            case 'n':
                if (!consume_literal("null")) {
                    fail("invalid proof JSON: malformed literal");
                    return false;
                }
                out.type = Value::Type::null;
                return true;
            default:
                if (peek() == '-' || (peek() >= '0' && peek() <= '9')) {
                    return parse_number(out);
                }
                fail("invalid proof JSON: unexpected character at byte "
                     "offset " + std::to_string(pos_));
                return false;
        }
    }

    bool parse_object(Value& out) {
        DepthGuard depth(*this);
        if (!depth.allowed) {
            fail("invalid proof JSON: nesting is too deep");
            return false;
        }
        out.type = Value::Type::object;
        ++pos_;  // '{'
        skip_ws();
        if (peek() == '}') {
            ++pos_;
            return true;
        }
        while (true) {
            skip_ws();
            if (peek() != '"') {
                fail("invalid proof JSON: expected a quoted field name in "
                     "object");
                return false;
            }
            std::string key;
            if (!parse_string(key)) {
                return false;
            }
            skip_ws();
            if (peek() != ':') {
                fail("invalid proof JSON: expected ':' after field name");
                return false;
            }
            ++pos_;
            skip_ws();
            Value value;
            if (!parse_value(value)) {
                return false;
            }
            // 同一对象出现重复字段：直接判失败，不做“后者覆盖前者”。
            for (const auto& entry : out.object) {
                if (entry.first == key) {
                    fail("invalid proof JSON: duplicate field \"" + key +
                         "\" in the same object");
                    return false;
                }
            }
            out.object.emplace_back(std::move(key), std::move(value));
            skip_ws();
            const char c = peek();
            if (c == ',') {
                ++pos_;
                continue;  // 尾逗号会在下一轮因缺少引号而失败
            }
            if (c == '}') {
                ++pos_;
                return true;
            }
            fail("invalid proof JSON: expected ',' or '}' in object");
            return false;
        }
    }

    bool parse_array(Value& out) {
        DepthGuard depth(*this);
        if (!depth.allowed) {
            fail("invalid proof JSON: nesting is too deep");
            return false;
        }
        out.type = Value::Type::array;
        ++pos_;  // '['
        skip_ws();
        if (peek() == ']') {
            ++pos_;
            return true;
        }
        while (true) {
            skip_ws();
            Value value;
            if (!parse_value(value)) {
                return false;
            }
            out.array.push_back(std::move(value));
            skip_ws();
            const char c = peek();
            if (c == ',') {
                ++pos_;
                continue;  // 尾逗号会在下一轮 parse_value 处失败
            }
            if (c == ']') {
                ++pos_;
                return true;
            }
            fail("invalid proof JSON: expected ',' or ']' in array");
            return false;
        }
    }

    // 解析 JSON 字符串（含完整转义）；成功时 out 为已反转义的 UTF-8 内容。
    // 控制字符必须转义；非法转义、代理项不配对与半截 UTF-8 都判失败。
    // 入口与出口时 pos_ 都指向下一个待处理字符（入口为开引号，函数先跨过
    // 它；出口指向闭引号之后）。
    bool parse_string(std::string& out) {
        ++pos_;  // 跨过开引号
        while (true) {
            if (pos_ >= text_.size()) {
                fail("invalid proof JSON: unterminated string");
                return false;
            }
            const unsigned char c =
                static_cast<unsigned char>(text_[pos_]);
            if (c == '"') {
                ++pos_;  // 跨过闭引号
                return true;
            }
            if (c == '\\') {
                ++pos_;  // 跨过反斜杠，指向转义字符
                if (pos_ >= text_.size()) {
                    fail("invalid proof JSON: unterminated escape");
                    return false;
                }
                const char e = text_[pos_];
                if (e == 'u') {
                    std::uint32_t cp = 0;
                    ++pos_;  // 跨过 'u'，指向第一个十六进制数位
                    if (!parse_hex4(cp)) {
                        return false;
                    }
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        // 高代理项：必须紧跟 \uXXXX 形式的低代理项。
                        if (pos_ + 2 > text_.size() ||
                            text_[pos_] != '\\' ||
                            text_[pos_ + 1] != 'u') {
                            fail("invalid proof JSON: unpaired UTF-16 "
                                 "high surrogate");
                            return false;
                        }
                        pos_ += 2;  // 跳过 "\u"
                        std::uint32_t lo = 0;
                        if (!parse_hex4(lo) ||
                            lo < 0xDC00 || lo > 0xDFFF) {
                            fail("invalid proof JSON: invalid UTF-16 "
                                 "low surrogate");
                            return false;
                        }
                        cp = 0x10000 + ((cp - 0xD800) << 10) +
                             (lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        fail("invalid proof JSON: unpaired UTF-16 low "
                             "surrogate");
                        return false;
                    }
                    append_utf8(cp, out);
                    continue;  // parse_hex4 已把 pos_ 移到末数位之后
                }
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    default:
                        fail("invalid proof JSON: invalid escape sequence");
                        return false;
                }
                ++pos_;  // 跨过单字符转义
                continue;
            }
            if (c < 0x20) {
                fail("invalid proof JSON: unescaped control character in "
                     "string");
                return false;
            }
            // 原样保留 UTF-8 字节，但拒绝半截序列：读入一个完整码点。
            const std::size_t len = utf8_sequence_len(c);
            if (len == 0 || pos_ + len > text_.size()) {
                fail("invalid proof JSON: malformed UTF-8 in string");
                return false;
            }
            if (!utf8_tail_valid(c, len)) {
                fail("invalid proof JSON: malformed UTF-8 in string");
                return false;
            }
            out.append(text_.data() + pos_, len);
            pos_ += len;
        }
    }

    // 读取恰好 4 个十六进制数位；入口 pos_ 指向第一个数位，成功后 pos_
    // 指向末数位之后（即下一个待处理字符）。
    bool parse_hex4(std::uint32_t& out) {
        if (pos_ + 4 > text_.size()) {
            fail("invalid proof JSON: incomplete \\uXXXX escape");
            return false;
        }
        std::uint32_t value = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            const char c = text_[pos_ + i];
            value <<= 4;
            if (c >= '0' && c <= '9') {
                value |= static_cast<std::uint32_t>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                value |= static_cast<std::uint32_t>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                value |= static_cast<std::uint32_t>(c - 'A' + 10);
            } else {
                fail("invalid proof JSON: invalid hex digit in \\uXXXX "
                     "escape");
                return false;
            }
        }
        pos_ += 4;
        out = value;
        return true;
    }

    static std::size_t utf8_sequence_len(unsigned char lead) {
        if (lead < 0x80) return 1;
        if ((lead & 0xE0) == 0xC0) return 2;
        if ((lead & 0xF0) == 0xE0) return 3;
        if ((lead & 0xF8) == 0xF0) return 4;
        return 0;  // 孤立续字节或非法首字节（0xF8+）
    }

    bool utf8_tail_valid(unsigned char lead, std::size_t len) {
        // 续字节必须形如 10xxxxxx；首字节与长度匹配已由调用方保证。
        for (std::size_t i = 1; i < len; ++i) {
            const unsigned char t =
                static_cast<unsigned char>(text_[pos_ + i]);
            if ((t & 0xC0) != 0x80) {
                return false;
            }
        }
        // 拒绝过长编码与超范围码点。
        if (len == 2 && lead < 0xC2) return false;
        if (len == 3) {
            const unsigned char t1 =
                static_cast<unsigned char>(text_[pos_ + 1]);
            if (lead == 0xE0 && t1 < 0xA0) return false;
            if (lead == 0xED && t1 > 0x9F) return false;
        }
        if (len == 4) {
            const unsigned char t1 =
                static_cast<unsigned char>(text_[pos_ + 1]);
            if (lead == 0xF0 && t1 < 0x90) return false;
            if (lead == 0xF4 && t1 > 0x8F) return false;
            if (lead > 0xF4) return false;
        }
        return true;
    }

    static void append_utf8(std::uint32_t cp, std::string& out) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
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

    // 数字按 RFC 8259 词法解析；进一步区分 integer/real 并对整数做无符号
    // 64 位范围检查（含前导零、负号、小数部分与指数）。
    bool parse_number(Value& out) {
        const std::size_t start = pos_;
        bool negative = false;
        if (peek() == '-') {
            negative = true;
            ++pos_;
        }
        // 整数部分：0 不能有多位数；1-9 后接若干数位。
        if (peek() == '0') {
            ++pos_;
        } else if (peek() >= '1' && peek() <= '9') {
            while (peek() >= '0' && peek() <= '9') {
                ++pos_;
            }
        } else {
            fail("invalid proof JSON: malformed number");
            return false;
        }
        bool fractional = false;
        if (peek() == '.') {
            fractional = true;
            ++pos_;
            if (!(peek() >= '0' && peek() <= '9')) {
                fail("invalid proof JSON: malformed number: digits expected "
                     "after decimal point");
                return false;
            }
            while (peek() >= '0' && peek() <= '9') {
                ++pos_;
            }
        }
        bool exponent = false;
        if (peek() == 'e' || peek() == 'E') {
            exponent = true;
            ++pos_;
            if (peek() == '+' || peek() == '-') {
                ++pos_;
            }
            if (!(peek() >= '0' && peek() <= '9')) {
                fail("invalid proof JSON: malformed number: digits expected "
                     "in exponent");
                return false;
            }
            while (peek() >= '0' && peek() <= '9') {
                ++pos_;
            }
        }
        const std::string_view lexeme = text_.substr(
            start, pos_ - start);
        if (fractional || exponent) {
            // 小数值（含 -0.0、1e2）对所有字段都是错误类型；保留原文用于
            // 说明，绝不四舍五入成整数接受。
            out.type = Value::Type::real;
            out.string = std::string{lexeme};
            return true;
        }
        // 纯整数：负数在词法合法但所有证明字段都不接受；直接拒绝，无需
        // 再做无符号范围换算。
        if (negative) {
            fail("invalid proof JSON: negative number " +
                 std::string{lexeme} + " is not accepted");
            return false;
        }
        // 非负整数必须落在 UINT64_MAX 内；超出范围拒绝，不截断、不回绕。
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < lexeme.size(); ++i) {
            const unsigned d =
                static_cast<unsigned>(lexeme[i] - '0');
            if (value > (UINT64_MAX - d) / 10) {
                fail("invalid proof JSON: integer " +
                     std::string{lexeme} +
                     " exceeds the unsigned 64-bit range");
                return false;
            }
            value = value * 10 + d;
        }
        out.type = Value::Type::integer;
        out.integer = value;
        return true;
    }
};

}  // namespace json

// 取对象字段；缺失或重复（重复已在解析层拒绝）由 found 标志区分。
const json::Value* find_field(const json::Value& object,
                              const std::string& key) {
    for (const auto& entry : object.object) {
        if (entry.first == key) {
            return &entry.second;
        }
    }
    return nullptr;
}

// 恰好 64 个小写十六进制字符 -> 32 字节；任何不符都返回错误，不截断、
// 不替换损坏内容。
bool decode_digest(const std::string& text, Digest& out,
                   std::string& error) {
    if (text.size() != 64) {
        error = "invalid proof JSON: digest must be exactly 64 lowercase "
                "hex characters, got " + std::to_string(text.size()) +
                " character(s)";
        return false;
    }
    static constexpr std::uint8_t kBad = 0xFF;
    auto nibble = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
        if (c >= 'a' && c <= 'f')
            return static_cast<std::uint8_t>(c - 'a' + 10);
        return kBad;  // 大写字符与其他字符一律拒绝
    };
    for (std::size_t i = 0; i < 32; ++i) {
        const std::uint8_t hi = nibble(text[2 * i]);
        const std::uint8_t lo = nibble(text[2 * i + 1]);
        if (hi == kBad || lo == kBad) {
            error = "invalid proof JSON: digest must contain only lowercase "
                    "hexadecimal characters (0-9, a-f)";
            return false;
        }
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

std::string type_name(const json::Value& v) {
    using V = json::Value;
    switch (v.type) {
        case V::Type::null: return "null";
        case V::Type::boolean: return "boolean";
        case V::Type::integer: return "integer";
        case V::Type::real: return "number with a fraction or exponent";
        case V::Type::string: return "string";
        case V::Type::array: return "array";
        case V::Type::object: return "object";
    }
    return "value";
}

// 取一个“必须存在且为 JSON 整数（0..UINT64_MAX）”的字段。
bool require_uint_field(const json::Value& object, const char* key,
                        std::uint64_t& out, std::string& error) {
    const json::Value* v = find_field(object, key);
    if (v == nullptr) {
        error = std::string("invalid proof JSON: missing required field \"") +
                key + "\"";
        return false;
    }
    if (v->type != json::Value::Type::integer) {
        error = std::string("invalid proof JSON: field \"") + key +
                "\" must be a JSON integer in the unsigned 64-bit range, got " +
                type_name(*v);
        return false;
    }
    out = v->integer;
    return true;
}

// 取一个“必须存在且为 64 小写十六进制摘要字符串”的字段。
bool require_digest_field(const json::Value& object, const char* key,
                          Digest& out, std::string& error) {
    const json::Value* v = find_field(object, key);
    if (v == nullptr) {
        error = std::string("invalid proof JSON: missing required field \"") +
                key + "\"";
        return false;
    }
    if (v->type != json::Value::Type::string) {
        error = std::string("invalid proof JSON: field \"") + key +
                "\" must be a 64-character lowercase hex string, got " +
                type_name(*v);
        return false;
    }
    if (!decode_digest(v->string, out, error)) {
        return false;
    }
    return true;
}

}  // namespace

MerkleProofParseResult merkle_proof_from_json(std::string_view text) {
    MerkleProofParseResult result;

    json::Value root;
    std::string error;
    json::Parser parser(text);
    if (!parser.parse_document(root, error)) {
        result.error = std::move(error);
        return result;
    }

    if (root.type != json::Value::Type::object) {
        result.error =
            "invalid proof JSON: top-level value must be an object, got " +
            type_name(root);
        return result;
    }

    // 顶层对象恰好包含六个已定义字段：任何未定义字段（含拼写近似）都失败。
    static constexpr const char* kRequired[] = {
        "version", "root", "leaf_count", "leaf_index", "leaf", "siblings"};
    if (root.object.size() != std::size(kRequired)) {
        result.error =
            "invalid proof JSON: proof object must contain exactly the six "
            "version 1 fields (version, root, leaf_count, leaf_index, leaf, "
            "siblings)";
        return result;
    }
    for (const auto& entry : root.object) {
        bool defined = false;
        for (const char* name : kRequired) {
            if (entry.first == name) {
                defined = true;
                break;
            }
        }
        if (!defined) {
            result.error = "invalid proof JSON: undefined field \"" +
                           entry.first + "\" in proof object";
            return result;
        }
    }

    // version：只接受 JSON 整数 1。1.0、"1"、true 都在类型检查处拒绝；
    // 2 等其他整数版本明确不支持。
    const json::Value* version = find_field(root, "version");
    if (version->type != json::Value::Type::integer) {
        result.error =
            "invalid proof JSON: field \"version\" must be the JSON integer "
            "1, got " + type_name(*version);
        return result;
    }
    if (version->integer != 1) {
        result.error =
            "invalid proof JSON: unsupported proof version " +
            std::to_string(version->integer) + " (only version 1 is "
            "supported)";
        return result;
    }

    // 全部字段先解码进局部 proof：任何一步失败都直接返回，此时 result.proof
    // 保持默认构造——失败不向调用方提供任何可用的部分证明。
    MerkleProof proof;

    if (!require_digest_field(root, "root", proof.root, result.error) ||
        !require_uint_field(root, "leaf_count", proof.leaf_count,
                           result.error) ||
        !require_uint_field(root, "leaf_index", proof.leaf_index,
                           result.error) ||
        !require_digest_field(root, "leaf", proof.leaf, result.error)) {
        return result;
    }

    // siblings：数组；顺序、方向、摘要严格按输入保留，不重排、不去重、
    // 不为奇数提升层补记录。空数组（单文件证明）正常读入。
    const json::Value* siblings = find_field(root, "siblings");
    if (siblings->type != json::Value::Type::array) {
        result.error =
            "invalid proof JSON: field \"siblings\" must be an array, got " +
            type_name(*siblings);
        return result;
    }
    proof.siblings.reserve(siblings->array.size());
    for (std::size_t i = 0; i < siblings->array.size(); ++i) {
        const json::Value& entry = siblings->array[i];
        const std::string at = "sibling #" + std::to_string(i);
        if (entry.type != json::Value::Type::object) {
            result.error = "invalid proof JSON: " + at +
                           " must be an object, got " + type_name(entry);
            return result;
        }
        static constexpr const char* kSiblingFields[] = {"side", "digest"};
        if (entry.object.size() != std::size(kSiblingFields)) {
            result.error = "invalid proof JSON: " + at +
                           " must contain exactly the fields side and digest";
            return result;
        }
        for (const auto& field : entry.object) {
            if (field.first != "side" && field.first != "digest") {
                result.error = "invalid proof JSON: " + at +
                               " has undefined field \"" + field.first + "\"";
                return result;
            }
        }
        const json::Value* side = find_field(entry, "side");
        const json::Value* digest = find_field(entry, "digest");
        if (side == nullptr || digest == nullptr) {
            result.error = "invalid proof JSON: " + at +
                           " must contain both \"side\" and \"digest\"";
            return result;
        }
        MerkleSibling sibling;
        if (side->type != json::Value::Type::string) {
            result.error = "invalid proof JSON: " + at +
                           ": field \"side\" must be the string \"left\" or "
                           "\"right\", got " + type_name(*side);
            return result;
        }
        if (side->string == "left") {
            sibling.side = MerkleSibling::Side::left;
        } else if (side->string == "right") {
            sibling.side = MerkleSibling::Side::right;
        } else {
            result.error = "invalid proof JSON: " + at +
                           ": sibling side must be \"left\" or \"right\", "
                           "got \"" + side->string + "\"";
            return result;
        }
        if (digest->type != json::Value::Type::string) {
            result.error = "invalid proof JSON: " + at +
                           ": field \"digest\" must be a 64-character "
                           "lowercase hex string, got " + type_name(*digest);
            return result;
        }
        std::string digest_error;
        if (!decode_digest(digest->string, sibling.digest, digest_error)) {
            result.error = "invalid proof JSON: " + at + ": " + digest_error;
            return result;
        }
        proof.siblings.push_back(std::move(sibling));
    }

    // 全部字段成功后才发布证明。
    result.proof = std::move(proof);
    return result;
}

}  // namespace branchaudit
