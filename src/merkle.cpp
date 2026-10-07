#include "merkle.h"

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

}  // namespace branchaudit
