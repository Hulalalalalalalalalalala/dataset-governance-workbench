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

// 读取整个有序批次的叶子层。严格按 paths 下标顺序处理：不排序、不去重。
// root 与 prove 共用它，保证二者对同一批次得到完全一致的叶子与失败语义。
// 任一文件失败立即返回 error，已产出的叶子不会被调用方用于部分结果。
FileHashResult read_leaves(const std::vector<std::filesystem::path>& paths,
                           std::vector<Digest>& leaves) {
    leaves.clear();
    leaves.reserve(paths.size());
    for (const std::filesystem::path& path : paths) {
        FileHashResult leaf = leaf_file(path);
        if (!leaf.ok()) {
            return leaf;
        }
        leaves.push_back(leaf.digest);
    }
    return FileHashResult{};
}

}  // namespace

FileHashResult merkle_root_files(const std::vector<std::filesystem::path>& paths) {
    FileHashResult result;

    // 没有文件：空字节序列的 SHA-256。
    if (paths.empty()) {
        result.digest = merkle_empty_root();
        return result;
    }

    // 叶子层。严格按 paths 下标顺序处理：不排序、不去重。
    std::vector<Digest> level;
    if (FileHashResult leaves = read_leaves(paths, level); !leaves.ok()) {
        result.error = std::move(leaves.error);
        return result;
    }

    // 逐层相邻配对：先左后右；奇数个时末节点原样提升（不复制、不补零）。
    while (level.size() > 1) {
        std::vector<Digest> next;
        const bool odd = (level.size() % 2) != 0;
        next.reserve(level.size() / 2 + (odd ? 1 : 0));
        for (std::size_t i = 0; i + 1 < level.size(); i += 2) {
            next.push_back(merkle_parent(level[i], level[i + 1]));
        }
        if (odd) {
            next.push_back(level.back());
        }
        level = std::move(next);
    }

    result.digest = level.front();
    return result;
}

MerkleProofResult merkle_proof_files(
        const std::vector<std::filesystem::path>& paths,
        std::size_t leaf_index) {
    MerkleProofResult result;

    // 空批次没有合法位置；位置必须落在批次内。位置解析（仅十进制数字、
    // 溢出判定）属于命令行/调用方的职责，这里只做范围检查。
    if (paths.empty() || leaf_index >= paths.size()) {
        result.error = "leaf index out of range";
        return result;
    }

    // 与 root 共用同一条叶子读取路径：同样的流式字节规则与文件失败语义；
    // 任一文件失败立即返回，不产出部分证明。
    std::vector<Digest> level;
    if (FileHashResult leaves = read_leaves(paths, level); !leaves.ok()) {
        result.error = std::move(leaves.error);
        return result;
    }

    result.proof.leaf_count = level.size();
    result.proof.leaf_index = leaf_index;
    result.proof.leaf = level[leaf_index];

    // 追踪被选叶子逐层向上：当前节点在本层的位置 current。
    //  * current 为偶数：它是父节点的左子，兄弟（若存在）在右侧；
    //  * current 为奇数：它是父节点的右子，兄弟在左侧；
    //  * current 恰好是奇数层最后一个节点时没有伙伴，原样提升，本层不记录。
    std::size_t current = leaf_index;
    while (level.size() > 1) {
        const bool odd = (level.size() % 2) != 0;
        const bool is_unpaired_last = odd && current == level.size() - 1;
        if (!is_unpaired_last) {
            const std::size_t sibling_index =
                (current % 2 == 0) ? current + 1 : current - 1;
            result.proof.siblings.push_back(
                {current % 2 == 0 ? ProofSide::kRight : ProofSide::kLeft,
                 level[sibling_index]});
        }

        std::vector<Digest> next;
        next.reserve(level.size() / 2 + (odd ? 1 : 0));
        for (std::size_t i = 0; i + 1 < level.size(); i += 2) {
            next.push_back(merkle_parent(level[i], level[i + 1]));
        }
        if (odd) {
            next.push_back(level.back());
        }
        level = std::move(next);
        current /= 2;
    }

    result.proof.root = level.front();
    return result;
}

}  // namespace branchaudit
