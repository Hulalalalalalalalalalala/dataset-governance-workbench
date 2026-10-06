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

}  // namespace branchaudit
