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

}  // namespace

FileHashResult merkle_root_files(const std::vector<std::filesystem::path>& paths) {
    FileHashResult result;

    // 没有文件：空字节序列的 SHA-256。
    if (paths.empty()) {
        result.digest = merkle_empty_root();
        return result;
    }

    // 叶子层。严格按 paths 下标顺序处理：不排序、不去重。
    // 任一文件失败立即返回，不读取也不使用其后的任何文件。
    std::vector<Digest> level;
    level.reserve(paths.size());
    for (const std::filesystem::path& path : paths) {
        FileHashResult leaf = leaf_file(path);
        if (!leaf.ok()) {
            result.error = std::move(leaf.error);
            return result;
        }
        level.push_back(leaf.digest);
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

}  // namespace branchaudit
