#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "filehash.h"
#include "sha256.h"

namespace branchaudit {

// 32 字节原始摘要。Merkle 各层组合一律使用原始字节，不使用十六进制文本。
using Digest = std::array<std::uint8_t, Sha256::kDigestSize>;

// 空批次根：SHA-256 对空字节序列。
// 注意它与“单个空文件”的叶子摘要不同（叶子带 0x00 前缀）。
Digest merkle_empty_root();

// 文件叶子：SHA-256(0x00 || data)。
// 0x00 是值为 0x00 的单个原始前缀字节，不是字符串；data 为文件全部原始字节。
// 供已知字节内容时直接组合使用；文件请用流式的 merkle_root_files。
Digest merkle_leaf(const unsigned char* data, std::size_t size);

// 父摘要：SHA-256(0x01 || left || right)。
// 0x01 是值为 0x01 的单个原始前缀字节，left/right 各为 32 个原始字节，
// 先左后右，顺序不可交换。
Digest merkle_parent(const Digest& left, const Digest& right);

// 计算一个有序文件批次的 Merkle 根。
//
// 位置顺序完全取自 paths 的下标：不按文件名或摘要排序，也不去重；
// 同一路径重复出现、多个文件内容相同，都各自保留独立位置。根只反映各位置
// 的文件内容，不包含任何路径文字。
//
// 配对规则：每层相邻节点先左后右两两配对；若该层节点数为奇数，最后一个
// 节点没有伙伴，其摘要原样提升到上一层，不复制、不补零，直到只剩一个根。
// 只有一个文件时根即其叶子摘要；paths 为空时返回 merkle_empty_root()。
//
// 叶子按流式计算（固定缓冲），内存占用与文件大小无关。任一文件不存在、
// 指向目录、无法打开或读取失败时，整次计算失败：返回 error 非空的结果，
// 说明失败的路径和原因，不用其余文件产出部分结果。不打印、不退出进程。
FileHashResult merkle_root_files(const std::vector<std::filesystem::path>& paths);

// 证明路径上的一个兄弟节点：side 指明兄弟位于当前节点的哪一侧，
// digest 是该兄弟的摘要（32 个原始字节）。
struct MerkleSibling {
    enum class Side { left, right };
    Side side;
    Digest digest;
};

// 单个文件位置的成员证明。root 与 merkle_root_files 对同一有序批次的
// 结果一致；leaf 是被选文件带 0x00 前缀的叶子摘要；siblings 从叶子向根
// 逐层排列，只记录实际存在的兄弟——奇数末节点原样提升的层不添加记录，
// 不复制末节点、不补零。证明不含文件内容与路径。
struct MerkleProof {
    Digest root{};
    std::uint64_t leaf_count = 0;
    std::uint64_t leaf_index = 0;
    Digest leaf{};
    std::vector<MerkleSibling> siblings;
};

// merkle_proof_file 的结果：成功时 error 为空、proof 有效；
// 失败时 error 说明原因。
struct MerkleProofResult {
    MerkleProof proof;
    std::string error;

    bool ok() const { return error.empty(); }
};

// 为有序批次中位于 leaf_index（从 0 开始）的文件生成成员证明。
//
// 批次规则与 merkle_root_files 完全相同：位置顺序取自 paths 下标，
// 不排序、不去重，同一路径重复出现各占一个位置；叶子按流式计算，
// 内存占用与文件大小无关。
//
// leaf_index 不落在批次内（paths 为空时没有任何合法位置）时返回 error
// 非空的结果；任一文件不存在、指向目录、无法打开或读取失败时整次失败，
// 返回 error 说明失败的路径和原因，不产出部分证明。不打印、不退出进程。
MerkleProofResult merkle_proof_file(
    const std::vector<std::filesystem::path>& paths, std::uint64_t leaf_index);

}  // namespace branchaudit
