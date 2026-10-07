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

// merkle_verify_proof 的结果：通过时 valid 为真、error 为空；
// 任一条件不满足时 valid 为假，error 给出可供调用方直接展示的原因。
// 校验全程只返回结构化结果，不打印、不结束进程。
struct MerkleVerifyResult {
    bool valid = false;
    std::string error;

    bool ok() const { return valid && error.empty(); }
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

// 校验一份成员证明是否支持“某个内容受到可信批次根支持”。
//
// 只消费三项已有输入，不读取文件、不重新提供或扫描整个批次：
//  * proof：merkle_proof_file 产出的证明结构；
//  * trusted_root：调用方另行持有的可信批次根摘要（32 个原始字节，例如
//    来自独立渠道保存的 root 输出），不能用 proof.root 充当信任依据；
//  * content_leaf：待验证内容按现有叶子规则计算的摘要
//    SHA-256(0x00 || content)（32 个原始字节），即 merkle_leaf 对该内容
//    的输出；它带单个 0x00 前缀，不能用 hash/sha256_file 输出的普通文件
//    摘要替代。
//
// 仅当以下条件同时成立才通过：
//  1. content_leaf 与 proof.leaf 完全一致；
//  2. proof.root 与 trusted_root 完全一致（信任锚只来自调用方传入）；
//  3. proof.siblings 能按 0x01 父节点字节规则从 content_leaf 折叠回
//     trusted_root；
//  4. siblings 的方向、数量与从叶子向根的次序严格符合 proof.leaf_count 与
//     proof.leaf_index 所描述的位置：leaf_count 为零（空批次）没有成员；
//     leaf_index 必须小于 leaf_count；每项 side 只能是 left 或 right；
//     奇数层末节点原样提升的层本就没有兄弟，生成端省略这些层记录的证明
//     正常通过，不要求补齐；缺少必要项或多出项都判失败。因此一份内部
//     自洽但属于另一批次（另一可信根）或位置结构不符的证明不会通过。
//
// 保证范围——“内容受到可信根支持”与“批次大小、位置已认证”是两回事：
// 通过只说明 content_leaf 受到 trusted_root 支持，且兄弟记录与证明
// **自报**的 (leaf_count, leaf_index) 自洽。leaf_count/leaf_index 是
// 证明自带的声明，本函数的三项输入（证明、可信根、内容叶子）里没有任何
// 东西能把它们锚定到原始批次：仅改动这两个数字、保留根/叶子/兄弟记录的
// 证明，只要新数字与兄弟记录的形状相容，同样会通过（例如三条目批次
// 位置 2 的证明把声明改成 leaf_count=2、leaf_index=1 后仍通过）。这
// 不表示内容移动了位置或原批次只有两个条目——能得出的结论仍然只是
// “该内容受到同一可信根支持”。当然，并非任意改数都能通过：越界位置
// （leaf_index >= leaf_count）或与兄弟记录的方向/数量/次序不符的声明
// 仍会被拒绝。调用方若需要“内容属于条目数已知的批次且处于指定位置”的
// 结论，必须把批次大小与预期位置同可信根一起独立保存，并在本函数之外
// 比对 proof.leaf_count/proof.leaf_index；不一致时即使本函数通过，
// 也不能认定位置。
//
// leaf_count/leaf_index 沿用无符号 64 位范围；结构推导只做不回绕的整数
// 运算且层数有界，最大可表示的合法计数（UINT64_MAX）也有确定结果，不会
// 因数值回绕误判或无法结束。单文件批次只接受位置 0 与空兄弟列表；空文件
// 的叶子（SHA-256(0x00)）与空批次根不同，不会互相冒充；重复内容各占独立
// 位置，校验按位置结构核对，不按摘要去重。
//
// 成功时返回 {valid=true, error=""}；失败时 valid 为假，error 为可供调用
// 方直接展示的原因。函数只返回结构化结果，不打印、不退出进程。
MerkleVerifyResult merkle_verify_proof(const MerkleProof& proof,
                                       const Digest& trusted_root,
                                       const Digest& content_leaf);

}  // namespace branchaudit
