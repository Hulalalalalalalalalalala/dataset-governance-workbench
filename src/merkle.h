#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
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

}  // namespace branchaudit
