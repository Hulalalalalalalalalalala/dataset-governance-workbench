#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "sha256.h"

namespace branchaudit {

// 32 字节 SHA-256 摘要。
using Digest = std::array<std::uint8_t, Sha256::kDigestSize>;

// sha256_file 的结果：成功时 error 为空、digest 有效；失败时 error 说明原因。
struct FileHashResult {
    Digest digest{};
    std::string error;

    bool ok() const { return error.empty(); }
};

// merkle_root 的结果：成功时 error 为空、digest 为批次根摘要；批次中任一
// 文件失败时 error 说明失败路径和原因，digest 无效。
struct MerkleRootResult {
    Digest digest{};
    std::string error;

    bool ok() const { return error.empty(); }
};

// 计算文件内容的 SHA-256 摘要。
//
// 以实际读取的原始字节为输入：不包含文件名或路径，不做任何编码转换、
// 换行替换或空白处理。流式读取，内存占用与文件大小无关。
// 路径不存在、指向目录、无法打开或读取失败时，返回 error 非空的结果，
// 不打印、不退出进程，由调用方决定如何处理。
FileHashResult sha256_file(const std::filesystem::path& path);

// 计算一个有序文件批次的 Merkle 根。
//
// paths 的顺序就是批次中各位置的顺序：不按文件名或摘要排序，不去重；
// 同一路径重复出现或多个文件内容相同，都各自保留独立位置。根只反映各
// 位置的文件内容，不包含任何路径文字，文件改名或移动后以相同顺序传入
// 结果不变。
//
// 字节规则（全部使用原始字节，不是十六进制文本）：
//   - 文件叶子：SHA-256(0x00 || 文件全部原始字节)。
//   - 父节点：SHA-256(0x01 || 左摘要 32 字节 || 右摘要 32 字节)。
//   - 每层相邻节点先左后右配对；最后一个无伙伴的节点摘要原样进入上一层，
//     不复制、不补零，直到只剩一个根。
//   - 只传一个文件时根就是它的叶子摘要；空批次返回 SHA-256(空字节序列)，
//     这与传入一个空文件的根不同。
//
// 流式读取每个文件，内存占用为 O(文件数) 的摘要存储加上固定读取缓冲区，
// 与文件总大小无关。任一路径不存在、指向目录、无法打开或读取失败时，
// 返回 error 非空的结果，不使用其他文件产出任何摘要。
MerkleRootResult merkle_root(const std::vector<std::filesystem::path>& paths);

// 将 32 字节摘要格式化为 64 个小写十六进制字符。
std::string to_hex(const Digest& digest);

}  // namespace branchaudit
