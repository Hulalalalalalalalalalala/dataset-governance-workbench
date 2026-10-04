#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>

#include "sha256.h"

namespace branchaudit {

// sha256_file 的结果：成功时 error 为空、digest 有效；失败时 error 说明原因。
struct FileHashResult {
    std::array<std::uint8_t, Sha256::kDigestSize> digest{};
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

// 将 32 字节摘要格式化为 64 个小写十六进制字符。
std::string to_hex(const std::array<std::uint8_t, Sha256::kDigestSize>& digest);

}  // namespace branchaudit
