#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

namespace branchaudit {

// 标准 SHA-256 增量计算器：按调用方提供的原始字节流更新，
// 不做任何文本处理（不改编码、不换行、不去除空白）。
class Sha256 {
public:
    Sha256();

    void update(const unsigned char* data, std::size_t size);
    void update(const char* data, std::size_t size) {
        update(reinterpret_cast<const unsigned char*>(data), size);
    }

    // 结束计算并返回 32 字节摘要。调用后对象不可再使用。
    std::array<unsigned char, 32> finish();

private:
    void process_block(const unsigned char* block);

    std::uint64_t total_size_ = 0;
    std::array<std::uint32_t, 8> state_{};
    std::array<unsigned char, 64> buffer_{};
    std::size_t buffer_size_ = 0;
};

struct FileHashResult {
    bool ok = false;
    std::array<unsigned char, 32> digest{};  // 仅当 ok 为 true 时有效
    std::string error_message;               // 仅当 ok 为 false 时有效
};

// 可复用接口：计算指定文件内容的 SHA-256。
// 输入为实际读取到的原始字节，不包含文件名或路径，不做任何文本处理。
// 失败（路径不存在、是目录、无法打开或读取错误）时返回 ok=false 及原因，
// 不打印、不退出进程，由调用方决定如何处理。
FileHashResult hash_file_sha256(const std::filesystem::path& path);

// 把 32 字节摘要转成 64 个小写十六进制字符。
std::string to_hex(const std::array<unsigned char, 32>& digest);

}  // namespace branchaudit
