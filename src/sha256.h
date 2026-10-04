#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace branchaudit {

// 流式 SHA-256 计算器：内存占用固定，不随输入长度增长。
// 用法：构造后多次 update()，最后调用 final() 取得 32 字节摘要。
class Sha256 {
public:
    static constexpr std::size_t kDigestSize = 32;

    Sha256();

    // 追加原始字节。final() 之后不可再调用。
    void update(const unsigned char* data, std::size_t size);

    // 结束计算并返回 32 字节摘要。只能调用一次。
    std::array<std::uint8_t, kDigestSize> final();

private:
    void process_block(const unsigned char* block);

    std::uint32_t state_[8];
    std::uint64_t total_size_ = 0;
    std::array<unsigned char, 64> buffer_{};
    std::size_t buffer_size_ = 0;
};

}  // namespace branchaudit
