#include "filehash.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <system_error>

#include "file_digest_internal.h"

namespace branchaudit {

FileHashResult sha256_file(const std::filesystem::path& path) {
    // hash 不带任何 Merkle 前缀：只对文件原始字节计算标准 SHA-256。
    return internal::sha256_file_digest(path, nullptr);
}

std::string to_hex(const std::array<std::uint8_t, Sha256::kDigestSize>& digest) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(digest.size() * 2);
    for (std::uint8_t byte : digest) {
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 0x0f]);
    }
    return out;
}

namespace internal {

FileHashResult sha256_file_digest(const std::filesystem::path& path,
                                  const unsigned char* prefix_byte) {
    FileHashResult result;

    std::error_code ec;
    if (std::filesystem::is_directory(path, ec)) {
        result.error = path.string() + ": is a directory";
        return result;
    }

    errno = 0;
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        const int saved_errno = errno;
        result.error = path.string() + ": " +
                       (saved_errno != 0
                            ? std::strerror(saved_errno)
                            : "cannot open file");
        return result;
    }

    Sha256 sha;
    // 可选的单个前缀字节：在任何文件字节之前恰好参与一次（叶子为 0x00），
    // 空文件时也存在；放在读取循环之外，不会随分块重复加入。
    if (prefix_byte != nullptr) {
        sha.update(prefix_byte, 1);
    }
    // 固定大小缓冲区流式读取，内存占用不随文件长度增长。
    char buffer[64 * 1024];
    while (in) {
        in.read(buffer, sizeof(buffer));
        const std::streamsize count = in.gcount();
        if (count > 0) {
            sha.update(reinterpret_cast<const unsigned char*>(buffer),
                       static_cast<std::size_t>(count));
        }
    }
    if (in.bad()) {
        const int saved_errno = errno;
        result.error = path.string() + ": read error" +
                       (saved_errno != 0
                            ? std::string(": ") + std::strerror(saved_errno)
                            : std::string());
        return result;
    }

    result.digest = sha.final();
    return result;
}

}  // namespace internal

}  // namespace branchaudit
