#include "filehash.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <system_error>

namespace branchaudit {

FileHashResult sha256_file(const std::filesystem::path& path) {
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

}  // namespace branchaudit
