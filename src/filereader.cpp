#include "filereader.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <system_error>

namespace branchaudit {

std::string hash_file_into(const std::filesystem::path& path, Sha256& sha,
                           bool with_leaf_prefix) {
    std::error_code ec;
    if (std::filesystem::is_directory(path, ec)) {
        return path.string() + ": is a directory";
    }

    errno = 0;
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        const int saved_errno = errno;
        return path.string() + ": " +
               (saved_errno != 0 ? std::strerror(saved_errno)
                                 : "cannot open file");
    }

    // 叶子前缀在任何文件字节之前只追加一次；空文件时同样存在，
    // 也不会随下面的分块循环被重复加入。
    if (with_leaf_prefix) {
        const unsigned char prefix = 0x00;
        sha.update(&prefix, 1);
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
        return path.string() + ": read error" +
               (saved_errno != 0 ? std::string(": ") + std::strerror(saved_errno)
                                 : std::string());
    }

    return {};
}

}  // namespace branchaudit
