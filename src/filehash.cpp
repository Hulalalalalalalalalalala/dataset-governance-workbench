#include "filehash.h"

#include <cerrno>
#include <cstring>
#include <fstream>
#include <system_error>
#include <utility>
#include <vector>

namespace branchaudit {

namespace {

// 打开 path 并把文件全部原始字节流式追加到 sha 中。
// 固定大小缓冲区，内存占用不随文件长度增长。
// 成功返回空字符串；失败时返回说明失败路径和原因的错误文本。
std::string stream_file_into(const std::filesystem::path& path, Sha256& sha) {
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
    return "";
}

// 父节点摘要：SHA-256(0x01 || 左摘要原始字节 || 右摘要原始字节)。
Digest hash_parent(const Digest& left, const Digest& right) {
    static constexpr unsigned char kParentPrefix = 0x01;
    Sha256 sha;
    sha.update(&kParentPrefix, 1);
    sha.update(left.data(), left.size());
    sha.update(right.data(), right.size());
    return sha.final();
}

}  // namespace

FileHashResult sha256_file(const std::filesystem::path& path) {
    FileHashResult result;
    Sha256 sha;
    result.error = stream_file_into(path, sha);
    if (result.error.empty()) {
        result.digest = sha.final();
    }
    return result;
}

MerkleRootResult merkle_root(const std::vector<std::filesystem::path>& paths) {
    MerkleRootResult result;

    // 先按命令行顺序计算全部叶子；任一文件失败则整批失败，绝不产出部分根。
    static constexpr unsigned char kLeafPrefix = 0x00;
    std::vector<Digest> level;
    level.reserve(paths.size());
    for (const auto& path : paths) {
        Sha256 sha;
        sha.update(&kLeafPrefix, 1);  // 叶子域分隔前缀是单个 0x00 字节。
        const std::string error = stream_file_into(path, sha);
        if (!error.empty()) {
            result.error = error;
            return result;
        }
        level.push_back(sha.final());
    }

    if (level.empty()) {
        // 空批次：对空字节序列求 SHA-256，区别于单传一个空文件的叶子。
        Sha256 sha;
        result.digest = sha.final();
        return result;
    }

    // 每层相邻节点先左后右配对；落单节点的摘要原样上浮，不复制不补零。
    while (level.size() > 1) {
        std::vector<Digest> next;
        next.reserve((level.size() + 1) / 2);
        for (std::size_t i = 0; i < level.size(); i += 2) {
            if (i + 1 < level.size()) {
                next.push_back(hash_parent(level[i], level[i + 1]));
            } else {
                next.push_back(level[i]);
            }
        }
        level = std::move(next);
    }

    result.digest = level.front();
    return result;
}

std::string to_hex(const Digest& digest) {
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
