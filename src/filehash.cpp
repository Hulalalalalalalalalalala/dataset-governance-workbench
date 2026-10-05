#include "filehash.h"

#include "filereader.h"

namespace branchaudit {

FileHashResult sha256_file(const std::filesystem::path& path) {
    FileHashResult result;
    Sha256 sha;
    // 普通文件摘要：不带 Merkle 叶子前缀，直接对原始字节计算 SHA-256。
    // 路径检查、打开、分块读取与失败处理与 root 的文件叶子共用同一实现。
    result.error = hash_file_into(path, sha, /*with_leaf_prefix=*/false);
    if (result.error.empty()) {
        result.digest = sha.final();
    }
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
