#include <filesystem>
#include <iostream>
#include <string_view>
#include <vector>

#include "filehash.h"

namespace {

void print_usage() {
    std::cerr << "Usage: branchaudit --version\n"
                 "       branchaudit hash <file>\n"
                 "       branchaudit root [<file>...]\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "branchaudit 0.1.0\n";
        return 0;
    }

    if (argc == 3 && std::string_view(argv[1]) == "hash") {
        const branchaudit::FileHashResult result =
            branchaudit::sha256_file(argv[2]);
        if (!result.ok()) {
            std::cerr << "branchaudit: " << result.error << '\n';
            return 1;
        }
        std::cout << branchaudit::to_hex(result.digest) << '\n';
        return 0;
    }

    if (argc >= 2 && std::string_view(argv[1]) == "root") {
        // 参数顺序即批次中各文件的位置顺序：不排序、不去重。
        // 不带任何文件时根为 SHA-256(空字节序列)。
        std::vector<std::filesystem::path> paths;
        paths.reserve(static_cast<std::size_t>(argc - 2));
        for (int i = 2; i < argc; ++i) {
            paths.emplace_back(argv[i]);
        }
        const branchaudit::MerkleRootResult result =
            branchaudit::merkle_root(paths);
        if (!result.ok()) {
            std::cerr << "branchaudit: " << result.error << '\n';
            return 1;
        }
        std::cout << branchaudit::to_hex(result.digest) << '\n';
        return 0;
    }

    print_usage();
    return 2;
}
