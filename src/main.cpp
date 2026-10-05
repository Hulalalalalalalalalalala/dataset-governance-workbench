#include <filesystem>
#include <iostream>
#include <string_view>
#include <vector>

#include "filehash.h"
#include "merkle.h"

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

    if (argc >= 2 && std::string_view(argv[1]) == "hash") {
        // hash 恰好接受一个文件；缺失或多给都属于用法错误。
        if (argc != 3) {
            print_usage();
            return 2;
        }
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
        // root 接受零个或多个文件，顺序即命令行参数顺序：不排序、不去重。
        std::vector<std::filesystem::path> paths;
        paths.reserve(static_cast<std::size_t>(argc - 2));
        for (int i = 2; i < argc; ++i) {
            paths.emplace_back(argv[i]);
        }
        const branchaudit::FileHashResult result =
            branchaudit::merkle_root_files(paths);
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
