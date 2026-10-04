#include <iostream>
#include <string_view>

#include "sha256.h"

namespace {

void print_usage() {
    std::cerr << "Usage: branchaudit --version\n"
                 "       branchaudit hash <file>\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "branchaudit 0.1.0\n";
        return 0;
    }
    if (argc >= 2 && std::string_view(argv[1]) == "hash") {
        if (argc != 3) {
            print_usage();
            return 2;
        }
        // argv[2] 按调用者传入的完整参数使用，不拆分、不改写；
        // 相对路径由 std::filesystem 从当前工作目录解释。
        branchaudit::FileHashResult result = branchaudit::hash_file_sha256(argv[2]);
        if (!result.ok) {
            std::cerr << "branchaudit: cannot hash '" << argv[2]
                      << "': " << result.error_message << "\n";
            return 1;
        }
        std::cout << branchaudit::to_hex(result.digest) << "\n";
        return 0;
    }
    print_usage();
    return 2;
}
