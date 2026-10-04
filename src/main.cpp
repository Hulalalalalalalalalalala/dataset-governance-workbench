#include <iostream>
#include <string_view>

#include "filehash.h"

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

    print_usage();
    return 2;
}
