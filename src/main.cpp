#include <charconv>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "filehash.h"
#include "merkle.h"

namespace {

// hash/root 共用的文件参数解析规则：
//  * 第一个单独的 "--" 是选项结束标记，它本身不算文件；
//  * 结束标记之前，凡是以连字符开头的参数都按选项解释；这两个命令不支持
//    任何选项，因此一律构成用法错误（即使同名文件可以读取）；
//  * 结束标记之后的所有参数一律是文件路径（包括 "-notes.bin"、"--version"、
//    单独的 "-" 以及再次出现的 "--"），按字面定位真实文件。
struct FileArgs {
    std::vector<std::filesystem::path> files;
    std::string unsupported;  // 遇到的不支持选项原文；非空即用法错误
};

FileArgs parse_file_args(char* const* argv, int first, int last) {
    FileArgs args;
    bool options_ended = false;
    for (int i = first; i < last; ++i) {
        const std::string_view arg{argv[i]};
        if (!options_ended && arg == "--") {
            options_ended = true;
            continue;  // 结束标记本身不占文件位置
        }
        if (!options_ended && !arg.empty() && arg.front() == '-') {
            // 立即返回：批次中即使还有正常文件，也不能继续产出结果。
            args.unsupported = std::string{arg};
            return args;
        }
        args.files.emplace_back(argv[i]);
    }
    return args;
}

void print_hash_usage() {
    std::cerr << "Usage: branchaudit hash [--] <file>\n";
}

void print_root_usage() {
    std::cerr << "Usage: branchaudit root [--] [<file>...]\n";
}

void print_prove_usage() {
    std::cerr << "Usage: branchaudit prove <index> [--] <file>...\n";
}

void print_usage() {
    std::cerr << "Usage: branchaudit --version\n"
                 "       branchaudit hash [--] <file>\n"
                 "       branchaudit root [--] [<file>...]\n"
                 "       branchaudit prove <index> [--] <file>...\n";
}

// 解析 prove 的位置参数：只接受十进制数字（至少一位），且必须落在
// 可表示范围内；空串、含任何非数字字符或数值溢出都判为无效。
bool parse_index(const char* text, std::uint64_t& out) {
    const std::string_view sv{text};
    if (sv.empty()) {
        return false;
    }
    for (const char c : sv) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    const auto res =
        std::from_chars(sv.data(), sv.data() + sv.size(), out);
    return res.ec == std::errc{} && res.ptr == sv.data() + sv.size();
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "branchaudit 0.1.0\n";
        return 0;
    }

    if (argc >= 2 && std::string_view(argv[1]) == "hash") {
        const FileArgs args = parse_file_args(argv, 2, argc);
        if (!args.unsupported.empty()) {
            std::cerr << "branchaudit hash: unsupported option '"
                      << args.unsupported << "'\n";
            print_hash_usage();
            return 2;
        }
        // 扣除结束标记后，hash 恰好接受一个文件；缺失或多给都属于用法错误。
        if (args.files.size() != 1) {
            std::cerr << "branchaudit hash: expected exactly one file, got "
                      << args.files.size() << '\n';
            print_hash_usage();
            return 2;
        }
        const branchaudit::FileHashResult result =
            branchaudit::sha256_file(args.files.front());
        if (!result.ok()) {
            std::cerr << "branchaudit: " << result.error << '\n';
            return 1;
        }
        std::cout << branchaudit::to_hex(result.digest) << '\n';
        return 0;
    }

    if (argc >= 2 && std::string_view(argv[1]) == "root") {
        const FileArgs args = parse_file_args(argv, 2, argc);
        if (!args.unsupported.empty()) {
            std::cerr << "branchaudit root: unsupported option '"
                      << args.unsupported << "'\n";
            print_root_usage();
            return 2;
        }
        // root 接受零个或多个文件，顺序即命令行参数顺序：不排序、不去重。
        // 仅给结束标记时 files 为空，返回空批次根。
        const branchaudit::FileHashResult result =
            branchaudit::merkle_root_files(args.files);
        if (!result.ok()) {
            std::cerr << "branchaudit: " << result.error << '\n';
            return 1;
        }
        std::cout << branchaudit::to_hex(result.digest) << '\n';
        return 0;
    }

    if (argc >= 2 && std::string_view(argv[1]) == "prove") {
        // 位置是第一个参数：缺失、含非数字或超出可表示范围都是用法错误。
        if (argc < 3) {
            std::cerr << "branchaudit prove: missing leaf index\n";
            print_prove_usage();
            return 2;
        }
        std::uint64_t index = 0;
        if (!parse_index(argv[2], index)) {
            std::cerr << "branchaudit prove: invalid leaf index '" << argv[2]
                      << "' (expected a decimal number)\n";
            print_prove_usage();
            return 2;
        }
        // 文件参数与 root 共用同一套定位与 "--" 规则：不排序、不去重。
        const FileArgs args = parse_file_args(argv, 3, argc);
        if (!args.unsupported.empty()) {
            std::cerr << "branchaudit prove: unsupported option '"
                      << args.unsupported << "'\n";
            print_prove_usage();
            return 2;
        }
        // 位置必须落在批次内；空批次没有合法位置。
        if (index >= args.files.size()) {
            std::cerr << "branchaudit prove: leaf index " << index
                      << " out of range for batch of " << args.files.size()
                      << " file(s)\n";
            print_prove_usage();
            return 2;
        }
        const branchaudit::MerkleProofResult result =
            branchaudit::merkle_proof_file(args.files, index);
        if (!result.ok()) {
            std::cerr << "branchaudit: " << result.error << '\n';
            return 1;
        }
        // 单个 JSON 对象加换行；摘要均为 64 个小写十六进制字符。
        const branchaudit::MerkleProof& proof = result.proof;
        std::cout << "{\"version\":1"
                  << ",\"root\":\"" << branchaudit::to_hex(proof.root) << "\""
                  << ",\"leaf_count\":" << proof.leaf_count
                  << ",\"leaf_index\":" << proof.leaf_index
                  << ",\"leaf\":\"" << branchaudit::to_hex(proof.leaf) << "\""
                  << ",\"siblings\":[";
        for (std::size_t i = 0; i < proof.siblings.size(); ++i) {
            if (i != 0) {
                std::cout << ',';
            }
            const branchaudit::MerkleSibling& s = proof.siblings[i];
            std::cout << "{\"side\":\""
                      << (s.side == branchaudit::MerkleSibling::Side::left
                              ? "left"
                              : "right")
                      << "\",\"digest\":\"" << branchaudit::to_hex(s.digest)
                      << "\"}";
        }
        std::cout << "]}\n";
        return 0;
    }

    print_usage();
    return 2;
}
