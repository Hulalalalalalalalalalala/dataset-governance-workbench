#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include "filehash.h"
#include "merkle.h"

namespace {

// hash/root/prove 共用的文件参数解析规则：
//  * 第一个单独的 "--" 是选项结束标记，它本身不算文件；
//  * 结束标记之前，凡是以连字符开头的参数都按选项解释；这些命令不支持
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
    std::cerr << "Usage: branchaudit prove <position> [--] <file>...\n";
}

void print_usage() {
    std::cerr << "Usage: branchaudit --version\n"
                 "       branchaudit hash [--] <file>\n"
                 "       branchaudit root [--] [<file>...]\n"
                 "       branchaudit prove <position> [--] <file>...\n";
}

// prove 的参数解析：第一个位置参数是批次位置（十进制、从 0 开始），其余
// 位置参数按 root 的同一条规则视为有序批次文件。选项区分规则与
// parse_file_args 完全一致（第一个单独的 "--" 结束选项；结束标记之前以
// 连字符开头的参数都是不支持选项）；结束标记可以出现在位置之前，不改变
// 任何判断（位置本身只可能由数字组成，不会以连字符开头）。
struct ProveArgs {
    std::string position;  // 原始位置文本；空表示缺失
    std::vector<std::filesystem::path> files;
    std::string unsupported;  // 非空即用法错误
};

ProveArgs parse_prove_args(char* const* argv, int first, int last) {
    ProveArgs args;
    bool options_ended = false;
    for (int i = first; i < last; ++i) {
        const std::string_view arg{argv[i]};
        if (!options_ended && arg == "--") {
            options_ended = true;
            continue;  // 结束标记本身既不算位置也不算文件
        }
        if (!options_ended && !arg.empty() && arg.front() == '-') {
            args.unsupported = std::string{arg};
            return args;
        }
        if (args.position.empty()) {
            args.position = std::string{arg};
        } else {
            args.files.emplace_back(argv[i]);
        }
    }
    return args;
}

// 仅接受十进制数字（不接受符号、空白、"+1"、"0x1" 等写法）；溢出 size_t
// 可表示范围时通过 out_of_range 报告。返回 false 表示含非数字，
// out_of_range 为 true 表示数字合法但超出可表示范围。
bool parse_position(std::string_view text, std::size_t& value,
                    bool& out_of_range) {
    value = 0;
    out_of_range = false;
    if (text.empty()) {
        return false;
    }
    constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
    for (char c : text) {
        if (c < '0' || c > '9') {
            return false;
        }
        const unsigned digit = static_cast<unsigned>(c - '0');
        if (value > (kMax - digit) / 10) {
            out_of_range = true;
        } else {
            value = value * 10 + digit;
        }
    }
    return true;
}

// 成功时向标准输出写入唯一一份证明 JSON 对象及换行；不输出任何其他内容。
void emit_proof_json(const branchaudit::MerkleProof& proof) {
    std::cout << "{\"version\":1"
              << ",\"root\":\"" << branchaudit::to_hex(proof.root) << '"'
              << ",\"leaf_count\":" << proof.leaf_count
              << ",\"leaf_index\":" << proof.leaf_index
              << ",\"leaf\":\"" << branchaudit::to_hex(proof.leaf) << '"'
              << ",\"siblings\":[";
    for (std::size_t i = 0; i < proof.siblings.size(); ++i) {
        if (i != 0) {
            std::cout << ',';
        }
        const branchaudit::ProofSibling& sibling = proof.siblings[i];
        std::cout << "{\"side\":\""
                  << (sibling.side == branchaudit::ProofSide::kLeft
                          ? "left"
                          : "right")
                  << "\",\"digest\":\"" << branchaudit::to_hex(sibling.digest)
                  << "\"}";
    }
    std::cout << "]}\n";
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
        const ProveArgs args = parse_prove_args(argv, 2, argc);
        if (!args.unsupported.empty()) {
            std::cerr << "branchaudit prove: unsupported option '"
                      << args.unsupported << "'\n";
            print_prove_usage();
            return 2;
        }

        // 位置缺失：只给了结束标记或完全没给参数。
        if (args.position.empty()) {
            std::cerr << "branchaudit prove: missing position\n";
            print_prove_usage();
            return 2;
        }

        std::size_t position = 0;
        bool out_of_range = false;
        if (!parse_position(args.position, position, out_of_range)) {
            std::cerr << "branchaudit prove: invalid position '"
                      << args.position
                      << "': expected a non-negative decimal integer\n";
            print_prove_usage();
            return 2;
        }
        if (out_of_range || position >= args.files.size()) {
            // 空批次（files 为空）时任何位置都不落在批次内，也归到这里。
            std::cerr << "branchaudit prove: position " << args.position
                      << " is out of range for a batch of "
                      << args.files.size() << " file(s)\n";
            print_prove_usage();
            return 2;
        }

        // 文件错误（不存在、目录、打不开、读取失败）退出 1：库负责指出
        // 失败路径和原因，且不会产出部分证明。
        const branchaudit::MerkleProofResult result =
            branchaudit::merkle_proof_files(args.files, position);
        if (!result.ok()) {
            std::cerr << "branchaudit: " << result.error << '\n';
            return 1;
        }
        emit_proof_json(result.proof);
        return 0;
    }

    print_usage();
    return 2;
}
