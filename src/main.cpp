#include <filesystem>
#include <iostream>
#include <string>
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

// 命令的参数解析结果。
//   ok == false：遇到不支持的选项（参数以 '-' 开头且位于第一个单独的
//   "--" 之前）；bad_arg 保存该参数原文。
//   ok == true：files 即实际文件参数，保持命令行中的相对顺序，重复路径
//   保留各自的位置；第一个单独的 "--" 结束选项识别，它本身不算文件，
//   其后所有参数（含以连字符开头的名字、单独的 "-"、再次出现的 "--"）
//   都作为文件路径。
struct ParsedArgs {
    std::vector<std::filesystem::path> files;
    std::string bad_arg;
    bool ok = true;
};

// hash 与 root 共用同一项参数规则：
//   1. 第一个单独的 "--" 之前，以 '-' 开头的参数一律按选项解释；这两个
//      命令不支持其他选项，故命中即用法错误（退出码 2）。
//   2. 第一个单独的 "--" 结束选项识别，它本身不算文件；其后所有参数都
//      是文件路径，包括 -notes.bin、--version、单独的 -、再次出现的 "--"。
//   3. 用户也可以直接传入 ./-notes.bin：参数本身不以连字符开头，无需
//      结束标记。路径里的空格、中文和中间位置的连字符不改变这项判断。
ParsedArgs parse_command_args(int argc, char* argv[], int start) {
    ParsedArgs parsed;
    parsed.files.reserve(static_cast<std::size_t>(argc - start));
    bool no_more_options = false;
    for (int i = start; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (!no_more_options) {
            if (arg == "--") {
                no_more_options = true;
                continue;
            }
            if (!arg.empty() && arg.front() == '-') {
                parsed.ok = false;
                parsed.bad_arg = arg;
                return parsed;
            }
        }
        parsed.files.emplace_back(arg);
    }
    return parsed;
}

// 不支持的选项：标准输出必须为空，标准错误指出该参数并给出对应命令的用法。
void unsupported_option(std::string_view command, std::string_view usage_tail,
                        std::string_view arg) {
    std::cerr << "branchaudit " << command << ": unsupported option '" << arg
              << "'\n"
              << "Usage: branchaudit " << command << " " << usage_tail << '\n';
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--version") {
        std::cout << "branchaudit 0.1.0\n";
        return 0;
    }

    if (argc >= 2 && std::string_view(argv[1]) == "hash") {
        // hash 扣除结束标记后仍须恰好一个文件；缺少或多给都属于用法错误。
        ParsedArgs parsed = parse_command_args(argc, argv, 2);
        if (!parsed.ok) {
            unsupported_option("hash", "[--] <file>", parsed.bad_arg);
            return 2;
        }
        if (parsed.files.size() != 1) {
            print_usage();
            return 2;
        }
        const branchaudit::FileHashResult result =
            branchaudit::sha256_file(parsed.files.front());
        if (!result.ok()) {
            std::cerr << "branchaudit: " << result.error << '\n';
            return 1;
        }
        std::cout << branchaudit::to_hex(result.digest) << '\n';
        return 0;
    }

    if (argc >= 2 && std::string_view(argv[1]) == "root") {
        // root 接受零个或多个文件，顺序即实际文件参数顺序：不排序、不去重；
        // 仅给结束标记（root --）等价于空批次根。
        ParsedArgs parsed = parse_command_args(argc, argv, 2);
        if (!parsed.ok) {
            unsupported_option("root", "[--] [<file>...]", parsed.bad_arg);
            return 2;
        }
        const branchaudit::FileHashResult result =
            branchaudit::merkle_root_files(parsed.files);
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
