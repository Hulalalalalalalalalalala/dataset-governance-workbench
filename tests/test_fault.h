// 故障注入测试辅助（仅测试代码使用）。
//
// C++ 回归套件在本进程内直接调用 branchaudit_core 的文件计算接口，因此
// “打不开 / 中途读出错”需要故障注入共享库（tests/fault_inject.c）随本
// 进程一起预载：
//
//   * ctest 已通过 ENVIRONMENT 设置 LD_PRELOAD，正常运行时无需任何动作；
//   * 直接手工执行测试二进制时，ensure_fault_preloaded() 会在发现注入库
//     未加载时，带上 LD_PRELOAD 重新执行自身一次；
//   * 具体失败用例用 FaultTrigger 在作用域内设置精确路径触发变量，退出
//     作用域立即清除；其他路径与其余用例不受影响。

#pragma once

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <unistd.h>

namespace fault_test {

// 由 CMake 以编译定义注入故障库绝对路径；直接运行且无定义时退回环境变量。
inline const char *fault_lib_path() {
#ifdef BRANCHAUDIT_FAULT_LIB
    return BRANCHAUDIT_FAULT_LIB;
#else
    return std::getenv("BRANCHAUDIT_FAULT_LIB");
#endif
}

// /proc/self/maps 中是否已映射故障注入库。
inline bool fault_lib_loaded() {
    const char *lib = fault_lib_path();
    if (!lib) return false;
    const char *slash = std::strrchr(lib, '/');
    const std::string base = slash ? std::string(slash + 1) : std::string(lib);
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(base) != std::string::npos) return true;
    }
    return false;
}

// 未加载故障库时带 LD_PRELOAD 重新执行自身；已加载则直接返回。
inline void ensure_fault_preloaded(int argc, char **argv) {
    if (fault_lib_loaded()) return;
    const char *lib = fault_lib_path();
    // 已经重入过一次仍未加载（如库路径无效）：放弃注入，避免无限 re-exec。
    if (!lib || getenv("BRANCHAUDIT_FAULT_REEXECED")) return;

    std::string preload = lib;
    if (const char *existing = std::getenv("LD_PRELOAD")) {
        if (*existing) {
            preload.push_back(':');
            preload += existing;
        }
    }
    setenv("LD_PRELOAD", preload.c_str(), 1);
    setenv("BRANCHAUDIT_FAULT_REEXECED", "1", 1);

    std::string exe;
    {
        char buf[4096];
        ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
        if (n <= 0) return;
        buf[n] = '\0';
        exe = buf;
    }
    // argv[argc] 按标准即为空指针，execv 直接复用。
    execv(exe.c_str(), argv);
    // execv 失败则继续原进程；失败用例会如实报告未触发。
}

// 作用域内设置故障触发环境变量，退出作用域清除。
class FaultTrigger {
public:
    FaultTrigger(const char *variable, std::string value) : variable_(variable) {
        setenv(variable_, value.c_str(), 1);
    }
    ~FaultTrigger() { unsetenv(variable_); }

    FaultTrigger(const FaultTrigger &) = delete;
    FaultTrigger &operator=(const FaultTrigger &) = delete;

private:
    const char *variable_;
};

}  // namespace fault_test
