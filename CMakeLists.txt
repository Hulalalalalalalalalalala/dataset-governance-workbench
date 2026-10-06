cmake_minimum_required(VERSION 3.20)
project(branchaudit VERSION 0.1.0 LANGUAGES CXX C)

# 可复用核心库：其他 C++20 程序可链接 branchaudit_core 并包含 src/ 下的头文件。
add_library(branchaudit_core STATIC
    src/sha256.cpp
    src/filehash.cpp
    src/merkle.cpp
)
target_compile_features(branchaudit_core PUBLIC cxx_std_20)
set_target_properties(branchaudit_core PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(branchaudit_core PUBLIC src)

add_executable(branchaudit src/main.cpp)
target_link_libraries(branchaudit PRIVATE branchaudit_core)

# ---- 自动回归测试 ----------------------------------------------------------
# C++ 层：直接覆盖增量 Sha256 与 sha256_file/to_hex 库接口。
# Python 层：以独立实现（hashlib/OpenSSL）为标准依据，端到端校验命令行
# 的退出码、标准输出/错误字节契约与路径处理。
option(BRANCHAUDIT_BUILD_TESTS "Build branchaudit regression tests" ON)

if(BRANCHAUDIT_BUILD_TESTS)
    enable_testing()

    # 故障注入（LD_PRELOAD 预载 + /proc 进程文件信息）是 Linux 专用机制，
    # 仅在该平台构建故障库并启用对应检查。其他平台（如 macOS）照常构建并
    # 运行其余全部检查，仅“存在却打不开”与“部分读取后继续读出错”两类
    # 依赖注入的检查被明确跳过：配置时在此说明，运行时以 SKIP 标注，不计入
    # 通过数，也不显示为已验证。
    set(BRANCHAUDIT_HAVE_FAULT_INJECTION OFF)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(BRANCHAUDIT_HAVE_FAULT_INJECTION ON)

        # 测试专用故障注入库（LD_PRELOAD）：让测试在自己安排的条件下稳定
        # 触发“存在但打不开（EACCES）”与“部分读取后继续读出错（EIO）”两类
        # 真实文件访问错误。仅测试构建启用，不进入核心库或可执行文件。
        add_library(branchaudit_fault MODULE tests/fault_inject.c)
        set_target_properties(branchaudit_fault PROPERTIES
            POSITION_INDEPENDENT_CODE ON
            PREFIX "lib"
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS ON   # _GNU_SOURCE 需要 GNU 扩展支持
        )
    else()
        message(STATUS
            "branchaudit: 故障注入检查（存在却打不开 / 部分读取后继续读出错）"
            "依赖 Linux 的 LD_PRELOAD 与 /proc，本平台不适用，将明确跳过；"
            "其余全部检查照常执行，失败仍使回归失败。")
    endif()

    add_executable(sha256_test tests/sha256_test.cpp)
    target_link_libraries(sha256_test PRIVATE branchaudit_core)
    add_test(NAME sha256_unit COMMAND sha256_test)
    set_tests_properties(sha256_unit PROPERTIES TIMEOUT 30)

    add_executable(merkle_test tests/merkle_test.cpp)
    target_link_libraries(merkle_test PRIVATE branchaudit_core)
    add_test(NAME merkle_unit COMMAND merkle_test)
    set_tests_properties(merkle_unit PROPERTIES TIMEOUT 30)

    if(BRANCHAUDIT_HAVE_FAULT_INJECTION)
        foreach(test_target sha256_test merkle_test)
            target_compile_definitions(${test_target} PRIVATE
                BRANCHAUDIT_HAVE_FAULT_INJECTION=1
                BRANCHAUDIT_FAULT_LIB="$<TARGET_FILE:branchaudit_fault>")
        endforeach()
        # 故障库随测试进程预加载；未设置触发变量时它完全透传，对其余
        # 检查零影响。测试在具体失败用例附近才设置/清除触发变量。
        set_tests_properties(sha256_unit merkle_unit PROPERTIES
            ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:branchaudit_fault>")
        set(BRANCHAUDIT_CLI_FAULT_ARG "$<TARGET_FILE:branchaudit_fault>")
    else()
        # 无故障库的平台：cli_test.py 收到 none 后明确跳过注入类检查。
        set(BRANCHAUDIT_CLI_FAULT_ARG "none")
    endif()

    # cli_e2e 为可选的端到端层，仅在找到 Python 3 时启用；没有 Python 不
    # 影响核心库、命令行程序与 C++ 回归测试的构建和运行。
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(
            NAME cli_e2e
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_test.py
                    $<TARGET_FILE:branchaudit>
                    ${BRANCHAUDIT_CLI_FAULT_ARG}
        )
        set_tests_properties(cli_e2e PROPERTIES TIMEOUT 30)
    else()
        message(STATUS
            "branchaudit: 未找到 Python 3，跳过可选的 cli_e2e 端到端测试；"
            "核心库、命令行程序与 C++ 回归测试不受影响。")
    endif()
endif()
