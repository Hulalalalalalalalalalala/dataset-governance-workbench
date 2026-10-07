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

    # 故障注入检查（“文件存在却打不开”与“部分读取后继续读出错”）依赖
    # Linux 专有的机制：LD_PRELOAD 符号介入、/proc/self/fd 与
    # /proc/self/maps。仅 Linux 构建故障注入库并启用这两类检查；其他
    # 平台（如 macOS）明确跳过它们，其余全部检查照常执行。
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(BRANCHAUDIT_FAULT_INJECTION ON)
    else()
        set(BRANCHAUDIT_FAULT_INJECTION OFF)
        message(STATUS
            "branchaudit: 平台 ${CMAKE_SYSTEM_NAME} 无 LD_PRELOAD//proc "
            "故障注入支持，跳过“文件存在却打不开”与“部分读取后出错”两类"
            "检查（仅这两类）；其余摘要、Merkle 根与文件错误检查照常执行。")
    endif()

    if(BRANCHAUDIT_FAULT_INJECTION)
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
    endif()

    add_executable(sha256_test tests/sha256_test.cpp)
    target_link_libraries(sha256_test PRIVATE branchaudit_core)
    target_compile_definitions(sha256_test PRIVATE
        BRANCHAUDIT_FAULT_INJECTION=$<BOOL:${BRANCHAUDIT_FAULT_INJECTION}>)
    add_test(NAME sha256_unit COMMAND sha256_test)
    # 该套件含越过 2^32 位（512 MiB）长度边界的真实计算：三种长度各经增量
    # 与文件两个入口、另加一次边界附近重分段与末字节变体，合计约处理 4 GiB，
    # 时限不能沿用只针对短输入的 30s。
    set_tests_properties(sha256_unit PROPERTIES TIMEOUT 300)

    add_executable(merkle_test tests/merkle_test.cpp)
    target_link_libraries(merkle_test PRIVATE branchaudit_core)
    target_compile_definitions(merkle_test PRIVATE
        BRANCHAUDIT_FAULT_INJECTION=$<BOOL:${BRANCHAUDIT_FAULT_INJECTION}>)
    # “命令行 prove 原文 -> 库读取 -> 成员校验”回归需要在测试进程内实际
    # 执行命令行程序：把可执行文件路径以编译定义注入（跨配置生成器也能取到
    # 真实路径）；手工运行时可用环境变量 BRANCHAUDIT_EXE 覆盖。
    target_compile_definitions(merkle_test PRIVATE
        BRANCHAUDIT_EXE="$<TARGET_FILE:branchaudit>")
    add_test(NAME merkle_unit COMMAND merkle_test)
    set_tests_properties(merkle_unit PROPERTIES TIMEOUT 30)

    if(BRANCHAUDIT_FAULT_INJECTION)
        target_compile_definitions(sha256_test PRIVATE
            BRANCHAUDIT_FAULT_LIB="$<TARGET_FILE:branchaudit_fault>")
        target_compile_definitions(merkle_test PRIVATE
            BRANCHAUDIT_FAULT_LIB="$<TARGET_FILE:branchaudit_fault>")
        # 故障库随测试进程预加载；未设置触发变量时它完全透传，对其余
        # 检查零影响。测试在具体失败用例附近才设置/清除触发变量。
        set_tests_properties(sha256_unit merkle_unit PROPERTIES
            ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:branchaudit_fault>")
    endif()

    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        if(BRANCHAUDIT_FAULT_INJECTION)
            add_test(
                NAME cli_e2e
                COMMAND ${Python3_EXECUTABLE}
                        ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_test.py
                        $<TARGET_FILE:branchaudit>
                        $<TARGET_FILE:branchaudit_fault>
            )
        else()
            # 无故障注入库的平台：只传可执行文件，脚本内部明确跳过两类
            # 注入检查，其余端到端检查照常执行。
            add_test(
                NAME cli_e2e
                COMMAND ${Python3_EXECUTABLE}
                        ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_test.py
                        $<TARGET_FILE:branchaudit>
            )
        endif()
        # 端到端套件要真实生成并经命令行计算四份越过 2^32 位边界的
        # 512 MiB 级文件，默认 -O0 构建下仅被测程序就约处理 2 GiB，时限
        # 不能沿用只针对短输入的 30s，否则正常的大文件计算会被提前终止。
        set_tests_properties(cli_e2e PROPERTIES TIMEOUT 600)
    else()
        message(STATUS
            "branchaudit: 未找到 Python3，跳过 cli_e2e 端到端测试；"
            "核心库、命令行程序与 C++ 回归检查不受影响。")
    endif()
endif()
