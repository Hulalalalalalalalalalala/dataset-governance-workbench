cmake_minimum_required(VERSION 3.20)
project(branchaudit VERSION 0.1.0 LANGUAGES CXX)

# 可复用核心库：其他 C++20 程序可链接 branchaudit_core 并包含 src/ 下的头文件。
add_library(branchaudit_core STATIC
    src/sha256.cpp
    src/filereader.cpp
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

    add_executable(sha256_test tests/sha256_test.cpp)
    target_link_libraries(sha256_test PRIVATE branchaudit_core)
    add_test(NAME sha256_unit COMMAND sha256_test)
    set_tests_properties(sha256_unit PROPERTIES TIMEOUT 30)

    add_executable(merkle_test tests/merkle_test.cpp)
    target_link_libraries(merkle_test PRIVATE branchaudit_core)
    add_test(NAME merkle_unit COMMAND merkle_test)
    set_tests_properties(merkle_unit PROPERTIES TIMEOUT 30)

    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(
            NAME cli_e2e
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_test.py
                    $<TARGET_FILE:branchaudit>
        )
        set_tests_properties(cli_e2e PROPERTIES TIMEOUT 30)
    endif()
endif()
