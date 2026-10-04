cmake_minimum_required(VERSION 3.20)
project(branchaudit VERSION 0.1.0 LANGUAGES CXX)

# 可复用核心库：其他 C++20 程序可链接 branchaudit_core 并包含 src/ 下的头文件。
add_library(branchaudit_core STATIC
    src/sha256.cpp
    src/filehash.cpp
)
target_compile_features(branchaudit_core PUBLIC cxx_std_20)
set_target_properties(branchaudit_core PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(branchaudit_core PUBLIC src)

add_executable(branchaudit src/main.cpp)
target_link_libraries(branchaudit PRIVATE branchaudit_core)
