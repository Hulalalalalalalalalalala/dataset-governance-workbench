cmake_minimum_required(VERSION 3.20)
project(branchaudit VERSION 0.1.0 LANGUAGES CXX)

add_executable(branchaudit src/main.cpp)
target_compile_features(branchaudit PRIVATE cxx_std_20)
set_target_properties(branchaudit PROPERTIES CXX_EXTENSIONS OFF)
