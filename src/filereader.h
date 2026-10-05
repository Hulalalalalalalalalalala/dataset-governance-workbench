#pragma once

#include <filesystem>
#include <string>

#include "sha256.h"

namespace branchaudit {

// 打开 path 并以固定大小缓冲流式读取，把读取到的全部原始字节喂入 sha。
// hash 文件摘要与 Merkle 文件叶子共用这一定位/读取/失败处理逻辑，保证两者
// 对同一文件遵守完全一致的规则。
//
// with_leaf_prefix 为 true 时，在任何文件字节之前先喂入值为 0x00 的单个
// 前缀字节：整个文件只追加一次，不随读取分块重复；文件为空时前缀依然存在。
// 前缀是原始字节而非字符串，路径文字绝不参与摘要；文件字节不做编码转换、
// 换行替换或空白处理。流式读取，内存占用与文件长度无关，跨越读取块大小或
// 最后一块未填满时尾部内容同样完整喂入。
//
// 路径不存在、指向目录、无法打开或中途读取失败时，返回“失败路径: 原因”，
// 调用方不得把已喂入的部分字节当作成功结果；成功时返回空字符串。相对路径
// 以及含空格或中文的路径按 std::filesystem::path 原样定位。
//
// 注意：这是库内部共享实现，不是公开接口；对外仍只有 filehash.h / merkle.h
// 中声明的函数。
std::string hash_file_into(const std::filesystem::path& path, Sha256& sha,
                           bool with_leaf_prefix);

}  // namespace branchaudit
