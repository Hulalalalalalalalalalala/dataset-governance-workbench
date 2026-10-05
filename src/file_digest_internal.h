#pragma once

// branchaudit 内部共享头（非公开 API）：普通文件摘要（hash）与 Merkle 文件
// 叶子（root）通过这里共用同一套文件定位、打开、流式分块读取与读取失败
// 处理，保证两种计算对同一文件遵守一致规则，也避免同一种文件错误需要在
// 两处分别维护。对外公开的参数、结果类型与头文件仍保持 filehash.h /
// merkle.h 中已有的形态不变。

#include "filehash.h"

namespace branchaudit::internal {

// 流式计算 path 所指文件的 SHA-256 摘要。
//
// prefix_byte == nullptr：只对文件的全部原始字节计算标准 SHA-256（hash）。
// prefix_byte 指向单个字节：该字节在任何文件字节之前恰好参与一次摘要
// （Merkle 叶子的 0x00 前缀）——即使文件为空它也存在，且不会随读取分块
// 重复加入。两种情况下都只对实际读取到的字节计算：不包含路径文字，不做
// 编码转换、换行替换或空白处理。
//
// 路径不存在、指向目录、无法打开或中途读取失败时，返回 error 非空的结果，
// 已读到的部分内容不会成为成功结果。固定缓冲流式读取，内存占用与文件长度无关。
FileHashResult sha256_file_digest(const std::filesystem::path& path,
                                  const unsigned char* prefix_byte);

}  // namespace branchaudit::internal
