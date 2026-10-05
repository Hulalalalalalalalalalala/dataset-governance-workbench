# branchaudit

提供命令行版本查询、文件 SHA-256 摘要计算（`hash`）与有序文件批次的
Merkle 根计算（`root`）。

## 构建与运行

```sh
cmake -S . -B build
cmake --build build
./build/branchaudit --version
```

输出：

```text
branchaudit 0.1.0
```

## 计算文件摘要

```sh
./build/branchaudit hash <文件路径>
```

`hash` 接受唯一一个必填的位置参数作为文件路径（相对路径从当前工作目录解释；
路径含空格或中文时按传入的完整参数定位文件）。命令对文件的实际原始字节计算
标准 SHA-256：不包含文件名或路径，不做编码转换、换行替换或空白处理；空文件、
文本文件、含零字节的二进制文件都按同一规则处理。流式读取，内存占用与文件大小无关。

成功时退出码为 0，标准输出只有 64 个小写十六进制字符和一个换行，标准错误为空：

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

（上例为空文件的摘要。）

### 退出码

- `0`：成功，标准输出为摘要。
- `1`：文件错误（路径不存在、指向目录、无法打开或读取失败）。标准输出为空，
  标准错误说明失败的路径和原因。
- `2`：用法错误（未提供路径、多给路径或不支持的参数）。标准错误给出用法提示。

## 计算文件批次的 Merkle 根

```sh
./build/branchaudit root [<文件路径>...]
```

`root` 把命令行给出的文件视为一个**有序批次**，输出可保存和比较的单个根
摘要。位置顺序完全来自命令行参数：既不按文件名或摘要重新排序，也不自动
去重。同一路径重复传入、或多个文件内容相同，都各自保留独立位置。根只
反映各位置上的文件内容，不包含任何路径文字——文件移到别处后，只要仍按
相同顺序传入，结果保持一致。相对路径与含空格、中文的路径沿用与 `hash`
相同的定位规则；文件按固定缓冲流式读取，内存占用与文件总大小无关。

### 公开字节规则

- **文件叶子**：对“一个值为 `0x00` 的前缀字节”与“该文件的全部原始字节”
  依次连接后的序列计算 SHA-256：

  ```text
  leaf = SHA-256(0x00 || file_bytes)
  ```

  `0x00` 是单个原始字节，不是字符串；文件字节不做编码转换或换行处理。
- **父摘要**：对“一个值为 `0x01` 的前缀字节”、左子摘要的 32 个原始字节、
  右子摘要的 32 个原始字节依次连接后计算 SHA-256：

  ```text
  parent = SHA-256(0x01 || left[32] || right[32])
  ```

  子摘要一律使用 32 个**原始字节**，不能用十六进制文本代替；先左后右，
  顺序不可交换。
- **逐层配对**：每一层把相邻节点按先左后右两两配对；若该层最后一个节点
  没有伙伴，它的摘要**原样进入上一层**（不复制、不补零），直到只剩一个根。
- **单个文件**：根就是它的叶子摘要（带 `0x00` 前缀），因此与 `hash` 的
  结果不同。
- **零个文件**：成功返回 SHA-256 对空字节序列的摘要
  `e3b0c442…b855`。这与“传入一个空文件”不同——空文件的叶子是
  `SHA-256(0x00)`，即 `6e340b9c…a01d`。

### 示例

```sh
$ ./build/branchaudit root
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

$ printf 'a' > a.bin
$ ./build/branchaudit root a.bin
022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c
$ ./build/branchaudit hash a.bin   # 普通 hash 不带 0x00 前缀，结果不同
ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb

$ printf 'abc' > b.bin
$ ./build/branchaudit root a.bin b.bin
6a5c0676c6dd1efd519348f49315879d99549029726d5dd1a5dedbf700720761
$ ./build/branchaudit root b.bin a.bin   # 交换顺序，根不同
ece02d1ac6ea17f528a19562aea6b77f7e7d1d8224a7583d3fbfc9f6e3d426ab
```

成功时退出码为 `0`，标准输出仅为 64 个小写十六进制字符及一个换行，
标准错误为空。任一文件不存在、指向目录、无法打开或读取失败时，**整次
计算失败**：退出码为 `1`，标准输出为空，标准错误说明失败的路径和原因，
不会用剩余文件产出部分结果。`root` 的用法错误（如不支持的参数）退出码
为 `2`。

## 在其他 C++20 程序中使用

链接 `branchaudit_core` 库并包含 `src/` 下的头文件：

```cpp
#include "filehash.h"

branchaudit::FileHashResult result = branchaudit::sha256_file("/path/to/file");
if (result.ok()) {
    std::string hex = branchaudit::to_hex(result.digest);  // 64 个小写十六进制字符
} else {
    // result.error 说明失败的路径和原因
}
```

`sha256_file` 遵循与命令行相同的字节和失败规则，只返回结果，不打印、不退出进程。
也可以直接使用 `branchaudit::Sha256` 类对任意字节流做增量计算（`update()` /
`final()`）。

计算有序批次的 Merkle 根请包含 `merkle.h`：

```cpp
#include "merkle.h"

// 路径按给定顺序视为批次：不排序、不去重；任一文件失败则整次失败。
std::vector<std::filesystem::path> paths{"/path/a", "/path/b"};
branchaudit::FileHashResult r = branchaudit::merkle_root_files(paths);
if (r.ok()) {
    std::string hex = branchaudit::to_hex(r.digest);
}
```

也提供按公开字节规则直接组合的原语：`merkle_empty_root()`（空批次）、
`merkle_leaf(data, size)`（`SHA-256(0x00||data)`）与
`merkle_parent(left, right)`（`SHA-256(0x01||left||right)`）。叶子同样
流式计算，内存占用与文件大小无关。

## 测试

随仓库提供自动回归测试，覆盖标准测试向量、空文件/文本/二进制内容、分组与
填充边界长度、增量接口分段一致性、大文件尾部、含空格或中文的路径，以及四种
文件失败行为：路径不存在、指向目录、文件确实存在却不能打开，以及文件已打开
并读到真实内容后继续读取出错——后两种通过测试自身安排的故障注入稳定触发
（AF_UNIX 套接字制造打开失败，伪终端从端以“填满缓冲 + 非阻塞写”的内核握手
证明读取方确已消费确定数量的字节后再令其 read 返回 EIO），不依赖偶发磁盘
故障；空普通文件正常读完仍判定成功，不会因为“没读到内容”被误判为错误。
`root` 还覆盖 `0x00`/`0x01` 前缀规则、批次顺序、重复位置、奇数末节点原样
提升、空批次与单空文件的区别，以及任一文件失败即整次失败（含出错前已处理过
正常文件的有序批次：不输出已处理文件的根、出错文件的部分内容根或跳过该位置
后的根，错误指向真正出错的文件）。预期摘要以独立标准实现（FIPS 180-4 公布
向量、系统 `sha256sum` 与 Python `hashlib`/OpenSSL）为依据，不与本项目实现
互相比较。故障注入仅在 Linux 风格系统可用，其他平台测试会显式 SKIP，绝不把
“无法触发目标错误”算作通过。

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

包含三个测试：`sha256_unit` 与 `merkle_unit`（C++ 层，直接链接
`branchaudit_core`），以及 `cli_e2e`（Python 端到端，校验命令行退出码与
标准输出/错误契约）。可通过 `-DBRANCHAUDIT_BUILD_TESTS=OFF` 关闭测试构建。
