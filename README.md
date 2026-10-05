# branchaudit

提供命令行版本查询、单文件 SHA-256 摘要计算，以及有序文件批次的 Merkle 根计算。

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

- `0`：成功，标准输出为单文件摘要。
- `1`：文件错误（路径不存在、指向目录、无法打开或读取失败）。标准输出为空，
  标准错误说明失败的路径和原因。
- `2`：用法错误（未提供路径、多给路径或不支持的参数）。标准错误给出用法提示。

## 计算文件批次的 Merkle 根

```sh
./build/branchaudit root [<文件路径>...]
```

`root` 把命令行上的文件视为一个**有序批次**，产出一个可保存、可跨批次比较的
单个根摘要。批次中各位置的顺序完全来自命令行参数：不按文件名或叶子摘要排序，
也不自动去重——同一路径重复传入、或多个文件内容相同，都会各自保留一个位置。
根只反映各位置的文件内容，不包含任何路径文字；文件改名或移动到别处后，只要按
相同顺序传入，结果保持一致。相对路径从当前工作目录解释，含空格或中文的路径按
传入的完整参数定位，与 `hash` 相同。

### 公开字节规则

所有拼接都使用**原始字节**，前缀是字节而不是字符串，子摘要也不能写成十六进制文本：

- **文件叶子**：对一个值为 `0x00` 的前缀字节与该文件全部原始字节的连接计算
  SHA-256，即 `SHA-256(0x00 ‖ 文件字节)`。
- **父摘要**：对一个值为 `0x01` 的前缀字节、左摘要的 32 个原始字节、右摘要的
  32 个原始字节依次连接后计算 SHA-256，即
  `SHA-256(0x01 ‖ 左摘要 ‖ 右摘要)`。
- **配对方式**：每一层相邻节点按先左后右配对；若最后一个节点没有伙伴，它的
  摘要原样进入上一层，不复制、不补零；逐层向上直到只剩一个根。
- **单文件批次**：根就是该文件的叶子摘要 `SHA-256(0x00 ‖ 文件字节)`，与
  `hash` 的无前缀结果不同。
- **空批次**（不带任何路径）：成功返回 `SHA-256(空字节序列)`
  `e3b0c442…b855`，这与传入一个空文件的根
  `SHA-256(0x00)` = `6e340b…a01d` 不同。

各层固定 64KiB 缓冲区流式读取每个文件，只在内存中保存每层的 32 字节摘要，
内存占用与文件总大小无关，同一有序批次在不同平台上结果相同。

### 示例

```sh
$ printf abc > a.txt
$ printf hello > b.txt
$ ./build/branchaudit root a.txt b.txt
0dcf34a4e2201dbd93222ccdf2012a0de5ad4399afc0080d1b912d1f72cf0e7df
$ ./build/branchaudit root a.txt
609f6e36d2405585188d5cfd761f407c7cc46a7d3f314c88270469dde315fcd1
$ ./build/branchaudit root
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

第一个例子中：

```text
叶子_a = SHA-256(0x00 ‖ "abc")
叶子_b = SHA-256(0x00 ‖ "hello")
根     = SHA-256(0x01 ‖ 叶子_a ‖ 叶子_b)
```

交换两个参数的位置（`root b.txt a.txt`）会得到另一个根；`root a.txt a.txt`
不会被去重为一个位置。

### 成功输出与退出码

成功时退出码为 `0`，标准输出仅为 64 个小写十六进制字符加一个换行，标准错误
为空。任一文件不存在、指向目录、无法打开或读取失败时，整次计算失败：退出码为
`1`，标准输出为空，标准错误说明失败路径和原因，不会用剩余文件产出任何结果。
未知子命令等用法错误退出码为 `2`。

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

有序文件批次的 Merkle 根使用 `merkle_root`，顺序即向量中路径的顺序：

```cpp
#include <vector>

#include "filehash.h"

std::vector<std::filesystem::path> paths{"/path/a", "/path/b", "/path/c"};
branchaudit::MerkleRootResult root = branchaudit::merkle_root(paths);
if (root.ok()) {
    std::string hex = branchaudit::to_hex(root.digest);  // 64 个小写十六进制字符
} else {
    // root.error 说明失败的路径和原因；空向量返回 SHA-256(空字节序列)
}
```

`merkle_root` 遵循上文公开字节规则与 `root` 命令相同的失败契约：任一文件失败
时返回 `error` 非空的结果，不产出部分根；流式读取，只返回结果，不打印、不退出。

## 测试

随仓库提供自动回归测试，覆盖标准测试向量、空文件/文本/二进制内容、分组与
填充边界长度、增量接口分段一致性、大文件尾部、含空格或中文的路径，以及文件
不存在和指向目录两种失败行为；`root` 另覆盖空批次、单文件叶子、多文件分层
配对与落单上浮、命令行顺序敏感、重复路径与同内容文件不去重、移动改名后根
不变，以及批次中任一文件失败的整体失败契约。预期摘要以独立标准实现（FIPS
180-4 公布向量、系统 `sha256sum` 与 Python `hashlib`/OpenSSL，Merkle 根按
公开字节规则用 Python `hashlib` 逐层独立计算）为依据，不与本项目实现互相比较。

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

包含两个测试：`sha256_unit`（C++ 层，直接链接 `branchaudit_core`）和
`cli_e2e`（Python 端到端，校验命令行退出码与标准输出/错误契约）。
可通过 `-DBRANCHAUDIT_BUILD_TESTS=OFF` 关闭测试构建。
