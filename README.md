# branchaudit

提供命令行版本查询与文件 SHA-256 摘要计算。

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

## 测试

随仓库提供自动回归测试，覆盖标准测试向量、空文件/文本/二进制内容、分组与
填充边界长度、增量接口分段一致性、大文件尾部、含空格或中文的路径，以及文件
不存在和指向目录两种失败行为。预期摘要以独立标准实现（FIPS 180-4 公布向量、
系统 `sha256sum` 与 Python `hashlib`/OpenSSL）为依据，不与本项目实现互相比较。

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

包含两个测试：`sha256_unit`（C++ 层，直接链接 `branchaudit_core`）和
`cli_e2e`（Python 端到端，校验命令行退出码与标准输出/错误契约）。
可通过 `-DBRANCHAUDIT_BUILD_TESTS=OFF` 关闭测试构建。
