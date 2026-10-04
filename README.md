# branchaudit

当前版本提供命令行版本查询和文件 SHA-256 摘要计算。

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

`hash` 接受唯一一个必填的位置参数（文件路径）。路径按传入的完整参数解析，
可以包含空格或中文；相对路径从当前工作目录解释。

摘要为标准 SHA-256：以实际读取到的文件原始字节为输入，不包含文件名或路径，
不做编码转换、换行替换或去除空白等任何文本处理。空文件得到标准的空消息摘要。
文件以固定大小的块流式读取，内存占用不随文件长度增长。

### 输出形式与退出码

- 成功：标准输出只有 64 个小写十六进制字符和一个换行，标准错误为空，退出码 `0`。
- 失败（路径不存在、指向目录、无法打开或读取错误）：标准输出为空，
  标准错误说明失败的路径和原因，退出码 `1`。
- 用法错误（未提供路径、多给路径、不支持的参数）：标准错误给出用法提示，退出码 `2`。

```console
$ ./build/branchaudit hash hello.txt
b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
$ ./build/branchaudit hash missing.bin
branchaudit: cannot hash 'missing.bin': No such file or directory
```

## 在其他 C++20 程序中复用

核心功能在静态库 `branchaudit_core` 中。包含 `src/sha256.h` 并链接该库，
即可直接传入文件路径取得摘要；失败通过返回值表达，库本身不打印、不结束进程：

```cpp
#include "sha256.h"

branchaudit::FileHashResult result = branchaudit::hash_file_sha256("some/file.bin");
if (result.ok) {
    std::string hex = branchaudit::to_hex(result.digest);  // 64 个小写十六进制字符
} else {
    // result.error_message 说明失败原因
}
```

`FileHashResult` 遵循与命令行相同的字节和失败规则：摘要只取决于文件内容的
原始字节；路径不存在、是目录、无法打开或读取错误时 `ok` 为 `false`。
也可以使用 `branchaudit::Sha256` 类对任意字节流做增量计算（`update` / `finish`）。
