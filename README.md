# branchaudit

提供命令行版本查询、文件 SHA-256 摘要计算（`hash`）、有序文件批次的
Merkle 根计算（`root`）与单个文件位置的成员证明生成（`prove`）；可复用
C++20 核心库 `branchaudit_core` 另提供成员证明 JSON 文本的**读取**接口
`merkle_proof_from_json` 与**校验**接口
`merkle_verify_proof`（都只消费调用方给出的输入，无对应命令行子命令）。

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
./build/branchaudit hash [--] <文件路径>
```

`hash` 接受唯一一个必填的位置参数作为文件路径（相对路径从当前工作目录解释；
路径含空格或中文时按传入的完整参数定位文件）。命令对文件的实际原始字节计算
标准 SHA-256：不包含文件名或路径，不做编码转换、换行替换或空白处理；空文件、
文本文件、含零字节的二进制文件都按同一规则处理。流式读取，内存占用与文件大小无关。

### 文件参数与选项（`hash`、`root` 与 `prove` 共用）

三个子命令都不支持任何选项，按同一条规则区分选项与文件参数（`prove`
的位置参数在结束标记之前单独解析，见下文）：

- 第一个**单独的 `--`** 是选项结束标记：结束标记之前，凡是以连字符（`-`）
  开头的参数都按选项解释；这三个命令没有其他选项，遇到即判为用法错误——退出码
  为 `2`，标准输出为空，标准错误指出该参数并给出对应命令的用法。即使该参数文字
  恰好对应一个可读取的文件，也报用法错误；批次中即使还有正常文件，也不会产出
  任何摘要。
- 结束标记本身不算一个文件；标记之后的每个参数一律按字面当作文件路径，包括
  `-notes.bin`、`--version`、单独的 `-` 和再次出现的 `--`——这些名字都定位到
  真实文件，不会触发版本查询、不会被当作另一个标记丢弃，单独的 `-` 也不表示
  标准输入。
- 需要给出本身以连字符开头的文件名时，把它放在结束标记之后
  （`branchaudit hash -- -notes.bin`），也可以直接使用不以连字符开头的路径
  写法（`branchaudit hash ./-notes.bin`）。只有参数本身以连字符开头时才需要
  结束标记；路径中间的连字符、路径中的空格或中文都不改变这项判断。

顶层 `branchaudit --version` 的行为不受影响：版本查询只在它是唯一参数时生效。

成功时退出码为 0，标准输出只有 64 个小写十六进制字符和一个换行，标准错误为空：

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

（上例为空文件的摘要。）

### 退出码

- `0`：成功，标准输出为摘要。
- `1`：文件错误（路径不存在、指向目录、无法打开或读取失败）。标准输出为空，
  标准错误说明失败的路径和原因。
- `2`：用法错误（未提供路径、多给路径或不支持的参数/选项）。标准输出为空，
  标准错误指出问题参数并给出用法提示。参数区分规则见上文
  “文件参数与选项”。

## 计算文件批次的 Merkle 根

```sh
./build/branchaudit root [--] [<文件路径>...]
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
不会用剩余文件产出部分结果。`root` 的用法错误（如结束标记之前出现不支持的
选项）退出码为 `2`，标准输出为空。选项与文件参数的区分、以连字符开头的
文件名如何传入，与 `hash` 遵守同一条规则（见上文“文件参数与选项”）：
结束标记不计入文件，因此 `branchaudit root --` 与不带参数一样返回空批次根；
标记之后的参数全部按文件路径处理，插入标记不改变相同有序文件内容的根。

## 生成单个文件位置的成员证明

```sh
./build/branchaudit prove <位置> [--] <文件路径>...
```

`prove` 把命令行给出的文件视为与 `root` 完全相同的**有序批次**（不排序、
不去重，重复路径或相同内容各占一个位置），为其中 `<位置>` 上的文件生成
Merkle 成员证明。位置从 `0` 开始，只接受十进制数字。文件参数的路径定位与
`--` 结束标记规则同 `hash`/`root` 一致（见上文“文件参数与选项”），位置
参数在结束标记之前、按上述数字规则解析。

成功时退出码为 `0`，标准错误为空，标准输出只有一份 JSON 对象及一个换行：

```json
{"version":1,"root":"b3be…c99a","leaf_count":3,"leaf_index":2,"leaf":"6e34…a01d","siblings":[{"side":"left","digest":"6a5c…0761"}]}
```

- `version`：整数 `1`。
- `root`：与同一批次调用 `root` 的结果一致。
- `leaf_count` / `leaf_index`：批次文件数与指定位置，均为 JSON 整数。
- `leaf`：被选文件带 `0x00` 前缀的叶子摘要。
- `siblings`：从叶子向根逐层排列的兄弟摘要；每项只有 `side` 与
  `digest`，`side` 为 `left` 或 `right`，表示兄弟位于当前节点的哪一侧。
  只记录实际存在的兄弟：奇数末节点原样提升的层不添加记录，不复制末节点、
  不补零。单文件批次（含单个空文件）的 `siblings` 为空，`root` 等于
  `leaf`。

所有摘要均为 64 个小写十六进制字符；证明中不含文件内容和路径。文件仍按
固定缓冲流式读取，内存占用与文件内容总量无关。

### 退出码

- `0`：成功，标准输出为上述 JSON 对象及换行，标准错误为空。
- `1`：文件错误（任一路径不存在、指向目录、无法打开或读取失败）。标准
  输出为空，标准错误指出失败的路径和原因，不输出部分证明。
- `2`：用法错误（位置缺失、含非数字字符、超出可表示范围、不落在批次内，
  或结束标记之前出现不支持的选项）。空批次没有任何合法位置。标准输出为
  空，标准错误说明问题并给出用法。

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

生成单个文件位置的成员证明使用同一头文件中的 `merkle_proof_file`：

```cpp
#include "merkle.h"

// 与 merkle_root_files 相同的有序批次规则；位置从 0 开始。
branchaudit::MerkleProofResult r =
    branchaudit::merkle_proof_file(paths, /*leaf_index=*/2);
if (r.ok()) {
    const branchaudit::MerkleProof& p = r.proof;
    // p.root / p.leaf_count / p.leaf_index / p.leaf / p.siblings
    // siblings 从叶子向根排列，每项为 {side, digest}，
    // side 是 MerkleSibling::Side::left 或 right。
} else {
    // r.error 说明失败原因（位置越界或文件错误）。
}
```

`merkle_proof_file` 遵循与命令行相同的批次、配对与失败规则，只返回结构化
结果，不打印、不退出进程。

## 从 prove 输出的 JSON 文本读取成员证明

调用方拿到一段 `prove` 风格的证明文本（命令输出、网络消息、文件内容皆可）
后，用同一头文件中的 `merkle_proof_from_json` 把它读成上面的
`MerkleProof`：

```cpp
#include "merkle.h"

// text 是调用方自己持有的整段证明文本；读取只消费这段文本：
// 不打开或读取任何批次文件，也不替调用方选择可信根。
branchaudit::MerkleProofParseResult parsed =
    branchaudit::merkle_proof_from_json(text);
if (!parsed.ok()) {
    // parsed.error 是一句可直接展示给用户的失败原因（英文）。
    // 失败时没有可用的部分证明，函数不打印、不退出进程。
}
const branchaudit::MerkleProof& proof = parsed.proof;
```

读取沿用 `prove` 已公开的**版本 1**字段与兄弟记录格式，完整接受命令输出，
包括末尾的换行：

- 合法 JSON 空白（空格、制表符、回车、换行）出现在记号之间、对象字段
  次序任意变化，都不影响读取结果；
- 兄弟数组的**顺序、方向与摘要严格按输入保留**——读取端不重新排序、不
  去重，也不会为奇数末节点原样提升的层补造记录；单文件证明的空
  `siblings` 数组正常读入；
- 摘要（`root`、`leaf` 与每个兄弟的 `digest`）只接受**恰好 64 个小写
  十六进制字符**，并还原为 32 个原始字节；长度不符、出现十六进制以外的
  字符或使用大写字符都明确失败，不截断、不替换损坏内容；
- `version` 只接受 JSON 整数 `1`；
- `leaf_count` / `leaf_index` 只接受从 `0` 到无符号 64 位最大值
  （`2^64-1`）的 JSON 整数，数值准确保留；负数、小数、指数写法
  （`1e3`）、数字字符串（`"2"`）、布尔值以及超出范围的数字都拒绝；
- 兄弟的 `side` 只接受现有字符串 `"left"` / `"right"`。

以下情况都返回读取失败与可展示的原因：文本为空或只有空白、JSON 语法
损坏、必填字段缺失、字段类型不符、不支持的版本、同一对象（含兄弟条目）
出现重复字段、出现未定义字段；顶层值不是单个 JSON 对象、或对象之后除
JSON 空白外还有任何内容（例如另一个对象、多余的逗号或字符）也失败——
不会只取前半段当作成功结果。失败只返回结构化错误：不提供可用的部分
证明，不向标准输出/标准错误打印，也不结束调用方进程。

**读取成功只表示文本符合证明格式，不等于成员校验通过。** 空批次、位置
越界、兄弟路径与 `leaf_count`/`leaf_index` 不匹配，以及摘要能否折叠到
可信根，全部继续由 `merkle_verify_proof` 判断；证明自报的 `root`、
`leaf_count`、`leaf_index` 仍是未经认证的声明。

### 读取后进行校验的完整流程

读入的 `MerkleProof` 要与两份**调用方自行准备**的输入一起交给
`merkle_verify_proof`：经独立渠道另行保存的**可信根**，以及待验证内容
按叶子规则算出的内容叶子。读取接口从不读取批次文件，也不会把证明里的
`root` 当作可信根——可信根必须由调用方单独提供：

```cpp
#include <string>
#include <string_view>

#include "merkle.h"

// text：收到的 prove 版本 1 JSON 文本（原样传入，末尾换行无需裁掉）。
branchaudit::MerkleProofParseResult parsed =
    branchaudit::merkle_proof_from_json(text);
if (!parsed.ok()) {
    // 证明文本不符合格式：展示 parsed.error 并停止。
    return;
}

// trusted_root：可信批次根（32 字节），与这份证明分开、经独立渠道保存
// 和核对——例如事先保存的 root 命令输出。绝不能用 parsed.proof.root
// 充当可信根，那只是被校验的声明。
branchaudit::Digest trusted_root = /* 来自独立信任渠道的 32 字节 */;

// content_leaf：待验证内容的叶子摘要 SHA-256(0x00 || content)，
// 规则与批次叶子完全相同；不能用 hash/sha256_file 的普通摘要代替。
branchaudit::Digest content_leaf =
    branchaudit::merkle_leaf(content_bytes, content_size);

branchaudit::MerkleVerifyResult v = branchaudit::merkle_verify_proof(
    parsed.proof, trusted_root, content_leaf);
if (v.ok()) {
    // 内容受到可信根支持。证明自报的批次大小/位置仍需按业务要求另行
    // 与独立保存的信息比对（见下文“通过结论的边界”）。
} else {
    // v.error 是可直接展示的失败原因。
}
```

从命令行拿到这三样输入的典型方式（根与证明分开获取）：

```sh
# 可信根：由掌握批次的一方/独立渠道另行计算并保存。
./build/branchaudit root a.bin b.bin c.bin > trusted-root.txt
# 证明：需要时由掌握批次的一方生成，原样（含换行）交给使用方。
./build/branchaudit prove 2 a.bin b.bin c.bin > proof.json
```

使用方读入 `proof.json` 的全部字节传给 `merkle_proof_from_json`，把
`trusted-root.txt` 中的 64 个十六进制字符自行还原为 32 字节可信根，再对
待验证内容计算叶子摘要后调用 `merkle_verify_proof`；整个过程不需要
`a.bin`、`b.bin`、`c.bin` 这些批次文件。

## 在 C++20 程序中校验成员证明

证明生成通常在掌握整个批次的一方完成；持有证明的一方只需三样东西就能判断
“某份内容是否受到这份证明支持”，无须重新提供或读取整个批次：

1. 生成接口返回的 `MerkleProof`；
2. **调用方另行持有的可信批次根摘要**（32 个原始字节）；
3. 待验证内容按现有叶子规则算出的**叶子摘要** `SHA-256(0x00 || content)`
   （32 个原始字节）。

校验函数只消费这三项，不读文件、不扫描批次，不打印、不结束进程：

```cpp
#include "merkle.h"

// trusted_root：可信批次根。必须来自独立的信任渠道单独保存，例如事先用
// root 命令/merkle_root_files 记下、另行核对过的那 32 字节；不能直接把
// proof.root 传进来充当信任依据——证明里的 root 字段是被校验的对象。
branchaudit::Digest trusted_root = /* 来自可信渠道的 32 字节根 */;

// content_leaf：待验证内容的叶子摘要，规则与批次叶子完全相同：
// SHA-256(0x00 || content)。用 merkle_leaf 计算；内容在文件里则可自行
// 流式地“先喂一个 0x00 字节、再喂文件全部字节”。绝不能用 hash /
// sha256_file 的普通文件摘要代替——那不带 0x00 前缀，必然不同。
const unsigned char content[] = {'a'};
branchaudit::Digest content_leaf =
    branchaudit::merkle_leaf(content, sizeof(content));

branchaudit::MerkleVerifyResult v =
    branchaudit::merkle_verify_proof(proof, trusted_root, content_leaf);
if (v.ok()) {
    // 内容受到可信根支持，且兄弟记录与证明自报的 leaf_count/leaf_index
    // 一致；但这两个数字是证明自带的声明，本身未经认证——不能仅凭此处
    // 通过就断言批次大小或位置（见下文“通过结论的边界”）。
} else {
    // v.error 是可供直接展示给用户的失败原因（英文一句话）。
}
```

典型用法是把 `root` 输出的可信根（通过独立渠道获得）与待验证内容的叶子
摘要分别传入；下面的例子演示两份摘要各自从何而来：

```cpp
// ① 可信根：与生成证明无关的一次独立批次根计算（实际中常是提前保存、
//    经其他渠道核对的常量），而不是 proof.root。
std::vector<std::filesystem::path> batch{"/path/a", "/path/b", "/path/c"};
branchaudit::Digest trusted_root =
    branchaudit::merkle_root_files(batch).digest;

// ② 证明：由掌握批次的一方生成（这里在同一进程演示；实际使用时证明
//    往往是收到的 prove JSON 文本，先用 merkle_proof_from_json 读入）。
branchaudit::MerkleProof proof =
    branchaudit::merkle_proof_file(batch, /*leaf_index=*/2).proof;

// ③ 内容叶子：只对待验证的那一份内容计算，带单个 0x00 前缀。
branchaudit::Digest content_leaf =
    branchaudit::merkle_leaf(/*data=*/..., /*size=*/...);

// 三样东西齐备后校验，不需要再次提供 /path/a 等整个批次。
branchaudit::MerkleVerifyResult v =
    branchaudit::merkle_verify_proof(proof, trusted_root, content_leaf);
```

只有以下条件**同时**成立才判定通过（任一不满足都返回失败原因）：

- 传入的内容叶子摘要与 `proof.leaf` 完全一致——普通文件摘要（无 `0x00`
  前缀）不能冒充叶子；
- `proof.root` 与调用方传入的**可信根**完全一致。信任锚只来自这份外部
  摘要；即使一份证明内部完全自洽，换成另一批次的可信根也会失败；
- 证明的兄弟摘要能按公开的 `SHA-256(0x01||left||right)` 字节规则，从
  内容叶子逐层折叠回可信根；
- 兄弟的**方向、数量与从叶子向根的次序**严格符合 `leaf_count` 与
  `leaf_index` 描述的位置（这两个数字是证明自带的声明，校验只核对
  兄弟记录与声明一致，无法认证声明本身），而不是只看最终摘要是否相等：
  - 空批次（`leaf_count == 0`）没有成员；位置必须从 0 开始且
    `leaf_index < leaf_count`；
  - 每个兄弟的方向只能是 `left` 或 `right`；缺项、多项、方向反了、次序
    调换都失败，即便这样篡改后凑出了某个相等摘要也不接受；
  - 奇数层末节点原样提升的层本就没有兄弟，生成端省略这些层记录的证明
    正常通过，不要求补齐；反过来给省略层补一条记录则按“多出项”拒绝；
  - 单文件批次只接受位置 `0` 和空兄弟列表；空文件的叶子
    `SHA-256(0x00)` 与空批次根不同，两者不能互相冒充；重复内容仍各占
    独立位置，按位置结构核对，不按摘要去重。

`leaf_count`/`leaf_index` 沿用无符号 64 位范围。校验只做**不回绕**的
整数层推导（上层大小用 `n - n/2` 而非可能回绕的 `(n+1)/2`，末节点判断
用 `pos == n-1` 而非可能回绕的 `pos+1`），层数至多 64，也不按
`leaf_count` 分配内存；因此最大可表示的合法计数（`2^64-1`）也会立即
得到确定结果，不会误判或无法结束。

### 通过结论的边界：内容受支持 ≠ 批次大小与位置已认证

校验通过只保证两件事：**该内容受到可信根支持**（内容叶子能沿兄弟记录
折叠进可信根），以及**兄弟记录与证明自报的 `leaf_count`/`leaf_index`
一致**。它**不**保证这两个数字就是原始批次的真实大小与位置：调用方
只有可信根、待验证内容和收到的证明，而 `leaf_count`/`leaf_index` 是
证明自带的声明，同一份根、叶子与兄弟记录可能同时与多组声明自洽。

下面的完整示例直接展示这一点。三份不同内容的文件按固定顺序组成批次，
为从零开始的位置 `2` 生成证明；可信根来自对同一批次**另行**的一次根
计算，内容叶子来自被选文件。先验证原证明，再只把证明自报的
`leaf_count` 改为 `2`、`leaf_index` 改为 `1`，根、叶子与兄弟记录
原样保留——在相同可信根和内容叶子下，校验仍然通过：

```cpp
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "filehash.h"
#include "merkle.h"

int main() {
    // 三份不同内容的文件，按固定顺序组成批次。
    const std::vector<std::filesystem::path> batch{
        "report-jan.bin", "report-feb.bin", "report-mar.bin"};
    {
        std::ofstream(batch[0], std::ios::binary) << "january";
        std::ofstream(batch[1], std::ios::binary) << "february";
        std::ofstream(batch[2], std::ios::binary) << "march";
    }

    // 可信根：与证明生成无关、对同一批次另行计算（实际部署中通常经独立
    // 渠道保存与核对）。绝不能拿 proof.root 充当可信根。
    branchaudit::FileHashResult root_result =
        branchaudit::merkle_root_files(batch);
    if (!root_result.ok()) {
        std::cerr << "root failed: " << root_result.error << '\n';
        return 1;
    }
    const branchaudit::Digest trusted_root = root_result.digest;

    // 为从零开始的位置 2（report-mar.bin）生成证明。
    branchaudit::MerkleProofResult proof_result =
        branchaudit::merkle_proof_file(batch, /*leaf_index=*/2);
    if (!proof_result.ok()) {
        std::cerr << "prove failed: " << proof_result.error << '\n';
        return 1;
    }
    const branchaudit::MerkleProof proof = proof_result.proof;

    // 内容叶子：只对待验证的被选文件计算 SHA-256(0x00 || content)。
    std::ifstream in(batch[2], std::ios::binary);
    if (!in) {
        std::cerr << "cannot open " << batch[2] << '\n';
        return 1;
    }
    const std::string content((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
    if (in.bad()) {
        std::cerr << "read error on " << batch[2] << '\n';
        return 1;
    }
    const branchaudit::Digest content_leaf = branchaudit::merkle_leaf(
        reinterpret_cast<const unsigned char*>(content.data()),
        content.size());

    // 第一次：原证明（leaf_count=3, leaf_index=2）。
    const branchaudit::MerkleVerifyResult original =
        branchaudit::merkle_verify_proof(proof, trusted_root, content_leaf);
    std::cout << "original proof (count=3, index=2): "
              << (original.ok() ? "PASS" : "FAIL") << '\n';

    // 第二次：只改证明自报的数字——leaf_count 3→2、leaf_index 2→1，
    // 根、叶子与兄弟记录原样保留。
    branchaudit::MerkleProof altered = proof;
    altered.leaf_count = 2;
    altered.leaf_index = 1;
    const branchaudit::MerkleVerifyResult tampered =
        branchaudit::merkle_verify_proof(altered, trusted_root,
                                         content_leaf);
    std::cout << "altered numbers (count=2, index=1): "
              << (tampered.ok() ? "PASS" : "FAIL") << '\n';
    return 0;
}
```

两次都输出 `PASS`：

- **第一次通过**：内容（`report-mar.bin`）受到可信根支持，且兄弟记录
  与“3 条目批次的位置 2”一致——这也正是生成证明时的真实批次。
- **第二次也通过**：位置 2 在 3 条目批次的首层是奇数末节点，原样提升、
  没有兄弟记录，其兄弟路径形状与“2 条目批次的位置 1”完全相同；同一份
  根、叶子和兄弟记录对两组数字都自洽，校验无法区分。

第二次通过**不能**解释成文件真的移动了、原批次变成两个条目，也不能
当作“它原本位于位置 1”的证明——真实批次仍是 3 个条目、文件仍在位置
2，只是证明自报的数字本身未经认证。当然，这并不意味着任意改写声明
数字都能通过：`leaf_index >= leaf_count` 的越界声明会被直接拒绝；
与保留的兄弟记录不符的声明（例如改成 `leaf_count=2, leaf_index=0`，
首层就需要 `right` 兄弟，与记录中的 `left` 兄弟冲突）同样失败。可信
根不符、内容叶子不符的失败规则也照旧不变。

### 业务需要确认批次大小与位置时

如果业务要求确认“文件属于一个条目数已知的批次并处于指定位置”，调用方
必须把批次大小与预期位置**与可信根一起经独立渠道保存**，在校验通过之
外再逐一比对证明自报的数字：

```cpp
// 与可信根一起经独立渠道保存的批次信息（不是从证明里取出的）。
const std::uint64_t expected_leaf_count = 3;
const std::uint64_t expected_leaf_index = 2;

branchaudit::MerkleVerifyResult v =
    branchaudit::merkle_verify_proof(proof, trusted_root, content_leaf);

if (!v.ok()) {
    // 内容不受可信根支持，或兄弟记录与证明自报的位置结构不符：拒绝。
} else if (proof.leaf_count != expected_leaf_count ||
           proof.leaf_index != expected_leaf_index) {
    // 库校验虽通过（内容确实受可信根支持），但证明自报的批次大小或
    // 位置与独立保存的信息不一致：必须明确拒绝位置认定，不能显示
    // “位置验证成功”。
} else {
    // 内容受到可信根支持，且证明自报的位置与独立保存的批次大小、
    // 预期位置一致：可以认定该内容受到指定位置的支持。
}
```

只有证明自报的 `leaf_count`/`leaf_index` 与独立保存的信息一致时，才能
结合校验通过得出“内容受到指定位置支持”的结论；不一致时即使
`merkle_verify_proof` 返回通过，应用也必须拒绝位置认定。

## 测试

随仓库提供自动回归测试，覆盖标准测试向量、空文件/文本/二进制内容、分组与
填充边界长度、增量接口分段一致性、大文件尾部、含空格或中文的路径、不支持的
选项与 `--` 结束标记（含以连字符开头的真实文件名）的参数判定，以及文件
不存在和指向目录两种失败行为；此外还覆盖**文件确实存在却不能打开**与
**文件已打开、取得部分内容后继续读取时出错**两类真实 I/O 错误（普通摘要
与批次文件叶子都受约束；后者不会被当作正常到达文件末尾，已读内容也不成为
成功摘要，空文件正常读完仍成功；这两类依赖 Linux 专用的故障注入，仅
Linux 执行，其他平台明确跳过，见下文）；`root` 还覆盖 `0x00`/`0x01` 前缀规则、
批次顺序、重复位置、奇数末节点原样提升、空批次与单空文件的区别，以及任一
文件失败即整次失败（含出错前已处理过正常文件的有序批次，且不输出任何部分
根）；`prove` 覆盖 JSON 输出契约（字段集合、`version` 整数、64 位小写
十六进制摘要、从叶子向根的兄弟序列与 `left`/`right` 侧向）、与 `root`
结果一致的根、单文件与单空文件的空兄弟表、跨层奇数提升不记录兄弟、重复
路径的位置区分、位置参数的缺失/非数字/超范围/越界用法错误、文件错误不
输出部分证明，以及 `--` 结束标记与连字符文件名的处理。成员证明**校验**
接口（`merkle_verify_proof`）覆盖：三项输入齐备时正常通过（单文件/单空
文件、两文件、三文件与五文件/七文件跨层奇数提升省略的兄弟层不要求补齐、
重复内容的各自位置）；内容叶子不符、以无 `0x00` 前缀的普通 `hash` 摘要
冒充叶子、证明根与可信根不符（含内部自洽但属于另一批次的证明、可信根仅
差一位）、空批次与位置越界、兄弟方向错/缺项/多项/从叶子向根次序调换、
兄弟摘要被篡改、root 字段被伪造成可信根但兄弟链折叠不到根、为省略的提升
层补记录、非法 side 值等结构与密码学失败；以及 `leaf_count` 取最大可表示
值 `2^64-1`（位置 0 为 64 层全 right、末位置首层提升省略后 63 层全
left）、`leaf_index == leaf_count` 越界、`2^63` 全 left 无省略等 64 位
边界——形状计数由独立 Python 模拟交叉核对，校验不按 `leaf_count` 分配
内存、无回绕且必定终止；成功与失败两条路径都验证库不打印、不退出，失败
时返回非空、可展示的原因。成员证明 JSON **读取**接口
（`merkle_proof_from_json`）覆盖：真实 `prove` 输出（含末尾换行）完整
读入并与生成端结构逐字段一致、pretty 空白与字段次序（含兄弟条目内字段
次序）变化不影响结果、兄弟顺序/方向/摘要按输入原样保留（不排序、不去重、
不为奇数提升层补记录）、单文件空兄弟数组；`version` 只接受整数 1（拒绝
`2`/`0`/负数/小数/指数/数字字符串/布尔/null/容器/前导零），
`leaf_count`/`leaf_index` 接受并准确保留 `0..2^64-1`（含 0 与
`18446744073709551615`），拒绝负数/小数/指数/数字字符串/布尔/null/
前导零/`+1`/超范围数字（`18446744073709551616` 等）；摘要严格要求
64 个小写十六进制字符（拒绝大写、非十六进制字符、63/65 字符、空串、
非字符串类型，含每个兄弟的 digest）；side 只接受 `left`/`right`（拒绝
大小写变体、其他词、非字符串类型）；空文本/纯空白、顶层非对象、空对象、
语法损坏（缺冒号、未闭合、尾逗号、兄弟数组未闭合、无效转义）、六个必填
字段逐个缺失、重复字段（顶层与兄弟对象均有）、未定义字段（顶层与兄弟
对象）、兄弟条目缺 side/digest、顶层 siblings 类型错误、对象后的非空白
尾随和另一个对象；并验证读入后以独立可信根与内容叶子经
`merkle_verify_proof` 成功校验的完整使用流程，以及“读入成功但内容叶子
不匹配时仍由校验接口拒绝”的读校分离；成功与失败都验证库不打印、不退出，
失败不提供可用的部分证明，失败原因非空且可展示。此外，
`proof_cli_roundtrip` 把**真实 `prove` 命令的标准输出**（逐字节原文、
含末尾换行，不经测试重新拼接）直接交给 `merkle_proof_from_json` 读取，
可信根取自对同一有序批次**另行执行的 `root` 命令**（不以证明里的 root
字段充当可信来源），待验证内容按带单个 `0x00` 前缀的叶子规则计算内容
叶子后交给 `merkle_verify_proof`：覆盖单个空文件（兄弟表为空、根等于
空文件叶子、区别于空批次根）与含重复内容的五文件批次的最后一个位置
（连续奇数末节点提升、省略的层不补记录、重复内容按传入顺序保留位置不
去重，删除批次文件后仍校验通过）；并覆盖两种失败——完整证明配改变过的
待验证内容时读取仍成功但校验明确拒绝并返回非空原因，真实证明文本被
截断（JSON 对象或字符串未闭合）时读取失败、返回非空原因且没有可用的
部分证明；读取与校验全程不向标准输出/标准错误写内容。预期摘要与证明以
独立标准实现（FIPS 180-4 公布向量、系统
`sha256sum` 与 Python `hashlib`/OpenSSL）为依据，不与本项目实现互相比较。

此外还覆盖 **SHA-256 末尾长度编码越过低 32 位边界**的回归：对
`536870911`、`536870912`、`536870913` 字节（即位长度 `2^32-8`、恰好
`2^32`、`2^32+8`，分别对应边界之前、恰好达到与越过 2³² 比特）三份消息，
经增量接口 `update()` 逐段提交与经 `hash`/`sha256_file` 读取真实文件两个
入口，都必须等于由 `sha256sum` 与 `hashlib`（OpenSSL）两个彼此独立的实现
交叉核对后固化的标准摘要；越过边界的同一消息在 2³² 比特边界附近改用不同
（且不与 64 字节分组对齐）的分段后仍得同一摘要；另取一份 `536870913`
字节而仅末字节不同的真实文件，证明越过边界后的最后一段确属输入，而不是只
返回边界之前内容的摘要。这能发现“长度高 32 位丢失或回绕”和“把字节数直接
当作比特数”一类在短输入上不可见的错误。三份大消息的期望值独立于本项目，
不以“命令行结果与库结果相等”充当正确性。准备与处理都以固定 1 MiB 缓冲
流式进行，整份消息从不装入内存，同一时刻至多保留一份 512 MiB 文件；若临时
目录可用空间不足，相关真实文件检查明确报告为跳过（不计为通过），增量接口的
长度边界检查不依赖磁盘，始终执行。

两种 I/O 错误由随测试构建的故障注入共享库 `tests/fault_inject.c` 在 libc
打开/读取接口处确定性触发（经 `LD_PRELOAD` 与 `BRANCHAUDIT_TEST_OPEN_FAIL`
/`BRANCHAUDIT_TEST_READ_FAIL` 环境变量按精确路径启用）：被测程序仍完整
执行“定位 → 打开 → 流式读取 → 错误传播”的真实路径，既不依赖碰巧出现的
磁盘故障，也无法用一个写死错误文字的返回值代替文件计算；不设置触发变量时
该库完全透传，对其余用例零影响，且与运行用户是否为 root 无关。该库仅在
Linux 上构建和预载；其他平台不构建它，相应检查按下文规则明确跳过。

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

包含四个测试：`sha256_unit` 与 `merkle_unit`（C++ 层，直接链接
`branchaudit_core`）、`proof_cli_roundtrip`（C++ 层，执行真实
`branchaudit` 命令行，把 prove/root 的标准输出交给库读取与校验），以及
`cli_e2e`（Python 端到端，校验命令行退出码与
标准输出/错误契约）。可通过 `-DBRANCHAUDIT_BUILD_TESTS=OFF` 关闭测试构建
（关闭后核心库与命令行程序照常构建和使用）。

### 各平台默认完成的检查

故障注入依赖 Linux 专有的 `LD_PRELOAD` 符号介入与 `/proc/self` 进程文件
信息，因此两类注入检查（“文件确实存在却不能打开”与“部分读取后继续读
出错”）**只在 Linux 上默认执行**：

- **Linux**：默认构建即执行全部检查，包括两类故障注入检查。
- **macOS**（Apple Clang，C++20）：保持默认选项即可构建核心库、命令行
  程序并完成该平台可执行的回归检查——标准向量与摘要正确性、Merkle 字节
  规则与批次顺序、文件不存在/指向目录等失败行为全部照常执行；只有两类
  故障注入检查因平台原因**明确跳过**。CMake 配置输出会说明跳过的检查，
  测试输出以 `SKIP:` 行列出它们，并在汇总中注明“skipped, not
  verified”——跳过的检查不计入已通过项，也不影响其余检查的判定：任何
  实际执行的检查失败都会使回归失败。

### 缺少可选工具与检查失败的区别

- 未找到 Python3 时，仅 `cli_e2e` 端到端测试不注册（配置输出会说明），
  核心库、命令行程序与两个 C++ 回归测试照常构建和执行；这不属于产品
  检查失败。
- 平台不支持的故障注入检查按上文报告为跳过，同样不属于失败。
- 越过 2³² 位边界的**真实大文件**检查需要临时目录有约 1 GiB 可用空间
  （同一时刻至多保留一份 512 MiB 文件）。空间不足时这部分文件检查明确
  报告为跳过、不计为通过；不依赖磁盘的增量接口长度边界检查仍照常执行。
  这些大文件计算耗时远超短输入，`sha256_unit` 与 `cli_e2e` 的 ctest
  时限已相应放宽（300s / 600s），正常的大文件计算不会被仅适用于短输入
  的时限提前终止。
- 除上述明确标注的跳过项外，任何检查失败都会使对应测试以非零退出，
  `ctest` 判定回归失败。
