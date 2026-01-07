# Fuzzing 变异算法全技术手册

## 1. 引擎变异哲学：混合变异架构

本引擎采用 **“结构引导 + 随机扰动”** 的双轨制变异架构：

*   **语法变异算子 (Structure-Aware Mutators)**：利用对目标格式（如 XML、ELF、JPEG）的先验知识，生成符合或接近协议规范的输入。这种方式能够绕过绝大多数初级校验（如 Magic Number 检查、CRC 校验、基础解析路径），使 Fuzzer 能够触达深层的业务逻辑。
*   **通用变异算法 (Havoc Mutator)**：在不破坏大框架的前提下，对局部数据进行“狂暴”修改。它擅长发现那些连开发者都未曾预料到的位级逻辑错误。

### 核心接口

```java
public interface Mutator {
    /**
     * 返回一个变异迭代器，支持惰性生成测试用例
     * 
     * @param seed 待变异的种子
     * @param energy 分配的能量（生成的测试用例数量）
     * @return 测试用例迭代器
     */
    Iterator<Testcase> mutate(Seed seed, int energy);
}
```

---

## 2. 通用变异算法：AflHavocMutator

`AflHavocMutator` 是本引擎的"乱拳"组件，是对经典 AFL (American Fuzzy Lop) 核心变异阶段的 Java 高性能实现。

### 算子权重分配

```java
// 权重表：让轻量级、保持结构的变异出现概率更高
private void initWeights() {
    // In-Place Ops (High Freq): ~50%
    fillWeight(10, OP_FLIP_BIT);
    fillWeight(10, OP_FLIP_BYTE);
    fillWeight(10, OP_ARITH_BYTE);
    fillWeight(10, OP_ARITH_SHORT);
    fillWeight(5,  OP_ARITH_INT);
    fillWeight(5,  OP_SWAP_BYTES);
    
    // Token & Interesting (High Value): ~20%
    fillWeight(10, OP_INTERESTING);
    fillWeight(10, OP_OVERWRITE_TOKEN);
    
    // Structural Ops (Expensive): ~30%
    fillWeight(5, OP_INSERT_TOKEN);
    fillWeight(5, OP_DELETE_BLOCK);
    fillWeight(5, OP_INSERT_BLOCK);
    fillWeight(5, OP_OVERWRITE_BLOCK);
    fillWeight(5, OP_CLONE_BLOCK);
}
```

### 变异策略
1.  **自适应堆叠 (Adaptive Stacking)**：每次变异不会只执行一个操作，而是随机堆叠 2 到 32 个算子。这种指数级的组合能力使得输入数据可以迅速从原始状态演化为面目全非的畸形状态。
2.  **原地变异优先 (In-Place First)**：优先使用位翻转（Bit-flip）、算术加减（Arithmetic）、魔法数字替换（Interesting Values），这些操作不需要重新分配内存，执行效率极高。
3.  **种子拼接 (Splicing)**：通过“跨物种杂交”，将当前种子与语料库中的另一个随机种子在随机位置断开并拼接。这种方式能有效地合并两个不同路径发现的特征。
4.  **字典感知 (Dictionary-Aware)**：如果用户提供了 `.dict` 文件，Havoc 会在变异过程中高频插入这些 Token，帮助 Fuzzer 突破 Strcmp 等强字符串检查。

### 优缺点分析
*   **优点**：完全不依赖格式知识，适用于任何二进制或文本目标。速度极快，是发现底层内存损坏漏洞（如缓冲区溢出）的利器。
*   **缺点**：盲目性强。在处理具有严格头部结构、长度校验或校验和（Checksum）的文件时，效率极低，大部分生成的用例会被目标程序在入口处直接丢弃。

---

## 3. 语法变异算子：文本类 (Text-based)

### 3.1 XmlMutator (XML 变异器)
*   **核心逻辑**：采用基于递归下降的生成策略，确保生成的标签、属性和 DTD 结构在语法层面是准合法的。
*   **变异策略**：
    *   **Billion Laughs 攻击**：通过在 DTD 中定义递归展开的实体，测试解析器的内存膨胀防御。
    *   **XXE (外部实体注入)**：尝试插入 `SYSTEM "file:///etc/passwd"` 等载荷，探测敏感信息泄露风险。
    *   **编码炸弹**：随机切换 UTF-8, UTF-16LE, UTF-16BE 编码并注入相应的 BOM 头，测试解析器底层的编码转换引擎。
*   **优点**：能产生极深层级的嵌套结构，是测试 XML 解析状态机的关键。
*   **缺点**：生成的属性名和标签名是随机选取的，可能无法触发特定业务逻辑（如具体的 Config 检查）。

### 3.2 MjsMutator (JavaScript 变异器)
*   **核心逻辑**：针对现代 JavaScript (ES Module) 语法，支持表达式、语句和声明的结构化变异。
*   **变异策略**：
    *   **变量作用域攻击**：制造复杂的闭包和 `let`/`const`/`var` 混用场景，测试作用域解析。
    *   **Unicode 标识符**：生成包含特殊 Unicode 字符的变量名，测试解析器的字符处理。
    *   **Arrow Function 嵌套**：构造深层嵌套的箭头函数表达式。
*   **优点**：能够生成语法正确的 JavaScript 代码，可穿透解析器校验。
*   **缺点**：生成的代码逻辑通常是随机的，难以触发特定业务逻辑。

### 3.3 LuaMutator (Lua 脚本变异器)
*   **核心逻辑**：模拟 Lua 脚本的语法树（Block -> Statement -> Expression）。
*   **变异策略**：
    *   **协程与作用域攻击**：制造复杂的 `coroutine.resume` 逻辑，测试 VM 在协程切换时的变量生存期管理。
    *   **元表 (Metatable) 劫持**：通过设置 `__index` 或 `__gc` 触发无限递归或垃圾回收异常。
    *   **正则模式匹配**：针对 Lua 特有的 `%b` (Balanced) 匹配符生成畸形 Pattern。
*   **优点**：深度触达脚本虚拟机的指令解析和 GC (垃圾回收) 逻辑。
*   **缺点**：很难生成具有复杂控制流逻辑的脚本（例如能计算出特定结果的循环）。

### 3.4 CxxMutator (C++ 符号变异器)
*   **核心逻辑**：针对 Itanium C++ ABI 符号修饰（Mangling）规范。
*   **变异策略**：
    *   **递归修饰符**：构造 `PPPPPP...i`（指向指针的指针...的整型），诱发 Demangler 的栈溢出。
    *   **模板递归**：构造深层嵌套模板 `I...I...E...E`。
    *   **操作符与构造函数**：随机注入 `C1`, `D2`, `nw` (operator new) 等特殊标记。
*   **优点**：专门针对二进制分析工具（如 `nm`, `readelf`, `gdb`）的解析核心。
*   **缺点**：生成的字符串通常非常短，攻击面相对集中。

---

## 4. 语法变异算子：二进制类 (Binary-based)

### 4.1 ElfMutator (ELF 变异器)
*   **核心逻辑**：构建合法的 ELF64 文件骨架，包含回填偏移量的 Header Table。
*   **变异策略**：
    *   **计数器炸弹**：设置 `e_phnum` 或 `e_shnum` 为 `0xFFFF`，测试解析器是否盲目分配大量内存。
    *   **段链接环**：使 Section 之间的 `sh_link` 指向自身，制造解析死循环。
    *   **PT_NOTE 溢出**：构造畸形的 Note 段长度，测试 Core Dump 分析器的边界。
*   **优点**：能穿透 Linux 二进制加载器的第一层检查。
*   **缺点**：ELF 格式非常严苛，稍有偏移不齐（Alignment）就会导致解析器直接报错退出。

### 4.2 JpegMutator (JPEG 变异器)
*   **核心逻辑**：基于 Marker（标记位）的流生成算法。
*   **变异策略**：
    *   **Exif/TIFF 伪造**：注入复杂的元数据块，元数据解析是图像处理库漏洞的“高发地”。
    *   **长度欺骗 (Length Spoofing)**：声明一个极大的段长度，但实际数据很短，诱发 OOB (越界读)。
    *   **渐进式扫描攻击**：使用 SOF2 标记，测试复杂的渐进式重组逻辑。
*   **优点**：相比随机位变异，该算法能产生更有意义的图片格式流。
*   **缺点**：生成的图像通常没有真实的视觉意义（像素是随机的），无法测试特定的滤镜算法（如模糊滤波）。

### 4.3 PngMutator (PNG 变异器)
*   **核心逻辑**：按 Chunk 结构构建，自动管理 CRC 校验和和 Zlib 压缩流。
*   **变异策略**：
    *   **iCCP 压缩炸弹**：在 ICC Profile 块中存入高压缩比的垃圾数据，诱发解压时的 OOM。
    *   **调色板 OOB**：定义一个小的调色板，但在像素数据中使用大的索引值。
    *   **CRC Fuzzing**：5% 概率生成错误的 CRC 值，探测解析器是否在校验前就处理了恶意数据。
*   **优点**：通过自动重算 CRC，使得变异后的用例 100% 能够进入图像处理内核。
*   **缺点**：Zlib 压缩过程相对耗时，会略微降低 Fuzzing 的吞吐量。

### 4.4 PcapMutator (网络报文变异器)
*   **核心逻辑**：构建包含 Ethernet -> IP -> TCP/UDP 完整协议栈的流量包。
*   **变异策略**：
    *   **长度不一致攻击**：构造 IP 头中的 Total Length 与 PCAP 头中的 `incl_len` 冲突的报文。
    *   **IHL/Offset 畸形**：设置非法的报文首部长度字段，诱发 DPI (深度包检测) 引擎的解析错位。
    *   **时间戳攻击**：生成时间回溯或跳跃极大的报文序列，测试流量重组器的状态管理。
*   **优点**：针对 IDS (入侵检测系统) 和防火墙提供高质量的测试输入。
*   **缺点**：目前主要支持 IPv4，对 IPv6 或更复杂的协议（如 HTTP 解析）支持有限。

---

## 5. 总结

变异算法的质量直接决定了 Fuzzing 的效率。**语法变异器**解决了“如何进得去”的问题，而 **AflHavocMutator** 解决了“如何挖得深”的问题。

在生产环境中，推荐将这些变异器与 **Coverage Feedback (覆盖率反馈)** 机制相结合。当语法变异器生成了一个有趣的结构并触发了新的代码路径时，Havoc 紧随其后对该路径上的种子进行微调，这是目前模糊测试领域的黄金策略。
---

## 6. 相关文档

- **[binary.md](binary.md)**：二进制结构感知变异框架详解，包含 FormatScanner、StructureMutator、ConstraintFixer 等组件
- **[grammar.md](grammar.md)**：语法感知变异框架详解，包含 Tokenizer、TreeBuilder、MutationStrategy 等组件
- **[MutatorFactory.md](MutatorFactory.md)**：变异器工厂模式的设计与实现
- **[MuatationOps.md](MuatationOps.md)**：底层变异操作的实现细节