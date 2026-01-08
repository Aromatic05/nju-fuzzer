# MutatorFactory 技术文档

## 1. 组件概述

`MutatorFactory` 是变异模块的**中央分发器**，位于 `edu.nju.fuzzing.mutate` 包中。它的核心职责是基于 `Seed` 的类型（`SeedType`）动态生产最合适的变异器实例。

在一个典型的 Fuzzing 流程中，我们往往拥有多种格式的种子（如 XML、JPEG、ELF 等）。如果对所有数据都使用盲目的位翻转，效率会非常低下；反之，如果只使用结构化变异，则可能无法触发底层的解析漏洞。`MutatorFactory` 通过**多态创建**和**混合变异策略**完美解决了这一矛盾。

---

## 2. 核心架构与实现

### 2.1 类结构分析

```java
public class MutatorFactory {
    private final List<Seed> corpus;
    private final Mutator defaultMutator;
    private static final int HAVOC_PROBABILITY = 10;  // 10% 概率使用 Havoc
    
    public MutatorFactory(List<Seed> corpus) {
        this.corpus = corpus;
        this.defaultMutator = new AflHavocMutator(corpus);
    }
    
    public Mutator createMutator(Seed seed) { ... }
}
```

*   **Corpus 引用**：工厂类持有 `corpus`（语料库）的引用，这主要是为了支持 `AflHavocMutator`。Havoc 变异中的"拼接（Splicing）"操作需要从语料库中随机抽取其他种子进行"杂交"。
*   **单例与多态混合**：
    *   **单例模式**：`defaultMutator` (Havoc) 被设计为单例，因为它不持有特定种子的状态，且调用频率最高，使用 `ThreadLocalRandom` 保证线程安全。
    *   **工厂模式**：针对特定格式的变异器（如 `XmlMutator`）采用"按需创建"模式，保证了变异过程的独立性。

### 2.2 变异分发策略
工厂类在执行 `createMutator(Seed seed)` 时遵循以下优先级逻辑：

1.  **兜底逻辑 (Fallback)**：如果种子类型为 `null` 或 `UNKNOWN`，直接分配 `AflHavocMutator`。
2.  **混合概率策略 (Hybrid Strategy)**：
    *   这是本工厂类最核心的**启发式设计**。
    *   即使种子类型已知（例如是一个 XML），工厂类仍有 **10% (HAVOC_PROBABILITY)** 的概率强制返回 `AflHavocMutator`。
    *   **设计目的**：语法变异器生成的结构通常过于“守规矩”，难以触发解析器最底层的缓冲区溢出等漏洞。通过混入 10% 的“乱拳”位变异，可以极大增强 Fuzzer 的鲁棒性攻击能力。
3.  **多态创建**：在通过概率筛选后，利用 `switch-case` 匹配 `SeedType`，返回对应的专业算子。

### 2.3 支持的类型映射

```java
switch (type) {
    // --- 文本类 ---
    case XML:   return new XmlMutator();
    case MJS:   return new MjsMutator();
    case LUA:   return new LuaMutator();
    case CXX:   return new CxxMutator();

    // --- 二进制类 ---
    case PNG:   return new PngMutator();
    case ELF:   return new ElfMutator();
    case JPEG:  return new JpegMutator();
    case PCAP:  return new PcapMutator();

    // --- 未实现的类型 ---
    default:    return defaultMutator;
}
```

---

## 3. 在主函数中的实际用法

`MutatorFactory` 处于 Fuzzing 执行循环的核心环路中。以下是它在项目主流程（Main Loop）中的典型应用场景：

### 3.1 代码集成示例

```java
public class FuzzerMain {
    public static void main(String[] args) {
        // 1. 初始化语料库
        List<Seed> corpus = loadInitialSeeds("seeds/");
        
        // 2. 初始化变异器工厂
        MutatorFactory factory = new MutatorFactory(corpus);

        while (true) {
            // 3. 调度器选出一个种子
            Seed currentSeed = scheduler.pickNextSeed(corpus);
            
            // 4. 根据当前种子，从工厂获取变异器
            // 这里体现了工厂模式的威力：主循环不需要知道具体的变异细节
            Mutator mutator = factory.createMutator(currentSeed);
            
            // 5. 分配能量并生成测试用例
            int energy = calculateEnergy(currentSeed);
            Iterator<Testcase> testcases = mutator.mutate(currentSeed, energy);
            
            // 6. 执行测试
            while (testcases.hasNext()) {
                executor.run(testcases.next());
            }
        }
    }
}
```

### 3.2 运行流程图解

```
┌─────────────────────────────────────────────────────────────────────┐
│                        createMutator(Seed)                          │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │  seed.getType() → SeedType    │
                    └───────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │   random.nextDouble() < 0.1?  │
                    └───────────────────────────────┘
                           │               │
                      YES  │               │  NO
                           ▼               ▼
              ┌─────────────────┐   ┌─────────────────────────┐
              │ defaultMutator  │   │ switch (type)           │
              │ (AflHavocMutator)│   │   XML  → XmlMutator     │
              └─────────────────┘   │   MJS  → MjsMutator     │
                                    │   LUA  → LuaMutator     │
                                    │   CXX  → CxxMutator     │
                                    │   PNG  → PngMutator     │
                                    │   ELF  → ElfMutator     │
                                    │   JPEG → JpegMutator    │
                                    │   PCAP → PcapMutator    │
                                    │   default → defaultMutator │
                                    └─────────────────────────┘
                           │               │
                           └───────┬───────┘
                                   ▼
                    ┌───────────────────────────────┐
                    │       返回 Mutator 实例       │
                    └───────────────────────────────┘
```

**流程说明**：
1.  **输入**：调度器选中的 `Seed` 对象。
2.  **检测**：工厂检查 `Seed.getType()` 获取种子类型。
3.  **掷骰子**：生成随机数，判定是否命中 10% 的 Havoc 回退逻辑。
4.  **构建**：如果未回退，根据类型 `new` 出对应的专业变异器。
5.  **输出**：返回一个实现了 `Mutator` 接口的对象，供后续迭代生成使用。

---

## 4. 关键作用与价值

### 4.1 提高变异的“命中深度”
通过将 PNG、XML、ELF 等格式的种子分发给专业的 **Structure-aware Mutator** 或 **Grammar-based Mutator**，生成的用例能够通过解析器的第一层校验（如格式检查、CRC 校验、标签闭合检查、Magic Number 验证），从而引导程序进入深层的业务逻辑处理代码。

- **文本类**（XML/MJS/LUA/CXX）：使用语法感知变异，保持语法正确性
- **二进制类**（PNG/ELF/JPEG/PCAP）：使用结构感知变异，保持格式有效性

### 4.2 策略的灵活性
`MutatorFactory` 统一了变异接口。如果你需要增加一种新的格式（如 `Protobuf` 或 `WASM`），你只需要：
1.  在 `SeedType` 枚举中添加新类型。
2.  实现一个新的 `Mutator` 类（可继承 `StructureMutator` 或使用 `grammar` 包）。
3.  在 `MutatorFactory` 的 `switch` 中增加一个 `case`。
4.  **完全不需要修改主循环逻辑**。

### 4.3 解决“语法陷阱”
纯语法变异器往往会陷入死胡同，无法生成破坏文件头或修改关键二进制位的用例。`MutatorFactory` 引入的 **10% Havoc 概率** 确保了种子库即便在高度结构化的变异下，依然保留了“暴力破坏”的基因，从而能够发现更底层的 C/C++ 内存安全漏洞。

---

## 5. 总结

`MutatorFactory` 不仅仅是一个简单的对象生成类，它实际上承载了本 Fuzzing 引擎的**变异调度哲学**。它通过对 `SeedType` 的智能感知和混合概率模型的应用，实现了“结构化探索”与“暴力变异”的完美平衡，是提升 Fuzzing 效率和覆盖率的核心引擎组件。