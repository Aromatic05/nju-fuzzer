# MutationOps 类使用文档

## 1. 概述

`MutationOps` 是一个**高性能、无状态的底层变异算子集合**。它参考了 AFL (American Fuzzy Lop) 的经典变异策略，并在此基础上进行了 Java 语言层面的深度优化。

该工具类主要用于对字节数组（`byte[]`）进行随机变异，以产生能够触发目标程序异常行为的测试用例。

### 核心设计与优化

*   **高性能 (High Performance)**：摒弃了 Java 中较为沉重的 `ByteBuffer` 包装，全部采用位运算（Bitwise Operations）手动处理多字节读写，最大化执行效率。
*   **无锁随机 (Lock-free Randomness)**：使用 `ThreadLocalRandom` 替代 `java.util.Random`，在多线程并发 Fuzzing 场景下避免锁竞争，大幅提升吞吐量。
*   **零 GC 压力 (Zero GC for In-Place)**：对于原地变异操作，直接修改原数组，不产生任何新的对象分配，减轻垃圾回收（Garbage Collection）压力。

---

## 2. 变异策略分类

`MutationOps` 将变异操作分为两大类：

1.  **原地变异 (In-Place Mutation)**：不改变数据长度，直接修改内容。
2.  **结构变异 (Structural Mutation)**：改变数据长度（插入或删除），返回新的数组。

### 2.1 魔法数字 (Interesting Values)

类中预定义了 AFL 经典的“魔法数字”集合（`INTERESTING_8`, `INTERESTING_16`, `INTERESTING_32`）。这些数值（如 `0`, `-1`, `MAX_INT`, `SIZE_MAX` 等）通常是整数溢出、缓冲区边界检查等漏洞的触发点。变异算子会随机选取这些值覆盖原有数据。

---

## 3. 方法详解

### 第一类：原地变异 (In-Place Mutation)

**特点**：
*   返回类型：`void`
*   副作用：直接修改传入的 `byte[] data`。
*   性能：极高（无内存分配）。

| 方法名 | 描述 | 逻辑细节 |
| :--- | :--- | :--- |
| **`flipBit`** | 随机位翻转 | 随机选择一个字节中的某一位（Bit），将其取反（0变1，1变0）。 |
| **`flipByte`** | 随机字节翻转 | 随机选择一个字节，与 `0xFF` 进行异或操作（即按位取反）。 |
| **`arithByte`** | 字节加减运算 | 随机选择一个字节，对其进行加或减操作，幅度为 `1` 到 `35` 之间的随机数。 |
| **`arithShort`** | Short (2字节) 加减 | 随机选择连续的2个字节，将其视为 Short 进行加减运算。**自动处理大端/小端序**。如果数组长度不足，自动降级为 `arithByte`。 |
| **`arithInt`** | Int (4字节) 加减 | 随机选择连续的4个字节，将其视为 Integer 进行加减运算。**自动处理大端/小端序**。如果数组长度不足，自动降级。 |
| **`setInteresting`** | 特殊值替换 | 随机选择 8bit, 16bit 或 32bit 宽度，用预定义的“魔法数字”覆盖原数据。这是触发边界条件漏洞的核心算子。 |
| **`swapBytes`** | 字节交换 | 随机选取两个不同的索引位置，交换这两个字节的值。用于破坏魔数或校验和结构。 |
| **`overwriteBlock`** | 块覆写 | 随机选取一段连续区域（长度 1-32），用随机生成的字节或同一个随机字节进行填充。 |
| **`overwriteToken`** | 字典覆写 | 将用户提供的关键字（Token/Dictionary）覆盖写入到数据的随机位置。用于通过魔数检查或关键字匹配。 |

---

### 第二类：结构变异 (Structural Mutation)

**特点**：
*   返回类型：`byte[]` (新数组)
*   副作用：不修改原数组，返回变异后的新副本。
*   性能：涉及内存分配和数组拷贝（`System.arraycopy`）。

| 方法名 | 描述 | 逻辑细节 |
| :--- | :--- | :--- |
| **`deleteBlock`** | 块删除 | 随机删除一段连续的数据。返回长度变短的新数组。 |
| **`insertBlock`** | 块插入 | 在随机位置插入一段新数据（长度 1-32）。填充内容可能是随机杂色，也可能是重复的某个字节（如填充 `A`）。 |
| **`cloneBlock`** | 块克隆 (拼接) | **非常有效的变异策略**。从原数据中复制一段内容，插入到原数据的另一个位置。这能保留数据的语义结构（如 XML 标签重复）。 |
| **`insertToken`** | 字典插入 | 将用户提供的关键字（Token）插入到数据的随机位置。 |

---

### 辅助方法 (Helpers)

这些私有方法用于处理多字节数据的读写，且**不需要创建 ByteBuffer 对象**，这是本类高性能的关键所在。

*   `getShort` / `putShort`: 通过位移运算处理 2 字节读写。
*   `getInt` / `putInt`: 通过位移运算处理 4 字节读写。
*   **Endianness**: 所有多字节操作都接受 `boolean bigEndian` 参数，变异时会随机选择大端或小端模式，以覆盖不同架构的目标程序。

---

## 4. 使用示例

以下代码展示了如何在 Fuzzing 循环中使用 `MutationOps`。

```java
import edu.nju.fuzzing.mutate.MutationOps;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

public class MutationExample {

    public static void main(String[] args) {
        // 1. 原始种子数据 (例如 "Hello World")
        byte[] originalData = "Hello World".getBytes();
        
        // 2. 模拟 Fuzzing 流程
        byte[] mutatedData = originalData.clone(); // 保护原始数据
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        // 随机选择一种变异策略
        int strategy = rand.nextInt(4);

        switch (strategy) {
            case 0:
                // --- 场景 A: 原地变异 (In-Place) ---
                System.out.println("Executing Bit Flip...");
                MutationOps.flipBit(mutatedData);
                break;

            case 1:
                // --- 场景 B: 算术变异 (Arithmetic) ---
                System.out.println("Executing Int Addition...");
                // 尝试修改前4个字节
                MutationOps.arithInt(mutatedData); 
                break;

            case 2:
                // --- 场景 C: 结构变异 (Structural - Insert) ---
                System.out.println("Executing Block Insertion...");
                // 注意：结构变异会返回新对象，需要接收返回值
                mutatedData = MutationOps.insertBlock(mutatedData);
                break;

            case 3:
                // --- 场景 D: 字典/Token 变异 ---
                System.out.println("Injecting Dictionary Token...");
                byte[] token = "admin".getBytes();
                // 50% 概率覆盖，50% 概率插入
                if (rand.nextBoolean()) {
                    MutationOps.overwriteToken(mutatedData, token);
                } else {
                    mutatedData = MutationOps.insertToken(mutatedData, token);
                }
                break;
        }

        // 3. 输出结果
        System.out.println("Original: " + Arrays.toString(originalData));
        System.out.println("Mutated : " + Arrays.toString(mutatedData));
        System.out.println("New Len : " + mutatedData.length);
    }
}
```

## 5. 最佳实践与注意事项

1.  **数据隔离**：
    *   对于 **In-Place** 方法，如果你的原始种子（Seed）对象是全局共享的，调用前**务必先 clone 一份副本**，否则会污染原始种子库。
    *   对于 **Structural** 方法，虽然它返回新数组，但输入数组通常不会被修改（除 `insertToken` 等内部逻辑外），但也建议操作副本以保持一致性。

2.  **调度策略 (Scheduling)**：
    *   在实现 Mutator 时，建议**高频使用 In-Place 操作**（如 80% 概率），**低频使用 Structural 操作**（如 20% 概率）。
    *   原因：Structural 操作涉及内存分配 (`new byte[]`) 和内存拷贝，过高频率会导致 Java GC 压力增大，降低 Fuzzing 的每秒执行次数 (Execs/sec)。

3.  **字典的使用**：
    *   `overwriteToken` 和 `insertToken` 极其依赖字典的质量。建议在 Fuzzer 启动时解析目标程序（如提取字符串常量）或加载用户提供的字典文件。

4.  **边界安全**：
    *   所有方法内部都已包含边界检查（例如 `data.length < 4` 时 `arithInt` 会自动降级或直接返回），调用者无需在外部额外判断数组长度。