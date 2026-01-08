# 二进制结构感知变异框架 (Binary Structure-Aware Mutation)

## 1. 概述

本框架提供了一套完整的**二进制格式感知变异引擎**，位于 `edu.nju.fuzzing.mutate.binary` 包中。与传统的盲目位翻转不同，该框架能够理解文件的内部结构，针对控制字段进行精确变异，从而显著提高漏洞发现的效率。

### 核心设计理念

*   **格式扫描 (Format Scanning)**：首先解析文件，识别出所有逻辑块和关键字段
*   **结构感知变异 (Structure-Aware Mutation)**：针对不同类型的字段采用不同的变异策略
*   **约束修复 (Constraint Fixing)**：变异后自动修复校验和、长度字段等，确保畸形数据能通过初步检查

---

## 2. 架构组件

### 2.1 核心类图

```
FormatScanner (接口)
    ├── ElfScanner     (ELF 格式扫描器)
    ├── PngScanner     (PNG 格式扫描器)
    ├── JpegScanner    (JPEG 格式扫描器)
    └── PcapScanner    (PCAP 格式扫描器)

ScanResult
    ├── BinaryChunk[]     (识别出的块列表)
    └── FieldMapping[]    (全局字段映射)

BinaryChunk
    ├── startOffset       (块起始位置)
    ├── totalLength       (块总长度)
    ├── chunkType         (块类型标识)
    ├── rawData           (原始数据)
    ├── fields            (块内字段映射)
    └── critical          (是否为关键块)

FieldMapping
    ├── offset            (字段偏移)
    ├── length            (字段长度)
    ├── type              (字段类型)
    ├── byteOrder         (字节序)
    └── originalValue     (原始值)

StructureMutator        (静态变异方法集合)
ConstraintFixer         (约束修复工具)
```

### 2.2 扫描模式

框架支持两种文件结构扫描模式：

| 模式 | 适用格式 | 结构特点 |
| :--- | :--- | :--- |
| **TLV 模式** (Type-Length-Value) | PNG, JPEG, PCAP | 数据由连续的"块"组成，每个块包含类型标识、长度字段和数据 |
| **Offset 模式** (Header-Section) | ELF, PE | 文件头包含指向各个 Section 的偏移量 |

---

## 3. 字段类型枚举 (`FieldType`)

`FieldType` 定义了二进制文件中可识别的字段类型，变异器会根据字段类型选择不同的攻击策略：

| 字段类型 | 描述 | 变异策略 |
| :--- | :--- | :--- |
| `MAGIC` | 文件头或块头的标识符 | 通常保持不变或谨慎破坏 |
| `TYPE` | 块类型、段类型 | 随机替换为未知类型 |
| `LENGTH` | 数据大小字段 | **高价值目标**：溢出值、0、MAX_INT |
| `OFFSET` | 指向文件其他位置的地址 | 越界指针、负值、环形引用 |
| `COUNT` | 元素个数 | 极大值、0 |
| `CHECKSUM` | 完整性校验值 | 变异后需重算 |
| `FLAGS` | 布尔标志位 | 全0、全1、随机翻转 |
| `VERSION` | 版本号 | 非法版本、极端值 |
| `DATA` | 数据区 | 可随意变异 |
| `PADDING` | 填充/对齐 | 可删除或填充垃圾 |

---

## 4. 格式扫描器

### 4.1 FormatScanner 接口

```java
public interface FormatScanner {
    /**
     * 扫描文件，识别结构
     */
    ScanResult scan(byte[] data);
    
    /**
     * 检查文件是否符合此格式
     */
    boolean matches(byte[] data);
    
    /**
     * 获取格式名称
     */
    String getFormatName();
}
```

### 4.2 已实现的扫描器

#### ElfScanner

解析 ELF 可执行文件结构：

*   **识别内容**：ELF Header、Program Headers、Section Headers
*   **字段映射**：`e_type`, `e_machine`, `e_entry`, `e_phoff`, `e_shoff`, `e_phnum`, `e_shnum` 等
*   **字节序检测**：根据 `e_ident[EI_DATA]` 自动切换大小端

#### PngScanner

解析 PNG 图像格式：

*   **识别内容**：8字节签名 + 连续的 Chunk 结构
*   **Chunk 结构**：Length(4) + Type(4) + Data(n) + CRC32(4)
*   **关键块识别**：IHDR、IDAT、IEND 标记为 critical

#### JpegScanner

解析 JPEG 图像格式：

*   **识别内容**：SOI 标记 + 连续的 Segment 结构
*   **Segment 结构**：Marker(2) + Length(2) + Data(n-2)
*   **特殊处理**：SOF、DQT、DHT、SOS 等关键段

#### PcapScanner

解析 PCAP 网络抓包格式：

*   **识别内容**：Global Header + Packet Records
*   **字段映射**：`ts_sec`, `ts_usec`, `incl_len`, `orig_len`
*   **协议层解析**：Ethernet → IP → TCP/UDP

---

## 5. 结构变异器 (`StructureMutator`)

`StructureMutator` 提供静态方法用于结构感知变异。

### 5.1 整数溢出攻击

```java
// 预定义的危险整数值
public static final long[] EVIL_INTEGERS = {
    0L, 1L, -1L,
    0x7FL, 0x80L, 0xFFL,                    // 8-bit boundaries
    0x7FFFL, 0x8000L, 0xFFFFL,              // 16-bit boundaries
    0x7FFFFFFFL, 0x80000000L, 0xFFFFFFFFL,  // 32-bit boundaries
    0x7FFFFFFFFFFFFFFFL, 0x8000000000000000L, // 64-bit boundaries
    Integer.MAX_VALUE, Integer.MIN_VALUE,
    Long.MAX_VALUE, Long.MIN_VALUE
};
```

| 方法 | 描述 | 攻击目标 |
| :--- | :--- | :--- |
| `mutateLength` | 变异 LENGTH 字段 | Buffer Overflow/Over-read |
| `mutateOffset` | 变异 OFFSET 字段 | 越界读写、信息泄露 |
| `mutateCount` | 变异 COUNT 字段 | 内存耗尽、整数溢出 |
| `mutateFlags` | 变异 FLAGS 字段 | 逻辑错误、权限绕过 |

### 5.2 块操作

| 方法 | 描述 | 攻击效果 |
| :--- | :--- | :--- |
| `duplicateChunk` | 复制块 | 资源耗尽、状态混乱 |
| `deleteChunk` | 删除块 | 必需字段缺失错误 |
| `swapChunks` | 交换块位置 | 顺序依赖错误 |
| `clearChunkData` | 清空数据区 | 空数据处理错误 |

### 5.3 位级操作

```java
// 对块的数据区进行位翻转
public static byte[] bitFlipChunkData(byte[] data, BinaryChunk chunk, ThreadLocalRandom rand);

// 对指定范围进行随机字节替换
public static byte[] randomizeRegion(byte[] data, int start, int length, ThreadLocalRandom rand);

// 破坏 Magic 标识
public static byte[] corruptMagic(byte[] data, FieldMapping magicField, ThreadLocalRandom rand);
```

---

## 6. 约束修复器 (`ConstraintFixer`)

变异可能破坏文件的完整性约束，导致目标程序在早期检查阶段就拒绝处理。`ConstraintFixer` 用于修复这些约束，使畸形数据能够进入更深层的解析逻辑。

### 6.1 校验和修复

```java
// 修复单个 PNG 块的 CRC32
public static byte[] fixPngChunkCrc(byte[] data, int chunkStart);

// 修复所有 PNG 块的 CRC
public static byte[] fixAllPngCrcs(byte[] data);

// 修复 IP 头部校验和
public static byte[] fixIpChecksum(byte[] data, int ipHeaderOffset, int ihl);
```

### 6.2 长度字段修复

```java
// 更新 PNG 块的长度字段
public static byte[] fixPngChunkLength(byte[] data, int chunkStart, int newDataLength);

// 更新 PCAP 包记录的长度字段
public static byte[] fixPcapPacketLength(byte[] data, int packetHeaderOffset,
        int inclLen, int origLen, boolean bigEndian);

// 更新 ELF Section 的大小字段
public static byte[] fixElfSectionSize(byte[] data, int sectionHeaderOffset,
        long newSize, boolean is64Bit);
```

### 6.3 Magic 恢复

当变异意外破坏了文件签名时，使用以下方法恢复：

```java
public static byte[] restorePngMagic(byte[] data);  // 恢复 PNG 签名
public static byte[] restoreJpegMagic(byte[] data); // 恢复 JPEG SOI
public static byte[] restoreElfMagic(byte[] data);  // 恢复 ELF Magic
```

---

## 7. 使用示例

### 7.1 完整的 PNG 变异流程

```java
import edu.nju.fuzzing.mutate.binary.*;
import java.util.concurrent.ThreadLocalRandom;

public class PngFuzzer {
    
    public byte[] mutatePng(byte[] original) {
        ThreadLocalRandom rand = ThreadLocalRandom.current();
        
        // 1. 扫描文件结构
        PngScanner scanner = new PngScanner();
        if (!scanner.matches(original)) {
            return original;
        }
        ScanResult scanResult = scanner.scan(original);
        
        // 2. 选择变异策略
        byte[] mutated = original.clone();
        int strategy = rand.nextInt(5);
        
        switch (strategy) {
            case 0:
                // 变异 LENGTH 字段
                for (BinaryChunk chunk : scanResult.getChunks()) {
                    for (FieldMapping field : chunk.getFieldsByType(FieldType.LENGTH)) {
                        mutated = StructureMutator.mutateLength(mutated, field, rand);
                    }
                }
                break;
                
            case 1:
                // 复制非关键块
                var nonCritical = scanResult.getNonCriticalChunks();
                if (!nonCritical.isEmpty()) {
                    BinaryChunk target = nonCritical.get(rand.nextInt(nonCritical.size()));
                    mutated = StructureMutator.duplicateChunk(mutated, target, 3);
                }
                break;
                
            case 2:
                // 对数据区进行位翻转
                for (BinaryChunk chunk : scanResult.getChunks()) {
                    if (!chunk.isCritical()) {
                        mutated = StructureMutator.bitFlipChunkData(mutated, chunk, rand);
                    }
                }
                break;
                
            case 3:
                // 删除非关键块
                var deletable = scanResult.getNonCriticalChunks();
                if (!deletable.isEmpty()) {
                    BinaryChunk target = deletable.get(rand.nextInt(deletable.size()));
                    mutated = StructureMutator.deleteChunk(mutated, target);
                }
                break;
                
            default:
                // 随机化某个块的数据区
                if (!scanResult.getChunks().isEmpty()) {
                    BinaryChunk chunk = scanResult.getChunks().get(
                        rand.nextInt(scanResult.getChunks().size()));
                    int dataStart = chunk.getStartOffset() + chunk.getDataOffset();
                    mutated = StructureMutator.randomizeRegion(mutated, dataStart, 
                        chunk.getDataLength(), rand);
                }
        }
        
        // 3. 修复校验和
        mutated = ConstraintFixer.fixAllPngCrcs(mutated);
        
        return mutated;
    }
}
```

### 7.2 ELF 整数溢出攻击

```java
public byte[] attackElfHeaders(byte[] elfData) {
    ThreadLocalRandom rand = ThreadLocalRandom.current();
    
    ElfScanner scanner = new ElfScanner();
    ScanResult result = scanner.scan(elfData);
    
    byte[] mutated = elfData.clone();
    
    // 攻击所有 COUNT 字段
    for (FieldMapping field : result.getGlobalFields()) {
        if (field.getType() == FieldType.COUNT) {
            mutated = StructureMutator.mutateCount(mutated, field, rand);
        }
    }
    
    // 恢复 Magic 以通过初步检查
    mutated = ConstraintFixer.restoreElfMagic(mutated);
    
    return mutated;
}
```

---

## 8. 最佳实践

### 8.1 变异策略组合

推荐的变异策略权重分配：

| 策略类型 | 权重 | 理由 |
| :--- | :--- | :--- |
| LENGTH 变异 | 30% | 缓冲区溢出的主要触发点 |
| OFFSET 变异 | 25% | 越界读写的关键 |
| 块操作 | 20% | 状态机混乱 |
| 位翻转 | 15% | 底层解析错误 |
| COUNT 变异 | 10% | 内存分配问题 |

### 8.2 约束修复时机

```
变异操作 --> 90% 概率修复约束 --> 输出
                |
                +--> 10% 概率保持破坏 --> 输出 (测试严格校验)
```

### 8.3 与 Coverage 反馈结合

```java
// 当发现新覆盖时，优先使用结构感知变异
if (hasNewCoverage(seed)) {
    // 使用精细变异深入探索
    mutator = new StructureAwareMutator(scanner);
} else {
    // 使用暴力变异尝试突破
    mutator = new AflHavocMutator(corpus);
}
```

---

## 9. 扩展开发

### 9.1 添加新格式支持

1. 实现 `FormatScanner` 接口
2. 在 `scan()` 方法中解析文件结构，填充 `BinaryChunk` 和 `FieldMapping`
3. 在 `ConstraintFixer` 中添加对应的修复方法
4. 在 `MutatorFactory` 中注册新的变异器

### 9.2 自定义危险值集合

```java
// 针对特定目标的自定义危险值
public static final long[] CUSTOM_EVIL_VALUES = {
    0xCAFEBABE,     // Java Class Magic
    0xFEEDFACE,     // Mach-O Magic
    0x504B0304,     // ZIP Local File Header
    // ... 根据目标添加
};
```

---

## 10. 总结

二进制结构感知变异框架通过"理解"文件格式，实现了：

1. **精准攻击**：针对控制字段（长度、偏移、计数）进行变异
2. **深度渗透**：通过修复校验和等约束，使畸形数据能进入深层解析
3. **高效探索**：相比盲目变异，能更快地发现解析器漏洞

该框架与 `AflHavocMutator` 配合使用效果最佳：结构感知变异负责突破格式检查，Havoc 变异负责挖掘深层内存错误。
