# 开发日志（2026-01-08）- Mutate 二进制结构感知变异器

> 主题：二进制格式（PNG/ELF/JPEG/PCAP）的结构感知变异实现

---

## 1. 变更概览

### A. 扫描基础设施

目标：解析二进制格式，提取结构信息供变异使用。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/binary/FormatScanner.java](../../src/main/java/edu/nju/fuzzing/mutate/binary/FormatScanner.java)
  - 接口：`matches()` 检查 Magic Bytes，`scan()` 提取结构

- [src/main/java/edu/nju/fuzzing/mutate/binary/ScanResult.java](../../src/main/java/edu/nju/fuzzing/mutate/binary/ScanResult.java)
  - 结果：valid 标志、格式类型、chunks 列表、全局字段、字节序

- [src/main/java/edu/nju/fuzzing/mutate/binary/BinaryChunk.java](../../src/main/java/edu/nju/fuzzing/mutate/binary/BinaryChunk.java)
  - 块抽象：startOffset、totalLength、chunkType、rawData、fields、critical 标志

- [src/main/java/edu/nju/fuzzing/mutate/binary/FieldMapping.java](../../src/main/java/edu/nju/fuzzing/mutate/binary/FieldMapping.java)
  - 字段映射：offset、length、type、byteOrder、name、originalValue

- [src/main/java/edu/nju/fuzzing/mutate/binary/FieldType.java](../../src/main/java/edu/nju/fuzzing/mutate/binary/FieldType.java)
  - 类型枚举：LENGTH、OFFSET、COUNT、FLAGS、CHECKSUM、DATA、MAGIC、VERSION、TYPE

### B. StructureMutator 通用结构变异

目标：针对不同字段类型的智能变异。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/binary/StructureMutator.java](../../src/main/java/edu/nju/fuzzing/mutate/binary/StructureMutator.java)
  - 恶意值：`EVIL_INTEGERS`（溢出边界）、`EVIL_OFFSETS`（越界偏移）
  - 字段变异：`mutateLength`（整数溢出）、`mutateOffset`（OOB）、`mutateCount`（分配炸弹）、`mutateFlags`
  - 块操作：`duplicateChunk`、`deleteChunk`、`swapChunks`、`bitFlipChunkData`
  - ELF 特有：`mutateElfSectionType`、`mutateElfEntryPoint`、`mutateElfMachineType`、`createOverlappingSections`

- [src/main/java/edu/nju/fuzzing/mutate/binary/ConstraintFixer.java](../../src/main/java/edu/nju/fuzzing/mutate/binary/ConstraintFixer.java)
  - 可选修复：`fixPngCrc` 修复 CRC 校验和

### C. PNG 扫描与变异

目标：针对 PNG TLV 格式的结构感知变异。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/binary/PngScanner.java](../../src/main/java/edu/nju/fuzzing/mutate/binary/PngScanner.java)
  - TLV 解析：Length(4) + Type(4) + Data(N) + CRC(4)
  - 关键块识别：IHDR、IDAT、IEND

- [src/main/java/edu/nju/fuzzing/mutate/PngMutator.java](../../src/main/java/edu/nju/fuzzing/mutate/PngMutator.java)
  - 变异策略：长度变异、Chunk 删除/复制/交换、CRC 破坏
  - IHDR 攻击：无效 ColorType/BitDepth 组合、超大宽高
  - PLTE 攻击：超大调色板

### D. ELF 扫描与变异

目标：针对 ELF Offset 模式的结构感知变异。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/binary/ElfScanner.java](../../src/main/java/edu/nju/fuzzing/mutate/binary/ElfScanner.java)
  - Header 解析：32/64 位、字节序、e_phoff/e_shoff
  - Section/Program Header 解析

- [src/main/java/edu/nju/fuzzing/mutate/ElfMutator.java](../../src/main/java/edu/nju/fuzzing/mutate/ElfMutator.java)
  - 15 种变异策略：Offset 变异、Count 变异、Section 删除/复制、Header 位翻转
  - Flags/Type/Entry/Machine 变异、重叠 Section 创建
  - 95% 保护关键字段（Magic、Class、字节序标识）

### E. JPEG/PCAP 扫描与变异

落点：

- [src/main/java/edu/nju/fuzzing/mutate/binary/JpegScanner.java](../../src/main/java/edu/nju/fuzzing/mutate/binary/JpegScanner.java)
  - Segment 解析：SOI、APP0-15、DQT、DHT、SOF、SOS、EOI

- [src/main/java/edu/nju/fuzzing/mutate/JpegMutator.java](../../src/main/java/edu/nju/fuzzing/mutate/JpegMutator.java)
  - Marker 变异、Segment 长度篡改、Huffman 表破坏

- [src/main/java/edu/nju/fuzzing/mutate/binary/PcapScanner.java](../../src/main/java/edu/nju/fuzzing/mutate/binary/PcapScanner.java)
  - Global Header + Packet Records 解析

- [src/main/java/edu/nju/fuzzing/mutate/PcapMutator.java](../../src/main/java/edu/nju/fuzzing/mutate/PcapMutator.java)
  - 包长度变异、时间戳篡改、链路类型混淆

---

## 2. 设计决策

| 决策点 | 选择 | 理由 |
|--------|------|------|
| TLV vs Offset | 两种模式并存 | PNG/JPEG 适合 TLV，ELF 适合 Offset |
| 关键字段保护 | 95% 概率保护 | 允许变异进入深层解析 |
| CRC 修复 | 可选，默认不修复 | 两种路径都需要覆盖 |
| 恶意值选择 | 预定义边界值集合 | 高效触发整数溢出 |

---

## 3. 文件结构

```
src/main/java/edu/nju/fuzzing/mutate/
├── PngMutator.java
├── ElfMutator.java
├── JpegMutator.java
├── PcapMutator.java
└── binary/
    ├── FormatScanner.java
    ├── ScanResult.java
    ├── BinaryChunk.java
    ├── FieldMapping.java
    ├── FieldType.java
    ├── StructureMutator.java
    ├── ConstraintFixer.java
    ├── PngScanner.java
    ├── ElfScanner.java
    ├── JpegScanner.java
    └── PcapScanner.java
```

---

## 4. 后续规划

- [ ] 添加 PDF、PE/COFF 格式支持
- [ ] 基于覆盖反馈的自适应字段选择
- [ ] 智能 CRC 修复决策
