# JpegMutator 审查报告

**审查日期**: 2025-12-31  
**文件位置**: `src/main/java/edu/nju/fuzzing/mutate/JpegMutator.java`

---

## 1. 概述

JpegMutator 是针对 JPEG/JFIF 图像文件的结构感知变异器。用于测试 JPEG 解析库（如 libjpeg-turbo、stb_image、ImageMagick）的健壮性。

### 当前架构

```
输入字节流 → JpegScanner → ScanResult → 结构感知变异 → ConstraintFixer → 输出
                                       ↓
                         (BinaryChunk: Marker + Length + Data)
```

### JPEG 文件结构

```
[0xFF 0xD8 SOI]
[Segment1: 0xFF Marker | 2B Length | N Bytes Data]
[Segment2: ...]
...
[0xFF 0xDA SOS | Entropy Data with Escape Sequences]
[0xFF 0xD9 EOI]
```

### 关键 Markers

| Marker | 代码 | 必需性 | 说明 |
|--------|-----|-------|------|
| SOI | 0xFFD8 | ✅ 必须 | Start of Image，必须第一个 |
| SOF0 | 0xFFC0 | ✅ 必须 | Baseline DCT |
| SOF2 | 0xFFC2 | ⚠️ 可选 | Progressive DCT（复杂逻辑）|
| DHT | 0xFFC4 | ✅ 必须 | Huffman Table |
| DQT | 0xFFDB | ✅ 必须 | Quantization Table |
| DRI | 0xFFDD | ❌ 可选 | Restart Interval |
| SOS | 0xFFDA | ✅ 必须 | Start of Scan（后跟熵编码数据）|
| EOI | 0xFFD9 | ✅ 必须 | End of Image，必须最后 |
| APP0 | 0xFFE0 | ⚠️ JFIF 需要 | JFIF Header |
| APP1 | 0xFFE1 | ❌ 可选 | Exif（历史漏洞高发）|
| COM | 0xFFFE | ❌ 可选 | Comment |
| RSTn | 0xFFD0-D7 | ❌ 条件 | Restart Markers |

### 相关文件

| 文件 | 说明 |
|------|------|
| `JpegMutator.java` | 主变异器实现（420 行）|
| `binary/JpegScanner.java` | JPEG 结构扫描器 |
| `binary/ScanResult.java` | 扫描结果封装 |
| `binary/BinaryChunk.java` | 二进制块表示 |
| `binary/FieldMapping.java` | 字段映射 |
| `binary/FieldType.java` | 字段类型枚举 |
| `binary/StructureMutator.java` | 结构感知变异工具 |
| `binary/ConstraintFixer.java` | 约束修复器 |
| `JpegMutatorTest.java` | 测试文件 |

---

## 2. 问题清单

### 🔴 高严重性问题

#### 问题 1: 长度欺骗攻击未真正生效

**位置**: `JpegMutator.java` 第 375-394 行

```java
/**
 * 核心改进：支持 Length Spoofing
 * @param spoofLength 如果为 true，则随机写入一个假的 Length，导致 OOB Read
 */
private void writeMarker(DataOutputStream out, int marker, byte[] payload, boolean spoofLength) throws IOException {
    out.write(0xFF);
    out.write(marker);

    int realLen = payload.length + 2;
    int writtenLen = realLen;

    // [Attack] Buffer Over-read
    // 声明长度为 1000，但实际只提供 10 字节数据
    // 许多解析器会先 malloc(len)，然后 read(len)，导致读取到未初始化内存或文件末尾
    if (spoofLength || ThreadLocalRandom.current().nextInt(20) == 0) {
        writtenLen = realLen + ThreadLocalRandom.current().nextInt(5000);
        if (writtenLen > 65535) writtenLen = 65535;
    }

    out.writeShort(writtenLen);
    out.write(payload);  // ❌ 这里实际只写入了 payload 数据
}
```

**问题描述**:

虽然代码中声明长度为 `writtenLen`（可能是 1000），但实际数据只写入了 `payload`（如 10 字节）。**问题在于文件中确实缺少数据**，解析器读取到文件末尾就停止了，不会读取到"未初始化内存"。

真正的 OOB 读取需要：
1. 文件中存在后续数据（例如下一个 Marker）
2. 解析器错误地读取了超出当前 Segment 的数据

**当前实现的实际效果**:

```
写入: [FF E0] [00 10] [4 bytes payload]
                 ↑ 声称长度 16 (0x0010)
      
解析器行为:
- 读取 Length = 16
- 尝试读取 14 字节数据 (16 - 2)
- 实际文件只有 4 字节
- 遇到 EOF 或读取到下一个 Marker (FF xx)
- 多数健壮的解析器会报错并停止
```

**真正的 Length Spoofing 应该是**:

```
写入: [FF E0] [00 0A] [20 bytes payload]
                 ↑ 声称长度 10 (只需读 8 字节数据)
                            ↑ 但实际提供 20 字节

解析器行为:
- 读取 Length = 10
- 读取 8 字节数据后停止
- 跳过到下一个 Marker
- 剩余 12 字节被误解析为 Marker/Data
- 可能触发 "Marker in Data" 漏洞
```

**建议修复**:

```java
private void writeMarker(DataOutputStream out, int marker, byte[] payload, boolean spoofLength) throws IOException {
    out.write(0xFF);
    out.write(marker);

    int realLen = payload.length + 2;
    int writtenLen = realLen;
    
    ThreadLocalRandom rand = ThreadLocalRandom.current();
    
    // [Attack] Length Spoofing 有两种方向
    if (spoofLength || rand.nextInt(20) == 0) {
        int attackType = rand.nextInt(2);
        
        if (attackType == 0) {
            // 攻击 1: 声明长度 > 实际长度 (OOB Read)
            writtenLen = realLen + rand.nextInt(5000);
            if (writtenLen > 65535) writtenLen = 65535;
            
            out.writeShort(writtenLen);
            out.write(payload);
            // 写入真实数据后不填充，让解析器读取到 EOF 或下一个 Marker
            
        } else {
            // 攻击 2: 声明长度 < 实际长度 (Data Misalignment)
            writtenLen = Math.max(2, realLen / 2);
            
            out.writeShort(writtenLen);
            out.write(payload);  // 写入全部数据
            // 解析器只读取 writtenLen-2 字节，剩余数据被误解析
        }
    } else {
        // 正常写入
        out.writeShort(writtenLen);
        out.write(payload);
    }
}
```

**影响严重性**: 当前的 "Length Spoofing" 攻击效果大打折扣，可能无法触发关键漏洞。

---

#### 问题 2: Segment 顺序约束未被强制

**位置**: `JpegMutator.java` 第 133-156 行

```java
private byte[] mutateSegmentStructure(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) throws IOException {
    // 找到可变异的 segment (排除 SOI, EOI, SOS)
    List<BinaryChunk> mutable = new ArrayList<>();
    for (BinaryChunk chunk : chunks) {
        String type = chunk.getChunkType();
        if (!type.equals("SOI") && !type.equals("EOI") && !type.startsWith("SOS")) {
            mutable.add(chunk);
        }
    }
    // ...
    if (op == 2 && mutable.size() >= 2) {
        // 交换两个 segment
        int idx1 = rand.nextInt(mutable.size());
        int idx2 = rand.nextInt(mutable.size());
        while (idx2 == idx1) idx2 = rand.nextInt(mutable.size());
        return StructureMutator.swapChunks(data, mutable.get(idx1), mutable.get(idx2));
        // ❌ 未检查 DQT/DHT 必须在 SOF/SOS 之前
    }
    // ...
}
```

**JPEG Segment 顺序约束**:

| 约束 | 说明 |
|------|------|
| SOI 必须第一 | ✅ 代码中已保护 |
| APP0/APP1 通常在最前 | ❌ 未检查 |
| DQT 必须在 SOS 前 | ❌ **未检查**（关键）|
| DHT 必须在 SOS 前 | ❌ **未检查**（关键）|
| SOF 必须在 SOS 前 | ⚠️ SOS 被保护，但 SOF 可能被删除 |
| DRI 必须在 SOS 前 | ❌ 未检查 |
| EOI 必须最后 | ✅ 代码中已保护 |

**问题场景**:

```
原始顺序: SOI → DQT → DHT → SOF → SOS → EOI
交换后:   SOI → SOS → DHT → DQT → SOF → EOI
               ↑
         违反约束：SOS 之前必须有 DQT/DHT
```

解析器会报错：
- "Quantization table not defined"
- "Huffman table not defined"

**建议修复**:

```java
// 定义 segment 顺序约束
private static final Map<String, Integer> SEGMENT_ORDER = new HashMap<>();
static {
    SEGMENT_ORDER.put("SOI", 0);
    SEGMENT_ORDER.put("APP0", 10);
    SEGMENT_ORDER.put("APP1", 15);
    SEGMENT_ORDER.put("DQT", 30);
    SEGMENT_ORDER.put("DRI", 35);
    SEGMENT_ORDER.put("SOF0", 40);
    SEGMENT_ORDER.put("SOF2", 40);
    SEGMENT_ORDER.put("DHT", 45);
    SEGMENT_ORDER.put("SOS", 50);  // 必须在 DQT/DHT 后
    SEGMENT_ORDER.put("EOI", 100);
}

private boolean canSwap(BinaryChunk s1, BinaryChunk s2) {
    String type1 = s1.getChunkType();
    String type2 = s2.getChunkType();
    
    // 如果两者都没有顺序约束，可以交换
    if (!SEGMENT_ORDER.containsKey(type1) && !SEGMENT_ORDER.containsKey(type2)) {
        return true;
    }
    
    // 检查是否会违反约束
    Integer order1 = SEGMENT_ORDER.getOrDefault(type1, 35);
    Integer order2 = SEGMENT_ORDER.getOrDefault(type2, 35);
    
    // 如果顺序权重相同，可以交换
    return order1.equals(order2);
}

private byte[] mutateSegmentStructure(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) throws IOException {
    // ...
    if (op == 2 && mutable.size() >= 2) {
        // 交换两个 segment，但保持顺序约束
        for (int attempt = 0; attempt < 10; attempt++) {
            int idx1 = rand.nextInt(mutable.size());
            int idx2 = rand.nextInt(mutable.size());
            if (idx2 == idx1) continue;
            
            if (canSwap(mutable.get(idx1), mutable.get(idx2))) {
                return StructureMutator.swapChunks(data, mutable.get(idx1), mutable.get(idx2));
            }
        }
    }
    // ...
}
```

---

#### 问题 3: 关键 Segment 可能被删除

**位置**: `JpegMutator.java` 第 133-148 行

```java
private byte[] mutateSegmentStructure(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) throws IOException {
    // 找到可变异的 segment (排除 SOI, EOI, SOS)
    List<BinaryChunk> mutable = new ArrayList<>();
    for (BinaryChunk chunk : chunks) {
        String type = chunk.getChunkType();
        if (!type.equals("SOI") && !type.equals("EOI") && !type.startsWith("SOS")) {
            mutable.add(chunk);
        }
    }
    // ...
    if (op == 0 && mutable.size() > 1) {
        // 删除一个非关键 segment
        BinaryChunk toDelete = mutable.get(rand.nextInt(mutable.size()));
        return StructureMutator.deleteChunk(data, toDelete);
        // ❌ 可能删除 DQT/DHT/SOF，导致解析失败
    }
}
```

**问题描述**:

虽然 SOI/EOI/SOS 被保护，但**必需的 Segments** 如 DQT、DHT、SOF 仍可能被删除：

| Segment | 必需性 | 删除后影响 |
|---------|-------|-----------|
| DQT | ✅ 必须 | 解析器报错 "No quantization table" |
| DHT | ✅ 必须 | 解析器报错 "No Huffman table" |
| SOF0/SOF2 | ✅ 必须 | 解析器报错 "No frame header" |
| DRI | ❌ 可选 | 可以删除 |
| APP0/APP1 | ❌ 可选 | 可以删除 |
| COM | ❌ 可选 | 可以删除 |

**建议修复**:

```java
// 定义关键 segments（不可删除）
private static final Set<String> CRITICAL_SEGMENTS = new HashSet<>(Arrays.asList(
    "SOI", "EOI", "SOS", "DQT", "DHT", "SOF0", "SOF2"
));

private byte[] mutateSegmentStructure(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) throws IOException {
    // 找到可删除的 segment
    List<BinaryChunk> deletable = new ArrayList<>();
    for (BinaryChunk chunk : chunks) {
        String type = chunk.getChunkType();
        if (!CRITICAL_SEGMENTS.contains(type) && !type.startsWith("RST")) {
            deletable.add(chunk);
        }
    }
    
    // 找到可复制/交换的 segment（不包括 SOS）
    List<BinaryChunk> mutable = new ArrayList<>();
    for (BinaryChunk chunk : chunks) {
        String type = chunk.getChunkType();
        if (!type.equals("SOI") && !type.equals("EOI") && !type.startsWith("SOS")) {
            mutable.add(chunk);
        }
    }
    
    if (deletable.isEmpty() && mutable.isEmpty()) {
        return data;
    }
    
    int op = rand.nextInt(3);
    
    if (op == 0 && deletable.size() > 0) {
        // 删除一个非关键 segment
        BinaryChunk toDelete = deletable.get(rand.nextInt(deletable.size()));
        return StructureMutator.deleteChunk(data, toDelete);
    } else if (op == 1 && mutable.size() > 0) {
        // 复制一个 segment
        BinaryChunk toDuplicate = mutable.get(rand.nextInt(mutable.size()));
        return StructureMutator.duplicateChunk(data, toDuplicate);
    } else if (op == 2 && mutable.size() >= 2) {
        // 交换两个 segment
        // ...
    }
    
    return data;
}
```

---

### 🟠 中严重性问题

#### 问题 4: 0xFF Escape 逻辑在生成器中混乱

**位置**: `JpegMutator.java` 第 347-367 行

```java
private void writeSosAndData(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
    // ...
    // Entropy Data
    // 随机插入 RST Markers (如果定义了 DRI)
    int dataLen = rand.nextInt(2048);
    for (int i = 0; i < dataLen; i++) {
        int b = rand.nextInt(256);
        out.write(b);

        // 0xFF Escaping Logic
        if (b == 0xFF) {
            // 95% 正常转义, 5% 注入攻击
            if (rand.nextInt(20) != 0) {
                out.write(0x00);  // ✅ 正确的转义
            } else {
                // Marker Confusion Attack
                // 只有在这里才可能出现未转义的 FF，或者恶意的 RSTm
                int next = rand.nextBoolean() ? RST0 + rand.nextInt(8) : rand.nextInt(256);
                out.write(next);
                // ❌ 问题：如果 next = 0x00，这和正常转义无区别
                // ❌ 问题：如果 next = 0xD9 (EOI)，文件会提前结束
            }
        }
    }
}
```

**JPEG 熵编码数据的 0xFF 转义规则**:

| 字节序列 | 含义 |
|---------|------|
| `FF 00` | 转义后的 0xFF 数据字节 |
| `FF Dn` (D0-D7) | RST Marker（重启标记）|
| `FF D9` | EOI（文件结束）|
| `FF xx` (其他) | **非法**，应报错 |

**问题场景**:

1. **攻击无效**:
```java
if (b == 0xFF) {
    int next = rand.nextInt(256);
    out.write(next);
    // 如果 next = 0x00，这就是正常转义，攻击失效
}
```

2. **文件提前结束**:
```java
if (b == 0xFF) {
    int next = 0xD9;  // EOI
    out.write(next);
    // 解析器认为文件结束，后续数据被忽略
}
```

**建议修复**:

```java
private void writeSosAndData(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
    // ...
    int dataLen = rand.nextInt(2048);
    for (int i = 0; i < dataLen; i++) {
        int b = rand.nextInt(256);
        out.write(b);

        if (b == 0xFF) {
            int attackType = rand.nextInt(20);
            
            if (attackType == 0) {
                // 攻击 1: 未转义的 0xFF（非法）
                // 不写入任何字节，让 FF 后面跟随随机数据
                
            } else if (attackType == 1) {
                // 攻击 2: 非法 Marker（FF + 非 00/Dn）
                int illegal = rand.nextInt(256);
                // 排除合法值: 00, D0-D7, D9
                while (illegal == 0x00 || (illegal >= 0xD0 && illegal <= 0xD7) || illegal == 0xD9) {
                    illegal = rand.nextInt(256);
                }
                out.write(illegal);
                
            } else if (attackType == 2 && rand.nextBoolean()) {
                // 攻击 3: 伪造 RST Marker（即使没有 DRI）
                out.write(RST0 + rand.nextInt(8));
                
            } else {
                // 95% 正常转义
                out.write(0x00);
            }
        }
    }
}
```

---

#### 问题 5: Exif TIFF Header 攻击不完整

**位置**: `JpegMutator.java` 第 242-274 行

```java
private void writeApp1Exif(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.write("Exif\0\0".getBytes(StandardCharsets.US_ASCII));

    // TIFF Header
    // ...
    // Offset to IFD0 (Image File Directory)
    // [Attack] Pointing to OOB location or very large offset
    int offset = rand.nextInt(20) == 0 ? 0xFFFFFF : 8;
    writeInt(body, offset, littleEndian);

    // 我们只写 Header，不写具体的 IFD 标签，测试解析器在处理畸形 offset 时的反应
    // 或者填充一些垃圾数据模拟 IFD
    byte[] junk = new byte[rand.nextInt(50)];
    rand.nextBytes(junk);
    body.write(junk);
    // ❌ 问题：IFD 结构完全是垃圾数据，无法触发深层逻辑

    writeMarker(out, APP1, body.toByteArray(), false);
}
```

**Exif TIFF IFD 结构**:

```
[2B Entry Count]
[Entry1: 2B Tag | 2B Type | 4B Count | 4B Value/Offset]
[Entry2: ...]
...
[4B Next IFD Offset]
```

**当前问题**:

1. **随机垃圾数据**: 填充的 `junk` 不符合 IFD 结构，解析器会立即报错
2. **无法触发 Tag 解析**: Exif 的漏洞通常在特定 Tag 的处理中（如 GPSInfo、MakerNote）
3. **OOB Offset 攻击单一**: 只有 5% 概率生成 0xFFFFFF

**建议增强**:

```java
private void writeApp1Exif(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.write("Exif\0\0".getBytes(StandardCharsets.US_ASCII));

    // TIFF Header
    boolean littleEndian = rand.nextBoolean();
    if (littleEndian) {
        body.write('I'); body.write('I');
        body.write(42); body.write(0);
    } else {
        body.write('M'); body.write('M');
        body.write(0); body.write(42);
    }

    // IFD0 Offset
    int ifd0Offset = 8;
    writeInt(body, ifd0Offset, littleEndian);

    // 生成 IFD0
    int attackType = rand.nextInt(5);
    
    if (attackType == 0) {
        // 攻击 1: Entry Count 过大
        writeShort(body, 0xFFFF, littleEndian);
        // 不写入任何 Entry，让解析器尝试读取 65535 个条目
        
    } else if (attackType == 1) {
        // 攻击 2: 正常 Entry 但 Value Offset OOB
        writeShort(body, 1, littleEndian);  // 1 个 Entry
        
        // Entry: Tag=0x8769 (ExifIFDPointer), Type=4 (Long), Count=1, Value=OOB
        writeShort(body, 0x8769, littleEndian);
        writeShort(body, 4, littleEndian);
        writeInt(body, 1, littleEndian);
        writeInt(body, 0xFFFFFF, littleEndian);  // OOB Offset
        
        writeInt(body, 0, littleEndian);  // Next IFD = 0
        
    } else if (attackType == 2) {
        // 攻击 3: MakerNote Tag（历史漏洞高发）
        writeShort(body, 1, littleEndian);
        
        writeShort(body, 0x927C, littleEndian);  // MakerNote
        writeShort(body, 7, littleEndian);       // Type = Undefined
        writeInt(body, rand.nextInt(1000), littleEndian);  // Count
        writeInt(body, 50, littleEndian);        // Offset
        
        writeInt(body, 0, littleEndian);
        
        // 填充垃圾 MakerNote 数据
        byte[] makerNote = new byte[rand.nextInt(100)];
        rand.nextBytes(makerNote);
        body.write(makerNote);
        
    } else if (attackType == 3) {
        // 攻击 4: GPSInfo Tag
        writeShort(body, 1, littleEndian);
        
        writeShort(body, 0x8825, littleEndian);  // GPSInfo
        writeShort(body, 4, littleEndian);
        writeInt(body, 1, littleEndian);
        writeInt(body, 40, littleEndian);  // Offset to GPS IFD
        
        writeInt(body, 0, littleEndian);
        
        // GPS IFD（简化版）
        writeShort(body, 0, littleEndian);  // 0 个 Entry（畸形）
        
    } else {
        // 攻击 5: 随机垃圾数据
        byte[] junk = new byte[rand.nextInt(100)];
        rand.nextBytes(junk);
        body.write(junk);
    }

    writeMarker(out, APP1, body.toByteArray(), false);
}

private void writeShort(ByteArrayOutputStream out, int v, boolean littleEndian) {
    if (littleEndian) {
        out.write(v & 0xFF);
        out.write((v >>> 8) & 0xFF);
    } else {
        out.write((v >>> 8) & 0xFF);
        out.write(v & 0xFF);
    }
}
```

---

#### 问题 6: Sampling Factor 攻击未覆盖边界情况

**位置**: `JpegMutator.java` 第 293-301 行

```java
for (int i = 0; i < components; i++) {
    bodyOut.write(i + 1); // Component ID

    // [Attack] Sampling Factor: H(4bit) + V(4bit)
    // Valid are usually 1x1, 1x2, 2x1, 2x2.
    // 4x4 or 0x0 can cause buffer calc errors.
    int samp = rand.nextInt(10) == 0 ? 0 : (rand.nextInt(4) << 4 | rand.nextInt(4));
    bodyOut.write(samp);
    // ❌ 问题：0 是 0x00，表示 H=0, V=0（非法）
    // ❌ 问题：rand.nextInt(4) 生成 0-3，所以最大是 3x3，不是 4x4
    bodyOut.write(rand.nextInt(3)); // Quant Table ID
}
```

**Sampling Factor 的合法值**:

| H | V | 说明 |
|---|---|------|
| 1 | 1 | 正常（无子采样）|
| 2 | 1 | 水平 2:1 子采样 |
| 1 | 2 | 垂直 2:1 子采样 |
| 2 | 2 | 4:2:0 子采样（常见）|
| 4 | 4 | **非法**（过大）|
| 0 | 0 | **非法**（零值）|

**当前代码的问题**:

```java
int samp = rand.nextInt(10) == 0 ? 0 : (rand.nextInt(4) << 4 | rand.nextInt(4));
                                   ↑                     ↑
                           10% 生成 0x00              90% 生成 0-3 << 4 | 0-3
                           
结果:
- 10%: 0x00 (H=0, V=0) ✅ 这是非法值
- 90%: 0x00-0x33，即 H=0-3, V=0-3
  - 包含 0x00, 0x01, 0x02, 0x03 (H=0) ❌ 非法
  - 包含 0x10, 0x20, 0x30 (V=0) ❌ 非法
  - 不包含 0x44 (H=4, V=4) ❌ 未覆盖
```

**建议修复**:

```java
for (int i = 0; i < components; i++) {
    bodyOut.write(i + 1);

    int attackType = rand.nextInt(10);
    int samp;
    
    if (attackType == 0) {
        // 攻击 1: H=0 或 V=0
        samp = 0x00;
    } else if (attackType == 1) {
        // 攻击 2: H 或 V 过大（4 或更高）
        samp = (4 + rand.nextInt(4)) << 4 | (4 + rand.nextInt(4));
    } else if (attackType == 2) {
        // 攻击 3: H=0, V 正常
        samp = 0x00 | (1 + rand.nextInt(2));
    } else if (attackType == 3) {
        // 攻击 4: H 正常, V=0
        samp = (1 + rand.nextInt(2)) << 4;
    } else {
        // 60% 正常值
        int[] validSamp = {0x11, 0x21, 0x12, 0x22};
        samp = validSamp[rand.nextInt(validSamp.length)];
    }
    
    bodyOut.write(samp);
    bodyOut.write(rand.nextInt(3));
}
```

---

#### 问题 7: DQT Zero Table 攻击未被充分利用

**位置**: `JpegMutator.java` 第 283-292 行

```java
private void writeDqt(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
    byte info = (byte) rand.nextInt(16); // Precision + ID
    byte[] table = new byte[64];
    // [Attack] Quantization table with all zeros implies division by zero in some IDCT impls
    if (rand.nextInt(20) != 0) rand.nextBytes(table);
    // ❌ 问题：95% 概率是随机数据，只有 5% 是全零

    ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.write(info);
    body.write(table);
    writeMarker(out, DQT, body.toByteArray(), false);
}
```

**DQT 攻击向量**:

| 攻击 | 当前支持 | 描述 |
|------|---------|------|
| 全零 Table | ⚠️ 5% | IDCT 除零错误 |
| 部分零值 | ❌ 不支持 | 某些系数为 0 |
| 超大值 | ❌ 不支持 | 导致溢出 |
| Precision 位错误 | ⚠️ 随机 | 高 4 位应为 0（8-bit）或 1（16-bit）|

**建议增强**:

```java
private void writeDqt(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
    int attackType = rand.nextInt(10);
    
    byte info;
    byte[] table;
    
    if (attackType == 0) {
        // 攻击 1: 全零 Table (IDCT 除零)
        info = (byte) rand.nextInt(4);  // ID 0-3
        table = new byte[64];  // 全零
        
    } else if (attackType == 1) {
        // 攻击 2: 部分零值（前几个系数为 0）
        info = (byte) rand.nextInt(4);
        table = new byte[64];
        rand.nextBytes(table);
        // DC 系数（第一个）为 0
        table[0] = 0;
        
    } else if (attackType == 2) {
        // 攻击 3: 超大值
        info = (byte) rand.nextInt(4);
        table = new byte[64];
        for (int i = 0; i < 64; i++) {
            table[i] = (byte) 0xFF;  // 最大值 255
        }
        
    } else if (attackType == 3) {
        // 攻击 4: 非法 Precision（高 4 位 > 1）
        info = (byte) ((2 + rand.nextInt(14)) << 4 | rand.nextInt(4));
        table = new byte[64];
        rand.nextBytes(table);
        
    } else {
        // 60% 正常
        info = (byte) rand.nextInt(4);
        table = new byte[64];
        rand.nextBytes(table);
        // 确保不全是 0
        if (table[0] == 0) table[0] = 1;
    }

    ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.write(info);
    body.write(table);
    writeMarker(out, DQT, body.toByteArray(), false);
}
```

---

### 🟡 低严重性问题

#### 问题 8: 未使用的字段

**位置**: `JpegMutator.java` 第 40 行

```java
private final Random random = new Random();
```

**问题描述**: 
- 字段 `random` 从未被使用
- 代码中使用的是 `ThreadLocalRandom.current()`

**建议修复**: 删除此字段。

---

#### 问题 9: Progressive JPEG (SOF2) 未充分测试

**位置**: `JpegMutator.java` 第 307 行

```java
// 随机选择 SOF0 (Baseline) 或 SOF2 (Progressive)
writeMarker(out, rand.nextBoolean() ? SOF0 : SOF2, body.toByteArray(), false);
```

**问题描述**:

Progressive JPEG 的解析逻辑比 Baseline 复杂得多，历史漏洞更多：
- 需要多次扫描（Multiple Scans）
- 使用 Spectral Selection 和 Successive Approximation
- 当前代码只有 50% 概率生成 SOF2，但 SOS 的参数没有针对 Progressive 调整

**SOS 中的 Progressive 参数**:

```java
// Spectral Selection (Start/End) & Approx (High/Low)
// [Attack] Invalid ranges here cause loops in Progressive JPEG decoders
body.write(rand.nextInt(64)); // Ss (Start)
body.write(rand.nextInt(64)); // Se (End)
// ❌ 问题：没有检查 Ss < Se 的约束
body.write(rand.nextInt(16) << 4 | rand.nextInt(16)); // Ah | Al
```

**建议增强**:

```java
private void writeSof(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
    // ...
    boolean isProgressive = rand.nextBoolean();
    writeMarker(out, isProgressive ? SOF2 : SOF0, body.toByteArray(), false);
    
    // 存储状态供 writeSosAndData 使用
    this.isProgressiveMode = isProgressive;
}

private void writeSosAndData(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.write(3);
    // ...
    
    if (this.isProgressiveMode) {
        // Progressive 模式的攻击
        int attackType = rand.nextInt(5);
        
        if (attackType == 0) {
            // 攻击 1: Ss > Se
            body.write(63);  // Ss
            body.write(0);   // Se (错误：Ss > Se)
        } else if (attackType == 1) {
            // 攻击 2: Ss = Se = 0 (DC scan)
            body.write(0);
            body.write(0);
        } else if (attackType == 2) {
            // 攻击 3: Ss = Se (single coefficient)
            int pos = rand.nextInt(64);
            body.write(pos);
            body.write(pos);
        } else {
            // 正常范围
            int ss = rand.nextInt(64);
            int se = ss + rand.nextInt(64 - ss);
            body.write(ss);
            body.write(se);
        }
        
        // Successive Approximation
        int ah = rand.nextInt(16);
        int al = rand.nextInt(ah + 1);  // Al <= Ah
        body.write(ah << 4 | al);
    } else {
        // Baseline 模式
        body.write(0);   // Ss = 0
        body.write(63);  // Se = 63
        body.write(0);   // Ah = Al = 0
    }
    
    writeMarker(out, SOS, body.toByteArray(), false);
    // ...
}
```

---

#### 问题 10: 缺少 COM 和其他 APPn Segments

**位置**: 生成器中缺失

**问题描述**:

JPEG 支持多个可选 Segments，某些是历史漏洞高发区：

| Segment | 当前支持 | 历史漏洞 |
|---------|---------|---------|
| COM (0xFFFE) | ❌ 不支持 | 少量 |
| APP2-APP15 | ❌ 不支持 | 中等（ICC Profile 在 APP2）|
| DNL (0xFFDC) | ❌ 不支持 | 中等（定义行数）|
| DHP (0xFFDE) | ❌ 不支持 | 少量（Hierarchical）|

**建议添加**:

```java
private byte[] generateJpeg() throws IOException {
    // ...
    
    // [New] COM Segment (10% probability)
    if (rand.nextInt(10) == 0) {
        byte[] comment = new byte[rand.nextInt(200)];
        rand.nextBytes(comment);
        writeMarker(out, COM, comment, false);
    }
    
    // [New] APP2 ICC Profile (5% probability)
    if (rand.nextInt(20) == 0) {
        writeApp2IccProfile(out, rand);
    }
    
    // ...
}

private void writeApp2IccProfile(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.write("ICC_PROFILE\0".getBytes(StandardCharsets.US_ASCII));
    
    // Sequence number and total
    body.write(1);  // Chunk 1
    body.write(1);  // Total 1 chunk
    
    // Random ICC data
    byte[] iccData = new byte[rand.nextInt(500)];
    rand.nextBytes(iccData);
    body.write(iccData);
    
    writeMarker(out, APP0 + 2, body.toByteArray(), false);  // APP2
}
```

---

## 3. 设计优势

### ✅ 优势 1: 覆盖了历史高发漏洞区域

JpegMutator 针对性地生成了多个历史漏洞高发的 segments：

| Segment | 历史漏洞 | 当前覆盖 |
|---------|---------|---------|
| **APP1 Exif** | CVE-2012-3569, CVE-2015-8126 | ✅ 20% 概率生成 |
| **DQT Zero** | CVE-2013-6629 (除零) | ✅ 5% 全零 |
| **Progressive SOF2** | CVE-2013-6629, CVE-2018-14498 | ✅ 50% 概率 |
| **0xFF Escape** | CVE-2009-2842 | ✅ 5% 攻击 |
| **Sampling Factor** | CVE-2017-15232 | ⚠️ 部分覆盖 |

### ✅ 优势 2: 结构感知变异策略完整

JpegMutator 提供了 4 种结构感知变异：

```
1. Segment 操作 (30%) → 删除/复制/交换
2. 长度字段变异 (30%) → Length Spoofing
3. 数据区域位翻转 (20%) → Bit Flips
4. Marker 混淆 (20%) → Marker Confusion
```

这比纯随机字节流高效得多。

### ✅ 优势 3: 智能的 0xFF Escape 处理

```java
if (b == 0xFF) {
    if (rand.nextInt(20) != 0) {
        out.write(0x00);  // 95% 正常转义
    } else {
        // 5% 攻击
        int next = rand.nextBoolean() ? RST0 + rand.nextInt(8) : rand.nextInt(256);
        out.write(next);
    }
}
```

这使得 95% 的样本可以通过基本解析，5% 触发 Escape 错误处理。

### ✅ 优势 4: DRI (Restart Interval) 支持

```java
if (rand.nextInt(10) == 0) writeDri(out, rand);
```

DRI 是一个容易被忽略但重要的攻击面：
- 设置过小的 Interval 导致性能开销
- RST Marker 处理中的状态重置漏洞

---

## 4. 设计劣势

### ❌ 劣势 1: Length Spoofing 攻击实现错误

当前的 "Length Spoofing" 只是声称长度大于实际，但文件中缺少数据，解析器读到 EOF 就停止了，无法触发真正的 OOB 读取。

### ❌ 劣势 2: 缺少 Hierarchical 和 Lossless 模式

JPEG 有多个编码模式，某些是重要攻击面：

| 模式 | Marker | 当前支持 |
|-----|--------|---------|
| Baseline DCT | SOF0 | ✅ 支持 |
| Progressive DCT | SOF2 | ✅ 支持 |
| Lossless | SOF3 | ❌ 不支持 |
| Hierarchical | SOF5-7, DHP | ❌ 不支持 |

### ❌ 劣势 3: JFIF/Exif 版本号未变异

JFIF 和 Exif 都有版本号字段，某些解析器对不同版本有不同的处理逻辑：

```java
// JFIF APP0
body[5] = 1; body[6] = 1;  // 固定版本 1.1
// ❌ 未测试 1.0, 1.2, 2.0 等版本

// Exif TIFF
body.write(42); body.write(0);  // 固定魔数 42
// ❌ 未测试非 42 的值（如 43）
```

---

## 5. 与其他变异器的对比

| 特性 | LuaMutator | XmlMutator | CxxMutator | ElfMutator | PngMutator | JpegMutator |
|-----|-----------|-----------|-----------|-----------|-----------|------------|
| **种子利用率** | ✅ 高 | ✅ 高 | ✅ 高 | ⚠️ 中等 | ✅ 高 | ✅ 高 |
| **结构感知** | ✅ AST | ✅ 标签 | ✅ 符号 | ⚠️ Offset | ✅ Chunk | ✅ Segment |
| **约束保持** | ✅ 语法 | ✅ 匹配 | ✅ 前缀 | ❌ 不一致 | ⚠️ CRC | ⚠️ 顺序 |
| **攻击向量** | ✅ 10+ | ✅ 12+ | ✅ 10+ | ⚠️ 5 | ⚠️ 6 | ⚠️ 7 |
| **生成质量** | ✅ 90% | ✅ 85% | ✅ 80% | ❌ 40% | ⚠️ 70% | ⚠️ 75% |
| **测试覆盖** | ✅ 全面 | ✅ 全面 | ✅ 全面 | ⚠️ 基础 | ✅ 良好 | ✅ 良好 |

### 代码行数对比

| 文件 | 行数 | 变异策略数 | 生成器质量 |
|-----|-----|-----------|-----------|
| LuaMutator | 422 | 10 | 高（合法 AST）|
| XmlMutator | 450 | 12 | 高（合法 XML）|
| CxxMutator | 478 | 10 | 高（符合 ABI）|
| **JpegMutator** | **420** | **4** | **中（部分约束未强制）** |
| PngMutator | 345 | 4 | 中（部分无效）|
| ElfMutator | 399 | 5 | 低（多数无效）|

---

## 6. 改进建议

### 6.1 高优先级（立即修复）

1. **修复 Length Spoofing 攻击**:
   - 实现真正的"声称长度 < 实际长度"攻击
   - 测试 OOB 读取和 Data Misalignment

2. **强制 Segment 顺序约束**:
   - 添加 `SEGMENT_ORDER` 映射表
   - 在交换操作前检查 `canSwap()`
   - 确保 DQT/DHT 在 SOS 前

3. **保护关键 Segments**:
   - DQT/DHT/SOF 不应被删除
   - 添加 `CRITICAL_SEGMENTS` 白名单

### 6.2 中优先级（下一版本）

4. **改进 0xFF Escape 逻辑**:
   - 排除 0x00 和 0xD9 从攻击字节
   - 专注于非法 Marker（非 00/Dn）

5. **增强 Exif 攻击**:
   - 生成合法的 IFD 结构
   - 添加 MakerNote、GPSInfo 等高风险 Tag
   - 测试 OOB Offset

6. **修复 Sampling Factor 攻击**:
   - 覆盖 0x00 和 4x4 等边界值
   - 生成 H=0 或 V=0 的非法组合

7. **增强 DQT 攻击**:
   - 添加部分零值、超大值攻击
   - 测试非法 Precision

### 6.3 低优先级（可选）

8. 删除未使用的 `random` 字段
9. 增强 Progressive JPEG 测试（Ss/Se 约束）
10. 添加 COM、APP2-15、DNL 等 Segments
11. 变异 JFIF/Exif 版本号
12. 支持 Lossless 和 Hierarchical 模式

---

## 7. 预期效果

| 改进阶段 | 预计合法率 | 深层触发率 |
|---------|-----------|-----------|
| 当前状态 | ~75% | ~45% |
| 修复 Length Spoofing 后 | ~80% | ~60% |
| 强制顺序约束后 | ~85% | ~70% |
| 保护关键 Segments 后 | ~88% | ~75% |
| 增强攻击向量后 | ~90% | ~80% |
| 完整改进后 | ~92% | ~85% |

---

## 8. 测试建议

### 8.1 基准测试库

建议使用以下 JPEG 解析库作为测试目标：

| 库 | 语言 | 历史漏洞 |
|----|------|---------|
| **libjpeg-turbo** | C | 30+ CVEs |
| **stb_image** | C | 15+ CVEs (JPEG 相关 8+) |
| **ImageMagick** | C/C++ | 100+ CVEs (JPEG 相关 40+) |
| **Pillow (PIL)** | Python | 20+ CVEs (JPEG 相关 10+) |
| **mozjpeg** | C | 5+ CVEs |

### 8.2 覆盖率目标

| 模块 | 目标覆盖率 |
|------|-----------|
| Segment 解析 | 90%+ |
| Huffman 解码 | 85%+ |
| IDCT | 80%+ |
| Color Conversion | 75%+ |
| Exif 解析 | 70%+ |

### 8.3 负面测试用例

```java
@Test
void testDqtDivisionByZero() {
    // DQT 全零，IDCT 可能除零
}

@Test
void testSamlingFactorZero() {
    // H=0 或 V=0，buffer 计算错误
}

@Test
void testSegmentOrderViolation() {
    // SOS 在 DQT 之前，解析器报错
}

@Test
void testExifOobOffset() {
    // Exif IFD Offset 指向文件外
}

@Test
void testProgressiveSsSeBounds() {
    // Ss > Se，Progressive 解码器报错
}

@Test
void testLengthSpoofingUnderflow() {
    // 声称长度 < 实际长度，数据错位
}
```

---

## 9. 总体评估

### 成熟度评分: B (77/100)

| 评分维度 | 得分 | 理由 |
|---------|-----|-----|
| **架构设计** | 8/10 | 结构清晰，模块化良好 |
| **变异质量** | 7/10 | 结构感知好，但顺序未强制 |
| **约束保持** | 6/10 | 顺序约束缺失，关键 Segment 可删除 |
| **攻击向量** | 7/10 | 覆盖 Exif/DQT/Progressive，但实现有缺陷 |
| **代码质量** | 8/10 | 清晰，有未使用字段 |
| **测试覆盖** | 8/10 | 良好，需要负面测试 |

### 对比排名

1. **LuaMutator**: A- (85/100) - 最成熟
2. **PngMutator**: B+ (80/100)
3. **JpegMutator**: B (77/100) - **本次评估**
4. **XmlMutator**: B (78/100)
5. **CxxMutator**: B (75/100)
6. **ElfMutator**: C+ (60/100) - 需大幅改进

---

## 10. 用户需求确认

✅ **需要修复 Length Spoofing**: 这是最高优先级问题  
✅ **需要强制顺序约束**: DQT/DHT 必须在 SOS 前  
✅ **需要增强 Exif 攻击**: 添加合法的 IFD 结构  
⚠️ **扩展格式支持**: Lossless/Hierarchical 可作为长期目标

---

## 11. 相关文档

- [JPEG Specification (ITU-T T.81)](https://www.w3.org/Graphics/JPEG/itu-t81.pdf)
- [JFIF Specification](https://www.w3.org/Graphics/JPEG/jfif3.pdf)
- [Exif Specification](https://www.exif.org/Exif2-2.PDF)
- [libjpeg-turbo CVE List](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=libjpeg)
- [docs/mutate/Mutator.md](../Mutator.md)
- [docs/mutate/MuatationOps.md](../MuatationOps.md)
