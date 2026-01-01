package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.binary.*;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 结构感知型 JPEG 变异器
 *
 * 使用 JpegScanner 解析 seed 数据，提取 marker segment 结构，
 * 然后通过 StructureMutator 进行有针对性的变异：
 * 1. 长度字段变异 (真正的 Length Spoofing)
 * 2. Segment 删除/复制/交换 (遵守顺序约束)
 * 3. 数据区域位翻转
 * 4. Marker 混淆攻击
 * 5. Exif IFD 结构攻击
 * 6. Progressive JPEG 特殊攻击
 * 7. Hierarchical/Lossless 模式支持
 * 
 * 保留生成模式作为回退
 * 
 * 历史漏洞覆盖:
 * - CVE-2012-3569, CVE-2015-8126 (APP1 Exif)
 * - CVE-2013-6629 (DQT 零值除零)
 * - CVE-2018-14498 (Progressive SOF2)
 * - CVE-2009-2842 (0xFF Escape)
 * - CVE-2017-15232 (Sampling Factor)
 */
public class JpegMutator implements Mutator {

    // Markers
    private static final int SOI = 0xD8;
    private static final int EOI = 0xD9;
    private static final int SOS = 0xDA;
    private static final int DQT = 0xDB;
    private static final int DRI = 0xDD; // Define Restart Interval
    private static final int DNL = 0xDC; // Define Number of Lines
    private static final int SOF0 = 0xC0; // Baseline DCT
    private static final int SOF1 = 0xC1; // Extended Sequential DCT
    private static final int SOF2 = 0xC2; // Progressive DCT
    private static final int SOF3 = 0xC3; // Lossless (非DCT)
    private static final int SOF5 = 0xC5; // Differential Sequential DCT
    private static final int SOF6 = 0xC6; // Differential Progressive DCT
    private static final int SOF7 = 0xC7; // Differential Lossless
    private static final int DHP = 0xDE; // Define Hierarchical Progression
    private static final int DHT = 0xC4;
    private static final int COM = 0xFE;
    private static final int APP0 = 0xE0; // JFIF
    private static final int APP1 = 0xE1; // Exif (High Risk)
    private static final int APP2 = 0xE2; // ICC Profile
    private static final int RST0 = 0xD0; // Restart markers D0-D7

    private static final int[] EVIL_DIMS = {
            0, 1, 8, 10000, 32768, 65535, 65536 // 0 and 65536 are classic edges
    };

    // Segment 顺序约束 (遵守 JPEG 规范)
    private static final Map<String, Integer> SEGMENT_ORDER = new HashMap<>();
    static {
        SEGMENT_ORDER.put("SOI", 0);
        SEGMENT_ORDER.put("APP0", 10);
        SEGMENT_ORDER.put("APP1", 10);
        SEGMENT_ORDER.put("APP2", 10);
        SEGMENT_ORDER.put("APP3", 10);
        SEGMENT_ORDER.put("APP4", 10);
        SEGMENT_ORDER.put("APP5", 10);
        SEGMENT_ORDER.put("COM", 15);
        SEGMENT_ORDER.put("DQT", 20);
        SEGMENT_ORDER.put("DHT", 30);
        SEGMENT_ORDER.put("DRI", 35);
        SEGMENT_ORDER.put("DHP", 38); // Hierarchical
        SEGMENT_ORDER.put("DNL", 39); // Number of Lines
        SEGMENT_ORDER.put("SOF0", 40);
        SEGMENT_ORDER.put("SOF1", 40);
        SEGMENT_ORDER.put("SOF2", 40);
        SEGMENT_ORDER.put("SOF3", 40);
        SEGMENT_ORDER.put("SOF5", 40);
        SEGMENT_ORDER.put("SOF6", 40);
        SEGMENT_ORDER.put("SOF7", 40);
        SEGMENT_ORDER.put("SOS", 50);
        SEGMENT_ORDER.put("SCAN_DATA", 55);
        SEGMENT_ORDER.put("EOI", 100);
    }

    // 关键 Segments（不可删除，否则会导致解析器直接报错而非深入处理）
    private static final Set<String> CRITICAL_SEGMENTS = new HashSet<>(Arrays.asList(
            "SOI", "EOI", "SOS", "DQT", "DHT", "SOF0", "SOF1", "SOF2", "SOF3", "SOF5", "SOF6", "SOF7"));

    // 高风险 Exif Tags（历史漏洞高发）
    private static final int[] DANGEROUS_EXIF_TAGS = {
            0x8769, // ExifIFDPointer
            0x8825, // GPSInfoIFDPointer
            0xA005, // InteroperabilityIFDPointer
            0x927C, // MakerNote (厂商私有，解析复杂)
            0x9286, // UserComment
            0x0201, // JPEGInterchangeFormat (thumbnail offset)
            0x0202, // JPEGInterchangeFormatLength
            0x0103, // Compression
            0x0111, // StripOffsets
            0x0117, // StripByteCounts
            0x0144, // TileOffsets
            0x0145, // TileByteCounts
    };

    // Progressive 模式标记
    private boolean isProgressiveMode = false;

    // 编码模式类型
    private enum JpegMode {
        BASELINE, // SOF0
        EXTENDED, // SOF1
        PROGRESSIVE, // SOF2
        LOSSLESS, // SOF3
        HIERARCHICAL // SOF5-7 + DHP
    }

    private JpegMode currentMode = JpegMode.BASELINE;

    private final JpegScanner scanner = new JpegScanner();

    @Override
    public Iterator<Testcase> mutate(Seed seed, int energy) {
        int count = Math.max(1, energy);
        byte[] seedData = seed.getData();

        // 尝试解析 seed
        ScanResult scanResult = null;
        if (scanner.matches(seedData)) {
            scanResult = scanner.scan(seedData);
        }

        final ScanResult finalScanResult = scanResult;

        return new Iterator<Testcase>() {
            private int remaining = count;

            @Override
            public boolean hasNext() {
                return remaining > 0;
            }

            @Override
            public Testcase next() {
                if (remaining <= 0)
                    throw new NoSuchElementException();
                remaining--;
                try {
                    byte[] jpegData;

                    // 如果成功解析了 seed，使用结构感知变异
                    if (finalScanResult != null && finalScanResult.isValid()) {
                        jpegData = mutateFromSeed(finalScanResult);
                    } else {
                        // 回退到生成模式
                        jpegData = generateJpeg();
                    }

                    return new Testcase(jpegData, seed, "structure:JPEG");
                } catch (Exception e) {
                    try {
                        return new Testcase(generateJpeg(), seed, "grammar:JPEG");
                    } catch (IOException ex) {
                        throw new RuntimeException(ex);
                    }
                }
            }
        };
    }

    /**
     * 基于解析的 seed 进行结构感知变异
     */
    private byte[] mutateFromSeed(ScanResult result) throws IOException {
        byte[] data = result.getOriginalData().clone();
        List<BinaryChunk> chunks = result.getChunks();
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        // 选择变异策略 (扩展为 12 种)
        int strategy = rand.nextInt(24);

        if (strategy < 4 && chunks.size() > 2) {
            // 17%: Segment 操作 (删除、复制、交换)
            data = mutateSegmentStructure(data, chunks, rand);
        } else if (strategy < 8) {
            // 17%: 真正的 Length Spoofing
            data = mutateLengthSpoofing(data, chunks, rand);
        } else if (strategy < 11) {
            // 12%: 数据区域位翻转
            data = mutateDataRegions(data, chunks, rand);
        } else if (strategy < 14) {
            // 12%: Marker 混淆攻击
            data = mutateMarkers(data, chunks, rand);
        } else if (strategy < 17) {
            // 12%: Exif IFD 注入攻击
            data = mutateExifIfd(data, chunks, rand);
        } else if (strategy < 19) {
            // 8%: Quantization Table 攻击
            data = mutateDqtFields(data, chunks, rand);
        } else if (strategy < 21) {
            // 8%: Sampling Factor 攻击
            data = mutateSamplingFactors(data, chunks, rand);
        } else if (strategy < 23) {
            // 8%: Progressive/Spectral 攻击
            data = mutateProgressiveParams(data, chunks, rand);
        } else {
            // 4%: 组合攻击 (多策略叠加)
            data = mutateCombined(data, chunks, rand);
        }

        // 确保 SOI 和 EOI 正确 (90% 概率保护)
        if (rand.nextInt(10) > 0) {
            data = ConstraintFixer.restoreJpegMagic(data);
            data = ConstraintFixer.ensureJpegEoi(data);
        }

        return data;
    }

    /**
     * Segment 结构变异：删除/复制/交换
     */
    private byte[] mutateSegmentStructure(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand)
            throws IOException {
        // 找到可删除的 segment（排除 CRITICAL_SEGMENTS）
        List<BinaryChunk> deletable = new ArrayList<>();
        // 找到可复制/交换的 segment（排除 SOI, EOI）
        List<BinaryChunk> mutable = new ArrayList<>();

        for (BinaryChunk chunk : chunks) {
            String type = chunk.getChunkType();
            if (!type.equals("SOI") && !type.equals("EOI")) {
                mutable.add(chunk);
                // 只有非关键 segment 可以删除
                if (!CRITICAL_SEGMENTS.contains(type)) {
                    deletable.add(chunk);
                }
            }
        }

        if (mutable.isEmpty()) {
            return data;
        }

        int op = rand.nextInt(3);

        if (op == 0 && !deletable.isEmpty()) {
            // 删除一个非关键 segment（保护 DQT, DHT, SOF 等）
            BinaryChunk toDelete = deletable.get(rand.nextInt(deletable.size()));
            return StructureMutator.deleteChunk(data, toDelete);

        } else if (op == 1) {
            // 复制一个 segment
            BinaryChunk toDuplicate = mutable.get(rand.nextInt(mutable.size()));
            return StructureMutator.duplicateChunk(data, toDuplicate);

        } else if (op == 2 && mutable.size() >= 2) {
            // 交换两个同顺序级别的 segment（遵守顺序约束）
            // 最多尝试 10 次找到可交换的组合
            for (int attempt = 0; attempt < 10; attempt++) {
                int idx1 = rand.nextInt(mutable.size());
                int idx2 = rand.nextInt(mutable.size());
                if (idx1 != idx2 && canSwap(mutable.get(idx1), mutable.get(idx2))) {
                    return StructureMutator.swapChunks(data, mutable.get(idx1), mutable.get(idx2));
                }
            }
        }

        return data;
    }

    /**
     * 检查两个 segment 是否可以交换（同顺序级别）
     */
    private boolean canSwap(BinaryChunk s1, BinaryChunk s2) {
        String type1 = s1.getChunkType();
        String type2 = s2.getChunkType();

        Integer order1 = SEGMENT_ORDER.get(type1);
        Integer order2 = SEGMENT_ORDER.get(type2);

        // 未知类型的 segment 赋予中间顺序
        if (order1 == null)
            order1 = 25;
        if (order2 == null)
            order2 = 25;

        // 只有同顺序级别的 segment 才能交换
        return order1.equals(order2);
    }

    /**
     * 真正的 Length Spoofing 攻击
     * 
     * 问题1修复: 实现两种有效的 Length Spoofing 策略：
     * 1. Under-report: 声称长度 < 实际数据 → 后续数据被误解析为新 Marker
     * 2. Over-report: 声称长度 > 实际数据 → 读取后续 Marker 作为数据
     */
    private byte[] mutateLengthSpoofing(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // 找有长度字段的非关键 segment
        List<BinaryChunk> targets = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            String type = chunk.getChunkType();
            // 跳过 SOI, EOI, 和 SCAN_DATA
            if (type.equals("SOI") || type.equals("EOI") || type.equals("SCAN_DATA"))
                continue;
            // 需要有长度字段
            for (FieldMapping field : chunk.getFields()) {
                if (field.getType() == FieldType.LENGTH && field.getName().equals("length")) {
                    targets.add(chunk);
                    break;
                }
            }
        }

        if (targets.isEmpty())
            return data;

        BinaryChunk target = targets.get(rand.nextInt(targets.size()));
        byte[] result = data.clone();

        // 找到长度字段位置 (通常在 offset+2 处)
        int lengthOffset = target.getStartOffset() + 2;
        if (lengthOffset + 2 > result.length)
            return data;

        // 读取当前声明的长度
        int currentLen = ((result[lengthOffset] & 0xFF) << 8) | (result[lengthOffset + 1] & 0xFF);
        int actualDataLen = target.getDataLength() + 2; // +2 for length field itself

        int strategy = rand.nextInt(4);
        int newLen;

        if (strategy == 0 && actualDataLen > 6) {
            // Under-report: 声称长度比实际少
            // 例：实际 100 字节，声称只有 50 字节
            // 解析器读取 48 字节后跳到 "下一个 Marker"
            // 剩余 52 字节可能包含 0xFF xx 被误解析为 Marker
            newLen = 2 + rand.nextInt(actualDataLen / 2); // 至少 2
            if (newLen < 2)
                newLen = 2;
        } else if (strategy == 1) {
            // Over-report: 声称长度比实际多，读取后续 Marker
            // 目的是让解析器把后面的 Marker 当作数据读取
            int remaining = result.length - target.getEndOffset();
            if (remaining > 10) {
                newLen = actualDataLen + rand.nextInt(Math.min(remaining, 500)) + 10;
            } else {
                newLen = actualDataLen + rand.nextInt(100) + 10;
            }
            if (newLen > 65535)
                newLen = 65535;
        } else if (strategy == 2) {
            // 极端边界值
            int[] extremes = { 0, 1, 2, 65534, 65535 };
            newLen = extremes[rand.nextInt(extremes.length)];
        } else {
            // 微小差异 (检测 off-by-one 错误)
            newLen = actualDataLen + (rand.nextBoolean() ? 1 : -1);
            if (newLen < 0)
                newLen = 0;
        }

        // 写入新长度
        result[lengthOffset] = (byte) ((newLen >> 8) & 0xFF);
        result[lengthOffset + 1] = (byte) (newLen & 0xFF);

        return result;
    }

    /**
     * Exif IFD 结构注入攻击
     * 针对 APP1 Segment 进行 TIFF/IFD 结构攻击
     */
    private byte[] mutateExifIfd(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // 找到 APP1 segment
        BinaryChunk app1 = null;
        for (BinaryChunk chunk : chunks) {
            if (chunk.getChunkType().equals("APP1")) {
                app1 = chunk;
                break;
            }
        }

        if (app1 == null || app1.getDataLength() < 20)
            return data;

        byte[] result = data.clone();
        int dataStart = app1.getStartOffset() + app1.getDataOffset();

        // 检查是否是 Exif
        if (dataStart + 6 > result.length)
            return data;
        String header = new String(result, dataStart, Math.min(4, result.length - dataStart),
                StandardCharsets.US_ASCII);
        if (!header.startsWith("Exif"))
            return data;

        // TIFF Header 从 dataStart + 6 开始
        int tiffStart = dataStart + 6;
        if (tiffStart + 8 > result.length)
            return data;

        // 确定字节序
        boolean littleEndian = (result[tiffStart] == 'I');

        int attackType = rand.nextInt(6);

        if (attackType == 0) {
            // OOB Offset 攻击: 修改 IFD0 Offset 指向文件外部
            int offsetPos = tiffStart + 4;
            if (offsetPos + 4 <= result.length) {
                int[] evilOffsets = { 0x7FFFFFFF, 0xFFFFFFFE, 0xFFFFFF, -1 };
                int evil = evilOffsets[rand.nextInt(evilOffsets.length)];
                writeIntAt(result, offsetPos, evil, littleEndian);
            }
        } else if (attackType == 1) {
            // 循环引用: IFD Offset 指向自己
            int offsetPos = tiffStart + 4;
            if (offsetPos + 4 <= result.length) {
                writeIntAt(result, offsetPos, 0, littleEndian); // 指回 TIFF Header
            }
        } else if (attackType == 2) {
            // Entry Count 攻击: 设置巨大的 Entry Count
            int ifdOffset = readIntAt(result, tiffStart + 4, littleEndian);
            int ifdPos = tiffStart + ifdOffset;
            if (ifdPos + 2 <= result.length && ifdPos >= tiffStart) {
                int evilCount = rand.nextInt(5) == 0 ? 0xFFFF : rand.nextInt(1000) + 100;
                writeShortAt(result, ifdPos, evilCount, littleEndian);
            }
        } else if (attackType == 3) {
            // 危险 Tag 注入: 在 IFD 中注入已知高危 Tag
            int ifdOffset = readIntAt(result, tiffStart + 4, littleEndian);
            int ifdPos = tiffStart + ifdOffset;
            if (ifdPos + 14 <= result.length && ifdPos >= tiffStart) {
                // 读取 entry count
                int entryCount = readShortAt(result, ifdPos, littleEndian);
                if (entryCount > 0) {
                    // 修改第一个 entry 为危险 Tag
                    int entryPos = ifdPos + 2;
                    if (entryPos + 12 <= result.length) {
                        int dangerousTag = DANGEROUS_EXIF_TAGS[rand.nextInt(DANGEROUS_EXIF_TAGS.length)];
                        writeShortAt(result, entryPos, dangerousTag, littleEndian);
                        // Type = LONG (4)
                        writeShortAt(result, entryPos + 2, 4, littleEndian);
                        // Count = huge
                        writeIntAt(result, entryPos + 4, 0x7FFFFFFF, littleEndian);
                        // Offset = OOB
                        writeIntAt(result, entryPos + 8, 0xFFFFFF, littleEndian);
                    }
                }
            }
        } else if (attackType == 4) {
            // TIFF Magic 破坏
            if (tiffStart + 2 <= result.length) {
                // 修改 42 为其他值
                if (littleEndian) {
                    result[tiffStart + 2] = (byte) rand.nextInt(256);
                } else {
                    result[tiffStart + 3] = (byte) rand.nextInt(256);
                }
            }
        } else {
            // MakerNote 注入: 在数据区域注入垃圾
            int dataLen = app1.getDataLength();
            if (dataLen > 20) {
                int injectPos = dataStart + 10 + rand.nextInt(dataLen - 10);
                if (injectPos < result.length) {
                    int injectLen = Math.min(20, result.length - injectPos);
                    for (int i = 0; i < injectLen; i++) {
                        result[injectPos + i] = (byte) rand.nextInt(256);
                    }
                }
            }
        }

        return result;
    }

    /**
     * DQT 字段攻击
     */
    private byte[] mutateDqtFields(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // 找到 DQT segment
        List<BinaryChunk> dqts = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (chunk.getChunkType().equals("DQT")) {
                dqts.add(chunk);
            }
        }

        if (dqts.isEmpty())
            return data;

        BinaryChunk dqt = dqts.get(rand.nextInt(dqts.size()));
        byte[] result = data.clone();

        int dataStart = dqt.getStartOffset() + dqt.getDataOffset();
        int dataLen = dqt.getDataLength();

        if (dataStart >= result.length || dataLen < 1)
            return data;

        int attackType = rand.nextInt(6);

        if (attackType == 0) {
            // 全零表 (除零攻击)
            int tableStart = dataStart + 1; // 跳过 info byte
            int tableLen = Math.min(64, result.length - tableStart);
            for (int i = 0; i < tableLen; i++) {
                result[tableStart + i] = 0;
            }
        } else if (attackType == 1) {
            // DC 系数为零
            if (dataStart + 1 < result.length) {
                result[dataStart + 1] = 0; // table[0] = DC coefficient
            }
        } else if (attackType == 2) {
            // 全部 0xFF (溢出)
            int tableStart = dataStart + 1;
            int tableLen = Math.min(64, result.length - tableStart);
            for (int i = 0; i < tableLen; i++) {
                result[tableStart + i] = (byte) 0xFF;
            }
        } else if (attackType == 3) {
            // 非法 Precision (高4位 > 1)
            if (dataStart < result.length) {
                int id = result[dataStart] & 0x0F;
                int illegalPrecision = rand.nextInt(14) + 2; // 2-15
                result[dataStart] = (byte) ((illegalPrecision << 4) | id);
            }
        } else if (attackType == 4) {
            // 非法 ID (低4位 > 3)
            if (dataStart < result.length) {
                int precision = (result[dataStart] >> 4) & 0x0F;
                int illegalId = rand.nextInt(12) + 4; // 4-15
                result[dataStart] = (byte) ((precision << 4) | illegalId);
            }
        } else {
            // 随机翻转部分系数
            int tableStart = dataStart + 1;
            int flipCount = rand.nextInt(16) + 1;
            for (int i = 0; i < flipCount; i++) {
                int pos = tableStart + rand.nextInt(Math.min(64, result.length - tableStart));
                if (pos < result.length) {
                    result[pos] = (byte) (rand.nextBoolean() ? 0 : 0xFF);
                }
            }
        }

        return result;
    }

    /**
     * Sampling Factor 攻击
     */
    private byte[] mutateSamplingFactors(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // 找到 SOF segment
        BinaryChunk sof = null;
        for (BinaryChunk chunk : chunks) {
            String type = chunk.getChunkType();
            if (type.startsWith("SOF")) {
                sof = chunk;
                break;
            }
        }

        if (sof == null)
            return data;

        byte[] result = data.clone();
        int dataStart = sof.getStartOffset() + sof.getDataOffset();

        // SOF 结构: Precision(1) + Height(2) + Width(2) + Components(1) +
        // ComponentData...
        // ComponentData: ID(1) + SamplingFactor(1) + QuantTableId(1)
        if (dataStart + 6 > result.length)
            return data;

        int components = result[dataStart + 5] & 0xFF;
        if (components == 0 || components > 4)
            components = 3;

        int attackType = rand.nextInt(6);

        // 选择一个 component 进行攻击
        int targetComponent = rand.nextInt(components);
        int sampPos = dataStart + 6 + targetComponent * 3 + 1; // sampling factor position

        if (sampPos >= result.length)
            return data;

        if (attackType == 0) {
            // H=0 (非法)
            result[sampPos] = (byte) ((rand.nextInt(4) << 4) | 0); // H=0-3, V=0
        } else if (attackType == 1) {
            // V=0 (非法)
            result[sampPos] = (byte) (0 | (rand.nextInt(4))); // H=0, V=0-3
        } else if (attackType == 2) {
            // 0x00 (完全非法)
            result[sampPos] = 0x00;
        } else if (attackType == 3) {
            // 0xFF (H=15, V=15 超大)
            result[sampPos] = (byte) 0xFF;
        } else if (attackType == 4) {
            // 0x44 (H=4, V=4 刚好超限)
            result[sampPos] = 0x44;
        } else {
            // H 或 V > 4
            int h = rand.nextInt(12) + 5; // 5-16
            int v = rand.nextInt(12) + 5;
            result[sampPos] = (byte) ((h << 4) | (v & 0x0F));
        }

        return result;
    }

    /**
     * Progressive JPEG Spectral Selection 攻击
     */
    private byte[] mutateProgressiveParams(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // 找到 SOS segment
        BinaryChunk sos = null;
        for (BinaryChunk chunk : chunks) {
            if (chunk.getChunkType().equals("SOS")) {
                sos = chunk;
                break;
            }
        }

        if (sos == null)
            return data;

        byte[] result = data.clone();
        int dataStart = sos.getStartOffset() + sos.getDataOffset();
        int dataLen = sos.getDataLength();

        // SOS 结构: ComponentCount(1) + ComponentSelectors(2*N) + Ss(1) + Se(1) + AhAl(1)
        if (dataLen < 4)
            return data;

        int components = result[dataStart] & 0xFF;
        if (components > 4)
            components = 3;

        int ssPos = dataStart + 1 + components * 2;
        int sePos = ssPos + 1;
        int ahalPos = sePos + 1;

        if (ahalPos >= result.length)
            return data;

        int attackType = rand.nextInt(5);

        if (attackType == 0) {
            // Ss > Se (非法: 起点大于终点)
            result[ssPos] = (byte) (rand.nextInt(32) + 32); // 32-63
            result[sePos] = (byte) (rand.nextInt(32)); // 0-31
        } else if (attackType == 1) {
            // Se > 63 (超出合法范围)
            result[ssPos] = 0;
            result[sePos] = (byte) (64 + rand.nextInt(192)); // 64-255
        } else if (attackType == 2) {
            // Ah > Al (对于 DC 扫描，首次扫描 Ah 应为 0)
            int ah = rand.nextInt(14) + 1; // 1-14
            int al = rand.nextInt(ah); // 0 to ah-1
            result[ahalPos] = (byte) ((ah << 4) | al);
        } else if (attackType == 3) {
            // DC-only scan (Ss=Se=0) 但使用非法 approximation
            result[ssPos] = 0;
            result[sePos] = 0;
            result[ahalPos] = (byte) 0xFF; // 非法值
        } else {
            // 超大的 approximation 位
            int ah = rand.nextInt(16);
            int al = 15; // 最大值
            result[ahalPos] = (byte) ((ah << 4) | al);
        }

        return result;
    }

    /**
     * 组合攻击: 同时应用多种变异策略
     */
    private byte[] mutateCombined(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        byte[] result = data;

        // 随机选择 2-4 种策略组合
        int strategies = 2 + rand.nextInt(3);

        for (int i = 0; i < strategies; i++) {
            int choice = rand.nextInt(6);
            switch (choice) {
                case 0:
                    result = mutateLengthSpoofing(result, chunks, rand);
                    break;
                case 1:
                    result = mutateMarkers(result, chunks, rand);
                    break;
                case 2:
                    result = mutateDqtFields(result, chunks, rand);
                    break;
                case 3:
                    result = mutateSamplingFactors(result, chunks, rand);
                    break;
                case 4:
                    result = mutateProgressiveParams(result, chunks, rand);
                    break;
                default:
                    result = mutateDataRegions(result, chunks, rand);
                    break;
            }
        }

        return result;
    }

    // 辅助方法: 字节数组读写
    private int readShortAt(byte[] data, int offset, boolean littleEndian) {
        if (offset + 2 > data.length)
            return 0;
        if (littleEndian) {
            return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
        } else {
            return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        }
    }

    private void writeShortAt(byte[] data, int offset, int value, boolean littleEndian) {
        if (offset + 2 > data.length)
            return;
        if (littleEndian) {
            data[offset] = (byte) (value & 0xFF);
            data[offset + 1] = (byte) ((value >> 8) & 0xFF);
        } else {
            data[offset] = (byte) ((value >> 8) & 0xFF);
            data[offset + 1] = (byte) (value & 0xFF);
        }
    }

    private int readIntAt(byte[] data, int offset, boolean littleEndian) {
        if (offset + 4 > data.length)
            return 0;
        if (littleEndian) {
            return (data[offset] & 0xFF) |
                    ((data[offset + 1] & 0xFF) << 8) |
                    ((data[offset + 2] & 0xFF) << 16) |
                    ((data[offset + 3] & 0xFF) << 24);
        } else {
            return ((data[offset] & 0xFF) << 24) |
                    ((data[offset + 1] & 0xFF) << 16) |
                    ((data[offset + 2] & 0xFF) << 8) |
                    (data[offset + 3] & 0xFF);
        }
    }

    private void writeIntAt(byte[] data, int offset, int value, boolean littleEndian) {
        if (offset + 4 > data.length)
            return;
        if (littleEndian) {
            data[offset] = (byte) (value & 0xFF);
            data[offset + 1] = (byte) ((value >> 8) & 0xFF);
            data[offset + 2] = (byte) ((value >> 16) & 0xFF);
            data[offset + 3] = (byte) ((value >> 24) & 0xFF);
        } else {
            data[offset] = (byte) ((value >> 24) & 0xFF);
            data[offset + 1] = (byte) ((value >> 16) & 0xFF);
            data[offset + 2] = (byte) ((value >> 8) & 0xFF);
            data[offset + 3] = (byte) (value & 0xFF);
        }
    }

    /**
     * 长度字段变异 (旧方法, 保留作为回退)
     */
    private byte[] mutateLengthFields(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        return mutateLengthSpoofing(data, chunks, rand);
    }

    /**
     * 数据区域位翻转
     */
    private byte[] mutateDataRegions(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        List<BinaryChunk> withData = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (chunk.getDataLength() > 0) {
                withData.add(chunk);
            }
        }

        if (withData.isEmpty())
            return data;

        BinaryChunk target = withData.get(rand.nextInt(withData.size()));
        int dataStart = target.getStartOffset() + target.getDataOffset();
        int dataLen = target.getDataLength();

        if (dataStart + dataLen > data.length || dataLen <= 0)
            return data;

        return StructureMutator.bitFlipDataRegion(data, dataStart, dataLen, rand);
    }

    /**
     * Marker 混淆攻击
     */
    private byte[] mutateMarkers(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        if (chunks.size() < 2)
            return data;

        // 随机选择一个 segment 修改其 marker
        BinaryChunk target = chunks.get(rand.nextInt(chunks.size()));
        String type = target.getChunkType();

        // 跳过 SOI 和 EOI
        if (type.equals("SOI") || type.equals("EOI"))
            return data;

        int markerOffset = target.getStartOffset() + 1; // 跳过 0xFF
        if (markerOffset >= data.length)
            return data;

        byte[] result = data.clone();

        // 随机改变 marker 类型
        int newMarker = rand.nextInt(256);
        result[markerOffset] = (byte) newMarker;

        return result;
    }

    private byte[] generateJpeg() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(baos);
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        out.write(0xFF);
        out.write(SOI);

        // 选择编码模式 (扩展支持 Lossless 和 Hierarchical)
        int modeChoice = rand.nextInt(20);
        if (modeChoice < 8) {
            currentMode = JpegMode.BASELINE; // 40%
        } else if (modeChoice < 14) {
            currentMode = JpegMode.PROGRESSIVE; // 30%
        } else if (modeChoice < 17) {
            currentMode = JpegMode.LOSSLESS; // 15%
        } else if (modeChoice < 19) {
            currentMode = JpegMode.HIERARCHICAL; // 10%
        } else {
            currentMode = JpegMode.EXTENDED; // 5%
        }
        this.isProgressiveMode = (currentMode == JpegMode.PROGRESSIVE);

        // APP0/APP1/APP2/其他 APPn 选择
        int appChoice = rand.nextInt(15);
        if (appChoice < 3) {
            writeApp1Exif(out, rand); // 20%: Exif 攻击
        } else if (appChoice < 5) {
            writeApp2IccProfile(out, rand);// 13%: ICC Profile 攻击
        } else if (appChoice < 8) {
            writeApp0(out, rand); // 20%: JFIF (可能带版本号攻击)
        } else if (appChoice < 10) {
            writeAppN(out, rand); // 13%: 其他 APPn
        }
        // 33%: 无 APP 段

        // COM 段 (25% 概率)
        if (rand.nextInt(4) == 0) {
            writeComment(out, rand);
        }

        // DNL 段 (5% 概率，定义行数)
        if (rand.nextInt(20) == 0) {
            writeDnl(out, rand);
        }

        // DQTs (Lossless 模式通常不需要，但可以生成攻击)
        int dqtCount = 1 + rand.nextInt(3);
        for (int i = 0; i < dqtCount; i++)
            writeDqt(out, rand);

        // DRI (Restart Interval) - 10% 概率
        if (rand.nextInt(10) == 0)
            writeDri(out, rand);

        // Hierarchical 模式需要 DHP 段
        if (currentMode == JpegMode.HIERARCHICAL && rand.nextInt(2) == 0) {
            writeDhp(out, rand);
        }

        // SOF (根据编码模式选择)
        writeSof(out, rand);

        // DHTs
        int dhtCount = 1 + rand.nextInt(4);
        for (int i = 0; i < dhtCount; i++)
            writeDht(out, rand);

        // SOS and Scan Data
        writeSosAndData(out, rand);

        out.write(0xFF);
        out.write(EOI);

        return baos.toByteArray();
    }

    /**
     * DNL (Define Number of Lines) 段
     * 用于在 SOS 之后定义图像高度，某些解析器处理不当
     */
    private void writeDnl(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        byte[] body = new byte[2];
        int lines;

        int attackType = rand.nextInt(5);
        if (attackType == 0) {
            lines = 0; // 零行
        } else if (attackType == 1) {
            lines = 65535; // 最大值
        } else if (attackType == 2) {
            lines = 1; // 只有一行
        } else {
            lines = rand.nextInt(2000) + 1;
        }

        body[0] = (byte) ((lines >> 8) & 0xFF);
        body[1] = (byte) (lines & 0xFF);

        writeMarker(out, DNL, body, false);
    }

    /**
     * DHP (Define Hierarchical Progression) 段
     * 用于 Hierarchical JPEG 模式
     */
    private void writeDhp(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        DataOutputStream bodyOut = new DataOutputStream(body);

        // DHP 结构类似 SOF
        bodyOut.write(8); // Precision

        // 尺寸
        int h = EVIL_DIMS[rand.nextInt(EVIL_DIMS.length)];
        int w = EVIL_DIMS[rand.nextInt(EVIL_DIMS.length)];
        bodyOut.writeShort(h);
        bodyOut.writeShort(w);

        int components = rand.nextInt(4) + 1;
        bodyOut.write(components);

        for (int i = 0; i < components; i++) {
            bodyOut.write(i + 1); // Component ID
            bodyOut.write(0x11); // Sampling Factor
            bodyOut.write(0); // Quant Table ID
        }

        writeMarker(out, DHP, body.toByteArray(), false);
    }

    /**
     * 其他 APPn 段 (APP3-APP15)
     */
    private void writeAppN(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        int appNum = rand.nextInt(13) + 3; // APP3 - APP15

        byte[] body;
        int attackType = rand.nextInt(5);

        if (attackType == 0) {
            // 空数据
            body = new byte[0];
        } else if (attackType == 1) {
            // 超长数据
            body = new byte[rand.nextInt(1000) + 500];
            rand.nextBytes(body);
        } else if (attackType == 2) {
            // 包含 0xFF 的数据
            body = new byte[rand.nextInt(100) + 10];
            rand.nextBytes(body);
            for (int i = 0; i < body.length / 5; i++) {
                body[rand.nextInt(body.length)] = (byte) 0xFF;
            }
        } else {
            // 随机数据
            body = new byte[rand.nextInt(50)];
            rand.nextBytes(body);
        }

        writeMarker(out, APP0 + appNum, body, false);
    }

    /**
     * 问题10: APP2 ICC Profile 段
     * ICC Profile 解析器也是漏洞高发区
     */
    private void writeApp2IccProfile(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();

        // ICC Profile 标识
        body.write("ICC_PROFILE\0".getBytes(StandardCharsets.US_ASCII));

        // Chunk 序号 / 总数
        int chunkNum = rand.nextInt(256);
        int totalChunks = rand.nextInt(256);
        body.write(chunkNum);
        body.write(totalChunks);

        // ICC Profile Header (至少 128 字节)
        int attackType = rand.nextInt(5);
        if (attackType == 0) {
            // 攻击: 畸形的 Profile Size
            byte[] header = new byte[128];
            rand.nextBytes(header);
            // Profile Size (前4字节)
            int evilSize = rand.nextInt(5) == 0 ? 0x7FFFFFFF : rand.nextInt(0x100000);
            header[0] = (byte) (evilSize >>> 24);
            header[1] = (byte) (evilSize >>> 16);
            header[2] = (byte) (evilSize >>> 8);
            header[3] = (byte) evilSize;
            body.write(header);
        } else if (attackType == 1) {
            // 攻击: 空 Profile
            // 不写任何数据
        } else {
            // 随机数据
            byte[] data = new byte[rand.nextInt(200)];
            rand.nextBytes(data);
            body.write(data);
        }

        writeMarker(out, APP0 + 2, body.toByteArray(), false); // APP2 = 0xE2
    }

    /**
     * 问题10: COM 注释段
     */
    private void writeComment(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        byte[] comment;

        int attackType = rand.nextInt(5);
        if (attackType == 0) {
            // 攻击: 包含 0xFF 字节的注释（某些解析器不处理）
            comment = new byte[rand.nextInt(100) + 10];
            rand.nextBytes(comment);
            for (int i = 0; i < comment.length / 10; i++) {
                comment[rand.nextInt(comment.length)] = (byte) 0xFF;
            }
        } else if (attackType == 1) {
            // 攻击: 超长注释
            comment = new byte[0xFFFD - 2]; // 最大长度 - 2
            rand.nextBytes(comment);
        } else if (attackType == 2) {
            // 攻击: 空注释
            comment = new byte[0];
        } else {
            // 正常注释
            String[] comments = { "fuzzer test", "AAAA", "\0\0\0\0", "test image" };
            comment = comments[rand.nextInt(comments.length)].getBytes(StandardCharsets.US_ASCII);
        }

        writeMarker(out, COM, comment, false);
    }

    // --- Enhanced Segment Writers ---

    /**
     * JFIF APP0 段 - 增强版本号变异
     * 某些解析器对不同版本有不同的处理逻辑
     */
    private void writeApp0(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        byte[] body = new byte[14];
        System.arraycopy("JFIF\0".getBytes(StandardCharsets.US_ASCII), 0, body, 0, 5);

        // 版本号攻击
        int attackType = rand.nextInt(10);
        if (attackType == 0) {
            // 非法版本 0.0
            body[5] = 0;
            body[6] = 0;
        } else if (attackType == 1) {
            // 超前版本 2.0 (不存在)
            body[5] = 2;
            body[6] = 0;
        } else if (attackType == 2) {
            // 版本 1.0
            body[5] = 1;
            body[6] = 0;
        } else if (attackType == 3) {
            // 版本 1.2
            body[5] = 1;
            body[6] = 2;
        } else if (attackType == 4) {
            // 随机版本
            body[5] = (byte) rand.nextInt(256);
            body[6] = (byte) rand.nextInt(256);
        } else {
            // 正常版本 1.1
            body[5] = 1;
            body[6] = 1;
        }

        // Unit 攻击
        if (rand.nextInt(10) == 0) {
            body[7] = (byte) rand.nextInt(256); // 非法 Unit
        } else {
            body[7] = (byte) (rand.nextInt(3)); // 0, 1, 2
        }

        // Density 攻击
        if (rand.nextInt(10) == 0) {
            // 零密度
            body[8] = 0;
            body[9] = 0;
            body[10] = 0;
            body[11] = 0;
        } else {
            body[8] = 0;
            body[9] = 72; // X Density
            body[10] = 0;
            body[11] = 72; // Y Density
        }

        // Thumbnail 尺寸 (通常为 0)
        body[12] = (byte) rand.nextInt(16);
        body[13] = (byte) rand.nextInt(16);

        writeMarker(out, APP0, body, false);
    }

    /**
     * [Critical Attack Surface] APP1 / Exif
     * Exif 解析器通常很脆弱。这里构造一个完整的 TIFF/IFD 结构进行攻击。
     */
    private void writeApp1Exif(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write("Exif\0\0".getBytes(StandardCharsets.US_ASCII));

        // TIFF Header
        boolean littleEndian = rand.nextBoolean();
        if (littleEndian) {
            body.write('I');
            body.write('I');
            body.write(42);
            body.write(0);
        } else {
            body.write('M');
            body.write('M');
            body.write(0);
            body.write(42);
        }

        // 选择攻击类型
        int attackType = rand.nextInt(10);

        if (attackType < 2) {
            // 攻击1: OOB Offset（指向文件外部）
            int[] evilOffsets = { 0xFFFFFF, 0x7FFFFFFF, 0xFFFFFFFE, -1 };
            writeInt(body, evilOffsets[rand.nextInt(evilOffsets.length)], littleEndian);
        } else if (attackType < 4) {
            // 攻击2: 自引用循环（Offset 指向自己）
            writeInt(body, 0, littleEndian); // 指向 TIFF Header 开头
        } else if (attackType < 7) {
            // 攻击3: 生成畸形的 IFD 结构
            int ifdOffset = 8; // 紧跟 TIFF Header
            writeInt(body, ifdOffset, littleEndian);

            // IFD: Entry Count (2 bytes)
            int entryCount = rand.nextInt(10) == 0 ? 0xFFFF : rand.nextInt(20);
            writeShort(body, entryCount, littleEndian);

            // 高风险 Tag 列表
            int[] dangerousTags = {
                    0x8769, // ExifIFDPointer
                    0x8825, // GPSInfoIFDPointer
                    0xA005, // InteroperabilityIFDPointer
                    0x927C, // MakerNote (厂商私有，解析复杂)
                    0x9286, // UserComment
                    0x0201, // JPEGInterchangeFormat (thumbnail offset)
                    0x0202, // JPEGInterchangeFormatLength
            };

            // 生成 IFD Entries
            int actualEntries = Math.min(entryCount, 20);
            for (int i = 0; i < actualEntries; i++) {
                // Tag (2 bytes)
                int tag = rand.nextInt(3) == 0
                        ? dangerousTags[rand.nextInt(dangerousTags.length)]
                        : rand.nextInt(0x10000);
                writeShort(body, tag, littleEndian);

                // Type (2 bytes): 1=BYTE, 2=ASCII, 3=SHORT, 4=LONG, 5=RATIONAL...
                int type = rand.nextInt(13) + 1;
                writeShort(body, type, littleEndian);

                // Count (4 bytes)
                int count = rand.nextInt(5) == 0 ? 0x7FFFFFFF : rand.nextInt(100);
                writeInt(body, count, littleEndian);

                // Value/Offset (4 bytes)
                // 如果 Value 超过 4 字节，这里存储 Offset
                int valueOffset = rand.nextInt(5) == 0 ? 0xFFFFFF : rand.nextInt(500);
                writeInt(body, valueOffset, littleEndian);
            }

            // Next IFD Offset (4 bytes)
            int nextIfd = rand.nextInt(5) == 0 ? 0xFFFFFF : 0;
            writeInt(body, nextIfd, littleEndian);

        } else {
            // 正常 IFD 结构 + 随机数据
            writeInt(body, 8, littleEndian);
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

    private void writeDri(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        // DRI payload is always 2 bytes (Restart Interval)
        byte[] interval = new byte[2];
        // [Attack] Tiny interval causes massive overhead / state resets
        int val = rand.nextInt(100);
        interval[0] = (byte) (val >> 8);
        interval[1] = (byte) val;
        writeMarker(out, DRI, interval, false);
    }

    private void writeDqt(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        // 问题7: 增强 DQT 攻击向量
        int attackType = rand.nextInt(20);

        // Precision (高4位): 0=8-bit, 1=16-bit
        // ID (低4位): 量化表 ID (0-3)
        byte info;
        byte[] table;

        if (attackType == 0) {
            // 攻击1: 全零表（导致除零）
            info = (byte) rand.nextInt(4); // 8-bit, valid ID
            table = new byte[64];
            // 全部保持 0
        } else if (attackType == 1) {
            // 攻击2: 部分零值（特定系数为 0）
            info = (byte) rand.nextInt(4);
            table = new byte[64];
            rand.nextBytes(table);
            // 随机将一些位置置零
            int zeroCount = rand.nextInt(32) + 1;
            for (int i = 0; i < zeroCount; i++) {
                table[rand.nextInt(64)] = 0;
            }
            // 确保 DC 系数 (table[0]) 有概率为 0
            if (rand.nextInt(5) == 0) {
                table[0] = 0;
            }
        } else if (attackType == 2) {
            // 攻击3: 超大值（可能导致溢出）
            info = (byte) rand.nextInt(4);
            table = new byte[64];
            for (int i = 0; i < 64; i++) {
                table[i] = (byte) 0xFF; // 最大 8-bit 值
            }
        } else if (attackType == 3) {
            // 攻击4: 非法 Precision（高4位不为 0 或 1）
            info = (byte) ((rand.nextInt(14) + 2) << 4 | rand.nextInt(4)); // Precision = 2-15
            table = new byte[64];
            rand.nextBytes(table);
        } else if (attackType == 4) {
            // 攻击5: 16-bit 精度表（需要 128 字节）
            info = (byte) (0x10 | rand.nextInt(4)); // Precision = 1
            table = new byte[128]; // 16-bit 需要 128 字节
            rand.nextBytes(table);
            // 注入一些零值
            for (int i = 0; i < 8; i++) {
                int pos = rand.nextInt(64) * 2;
                table[pos] = 0;
                table[pos + 1] = 0;
            }
        } else if (attackType == 5) {
            // 攻击6: 边界 ID（ID > 3）
            info = (byte) (rand.nextInt(4) << 4 | (rand.nextInt(12) + 4)); // ID = 4-15
            table = new byte[64];
            rand.nextBytes(table);
        } else {
            // 正常随机表
            info = (byte) rand.nextInt(4);
            table = new byte[64];
            rand.nextBytes(table);
        }

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(info);
        body.write(table);
        writeMarker(out, DQT, body.toByteArray(), false);
    }

    private void writeSof(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        DataOutputStream bodyOut = new DataOutputStream(body);

        bodyOut.write(8); // Precision

        // Height & Width
        int h = (rand.nextInt(10) < 3) ? EVIL_DIMS[rand.nextInt(EVIL_DIMS.length)] : rand.nextInt(2000) + 1;
        int w = (rand.nextInt(10) < 3) ? EVIL_DIMS[rand.nextInt(EVIL_DIMS.length)] : rand.nextInt(2000) + 1;
        bodyOut.writeShort(h);
        bodyOut.writeShort(w);

        int components = rand.nextInt(4) + 1; // 1, 2, 3, 4
        bodyOut.write(components);

        for (int i = 0; i < components; i++) {
            bodyOut.write(i + 1); // Component ID

            // 问题6: 增强 Sampling Factor 攻击
            int samp;
            int attackType = rand.nextInt(20);

            if (attackType == 0) {
                // 攻击1: H=0 或 V=0（非法零值）
                samp = rand.nextBoolean() ? (rand.nextInt(4) << 4) : rand.nextInt(4);
            } else if (attackType == 1) {
                // 攻击2: H > 4 或 V > 4（超大值）
                int h_samp = rand.nextInt(12) + 5; // 5-16
                int v_samp = rand.nextInt(12) + 5;
                samp = (h_samp << 4) | v_samp;
            } else if (attackType == 2) {
                // 攻击3: 全零
                samp = 0x00;
            } else if (attackType == 3) {
                // 攻击4: 最大值 0xFF (H=15, V=15)
                samp = 0xFF;
            } else if (attackType == 4) {
                // 攻击5: 4x4（刚好超出常规限制）
                samp = 0x44;
            } else if (attackType < 10) {
                // 30%: 非法组合（H=0 或 V=0）
                if (rand.nextBoolean()) {
                    samp = rand.nextInt(4) << 4; // V=0
                } else {
                    samp = rand.nextInt(4); // H=0
                }
            } else {
                // 50%: 正常值 1x1, 1x2, 2x1, 2x2
                int[] validSamples = { 0x11, 0x12, 0x21, 0x22 };
                samp = validSamples[rand.nextInt(validSamples.length)];
            }
            bodyOut.write(samp);
            bodyOut.write(rand.nextInt(4)); // Quant Table ID (0-3)
        }

        // 根据当前编码模式选择 SOF Marker
        int sofMarker;
        switch (currentMode) {
            case BASELINE:
                sofMarker = SOF0;
                this.isProgressiveMode = false;
                break;
            case EXTENDED:
                sofMarker = SOF1;
                this.isProgressiveMode = false;
                break;
            case PROGRESSIVE:
                sofMarker = SOF2;
                this.isProgressiveMode = true;
                break;
            case LOSSLESS:
                sofMarker = SOF3;
                this.isProgressiveMode = false;
                break;
            case HIERARCHICAL:
                // Hierarchical 可以是 SOF5, SOF6, SOF7
                int[] hierSof = { SOF5, SOF6, SOF7 };
                sofMarker = hierSof[rand.nextInt(hierSof.length)];
                this.isProgressiveMode = (sofMarker == SOF6);
                break;
            default:
                sofMarker = SOF0;
                this.isProgressiveMode = false;
        }

        writeMarker(out, sofMarker, body.toByteArray(), false);
    }

    private void writeDht(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(rand.nextInt(4) << 4 | rand.nextInt(4)); // Class | ID

        byte[] counts = new byte[16];
        // Make sure sum of counts is reasonable to pass basic checks, or total garbage
        int totalSymbols = 0;
        if (rand.nextBoolean()) {
            for (int i = 0; i < 16; i++) {
                counts[i] = (byte) rand.nextInt(10);
                totalSymbols += counts[i];
            }
        } else {
            // Garbage counts
            rand.nextBytes(counts);
            totalSymbols = rand.nextInt(200);
        }
        body.write(counts);

        byte[] symbols = new byte[totalSymbols];
        rand.nextBytes(symbols);
        body.write(symbols);

        writeMarker(out, DHT, body.toByteArray(), false);
    }

    private void writeSosAndData(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(3); // Component count
        // Selectors
        body.write(1);
        body.write(0);
        body.write(2);
        body.write(0);
        body.write(3);
        body.write(0);

        // 问题9: Progressive JPEG 需要更精确的 Spectral Selection
        int ss, se, ah, al;
        if (isProgressiveMode) {
            int attackType = rand.nextInt(5);
            if (attackType == 0) {
                // 攻击：Ss > Se
                ss = rand.nextInt(32) + 32; // 32-63
                se = rand.nextInt(32); // 0-31
            } else if (attackType == 1) {
                // 攻击：Se > 63
                ss = 0;
                se = 64 + rand.nextInt(192); // 64-255
            } else if (attackType == 2) {
                // 攻击：DC-only scan (Ss=Se=0) with bad approx
                ss = 0;
                se = 0;
                ah = rand.nextInt(14) + 1; // 1-14 (should be 0 for first DC scan)
                al = rand.nextInt(13) + ah; // ah <= al is wrong!
                body.write(ss);
                body.write(se);
                body.write((ah << 4) | al);
                writeMarker(out, SOS, body.toByteArray(), false);
                writeEntropyData(out, rand);
                return;
            } else {
                // 正常 Progressive 范围
                ss = rand.nextInt(64);
                se = ss + rand.nextInt(64 - ss);
            }
            ah = rand.nextInt(14);
            al = rand.nextInt(14);
        } else {
            // Baseline: Ss=0, Se=63, Ah=Al=0
            ss = 0;
            se = 63;
            ah = 0;
            al = 0;
            // 10% 概率注入非法值
            if (rand.nextInt(10) == 0) {
                ss = rand.nextInt(64);
                se = rand.nextInt(64);
                ah = rand.nextInt(16);
                al = rand.nextInt(16);
            }
        }

        body.write(ss);
        body.write(se);
        body.write((ah << 4) | al);

        writeMarker(out, SOS, body.toByteArray(), false);

        writeEntropyData(out, rand);
    }

    /**
     * 问题4: 改进的熵编码数据写入
     * 
     * 关键改进:
     * 1. 排除 0x00 和 0xD9 从攻击字节（0x00 是正常转义，0xD9 会提前结束文件）
     * 2. 专注于非法 Marker（非 00/Dn）触发真正的解析错误
     * 3. 支持 Lossless 模式的不同数据模式
     */
    private void writeEntropyData(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        int dataLen = rand.nextInt(2048) + 10;

        // 选择攻击模式 (更精细的控制)
        int attackMode = rand.nextInt(25);

        // 非法 Marker 列表 (排除 0x00, 0xD0-D7, 0xD9)
        int[] illegalMarkers = {
                0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
                0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
                0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
                0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
                0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
                0xFE
        };

        for (int i = 0; i < dataLen; i++) {
            int b = rand.nextInt(256);
            out.write(b);

            // 0xFF Escaping Logic - 改进版
            if (b == 0xFF) {
                if (attackMode == 0) {
                    // 攻击1: 未转义的 0xFF，写入非法 Marker
                    // 这会触发 "Marker in scan data" 错误
                    out.write(illegalMarkers[rand.nextInt(illegalMarkers.length)]);
                } else if (attackMode == 1) {
                    // 攻击2: 伪造 EOI (提前结束)
                    // 注意：这会导致后续数据被忽略
                    out.write(0xD9);
                } else if (attackMode == 2) {
                    // 攻击3: 随机非转义字节 (排除 0x00, 0xD0-D7, 0xD9)
                    int next;
                    do {
                        next = rand.nextInt(256);
                    } while (next == 0x00 || (next >= 0xD0 && next <= 0xD9));
                    out.write(next);
                } else if (attackMode == 3) {
                    // 攻击4: 错误的 RST 顺序 (RST markers 应该按 0-7 循环)
                    out.write(RST0 + rand.nextInt(8));
                } else if (attackMode == 4) {
                    // 攻击5: 写入 TEM (0x01) - 算术编码标记
                    out.write(0x01);
                } else if (attackMode == 5) {
                    // 攻击6: 写入保留 Marker (0x02-0xBF)
                    out.write(rand.nextInt(0xBE) + 0x02);
                } else if (rand.nextInt(30) == 0) {
                    // 3%: 随机干扰 RST
                    out.write(RST0 + rand.nextInt(8));
                } else {
                    // 正常转义 (0xFF 0x00)
                    out.write(0x00);
                }
            }
        }

        // 确保数据以非 0xFF 结尾（避免解析器等待更多数据）
        if (rand.nextInt(10) > 0) {
            out.write(rand.nextInt(0xFF)); // 0x00-0xFE
        }
    }

    /**
     * 核心改进：支持 Length Spoofing
     * 
     * @param spoofLength 如果为 true，则随机写入一个假的 Length
     * 
     *                    真正的 Length Spoofing 策略:
     *                    1. Under-report: 声称长度 < 实际数据 → 解析器跳过到 "下一个 Marker" 时错位
     *                    2. Over-report: 声称长度 > 实际数据 → 可能读取后续 Marker 作为数据
     */
    private void writeMarker(DataOutputStream out, int marker, byte[] payload, boolean spoofLength) throws IOException {
        out.write(0xFF);
        out.write(marker);

        int realLen = payload.length + 2; // +2 包含 Length 字段本身
        int writtenLen = realLen;
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        // [Attack] 5% 概率进行 Length Spoofing
        if (spoofLength || rand.nextInt(20) == 0) {
            int strategy = rand.nextInt(3);

            if (strategy == 0 && payload.length > 4) {
                // Under-report: 声称长度比实际少，导致后续数据被误解析
                // 例：实际 100 字节，声称只有 50 字节
                // 解析器读取 48 字节后跳到 "下一个 Marker"
                // 剩余 52 字节可能被误解析为新 Marker
                int underReport = rand.nextInt(payload.length / 2) + 2; // 至少 2
                writtenLen = underReport;
            } else if (strategy == 1) {
                // Over-report: 声称长度比实际多，读取到后续 Marker
                writtenLen = realLen + rand.nextInt(500) + 10;
                if (writtenLen > 65535)
                    writtenLen = 65535;
            } else {
                // 边界值攻击
                int[] evilLengths = { 0, 1, 2, 0xFFFF, 0xFFFE };
                writtenLen = evilLengths[rand.nextInt(evilLengths.length)];
            }
        }

        out.writeShort(writtenLen);
        out.write(payload);
    }

    // Helper for Little Endian writing in Exif
    private void writeInt(ByteArrayOutputStream out, int v, boolean littleEndian) {
        if (littleEndian) {
            out.write(v & 0xFF);
            out.write((v >>> 8) & 0xFF);
            out.write((v >>> 16) & 0xFF);
            out.write((v >>> 24) & 0xFF);
        } else {
            out.write((v >>> 24) & 0xFF);
            out.write((v >>> 16) & 0xFF);
            out.write((v >>> 8) & 0xFF);
            out.write(v & 0xFF);
        }
    }
}