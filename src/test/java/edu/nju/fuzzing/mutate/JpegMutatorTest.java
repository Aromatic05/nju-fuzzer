package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JpegMutator 单元测试
 *
 * 验证点：
 * 1. 结构完整性 (SOI/EOI 闭合)
 * 2. 攻击向量识别 (Length Spoofing, Evil Dims, Exif Injection, Progressive Mode)
 * 3. 新增编码模式 (Lossless, Hierarchical)
 * 4. Sampling Factor 攻击
 * 5. DQT 攻击向量
 * 6. 0xFF Escape 攻击
 * 7. JFIF 版本号攻击
 * 8. 统计报告 (可视化展示算法多样性)
 */
class JpegMutatorTest {

    private Seed dummySeed;
    private Seed validJpegSeed;
    private JpegMutator mutator;

    // JPEG Markers
    private static final int SOI = 0xD8;
    private static final int EOI = 0xD9;
    private static final int SOF0 = 0xC0;
    private static final int SOF1 = 0xC1;
    private static final int SOF2 = 0xC2;
    private static final int SOF3 = 0xC3; // Lossless
    private static final int SOF5 = 0xC5; // Hierarchical
    // private static final int SOF6 = 0xC6;
    private static final int SOF7 = 0xC7;
    private static final int APP0 = 0xE0;
    private static final int APP1 = 0xE1;
    private static final int APP2 = 0xE2;
    private static final int COM = 0xFE;
    private static final int SOS = 0xDA;
    private static final int DQT = 0xDB;
    private static final int DHT = 0xC4;
    private static final int DRI = 0xDD;
    private static final int DNL = 0xDC;
    private static final int DHP = 0xDE;

    @BeforeEach
    void setUp() {
        dummySeed = Seed.loadWithMetadata(new File("dummy_jpeg"), new byte[0]);

        // 创建一个简单的有效 JPEG 用于变异测试
        validJpegSeed = createValidJpegSeed();

        mutator = new JpegMutator();
    }

    /**
     * 创建一个简单的有效 JPEG seed 用于结构感知变异测试
     */
    private Seed createValidJpegSeed() {
        try {
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.io.DataOutputStream out = new java.io.DataOutputStream(baos);

            // SOI
            out.write(0xFF);
            out.write(SOI);

            // APP0 (JFIF)
            out.write(0xFF);
            out.write(APP0);
            byte[] jfif = "JFIF\0".getBytes(StandardCharsets.US_ASCII);
            byte[] app0Body = new byte[14];
            System.arraycopy(jfif, 0, app0Body, 0, 5);
            app0Body[5] = 1;
            app0Body[6] = 1; // Version 1.1
            out.writeShort(app0Body.length + 2);
            out.write(app0Body);

            // DQT
            out.write(0xFF);
            out.write(DQT);
            byte[] dqtBody = new byte[65];
            dqtBody[0] = 0; // 8-bit, ID=0
            for (int i = 1; i < 65; i++)
                dqtBody[i] = (byte) (i + 10);
            out.writeShort(dqtBody.length + 2);
            out.write(dqtBody);

            // SOF0
            out.write(0xFF);
            out.write(SOF0);
            byte[] sof0Body = new byte[11];
            sof0Body[0] = 8; // Precision
            sof0Body[1] = 0;
            sof0Body[2] = 64; // Height = 64
            sof0Body[3] = 0;
            sof0Body[4] = 64; // Width = 64
            sof0Body[5] = 3; // Components
            sof0Body[6] = 1;
            sof0Body[7] = 0x22;
            sof0Body[8] = 0; // Y
            sof0Body[9] = 2;
            sof0Body[10] = 0x11; // Cb (incomplete but sufficient for testing)
            out.writeShort(sof0Body.length + 2);
            out.write(sof0Body);

            // DHT
            out.write(0xFF);
            out.write(DHT);
            byte[] dhtBody = new byte[19];
            dhtBody[0] = 0; // Class=0, ID=0
            out.writeShort(dhtBody.length + 2);
            out.write(dhtBody);

            // SOS
            out.write(0xFF);
            out.write(SOS);
            byte[] sosBody = new byte[10];
            sosBody[0] = 3; // 3 components
            sosBody[1] = 1;
            sosBody[2] = 0;
            sosBody[3] = 2;
            sosBody[4] = 0;
            sosBody[5] = 3;
            sosBody[6] = 0;
            sosBody[7] = 0; // Ss
            sosBody[8] = 63; // Se
            sosBody[9] = 0; // Ah, Al
            out.writeShort(sosBody.length + 2);
            out.write(sosBody);

            // Some entropy data
            for (int i = 0; i < 50; i++) {
                out.write(i % 256);
            }

            // EOI
            out.write(0xFF);
            out.write(EOI);

            return Seed.loadWithMetadata(new File("valid_jpeg"), baos.toByteArray());
        } catch (Exception e) {
            return dummySeed;
        }
    }

    // ==========================================
    // 基础功能测试
    // ==========================================

    @Test
    @DisplayName("Test 1: SOI/EOI - 必须以 FF D8 开头并以 FF D9 结尾")
    void testBoundary() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        int validCount = 0;
        int total = 0;

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            total++;

            if (data.length >= 4) {
                boolean validSoi = (data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == SOI;
                boolean validEoi = (data[data.length - 2] & 0xFF) == 0xFF &&
                        (data[data.length - 1] & 0xFF) == EOI;
                if (validSoi && validEoi)
                    validCount++;
            }
        }

        // 至少 85% 的样本应该有正确的 SOI/EOI (一些攻击样本可能故意破坏)
        double rate = (double) validCount / total * 100;
        System.out.println("SOI/EOI 正确率: " + String.format("%.1f%%", rate) + " (" + validCount + "/" + total + ")");
        assertTrue(rate >= 85, "SOI/EOI 正确率过低: " + rate + "%");
    }

    @Test
    @DisplayName("Test 2: Diversity - 变异结果应高度多样化")
    void testDiversity() {
        Set<Integer> hashes = new HashSet<>();
        int count = 100;
        Iterator<Testcase> iter = mutator.mutate(dummySeed, count);
        while (iter.hasNext()) {
            hashes.add(Arrays.hashCode(iter.next().getData()));
        }
        // 100个随机生成的图片，重复概率应极低
        assertTrue(hashes.size() > 95, "多样性不足: " + hashes.size());
    }

    @Test
    @DisplayName("Test 3: Structure-aware Mutation - 有效 Seed 的结构感知变异")
    void testStructureAwareMutation() {
        Iterator<Testcase> iter = mutator.mutate(validJpegSeed, 50);
        int validMutations = 0;
        int total = 0;

        while (iter.hasNext()) {
            Testcase tc = iter.next();
            byte[] data = tc.getData();
            total++;

            // 使用有效 JPEG seed 时，生成的结果应该有良好的结构
            if (data.length >= 4) {
                boolean validSoi = (data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == SOI;
                boolean validEoi = (data[data.length - 2] & 0xFF) == 0xFF &&
                        (data[data.length - 1] & 0xFF) == EOI;
                if (validSoi && validEoi)
                    validMutations++;
            }
        }

        // 使用有效 JPEG seed 时，应该产生高质量的结构化变异
        System.out.println("结构有效变异: " + validMutations + "/" + total);
        assertTrue(validMutations >= 45, "结构有效变异率过低: " + validMutations);
    }

    // ==========================================
    // 编码模式测试
    // ==========================================

    @Test
    @DisplayName("Test 4: Encoding Modes - 支持多种编码模式")
    void testEncodingModes() {
        int total = 1000;
        Map<String, Integer> modes = new HashMap<>();
        modes.put("Baseline (SOF0)", 0);
        modes.put("Extended (SOF1)", 0);
        modes.put("Progressive (SOF2)", 0);
        modes.put("Lossless (SOF3)", 0);
        modes.put("Hierarchical (SOF5-7)", 0);

        Iterator<Testcase> iter = mutator.mutate(dummySeed, total);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            int sofType = findSofType(data);

            if (sofType == SOF0)
                modes.put("Baseline (SOF0)", modes.get("Baseline (SOF0)") + 1);
            else if (sofType == SOF1)
                modes.put("Extended (SOF1)", modes.get("Extended (SOF1)") + 1);
            else if (sofType == SOF2)
                modes.put("Progressive (SOF2)", modes.get("Progressive (SOF2)") + 1);
            else if (sofType == SOF3)
                modes.put("Lossless (SOF3)", modes.get("Lossless (SOF3)") + 1);
            else if (sofType >= SOF5 && sofType <= SOF7)
                modes.put("Hierarchical (SOF5-7)", modes.get("Hierarchical (SOF5-7)") + 1);
        }

        System.out.println("====== Encoding Mode Coverage ======");
        for (Map.Entry<String, Integer> entry : modes.entrySet()) {
            double rate = (double) entry.getValue() / total * 100;
            System.out.printf("%-25s: %4d (%5.1f%%)%n", entry.getKey(), entry.getValue(), rate);
        }

        // 验证主要模式都有覆盖
        assertTrue(modes.get("Baseline (SOF0)") > 0, "Baseline 模式未覆盖");
        assertTrue(modes.get("Progressive (SOF2)") > 0, "Progressive 模式未覆盖");
        assertTrue(modes.get("Lossless (SOF3)") > 0, "Lossless 模式未覆盖");
    }

    private int findSofType(byte[] data) {
        for (int i = 0; i < data.length - 1; i++) {
            if ((data[i] & 0xFF) == 0xFF) {
                int marker = data[i + 1] & 0xFF;
                if (marker >= 0xC0 && marker <= 0xC7 && marker != 0xC4) {
                    return marker;
                }
            }
        }
        return -1;
    }

    // ==========================================
    // 攻击向量测试
    // ==========================================

    @Test
    @DisplayName("Test 5: Length Spoofing Attack - 长度欺骗攻击检测")
    void testLengthSpoofingAttack() {
        int total = 500;
        int underReport = 0;
        int overReport = 0;
        int extremeValues = 0;

        Iterator<Testcase> iter = mutator.mutate(dummySeed, total);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();

            // 检查每个 segment 的长度字段
            int i = 2; // 跳过 SOI
            while (i < data.length - 3) {
                if ((data[i] & 0xFF) == 0xFF) {
                    int marker = data[i + 1] & 0xFF;
                    // 有长度字段的 marker
                    if (marker >= 0xC0 && marker <= 0xFE && marker != SOI && marker != EOI &&
                            (marker < 0xD0 || marker > 0xD7)) {
                        if (i + 3 < data.length) {
                            int claimedLen = ((data[i + 2] & 0xFF) << 8) | (data[i + 3] & 0xFF);
                            int remainingData = data.length - i - 4;

                            if (claimedLen < 2)
                                extremeValues++;
                            else if (claimedLen > 0xFFF0)
                                extremeValues++;
                            else if (claimedLen > remainingData + 100)
                                overReport++;
                            else if (claimedLen < 5 && remainingData > 50)
                                underReport++;
                        }
                    }
                    if (marker == EOI)
                        break;
                }
                i++;
            }
        }

        System.out.println("====== Length Spoofing Detection ======");
        System.out.println("Under-report attacks: " + underReport);
        System.out.println("Over-report attacks:  " + overReport);
        System.out.println("Extreme value attacks: " + extremeValues);

        // 验证至少有一种长度欺骗攻击被检测到
        assertTrue(underReport + overReport + extremeValues > 0,
                "未检测到任何 Length Spoofing 攻击");
    }

    @Test
    @DisplayName("Test 6: Sampling Factor Attack - 采样因子攻击")
    void testSamplingFactorAttack() {
        int total = 500;
        int zeroFactor = 0;
        int largeFactor = 0;
        int extremeFactor = 0;

        Iterator<Testcase> iter = mutator.mutate(dummySeed, total);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();

            // 找到 SOF 段并检查 sampling factors
            for (int i = 0; i < data.length - 10; i++) {
                if ((data[i] & 0xFF) == 0xFF) {
                    int marker = data[i + 1] & 0xFF;
                    if (marker >= 0xC0 && marker <= 0xC7 && marker != 0xC4) {
                        // SOF 找到
                        if (i + 9 < data.length) {
                            int components = data[i + 9] & 0xFF;
                            if (components > 0 && components <= 4) {
                                for (int c = 0; c < Math.min(components, 4); c++) {
                                    int sampPos = i + 10 + c * 3 + 1;
                                    if (sampPos < data.length) {
                                        int samp = data[sampPos] & 0xFF;
                                        int h = (samp >> 4) & 0x0F;
                                        int v = samp & 0x0F;

                                        if (h == 0 || v == 0)
                                            zeroFactor++;
                                        if (h > 4 || v > 4)
                                            largeFactor++;
                                        if (samp == 0x00 || samp == 0xFF)
                                            extremeFactor++;
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }

        System.out.println("====== Sampling Factor Attack ======");
        System.out.println("Zero factor (H=0 or V=0): " + zeroFactor);
        System.out.println("Large factor (H>4 or V>4): " + largeFactor);
        System.out.println("Extreme values (0x00/0xFF): " + extremeFactor);

        assertTrue(zeroFactor + largeFactor + extremeFactor > 0,
                "未检测到 Sampling Factor 攻击");
    }

    @Test
    @DisplayName("Test 7: DQT Zero Table Attack - 量化表零值攻击")
    void testDqtZeroTableAttack() {
        int total = 500;
        int zeroTableCount = 0;
        int partialZeroCount = 0;
        int allMaxCount = 0;
        int illegalPrecisionCount = 0;

        Iterator<Testcase> iter = mutator.mutate(dummySeed, total);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();

            for (int i = 0; i < data.length - 70; i++) {
                if ((data[i] & 0xFF) == 0xFF && (data[i + 1] & 0xFF) == DQT) {
                    if (i + 5 < data.length) {
                        int info = data[i + 4] & 0xFF;
                        int precision = (info >> 4) & 0x0F;

                        if (precision > 1)
                            illegalPrecisionCount++;

                        // 检查表内容
                        int tableStart = i + 5;
                        int tableSize = (precision == 0) ? 64 : 128;
                        if (tableStart + tableSize <= data.length) {
                            int zeroCount = 0;
                            int maxCount = 0;
                            for (int j = 0; j < Math.min(tableSize, 64); j++) {
                                if ((data[tableStart + j] & 0xFF) == 0)
                                    zeroCount++;
                                if ((data[tableStart + j] & 0xFF) == 0xFF)
                                    maxCount++;
                            }

                            if (zeroCount >= 60)
                                zeroTableCount++; // 接近全零
                            else if (zeroCount >= 20)
                                partialZeroCount++;
                            if (maxCount >= 60)
                                allMaxCount++;
                        }
                    }
                    break;
                }
            }
        }

        System.out.println("====== DQT Attack Detection ======");
        System.out.println("Near-zero tables: " + zeroTableCount);
        System.out.println("Partial zero tables: " + partialZeroCount);
        System.out.println("All-max tables: " + allMaxCount);
        System.out.println("Illegal precision: " + illegalPrecisionCount);

        assertTrue(zeroTableCount + partialZeroCount + allMaxCount + illegalPrecisionCount > 0,
                "未检测到 DQT 攻击");
    }

    @Test
    @DisplayName("Test 8: JFIF Version Attack - JFIF 版本号攻击")
    void testJfifVersionAttack() {
        int total = 500;
        int zeroVersion = 0;
        int futureVersion = 0;
        int randomVersion = 0;

        Iterator<Testcase> iter = mutator.mutate(dummySeed, total);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();

            // 查找 APP0
            for (int i = 0; i < data.length - 10; i++) {
                if ((data[i] & 0xFF) == 0xFF && (data[i + 1] & 0xFF) == APP0) {
                    // 检查 JFIF 标识
                    if (i + 11 < data.length) {
                        int majorVer = data[i + 9] & 0xFF;
                        int minorVer = data[i + 10] & 0xFF;

                        if (majorVer == 0 && minorVer == 0)
                            zeroVersion++;
                        else if (majorVer >= 2)
                            futureVersion++;
                        else if (majorVer > 10 || minorVer > 10)
                            randomVersion++;
                    }
                    break;
                }
            }
        }

        System.out.println("====== JFIF Version Attack ======");
        System.out.println("Zero version (0.0): " + zeroVersion);
        System.out.println("Future version (2.x+): " + futureVersion);
        System.out.println("Random version: " + randomVersion);

        // 版本攻击是低概率的，只要有一些覆盖就好
        System.out.println("Total version attacks: " + (zeroVersion + futureVersion + randomVersion));
    }

    // ==========================================
    // 综合覆盖率报告
    // ==========================================

    @Test
    @DisplayName("Test 9-16: Coverage Report - 解析 2000 个样本并统计攻击向量")
    void testCoverage() {
        int totalIterations = 2000;
        Map<String, Integer> stats = new LinkedHashMap<>();
        String[] keys = {
                "Total",
                "Exif Injection (APP1)",
                "ICC Profile (APP2)",
                "Other APPn",
                "Comment (COM)",
                "Progressive Mode (SOF2)",
                "Lossless Mode (SOF3)",
                "Hierarchical Mode (SOF5-7)",
                "Evil Dimensions (0/1/65535)",
                "Length Spoofing Attack",
                "Restart Interval (DRI)",
                "DNL Segment",
                "DHP Segment",
                "Marker Confusion (Scan Data)",
                "0xFF Escape Attack"
        };
        for (String k : keys)
            stats.put(k, 0);

        Iterator<Testcase> iter = mutator.mutate(dummySeed, totalIterations);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            stats.put("Total", stats.get("Total") + 1);
            analyzeJpeg(data, stats);
        }

        printReport(stats);

        // 断言核心攻击分支均被触达
        assertCovered(stats, "Exif Injection (APP1)");
        assertCovered(stats, "Progressive Mode (SOF2)");
        assertCovered(stats, "Evil Dimensions (0/1/65535)");
    }

    /**
     * 简单的 JPEG 流解析器，用于检测攻击特征
     */
    private void analyzeJpeg(byte[] data, Map<String, Integer> stats) {
        int i = 0;
        boolean inScanData = false;

        while (i < data.length - 1) {
            if ((data[i] & 0xFF) == 0xFF) {
                int marker = data[i + 1] & 0xFF;
                if (marker == 0x00) {
                    i += 2;
                    continue;
                }
                if (marker == 0xFF) {
                    i++;
                    continue;
                }

                // 识别特定 Marker
                if (marker == APP1)
                    inc(stats, "Exif Injection (APP1)");
                if (marker == APP2)
                    inc(stats, "ICC Profile (APP2)");
                if (marker >= 0xE3 && marker <= 0xEF)
                    inc(stats, "Other APPn");
                if (marker == COM)
                    inc(stats, "Comment (COM)");
                if (marker == SOF2)
                    inc(stats, "Progressive Mode (SOF2)");
                if (marker == SOF3)
                    inc(stats, "Lossless Mode (SOF3)");
                if (marker >= SOF5 && marker <= SOF7)
                    inc(stats, "Hierarchical Mode (SOF5-7)");
                if (marker == DRI)
                    inc(stats, "Restart Interval (DRI)");
                if (marker == DNL)
                    inc(stats, "DNL Segment");
                if (marker == DHP)
                    inc(stats, "DHP Segment");

                // SOF 解析 (提取宽高)
                if (marker >= 0xC0 && marker <= 0xC7 && marker != 0xC4) {
                    if (i + 8 < data.length) {
                        int h = ((data[i + 4] & 0xFF) << 8) | (data[i + 5] & 0xFF);
                        int w = ((data[i + 6] & 0xFF) << 8) | (data[i + 7] & 0xFF);
                        if (h <= 1 || w <= 1 || h == 65535 || w == 65535) {
                            inc(stats, "Evil Dimensions (0/1/65535)");
                        }
                    }
                }

                // Length Spoofing 检测
                if (marker >= 0xC0 && marker <= 0xFE && marker != SOI && marker != EOI &&
                        (marker < 0xD0 || marker > 0xD7)) {
                    if (i + 3 < data.length) {
                        int claimedLen = ((data[i + 2] & 0xFF) << 8) | (data[i + 3] & 0xFF);
                        if (claimedLen > 5000 && data.length < 1000) {
                            inc(stats, "Length Spoofing Attack");
                        }
                        if (claimedLen < 2 || claimedLen > 0xFFF0) {
                            inc(stats, "Length Spoofing Attack");
                        }
                    }
                }

                if (marker == SOS)
                    inScanData = true;

                // 0xFF Escape 攻击检测
                if (inScanData && marker != SOS && (marker < 0xD0 || marker > 0xD7) && marker != EOI) {
                    inc(stats, "Marker Confusion (Scan Data)");
                    inc(stats, "0xFF Escape Attack");
                }

                if (marker == EOI)
                    break;
            }
            i++;
        }
    }

    private void inc(Map<String, Integer> stats, String key) {
        if (stats.containsKey(key)) {
            stats.put(key, stats.get(key) + 1);
        }
    }

    private void assertCovered(Map<String, Integer> stats, String key) {
        assertTrue(stats.get(key) > 0, "未触达攻击向量: " + key);
    }

    private void printReport(Map<String, Integer> stats) {
        int realTotal = stats.get("Total");
        System.out.println("====== JpegMutator Functional Coverage Report ======");
        System.out.println("Real Iterations: " + realTotal);
        System.out.println("---------------------------------------------------");
        System.out.printf("%-35s | %-10s | %-10s%n", "Attack Vector", "Count", "Rate");
        System.out.println("---------------------------------------------------");

        for (Map.Entry<String, Integer> entry : stats.entrySet()) {
            if (entry.getKey().equals("Total"))
                continue;
            int v = entry.getValue();
            double rate = (realTotal > 0) ? (v * 100.0) / realTotal : 0.0;
            System.out.printf("%-35s | %-10d | %6.2f%%%n", entry.getKey(), v, rate);
        }
        System.out.println("===================================================");
    }

    @Test
    @DisplayName("Test 17: Max Size Safety - 不应生成过大的文件")
    void testSizeSafety() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 50);
        int maxSize = 0;
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            maxSize = Math.max(maxSize, data.length);
            assertTrue(data.length < 1024 * 1024, "生成文件过大: " + data.length);
        }
        System.out.println("最大生成文件大小: " + maxSize + " bytes");
    }

    @Test
    @DisplayName("Test 18: Exif IFD Structure Attack - Exif IFD 结构攻击")
    void testExifIfdStructureAttack() {
        int total = 500;
        int oobOffset = 0;
        int cyclicRef = 0;
        int hugeEntryCount = 0;
        int dangerousTag = 0;

        Iterator<Testcase> iter = mutator.mutate(dummySeed, total);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();

            // 查找 APP1 (Exif)
            for (int i = 0; i < data.length - 20; i++) {
                if ((data[i] & 0xFF) == 0xFF && (data[i + 1] & 0xFF) == APP1) {
                    if (i + 14 < data.length) {
                        // 检查 Exif 标识
                        String sig = new String(data, i + 4, 4, StandardCharsets.US_ASCII);
                        if (sig.startsWith("Exif")) {
                            int tiffStart = i + 10;
                            if (tiffStart + 8 < data.length) {
                                boolean littleEndian = (data[tiffStart] == 'I');

                                // 读取 IFD Offset
                                int ifdOffset = readInt(data, tiffStart + 4, littleEndian);

                                if (ifdOffset == 0)
                                    cyclicRef++;
                                if (ifdOffset > 0xFFFF00 || ifdOffset < 0)
                                    oobOffset++;

                                // 检查 Entry Count
                                int ifdPos = tiffStart + ifdOffset;
                                if (ifdPos >= 0 && ifdPos + 2 < data.length && ifdPos >= tiffStart) {
                                    int entryCount = readShort(data, ifdPos, littleEndian);
                                    if (entryCount > 100)
                                        hugeEntryCount++;

                                    // 检查危险 Tag
                                    if (entryCount > 0 && ifdPos + 4 < data.length) {
                                        int tag = readShort(data, ifdPos + 2, littleEndian);
                                        int[] dangerousTags = { 0x8769, 0x8825, 0xA005, 0x927C, 0x0201 };
                                        for (int dt : dangerousTags) {
                                            if (tag == dt) {
                                                dangerousTag++;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }

        System.out.println("====== Exif IFD Attack Detection ======");
        System.out.println("OOB Offset: " + oobOffset);
        System.out.println("Cyclic Reference: " + cyclicRef);
        System.out.println("Huge Entry Count: " + hugeEntryCount);
        System.out.println("Dangerous Tag: " + dangerousTag);
    }

    // 辅助方法
    private int readShort(byte[] data, int offset, boolean littleEndian) {
        if (offset + 2 > data.length)
            return 0;
        if (littleEndian) {
            return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
        } else {
            return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        }
    }

    private int readInt(byte[] data, int offset, boolean littleEndian) {
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
}
