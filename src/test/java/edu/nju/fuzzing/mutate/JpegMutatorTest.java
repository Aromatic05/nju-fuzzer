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
 * 3. 统计报告 (可视化展示算法多样性)
 */
class JpegMutatorTest {

    private Seed dummySeed;
    private JpegMutator mutator;

    // JPEG Markers
    private static final int SOI = 0xD8;
    private static final int EOI = 0xD9;
    private static final int SOF0 = 0xC0;
    private static final int SOF2 = 0xC2;
    private static final int APP1 = 0xE1;
    private static final int SOS = 0xDA;
    private static final int DRI = 0xDD;

    @BeforeEach
    void setUp() {
        dummySeed = Seed.loadWithMetadata(new File("dummy_jpeg"), new byte[0]);
        mutator = new JpegMutator();
    }

    // ==========================================
    // 基础功能测试
    // ==========================================

    @Test
    @DisplayName("Test 1: SOI/EOI - 必须以 FF D8 开头并以 FF D9 结尾")
    void testBoundary() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            assertTrue(data.length >= 4);

            // === 修正点：统一使用 int 进行比较 (通过 & 0xFF) ===

            // Start of Image: 0xFF 0xD8
            assertEquals(0xFF, data[0] & 0xFF);
            assertEquals(SOI, data[1] & 0xFF); // SOI 为 0xD8 (216), data[1]&0xFF 也是 216

            // End of Image: 0xFF 0xD9
            assertEquals(0xFF, data[data.length - 2] & 0xFF);
            assertEquals(EOI, data[data.length - 1] & 0xFF); // EOI 为 0xD9 (217)
        }
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

    // ==========================================
    // 结构分析与覆盖率报告
    // ==========================================

    @Test
    @DisplayName("Test 3-10: Coverage Report - 解析 2000 个样本并统计攻击向量")
    void testCoverage() {
        int totalIterations = 2000;
        Map<String, Integer> stats = new HashMap<>();
        String[] keys = {
                "Total", "Exif Injection (APP1)", "Progressive Mode (SOF2)",
                "Evil Dimensions (0/1/65535)", "Length Spoofing Attack",
                "Restart Interval (DRI)", "Marker Confusion (Scan Data)"
        };
        for (String k : keys) stats.put(k, 0);

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
        assertCovered(stats, "Length Spoofing Attack");
        assertCovered(stats, "Evil Dimensions (0/1/65535)");
    }

    /**
     * 简单的 JPEG 流解析器，用于检测攻击特征
     */
    private void analyzeJpeg(byte[] data, Map<String, Integer> stats) {
        int i = 0;
        boolean inScanData = false;

        while (i < data.length - 1) {
            // 查找 Marker (0xFF 后面跟一个非 0x00 的字节)
            if ((data[i] & 0xFF) == 0xFF) {
                int marker = data[i + 1] & 0xFF;
                if (marker == 0x00) {
                    i += 2; continue; // 转义字节
                }
                if (marker == 0xFF) {
                    i++; continue; // 连续 FF
                }

                // 识别特定 Marker
                if (marker == APP1) inc(stats, "Exif Injection (APP1)");
                if (marker == SOF2) inc(stats, "Progressive Mode (SOF2)");
                if (marker == DRI)  inc(stats, "Restart Interval (DRI)");

                // SOF 解析 (提取宽高)
                if (marker == SOF0 || marker == SOF2) {
                    if (i + 8 < data.length) {
                        int h = ((data[i + 4] & 0xFF) << 8) | (data[i + 5] & 0xFF);
                        int w = ((data[i + 6] & 0xFF) << 8) | (data[i + 7] & 0xFF);
                        if (h <= 1 || w <= 1 || h == 65535 || w == 65535) {
                            inc(stats, "Evil Dimensions (0/1/65535)");
                        }
                    }
                }

                // Length Spoofing 检测
                // 大多数 Marker 后面跟着 2 字节长度 (除了 SOI, EOI, RSTn, TEM)
                if (marker >= 0xC0 && marker <= 0xFE && marker != SOI && marker != EOI && (marker < 0xD0 || marker > 0xD7)) {
                    if (i + 3 < data.length) {
                        int claimedLen = ((data[i + 2] & 0xFF) << 8) | (data[i + 3] & 0xFF);
                        // 如果声明长度 > 剩余数据长度，或者后面紧跟了另一个不该出现的 Marker
                        // 这里通过判断 Mutation 逻辑中的偏移来识别
                        // 由于很难从二进制绝对判断是否是“欺骗”，我们根据变异器特征：
                        // 当声明长度远大于实际填充的数据时记录
                        if (claimedLen > 5000 && data.length < 1000) {
                            inc(stats, "Length Spoofing Attack");
                        }
                    }
                }

                // 标记进入扫描数据区
                if (marker == SOS) inScanData = true;

                // 如果在扫描区发现了未转义的 0xFF (非 RST 标记)，计入 Marker Confusion
                if (inScanData && marker != SOS && (marker < 0xD0 || marker > 0xD7) && marker != EOI) {
                    inc(stats, "Marker Confusion (Scan Data)");
                }

                if (marker == EOI) break;
            }
            i++;
        }
    }

    private void inc(Map<String, Integer> stats, String key) {
        stats.put(key, stats.get(key) + 1);
    }

    private void assertCovered(Map<String, Integer> stats, String key) {
        assertTrue(stats.get(key) > 0, "未触达攻击向量: " + key);
    }

    private void printReport(Map<String, Integer> stats) {
        int realTotal = stats.get("Total");
        System.out.println("====== JpegMutator Functional Coverage Report ======");
        System.out.println("Real Iterations: " + realTotal);
        System.out.println("---------------------------------------------------");
        System.out.printf("%-30s | %-10s | %-10s%n", "Attack Vector", "Count", "Rate");
        System.out.println("---------------------------------------------------");

        String[] order = {
                "Exif Injection (APP1)", "Progressive Mode (SOF2)",
                "Evil Dimensions (0/1/65535)", "Length Spoofing Attack",
                "Restart Interval (DRI)", "Marker Confusion (Scan Data)"
        };

        for (String k : order) {
            int v = stats.get(k);
            double rate = (realTotal > 0) ? (v * 100.0) / realTotal : 0.0;
            System.out.printf("%-30s | %-10d | %6.2f%%%n", k, v, rate);
        }
        System.out.println("===================================================");
    }

    @Test
    @DisplayName("Test 11: Max Size Safety - 不应生成过大的文件")
    void testSizeSafety() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 50);
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            // JPEG segment max is 64KB, with multiple segments, a few hundred KB is expected.
            // But it shouldn't be MBs for a simple mutator.
            assertTrue(data.length < 1024 * 1024, "生成文件过大: " + data.length);
        }
    }
}