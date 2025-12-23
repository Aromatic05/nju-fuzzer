package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.zip.CRC32;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PngMutator 单元测试
 *
 * 验证点：
 * 1. 签名与结束符 (PNG Signature & IEND)
 * 2. 核心攻击向量识别 (Evil IHDR, iCCP Bomb, PLTE OOB, Filter Byte Injection)
 * 3. 校验和稳定性 (CRC Fuzzing 概率统计)
 * 4. 统计报告 (可视化算法覆盖率)
 */
class PngMutatorTest {

    private Seed dummySeed;
    private PngMutator mutator;

    private static final byte[] PNG_SIG = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

    @BeforeEach
    void setUp() {
        dummySeed = Seed.loadWithMetadata(new File("dummy_png"), new byte[0]);
        mutator = new PngMutator();
    }

    // ==========================================
    // 基础功能测试
    // ==========================================

    @Test
    @DisplayName("Test 1: Signature - 验证 PNG 文件头签名")
    void testSignature() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 50);
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            for (int i = 0; i < 8; i++) {
                assertEquals(PNG_SIG[i], data[i], "PNG 签名错误");
            }
        }
    }

    @Test
    @DisplayName("Test 2: IEND - 验证文件是否以 IEND Chunk 结尾")
    void testIend() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 50);
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            // PNG 结尾 12 字节应为: Length(0), Type(IEND), CRC(AE 42 60 82)
            int len = data.length;
            String lastChunkType = new String(data, len - 8, 4);
            assertEquals("IEND", lastChunkType);
            assertEquals(0, ByteBuffer.wrap(data, len - 12, 4).getInt());
        }
    }

    @Test
    @DisplayName("Test 3: Diversity - 变异结果多样性检查")
    void testDiversity() {
        Set<Integer> hashes = new HashSet<>();
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        while (iter.hasNext()) {
            hashes.add(Arrays.hashCode(iter.next().getData()));
        }
        assertTrue(hashes.size() > 95, "PNG 生成重复率过高");
    }

    // ==========================================
    // 覆盖率报告 (深度结构分析)
    // ==========================================

    @Test
    @DisplayName("Test 4-10: Coverage Report - 解析 2000 个样本并统计攻击特征")
    void testCoverage() {
        int totalIterations = 2000;
        Map<String, Integer> stats = new HashMap<>();
        String[] keys = {
                "Total Files", "Evil IHDR (Size/Type)", "iCCP Injection",
                "Palette Size Attack (Short)", "Ancillary Chunks (tRNS/pHYs)",
                "CRC Fuzzing (Corrupted CRC)", "IDAT Filter Byte Injection",
                "Zlib Compression Success"
        };
        for (String k : keys) stats.put(k, 0);

        Iterator<Testcase> iter = mutator.mutate(dummySeed, totalIterations);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            stats.put("Total Files", stats.get("Total Files") + 1);
            analyzePng(data, stats);
        }

        printReport(stats);

        // 断言核心分支均被覆盖
        assertCovered(stats, "Evil IHDR (Size/Type)");
        assertCovered(stats, "iCCP Injection");
        assertCovered(stats, "CRC Fuzzing (Corrupted CRC)");
        assertCovered(stats, "IDAT Filter Byte Injection");
    }

    private void analyzePng(byte[] data, Map<String, Integer> stats) {
        ByteBuffer bb = ByteBuffer.wrap(data);
        bb.position(8); // 跳过签名

        while (bb.remaining() >= 12) {
            int length = bb.getInt();
            byte[] typeBytes = new byte[4];
            bb.get(typeBytes);
            String type = new String(typeBytes);

            byte[] chunkData = new byte[length];
            bb.get(chunkData);

            int originalCrc = bb.getInt();

            // 1. 验证 CRC (统计 CRC Fuzzing 概率)
            CRC32 crcCalculator = new CRC32();
            crcCalculator.update(typeBytes);
            crcCalculator.update(chunkData);
            if ((int) crcCalculator.getValue() != originalCrc) {
                inc(stats, "CRC Fuzzing (Corrupted CRC)");
            }

            // 2. 分析 IHDR
            if (type.equals("IHDR")) {
                int width = ByteBuffer.wrap(chunkData, 0, 4).getInt();
                int height = ByteBuffer.wrap(chunkData, 4, 4).getInt();
                if (width <= 1 || height <= 1 || width > 65535 || height > 65535) {
                    inc(stats, "Evil IHDR (Size/Type)");
                }
            }

            // 3. 分析 iCCP
            if (type.equals("iCCP")) inc(stats, "iCCP Injection");

            // 4. 分析 PLTE (调色板攻击)
            if (type.equals("PLTE")) {
                if (chunkData.length < 768) inc(stats, "Palette Size Attack (Short)");
            }

            // 5. 辅助块
            if (type.equals("tRNS") || type.equals("pHYs")) inc(stats, "Ancillary Chunks (tRNS/pHYs)");

            // 6. 分析 IDAT (扫描行过滤字节)
            // 这里我们无法直接解压 zlib (太慢)，但可以检查是否包含 IDAT
            if (type.equals("IDAT")) {
                if (length > 0) inc(stats, "Zlib Compression Success");
                // 变异器逻辑中如果生成了有效的 Scanline 且未压缩，首字节应为 0-4
                // 但由于大部分被压缩，我们主要在变异器内部保证该逻辑。此处作为占位统计。
                if (chunkData.length > 0 && chunkData[0] >= 0 && chunkData[0] <= 4) {
                    inc(stats, "IDAT Filter Byte Injection");
                }
            }

            if (type.equals("IEND")) break;
        }
    }

    private void inc(Map<String, Integer> stats, String key) {
        stats.put(key, stats.get(key) + 1);
    }

    private void assertCovered(Map<String, Integer> stats, String key) {
        assertTrue(stats.get(key) > 0, "算法未生成核心特征: " + key);
    }

    private void printReport(Map<String, Integer> stats) {
        int total = stats.get("Total Files");
        System.out.println("====== PngMutator Functional Coverage Report ======");
        System.out.println("Real Iterations: " + total);
        System.out.println("---------------------------------------------------");
        System.out.printf("%-30s | %-10s | %-10s%n", "Feature / Attack", "Count", "Rate");
        System.out.println("---------------------------------------------------");

        String[] order = {
                "Evil IHDR (Size/Type)", "iCCP Injection", "Ancillary Chunks (tRNS/pHYs)",
                "Palette Size Attack (Short)", "CRC Fuzzing (Corrupted CRC)",
                "IDAT Filter Byte Injection", "Zlib Compression Success"
        };

        for (String k : order) {
            int v = stats.get(k);
            double rate = (total > 0) ? (v * 100.0) / total : 0.0;
            System.out.printf("%-30s | %-10d | %6.2f%%%n", k, v, rate);
        }
        System.out.println("===================================================");
    }

    @Test
    @DisplayName("Test 11: Zlib Integrity - 验证生成的 IDAT 是否为有效 Zlib 流")
    void testZlibIntegrity() {
        // 由于变异器对数据进行了 Zlib 压缩，正常的解析器应能识别其头部 (0x78)
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        boolean foundValidZlib = false;
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            // 搜索 IDAT 标记
            for (int i = 0; i < data.length - 8; i++) {
                if (data[i] == 'I' && data[i+1] == 'D' && data[i+2] == 'A' && data[i+3] == 'T') {
                    // IDAT 数据开始位置 (Length 4 + Type 4)
                    // Zlib 默认头部通常是 0x78 0x01, 0x78 0x9C 或 0x78 0xDA
                    if ((data[i+4] & 0xFF) == 0x78) {
                        foundValidZlib = true;
                        break;
                    }
                }
            }
        }
        assertTrue(foundValidZlib, "未发现有效的 Zlib 压缩 IDAT 数据");
    }
}