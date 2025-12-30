package edu.nju.fuzzing.mutate;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

/**
 * ElfMutator 单元测试
 *
 * 包含：
 * 1. 基础格式校验 (Magic Number)
 * 2. 结构内容校验 (String Table 存在性)
 * 3. 攻击向量统计 (Allocation Bomb, PT_NOTE, OOB, Circular Link)
 * 4. 可视化覆盖率报告
 */
class ElfMutatorTest {

    private Seed dummySeed;
    private ElfMutator mutator;

    // ELF Header Offsets (64-bit)
    private static final int OFF_E_PHOFF = 32;
    private static final int OFF_E_SHOFF = 40;
    private static final int OFF_E_PHNUM = 56;
    private static final int OFF_E_SHNUM = 60;


    // ==========================================
    // 基础功能测试
    // ==========================================

    @Test
    @DisplayName("Test 1: Magic Bytes - 必须以 0x7F ELF 开头")
    void testMagic() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            assertEquals(0x7F, data[0]);
            assertEquals('E', data[1]);
            assertEquals('L', data[2]);
            assertEquals('F', data[3]);
        }
    }

    @Test
    @DisplayName("Test 2: Basic Headers - 必须是 64位 Little Endian")
    void testBasicHeaders() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 50);
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            // EI_CLASS = 2 (64-bit)
            assertEquals(2, data[4], "应为 64-bit ELF");
            // EI_DATA = 1 (Little Endian)
            assertEquals(1, data[5], "应为 Little Endian");
        }
    }

    @Test
    @DisplayName("Test 3: String Table Presence - 字符串表内容应存在")
    void testStringTable() {
        // 验证生成的 ELF 中确实包含段名字符串，如 ".text", ".shstrtab"
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 50);
        boolean foundText = false;
        boolean foundShstrtab = false;

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            String rawContent = new String(data, StandardCharsets.ISO_8859_1);
            if (rawContent.contains(".text")) foundText = true;
            if (rawContent.contains(".shstrtab")) foundShstrtab = true;
        }

        assertTrue(foundText, "生成的 ELF 应包含 .text 字符串");
        assertTrue(foundShstrtab, "生成的 ELF 应包含 .shstrtab 字符串");
    }

    // ==========================================
    // 深度结构分析与覆盖率报告
    // ==========================================

    @Test
    @DisplayName("Test 4-10: Coverage Report - 解析 2000 个样本并统计攻击向量")
    void testCoverage() {
        int totalIterations = 2000;
        Map<String, Integer> stats = new HashMap<>();
        String[] keys = {
                "Total", "Allocation Bomb (Phdr)", "Allocation Bomb (Shdr)",
                "PT_NOTE Attack", "OOB Offset (Header)", "Circular Link (Shdr)",
                "Valid Structure"
        };
        for (String k : keys) stats.put(k, 0);

        // 传入 2000，Mutator 应该返回 2000 个用例，足够触发 2%~5% 概率的攻击向量
        Iterator<Testcase> iter = mutator.mutate(dummySeed, totalIterations);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            stats.put("Total", stats.get("Total") + 1);
            analyzeElf(data, stats);
        }

        printReport(stats);

        // 断言：在 2000 次运行中，这些概率事件至少发生一次
        assertCovered(stats, "Allocation Bomb (Phdr)");
        assertCovered(stats, "PT_NOTE Attack");
        assertCovered(stats, "Circular Link (Shdr)");
        assertCovered(stats, "OOB Offset (Header)");
    }

    /**
     * 简单的 ELF 解析器，用于提取特征
     */
    private void analyzeElf(byte[] data, Map<String, Integer> stats) {
        if (data.length < 64) return; // Header incomplete

        ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        // 1. Check Allocation Bombs (0xFFFF)
        short phnum = bb.getShort(OFF_E_PHNUM);
        short shnum = bb.getShort(OFF_E_SHNUM);

        if ((phnum & 0xFFFF) == 0xFFFF) inc(stats, "Allocation Bomb (Phdr)");
        if ((shnum & 0xFFFF) == 0xFFFF) inc(stats, "Allocation Bomb (Shdr)");

        // 2. Check OOB Offsets
        long phoff = bb.getLong(OFF_E_PHOFF);
        long shoff = bb.getLong(OFF_E_SHOFF);

        // 如果偏移量是负数(-1)或者远超文件大小
        if (phoff < 0 || phoff > data.length + 1000 || shoff < 0 || shoff > data.length + 1000) {
            inc(stats, "OOB Offset (Header)");
        }

        // 3. Analyze Program Headers (Find PT_NOTE)
        // 只有当偏移量看似合法时才尝试解析
        if (phoff >= 64 && phoff + 56 <= data.length) {
            try {
                int limit = Math.min(phnum & 0xFFFF, 10); // 只看前10个防止卡死
                for (int i = 0; i < limit; i++) {
                    int pos = (int) phoff + i * 56;
                    if (pos + 4 > data.length) break;
                    int type = bb.getInt(pos);
                    if (type == 4) { // PT_NOTE
                        inc(stats, "PT_NOTE Attack");
                        break;
                    }
                }
            } catch (Exception ignored) {}
        }

        // 4. Analyze Section Headers (Find Circular Links)
        if (shoff >= 64 && shoff + 64 <= data.length) {
            inc(stats, "Valid Structure"); // 标记为结构基本合法
            try {
                int limit = Math.min(shnum & 0xFFFF, 10);
                for (int i = 0; i < limit; i++) {
                    int pos = (int) shoff + i * 64;
                    if (pos + 44 > data.length) break;
                    int link = bb.getInt(pos + 40); // sh_link offset

                    // 如果链接指向自己，或者是 Section 1 指向 0, 0 指向 1 的简单环
                    // 这里的判断比较简略，主要看 sh_link 是否非零且怪异
                    if (link == i || (i == 0 && link == 1)) {
                        inc(stats, "Circular Link (Shdr)");
                        break;
                    }
                }
            } catch (Exception ignored) {}
        }
    }

    private void inc(Map<String, Integer> stats, String key) {
        stats.put(key, stats.get(key) + 1);
    }

    private void assertCovered(Map<String, Integer> stats, String key) {
        assertTrue(stats.get(key) > 0, "Warning: 未生成 " + key);
    }

    private void printReport(Map<String, Integer> stats) {
        int realTotal = stats.get("Total");
        System.out.println("====== ElfMutator Functional Coverage Report ======");
        System.out.println("Real Iterations: " + realTotal);
        System.out.println("---------------------------------------------------");
        System.out.printf("%-25s | %-10s | %-10s%n", "Attack Vector / Feature", "Count", "Rate");
        System.out.println("---------------------------------------------------");

        String[] order = {
                "Valid Structure", "Allocation Bomb (Phdr)", "Allocation Bomb (Shdr)",
                "PT_NOTE Attack", "OOB Offset (Header)", "Circular Link (Shdr)"
        };

        for (String k : order) {
            int v = stats.get(k);
            double rate = (realTotal > 0) ? (v * 100.0) / realTotal : 0.0;
            System.out.printf("%-25s | %-10d | %6.2f%%%n", k, v, rate);
        }
        System.out.println("===================================================");
    }

    // ==========================================
    // 边界与多样性测试
    // ==========================================

    @Test
    @DisplayName("Test 11: Diversity - 生成结果应具有多样性")
    void testDiversity() {
        Set<String> hashes = new HashSet<>();
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            // 使用简单的 Arrays.hashCode 或转 String 来去重
            hashes.add(Arrays.toString(data));
        }
        assertTrue(hashes.size() > 50, "ELF 生成多样性不足: " + hashes.size());
    }

    @Test
    @DisplayName("Test 12: Minimum Size - 所有的 ELF 至少应包含 Header")
    void testMinSize() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        while(iter.hasNext()) {
            byte[] data = iter.next().getData();
            assertTrue(data.length >= 64, "生成的 ELF 长度不足 64 字节");
        }
    }

    @Test
    @DisplayName("Test 13: Exception Safety - 解析随机数据不应抛出异常")
    void testSafeParsing() {
        // 这个测试实际上是在运行 testCoverage 时隐式包含的
        // 但这里显式强调一下，我们不希望 Mutator 生成让 Java 抛出 BufferUnderflow 的数据
        // (虽然数据本身是畸形的，但生成过程应该是安全的)
        assertDoesNotThrow(() -> {
            Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
            while(iter.hasNext()) {
                iter.next();
            }
        });
    }
}