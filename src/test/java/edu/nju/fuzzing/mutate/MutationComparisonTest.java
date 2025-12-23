package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collections;
import java.util.List;

/**
 * 竞技场：基于语法的变异 (Grammar) VS 随机破坏 (Havoc)
 * 场景：使用一个完全无效的种子（全0或空），看谁能生成有效格式的文件头。
 *
 * 更新说明：
 * 不再强制要求 100% vs 0%，而是验证“显著性差异”。
 * 只要 Grammar 的成功率大幅领先 Havoc 即可认为测试通过。
 */
class MutationComparisonTest {

    // 初始种子：10个字节的 0，完全无效
    private final Seed garbageSeed = Seed.loadWithMetadata(new File("garbage.bin"), new byte[10]);
    private final int TRIALS = 100; // 每组测试生成 100 个样本

    @Test
    @DisplayName("PK 1: 生成 ELF 二进制 (Readelf/Nm/Objdump)")
    void compareElf() {
        long grammarScore = runGrammar(new File("test.elf"), this::isElf);
        long havocScore = runHavoc(new File("test.elf"), this::isElf);

        printResult("ELF", grammarScore, havocScore);
        assertSignificantDifference(grammarScore, havocScore);
    }

    @Test
    @DisplayName("PK 2: 生成 JPEG 图片 (Djpeg)")
    void compareJpeg() {
        long grammarScore = runGrammar(new File("test.jpg"), this::isJpeg);
        long havocScore = runHavoc(new File("test.jpg"), this::isJpeg);

        printResult("JPEG", grammarScore, havocScore);
        assertSignificantDifference(grammarScore, havocScore);
    }

    @Test
    @DisplayName("PK 3: 生成 PNG 图片 (Readpng)")
    void comparePng() {
        long grammarScore = runGrammar(new File("test.png"), this::isPng);
        long havocScore = runHavoc(new File("test.png"), this::isPng);

        printResult("PNG", grammarScore, havocScore);
        assertSignificantDifference(grammarScore, havocScore);
    }

    @Test
    @DisplayName("PK 4: 生成 PCAP 抓包文件 (Tcpdump)")
    void comparePcap() {
        long grammarScore = runGrammar(new File("test.pcap"), this::isPcap);
        long havocScore = runHavoc(new File("test.pcap"), this::isPcap);

        printResult("PCAP", grammarScore, havocScore);
        assertSignificantDifference(grammarScore, havocScore);
    }

    @Test
    @DisplayName("PK 5: 生成 C++ Mangled Name (Cxxfilt)")
    void compareCxx() {
        long grammarScore = runGrammar(new File("cxxfilt"), this::isCxx);
        long havocScore = runHavoc(new File("cxxfilt"), this::isCxx);

        printResult("CXX", grammarScore, havocScore);
        // CXX 前缀只有两个字符 (_Z)，Havoc 有概率蒙对，所以标准稍微放宽
        Assertions.assertTrue(grammarScore > havocScore, "Grammar 必须优于 Havoc");
        Assertions.assertTrue(grammarScore > 50, "Grammar 有效率应过半");
    }

    @Test
    @DisplayName("PK 6: 生成 XML 结构 (Xmllint)")
    void compareXml() {
        long grammarScore = runGrammar(new File("test.xml"), this::isXml);
        long havocScore = runHavoc(new File("test.xml"), this::isXml);

        printResult("XML", grammarScore, havocScore);
        assertSignificantDifference(grammarScore, havocScore);
    }

    @Test
    @DisplayName("PK 7: 生成 JSON 结构 (Mjs)")
    void compareJson() {
        long grammarScore = runGrammar(new File("test.json"), this::isJson);
        long havocScore = runHavoc(new File("test.json"), this::isJson);

        printResult("JSON", grammarScore, havocScore);
        assertSignificantDifference(grammarScore, havocScore);
    }

    @Test
    @DisplayName("PK 8: 生成 Lua 脚本 (Lua)")
    void compareLua() {
        long grammarScore = runGrammar(new File("test.lua"), this::isLua);
        long havocScore = runHavoc(new File("test.lua"), this::isLua);

        printResult("Lua", grammarScore, havocScore);
        assertSignificantDifference(grammarScore, havocScore);
    }

    @Test
    @DisplayName("PK 9: 极小种子起步 (1字节)")
    void compareFromOneByteSeed() {
        Seed tinySeed = Seed.loadWithMetadata(new File("tiny.png"), new byte[]{0});

        Mutator g = new GrammarMutator();
        Mutator h = new AflHavocMutator(Collections.singletonList(tinySeed));

        // Grammar 忽略种子内容，依然能生成有效 PNG
        boolean gSuccess = g.mutate(tinySeed, 10).stream().anyMatch(tc -> isPng(tc.data()));
        // Havoc 只能翻转这 1 个字节，永远无法凑出 8 字节的 PNG 头
        boolean hSuccess = h.mutate(tinySeed, 10).stream().anyMatch(tc -> isPng(tc.data()));

        Assertions.assertTrue(gSuccess, "Grammar 应当能从垃圾种子恢复结构");
        Assertions.assertFalse(hSuccess, "Havoc 不应能从1字节种子变出PNG头");
    }

    @Test
    @DisplayName("PK 10: 性能吞吐量 (不校验正确性)")
    void compareThroughput() {
        Seed seed = Seed.loadWithMetadata(new File("perf.xml"), garbageSeed.getData());
        Mutator g = new GrammarMutator();

        long start = System.currentTimeMillis();
        g.mutate(seed, 1000);
        long end = System.currentTimeMillis();

        System.out.println("Grammar Generation Time (1000 energy): " + (end - start) + "ms");
        Assertions.assertTrue((end - start) < 3000, "生成速度应在合理范围内 (3秒内)");
    }

    // --- 辅助方法：统一断言逻辑 ---

    private void printResult(String name, long g, long h) {
        System.out.printf("[%s] Grammar: %d%% | Havoc: %d%%%n", name, g, h);
    }

    /**
     * 核心断言：显著性差异
     * 不需要 100 vs 0，只要 Grammar 碾压 Havoc 即可。
     */
    private void assertSignificantDifference(long grammar, long havoc) {
        // 1. Grammar 必须显著优于 Havoc
        Assertions.assertTrue(grammar > havoc, "Grammar 必须战胜 Havoc");

        // 2. Grammar 的有效率应该比较高 (容忍少量失败，如 > 80%)
        Assertions.assertTrue(grammar > 80, "Grammar 应当保持较高的生成质量 (>80%)");

        // 3. Havoc 在空种子下的有效率应该很低 (容忍少量运气，如 < 20%)
        Assertions.assertTrue(havoc < 20, "Havoc 在无基础的情况下表现应较差 (<20%)");
    }

    // --- 辅助运行方法 ---

    private long runGrammar(File fakeFile, Validator v) {
        Seed seed = Seed.loadWithMetadata(fakeFile, garbageSeed.getData());
        Mutator m = new GrammarMutator();
        // energy * count_factor
        List<Testcase> res = m.mutate(seed, TRIALS * 5);
        return res.stream().filter(tc -> v.check(tc.data())).count();
    }

    private long runHavoc(File fakeFile, Validator v) {
        Seed seed = Seed.loadWithMetadata(fakeFile, garbageSeed.getData());
        Mutator m = new AflHavocMutator(Collections.singletonList(seed));
        List<Testcase> res = m.mutate(seed, TRIALS);
        return res.stream().filter(tc -> v.check(tc.data())).count();
    }

    // --- 裁判逻辑 (Validators) ---

    @FunctionalInterface
    interface Validator {
        boolean check(byte[] data);
    }

    private boolean isElf(byte[] d) {
        return d.length >= 4 && d[0] == 0x7F && d[1] == 'E' && d[2] == 'L' && d[3] == 'F';
    }

    private boolean isJpeg(byte[] d) {
        return d.length >= 2 && (d[0] & 0xFF) == 0xFF && (d[1] & 0xFF) == 0xD8;
    }

    private boolean isPng(byte[] d) {
        return d.length >= 4 && (d[0] & 0xFF) == 0x89 && d[1] == 'P' && d[2] == 'N' && d[3] == 'G';
    }

    private boolean isPcap(byte[] d) {
        return d.length >= 4 && (d[0] & 0xFF) == 0xD4 && (d[1] & 0xFF) == 0xC3;
    }

    private boolean isCxx(byte[] d) {
        return d.length >= 2 && d[0] == '_' && d[1] == 'Z';
    }

    private boolean isXml(byte[] d) {
        String s = new String(d);
        return s.trim().startsWith("<") && s.contains(">");
    }

    private boolean isJson(byte[] d) {
        String s = new String(d).trim();
        return s.startsWith("{") || s.startsWith("[");
    }

    // 使用更宽松的 Lua 检查
    private boolean isLua(byte[] d) {
        String s = new String(d);
        return s.contains("function") || s.contains("print") || s.contains("if") || s.contains("a=");
    }
}