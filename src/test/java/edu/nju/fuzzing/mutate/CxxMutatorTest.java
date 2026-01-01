package edu.nju.fuzzing.mutate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.nio.charset.StandardCharsets;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.grammar.CxxSyntaxChecker;

/**
 * CxxMutator 综合测试
 * 
 * 测试覆盖：
 * 1. 基本变异功能
 * 2. 语法检查集成
 * 3. 语法修复集成
 * 4. 语料库使用
 * 5. 攻击负载生成
 * 6. 各种问题修复验证
 */
public class CxxMutatorTest {

    @TempDir
    Path tempDir;

    private CxxMutator mutator;
    private int seedCounter = 0;

    @BeforeEach
    void setUp() {
        mutator = new CxxMutator();
        seedCounter = 0;
    }

    // Helper 方法：创建测试种子
    private Seed createSeed(String content) throws IOException {
        return createSeed(content.getBytes(StandardCharsets.UTF_8));
    }

    private Seed createSeed(byte[] data) throws IOException {
        File file = tempDir.resolve("seed_" + (seedCounter++) + ".txt").toFile();
        Files.write(file.toPath(), data);
        return Seed.loadWithMetadata(file, data);
    }

    // Helper 方法：收集变异结果
    private List<Testcase> collectMutations(Seed seed, int energy) {
        List<Testcase> results = new ArrayList<>();
        Iterator<Testcase> iter = mutator.mutate(seed, energy);
        while (iter.hasNext()) {
            results.add(iter.next());
        }
        return results;
    }

    // Helper 方法：提取 Testcase 数据为字符串
    private String getData(Testcase tc) {
        return new String(tc.getData(), StandardCharsets.UTF_8);
    }

    // ==========================================
    // 基本功能测试
    // ==========================================

    @Test
    void testMutateReturnsTestcases() throws IOException {
        Seed seed = createSeed("_Z4mainv");
        List<Testcase> results = collectMutations(seed, 5);

        assertEquals(5, results.size());
        for (Testcase tc : results) {
            assertNotNull(tc);
            assertNotNull(tc.getData());
            assertTrue(tc.getData().length > 0);
        }
    }

    @Test
    void testMutateEmptyInput() throws IOException {
        Seed seed = createSeed(new byte[0]);
        List<Testcase> results = collectMutations(seed, 3);

        assertEquals(3, results.size());
        // 应该返回一些有效数据（从语料库或生成）
        for (Testcase tc : results) {
            assertTrue(tc.getData().length > 0);
        }
    }

    @Test
    void testMutateDifferentOutputs() throws IOException {
        Seed seed = createSeed("_Z4funcv");
        Set<String> uniqueResults = new HashSet<>();

        List<Testcase> results = collectMutations(seed, 100);
        for (Testcase tc : results) {
            uniqueResults.add(getData(tc));
        }

        // 应该产生多种不同的变异结果
        assertTrue(uniqueResults.size() > 1, "Should produce varied mutations");
    }

    @Test
    void testMutatePreservesPrefix() throws IOException {
        // 当开启语法修复时，前缀应该被保留
        mutator.setEnforceSyntaxCorrectness(true);

        Seed seed = createSeed("_Z4mainv");
        List<Testcase> results = collectMutations(seed, 20);

        for (Testcase tc : results) {
            String result = getData(tc);
            assertTrue(result.startsWith("_Z"), "Should preserve _Z prefix: " + result);
        }
    }

    // ==========================================
    // 语法检查集成测试
    // ==========================================

    @Test
    void testCheckSyntaxValid() throws IOException {
        CxxSyntaxChecker.CheckResult result = mutator.checkSyntax("_Z4mainv");

        assertTrue(result.isValid);
        assertTrue(result.hasValidPrefix);
    }

    @Test
    void testCheckSyntaxInvalidPrefix() throws IOException {
        CxxSyntaxChecker.CheckResult result = mutator.checkSyntax("_X4mainv");

        assertFalse(result.hasValidPrefix);
    }

    @Test
    void testCheckSyntaxMissingE() throws IOException {
        CxxSyntaxChecker.CheckResult result = mutator.checkSyntax("_ZN3fooI4mainv");

        assertTrue(result.missingNestedE > 0 || result.missingTemplateE > 0);
    }

    @Test
    void testCheckSyntaxLengthMismatch() throws IOException {
        CxxSyntaxChecker.CheckResult result = mutator.checkSyntax("_Z10mainv");

        assertTrue(result.hasLengthMismatch);
    }

    // ==========================================
    // 语法修复集成测试
    // ==========================================

    @Test
    void testFixSyntaxMissingPrefix() throws IOException {
        String fixed = mutator.fixSyntax("4mainv");

        assertTrue(fixed.startsWith("_Z"));
    }

    @Test
    void testFixSyntaxMissingE() throws IOException {
        String input = "_ZN3foo4mainv";
        String fixed = mutator.fixSyntax(input);

        CxxSyntaxChecker.CheckResult result = mutator.checkSyntax(fixed);
        assertEquals(0, result.missingNestedE);
    }

    @Test
    void testEnforceSyntaxCorrectnessFlag() throws IOException {
        mutator.setEnforceSyntaxCorrectness(true);

        Seed seed = createSeed("_ZN3fooNNN4mainv"); // 故意破损
        List<Testcase> results = collectMutations(seed, 10);

        for (Testcase tc : results) {
            String result = getData(tc);
            CxxSyntaxChecker.CheckResult checkResult = mutator.checkSyntax(result);
            if (!checkResult.isValid) {
                String fixed = mutator.fixSyntax(result);
                CxxSyntaxChecker.CheckResult afterFix = mutator.checkSyntax(fixed);
                assertTrue(afterFix.isValid,
                        "With syntax enforcement, result should be valid after fix: " + fixed);
            }
        }
    }

    // ==========================================
    // 语料库测试
    // ==========================================

    @Test
    void testCorpusUsage() throws IOException {
        // 通过多次变异来验证语料库在使用
        Set<String> results = new HashSet<>();
        Seed seed = createSeed(new byte[0]);

        // 收集足够多的变异结果
        for (int i = 0; i < 50; i++) {
            List<Testcase> batch = collectMutations(seed, 10);
            for (Testcase tc : batch) {
                results.add(getData(tc));
            }
        }

        // 结果应该多样化
        assertTrue(results.size() > 1, "Should produce varied results");
    }

    // ==========================================
    // 问题修复验证
    // ==========================================

    /**
     * 问题 1: 长度前缀同步测试
     */
    @Test
    void testLengthPrefixSyncAfterMutation() throws IOException {
        mutator.setEnforceSyntaxCorrectness(true);

        Seed seed = createSeed("_Z4funcv");
        List<Testcase> results = collectMutations(seed, 50);

        for (Testcase tc : results) {
            String result = getData(tc);
            CxxSyntaxChecker.CheckResult checkResult = mutator.checkSyntax(result);
            assertFalse(checkResult.hasLengthMismatch,
                    "Length should be synced: " + result);
        }
    }

    /**
     * 问题 3: 模板配对测试
     */
    @Test
    void testTemplateClosureRate() throws IOException {
        int unclosedCount = 0;
        int totalWithTemplate = 0;

        // 启用语法修复以验证闭合效果
        mutator.setEnforceSyntaxCorrectness(true);

        Seed seed = createSeed("_Z4funcIiv"); // 模板输入
        List<Testcase> results = collectMutations(seed, 500);

        for (Testcase tc : results) {
            String result = getData(tc);
            if (result.contains("I")) {
                totalWithTemplate++;
                CxxSyntaxChecker.CheckResult checkResult = mutator.checkSyntax(result);
                if (checkResult.missingTemplateE > 0) {
                    unclosedCount++;
                }
            }
        }

        if (totalWithTemplate > 0) {
            double unclosedRate = (double) unclosedCount / totalWithTemplate;
            // 未闭合率应该降低到约 10%
            assertTrue(unclosedRate < 0.30,
                    "Unclosed template rate should be low: " + unclosedRate);
        }
    }

    /**
     * 问题 4: 替换序号范围测试
     */
    @Test
    void testSubstitutionInRange() throws IOException {
        mutator.setEnforceSyntaxCorrectness(true);

        Seed seed = createSeed("_ZN3fooS_3barEv");
        List<Testcase> results = collectMutations(seed, 50);

        for (Testcase tc : results) {
            String result = getData(tc);
            CxxSyntaxChecker.CheckResult checkResult = mutator.checkSyntax(result);
            // 如果存在替换越界，则经过 fixSyntax 后应被修复
            if (checkResult.hasInvalidSubstitution) {
                String fixed = mutator.fixSyntax(result);
                CxxSyntaxChecker.CheckResult afterFix = mutator.checkSyntax(fixed);
                assertFalse(afterFix.hasInvalidSubstitution,
                        "Substitution should be fixed into valid range: " + fixed);
            }
        }
    }

    /**
     * 问题 6: NUL 字符注入率测试
     */
    @Test
    void testNullCharacterInjectionRate() throws IOException {
        int nullCount = 0;

        Seed seed = createSeed("_Z4funcv");
        List<Testcase> results = collectMutations(seed, 500);

        for (Testcase tc : results) {
            String result = getData(tc);
            if (result.contains("\0")) {
                nullCount++;
            }
        }

        double nullRate = (double) nullCount / 500;
        // NUL 字符率应该降低到约 5%
        assertTrue(nullRate < 0.15,
                "NUL character rate should be low: " + nullRate);
    }

    /**
     * 问题 7: E 平衡测试
     */
    @Test
    void testEBalanceRate() throws IOException {
        int imbalancedCount = 0;

        mutator.setEnforceSyntaxCorrectness(true);

        Seed seed = createSeed("_ZN3foov");
        List<Testcase> results = collectMutations(seed, 500);

        for (Testcase tc : results) {
            String result = getData(tc);
            CxxSyntaxChecker.CheckResult checkResult = mutator.checkSyntax(result);
            if (checkResult.missingNestedE > 0 || checkResult.extraE > 0) {
                imbalancedCount++;
            }
        }

        double imbalanceRate = (double) imbalancedCount / 500;
        // 不平衡率应该降低到约 10%
        assertTrue(imbalanceRate < 0.30,
                "E imbalance rate should be low: " + imbalanceRate);
    }

    // ==========================================
    // 边界情况测试
    // ==========================================

    @Test
    void testMutateLongInput() throws IOException {
        StringBuilder sb = new StringBuilder("_Z");
        for (int i = 0; i < 100; i++) {
            sb.append("4func");
        }
        sb.append("v");

        Seed seed = createSeed(sb.toString());
        List<Testcase> results = collectMutations(seed, 5);

        assertEquals(5, results.size());
        for (Testcase tc : results) {
            assertNotNull(tc.getData());
        }
    }

    @Test
    void testMutateNestedInput() throws IOException {
        Seed seed = createSeed("_ZNNNNN3fooEEEEEv");
        List<Testcase> results = collectMutations(seed, 5);

        assertEquals(5, results.size());
    }

    @Test
    void testMutateTemplateInput() throws IOException {
        Seed seed = createSeed("_Z4funcIIIIIivEEEEv");
        List<Testcase> results = collectMutations(seed, 5);

        assertEquals(5, results.size());
    }

    @Test
    void testMutateSubstitutionInput() throws IOException {
        Seed seed = createSeed("_ZN3fooS_S0_S1_Ev");
        List<Testcase> results = collectMutations(seed, 5);

        assertEquals(5, results.size());
    }

    // ==========================================
    // 综合集成测试
    // ==========================================

    @Test
    void testFullMutationCycle() throws IOException {
        // 模拟一个完整的模糊测试循环
        Seed current = createSeed("_Z4mainv");

        for (int i = 0; i < 20; i++) {
            Iterator<Testcase> iter = mutator.mutate(current, 1);
            assertTrue(iter.hasNext());
            Testcase tc = iter.next();
            assertNotNull(tc.getData());
            assertTrue(tc.getData().length > 0);

            // 使用变异结果作为下一轮种子
            File newFile = tempDir.resolve("mutated_" + i + ".txt").toFile();
            Files.write(newFile.toPath(), tc.getData());
            current = Seed.loadWithMetadata(newFile, tc.getData());
        }
    }

    @Test
    void testMutationDiversity() throws IOException {
        Set<String> allResults = new HashSet<>();
        Seed seed = createSeed("_ZN3foo3barEv");

        List<Testcase> results = collectMutations(seed, 200);
        for (Testcase tc : results) {
            allResults.add(getData(tc));
        }

        // 应该产生足够的变异多样性
        assertTrue(allResults.size() > 10,
                "Should produce diverse mutations: " + allResults.size());
    }

    @Test
    void testIteratorBehavior() throws IOException {
        Seed seed = createSeed("_Z4funcv");
        Iterator<Testcase> iter = mutator.mutate(seed, 5);

        int count = 0;
        while (iter.hasNext()) {
            Testcase tc = iter.next();
            assertNotNull(tc);
            count++;
        }

        assertEquals(5, count);
        assertFalse(iter.hasNext());
    }

    @Test
    void testEnergyParameter() throws IOException {
        Seed seed = createSeed("_Z4funcv");

        // energy = 1
        List<Testcase> r1 = collectMutations(seed, 1);
        assertEquals(1, r1.size());

        // energy = 10
        List<Testcase> r10 = collectMutations(seed, 10);
        assertEquals(10, r10.size());

        // energy = 100
        List<Testcase> r100 = collectMutations(seed, 100);
        assertEquals(100, r100.size());
    }

    @Test
    void testZeroEnergy() throws IOException {
        Seed seed = createSeed("_Z4funcv");
        List<Testcase> results = collectMutations(seed, 0);

        // 根据实现，0 能量应该至少产生 1 个变异
        assertTrue(results.size() >= 1);
    }

    @Test
    void testNegativeEnergy() throws IOException {
        Seed seed = createSeed("_Z4funcv");
        List<Testcase> results = collectMutations(seed, -5);

        // 根据实现，负能量应该至少产生 1 个变异
        assertTrue(results.size() >= 1);
    }
}
