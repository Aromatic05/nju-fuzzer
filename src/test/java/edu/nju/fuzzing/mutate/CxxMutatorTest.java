package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CxxMutator 单元测试 (适配 energy == count 逻辑)
 *
 * 包含：
 * 1. 基础格式校验 (_Z 开头)
 * 2. 攻击向量识别 (栈溢出、整数溢出、模板炸弹)
 * 3. 语法结构校验 (数组、函数指针、操作符)
 * 4. 统计报告 (可视化覆盖率，修复了百分比计算问题)
 */
class CxxMutatorTest {

    private Seed dummySeed;
    private CxxMutator mutator;

    @BeforeEach
    void setUp() {
        // 创建一个用于测试的虚拟种子
        // CxxMutator 是生成式的，内容不重要，但对象必须存在
        dummySeed = Seed.loadWithMetadata(new File("dummy_cxx"), new byte[0]);
        mutator = new CxxMutator();
    }

    // ==========================================
    // 基础功能测试
    // ==========================================

    @Test
    @DisplayName("Test 1: Mangled Name Prefix - 必须以 _Z 开头")
    void testPrefix() {
        // 传入 100，期望生成 100 个
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        int count = 0;
        while (iter.hasNext()) {
            String mangle = new String(iter.next().getData(), StandardCharsets.ISO_8859_1);
            assertTrue(mangle.startsWith("_Z"), "所有生成的 C++ 符号都应以 _Z 开头: " + mangle);
            count++;
        }
        assertEquals(100, count, "生成的数量应等于传入的 Energy");
    }

    @Test
    @DisplayName("Test 2: Charset Validity - 字符集应合法")
    void testCharset() {
        // Itanium ABI 允许字母、数字、下划线 (及一些特殊符号如 $ 在某些扩展中，这里只测标准集)
        Pattern validChars = Pattern.compile("^[_a-zA-Z0-9]+$");
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 50);
        while (iter.hasNext()) {
            String mangle = new String(iter.next().getData(), StandardCharsets.ISO_8859_1);
            assertTrue(validChars.matcher(mangle).matches(), "包含非法字符: " + mangle);
        }
    }

    // ==========================================
    // 攻击向量与复杂语法覆盖测试 (统计法)
    // ==========================================

    @Test
    @DisplayName("Test 3-10: Coverage Report - 运行 2000 次并统计覆盖率")
    void testCoverage() {
        // 增加采样数到 2000，使统计数据更平滑
        int targetIterations = 2000;
        Map<String, Integer> stats = new HashMap<>();

        // 初始化统计项
        String[] keys = {
                "Total", "Integer Overflow", "Deep Recursion", "Substitution Attack",
                "Template Bomb", "Nested Name", "Operator", "Constructor/Destructor",
                "Array Type", "Function Pointer", "Std Library"
        };
        for (String k : keys) stats.put(k, 0);

        // 正则特征库
        Pattern pIntOverflow = Pattern.compile("\\d{9,}"); // 连续9个以上数字
        Pattern pDeepRecursion = Pattern.compile("P{10,}"); // 连续10个以上指针
        Pattern pSubAttack = Pattern.compile("S\\d+_|S_"); // S123_ 或 S_
        Pattern pTemplate = Pattern.compile("I.*E"); // 模板结构
        Pattern pNested = Pattern.compile("^N.*E$"); // 嵌套名字空间
        // 常见操作符
        Pattern pOperator = Pattern.compile("nw|na|dl|da|ps|ng|ad|de|co|nt|pl|mi|ml|dv|rm|an|or|eo|aS|eq|ne|lt|gt|cl|ix|qu");
        Pattern pCtorDtor = Pattern.compile("[CD][0-9]"); // C1, D2...
        Pattern pArray = Pattern.compile("A\\d*_"); // A10_i
        Pattern pFuncPtr = Pattern.compile("PF.*E"); // 函数指针
        Pattern pStd = Pattern.compile("St|Sa|Sb|Ss"); // std::

        // 由于修改了 CxxMutator 逻辑 (count = energy)，这里直接传 2000
        Iterator<Testcase> iter = mutator.mutate(dummySeed, targetIterations);

        while (iter.hasNext()) {
            String mangle = new String(iter.next().getData(), StandardCharsets.ISO_8859_1);
            // 去掉 _Z 前缀便于分析内部结构 (避免 _Z 干扰正则)
            String body = (mangle.length() > 2) ? mangle.substring(2) : "";

            // 记录真实的总数 (作为分母)
            stats.put("Total", stats.get("Total") + 1);

            // 统计特征
            if (pIntOverflow.matcher(body).find()) inc(stats, "Integer Overflow");
            if (pDeepRecursion.matcher(body).find()) inc(stats, "Deep Recursion");
            if (pSubAttack.matcher(body).find()) inc(stats, "Substitution Attack");
            if (pTemplate.matcher(body).find()) inc(stats, "Template Bomb");

            // 下面这些通常出现在 Complex Signature 分支
            // 嵌套名字空间通常以 N 开头 E 结尾
            if (body.startsWith("N") && body.endsWith("E")) {
                inc(stats, "Nested Name");
            }
            if (pOperator.matcher(body).find()) inc(stats, "Operator");
            if (pCtorDtor.matcher(body).find()) inc(stats, "Constructor/Destructor");
            if (pArray.matcher(body).find()) inc(stats, "Array Type");
            if (pFuncPtr.matcher(body).find()) inc(stats, "Function Pointer");
            if (pStd.matcher(body).find()) inc(stats, "Std Library");
        }

        // --- 输出可视化报告 ---
        // 使用实际统计到的 Total 作为分母，确保 Rate 准确
        printReport(stats);

        // --- 断言：确保主要攻击向量都被覆盖到了 ---
        // 如果这几个主要攻击都没生成，说明概率分布有问题
        assertCovered(stats, "Integer Overflow");
        assertCovered(stats, "Deep Recursion");
        assertCovered(stats, "Template Bomb");
        assertCovered(stats, "Array Type");
    }

    private void inc(Map<String, Integer> stats, String key) {
        stats.put(key, stats.get(key) + 1);
    }

    private void assertCovered(Map<String, Integer> stats, String key) {
        assertTrue(stats.get(key) > 0, "Warning: 在运行中未生成 " + key + "，请检查概率设置或逻辑实现。");
    }

    private void printReport(Map<String, Integer> stats) {
        int realTotal = stats.get("Total");
        System.out.println("====== CxxMutator Functional Coverage Report ======");
        System.out.println("Real Iterations: " + realTotal);
        System.out.println("---------------------------------------------------");
        System.out.printf("%-25s | %-10s | %-10s%n", "Feature / Attack", "Count", "Rate");
        System.out.println("---------------------------------------------------");

        // 固定的排序顺序输出，方便查看
        String[] order = {
                "Integer Overflow", "Deep Recursion", "Substitution Attack",
                "Template Bomb", "Nested Name", "Operator", "Constructor/Destructor",
                "Array Type", "Function Pointer", "Std Library"
        };

        for (String k : order) {
            int v = stats.get(k);
            double rate = (realTotal > 0) ? (v * 100.0) / realTotal : 0.0;
            System.out.printf("%-25s | %-10d | %6.2f%%%n", k, v, rate);
        }
        System.out.println("===================================================");
    }

    // ==========================================
    // 边界与健壮性测试
    // ==========================================

    @Test
    @DisplayName("Test 11: Length Check - 生成的名称长度应合理")
    void testLength() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        while(iter.hasNext()) {
            byte[] data = iter.next().getData();
            // _Z + 至少一个字符
            assertTrue(data.length >= 2, "名称太短: " + new String(data));
        }
    }

    @Test
    @DisplayName("Test 12: Independent Generation - 变异结果应多样化")
    void testDiversity() {
        Set<String> uniqueResults = new HashSet<>();
        // 传入 100，期望生成 100 个
        int requestedEnergy = 100;
        Iterator<Testcase> iter = mutator.mutate(dummySeed, requestedEnergy);

        while(iter.hasNext()) {
            uniqueResults.add(new String(iter.next().getData()));
        }

        // 打印实际结果数，方便调试
        System.out.println("Requested: " + requestedEnergy + ", Unique: " + uniqueResults.size());

        // 验证：生成的 100 个用例中，重复的不应太多
        // 只要大于 50 说明算法的随机性是有效的
        assertTrue(uniqueResults.size() > 50,
                "生成结果多样性不足，期望 > 50，实际: " + uniqueResults.size());
    }
}