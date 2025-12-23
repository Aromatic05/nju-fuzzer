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
 * LuaMutator 单元测试
 *
 * 验证点：
 * 1. 语法完整性 (能否生成合法的 Block 结构)
 * 2. 攻击向量识别 (Coroutine UAF, Metatable Bomb, Pattern Fuzzing)
 * 3. 现代特性覆盖 (Lua 5.3+ 位运算, Goto)
 * 4. 统计报告 (展示生成器的逻辑分布)
 */
class LuaMutatorTest {

    private Seed dummySeed;
    private LuaMutator mutator;

    @BeforeEach
    void setUp() {
        dummySeed = Seed.loadWithMetadata(new File("dummy_lua"), new byte[0]);
        mutator = new LuaMutator();
    }

    // ==========================================
    // 基础功能测试
    // ==========================================

    @Test
    @DisplayName("Test 1: Basic Structure - 验证 Lua 生成逻辑")
    void testBasicStructure() {
        // 增加样本数量以覆盖 90% 的生成逻辑
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);

        while (iter.hasNext()) {
            Testcase tc = iter.next();
            String code = new String(tc.getData(), StandardCharsets.ISO_8859_1);

            // 调试输出：如果失败了，你可以看到是哪一行代码导致
            // System.out.println("Testing Code: " + code);

            // 逻辑：要么它满足 generateChunk 的 do...end 结构，
            // 要么它属于 ATTACK_PAYLOADS（包含 local, goto, string.find, coroutine 等）
            boolean isStandardChunk = code.contains("do") && code.contains("end");
            boolean isAttackPayload = code.contains("local") ||
                    code.contains("goto") ||
                    code.contains("string") ||
                    code.contains("coroutine");

            assertTrue(isStandardChunk || isAttackPayload,
                    "脚本内容不符合 Lua 特征，可能是逻辑未覆盖: " + code);
        }
    }

    @Test
    @DisplayName("Test 2: Diversity - 变异结果多样性检查")
    void testDiversity() {
        Set<Integer> hashes = new HashSet<>();
        int count = 100;
        Iterator<Testcase> iter = mutator.mutate(dummySeed, count);
        while (iter.hasNext()) {
            hashes.add(Arrays.hashCode(iter.next().getData()));
        }
        // 由于是随机生成的脚本，重复率应该极低
        assertTrue(hashes.size() > 95, "Lua 脚本重复率过高: " + hashes.size());
    }

    // ==========================================
    // 覆盖率报告
    // ==========================================

    @Test
    @DisplayName("Test 3-10: Coverage Report - 解析 2000 个样本并统计语法特性")
    void testCoverage() {
        int totalIterations = 2000;
        Map<String, Integer> stats = new HashMap<>();
        String[] keys = {
                "Total", "Predefined Payloads", "Coroutine Ops", "Metatable/setmetatable",
                "Bitwise Ops (5.3+)", "GC Stress (collectgarbage)", "Goto/Labels",
                "Complex Patterns (%b/%f)", "Function Definitions", "Table Constructors"
        };
        for (String k : keys) stats.put(k, 0);

        Iterator<Testcase> iter = mutator.mutate(dummySeed, totalIterations);

        while (iter.hasNext()) {
            String code = new String(iter.next().getData(), StandardCharsets.ISO_8859_1);
            stats.put("Total", stats.get("Total") + 1);
            analyzeLua(code, stats);
        }

        printReport(stats);

        // 断言核心攻击分支均被触达
        assertCovered(stats, "Coroutine Ops");
        assertCovered(stats, "Metatable/setmetatable");
        assertCovered(stats, "GC Stress (collectgarbage)");
        assertCovered(stats, "Bitwise Ops (5.3+)");
        assertCovered(stats, "Goto/Labels");
    }

    private void analyzeLua(String code, Map<String, Integer> stats) {
        // 1. 预定义 Payload (根据常见特征判断)
        if (code.contains("string.rep") || code.contains("debug.upvaluejoin")) {
            inc(stats, "Predefined Payloads");
        }

        // 2. 协程
        if (code.contains("coroutine.")) inc(stats, "Coroutine Ops");

        // 3. 元表
        if (code.contains("setmetatable")) inc(stats, "Metatable/setmetatable");

        // 4. 位运算 (Lua 5.3 特性: &, |, ~, <<, >>, //)
        if (Pattern.compile("&|\\||~|<<|>>|//").matcher(code).find()) {
            inc(stats, "Bitwise Ops (5.3+)");
        }

        // 5. GC 压力测试
        if (code.contains("collectgarbage")) inc(stats, "GC Stress (collectgarbage)");

        // 6. Goto 和标签
        if (code.contains("goto") || code.contains("::")) inc(stats, "Goto/Labels");

        // 7. 复杂模式匹配
        if (code.contains("%b") || code.contains("%f")) inc(stats, "Complex Patterns (%b/%f)");

        // 8. 函数定义
        if (code.contains("function")) inc(stats, "Function Definitions");

        // 9. 表构造
        if (code.contains("{") && code.contains("}")) inc(stats, "Table Constructors");
    }

    private void inc(Map<String, Integer> stats, String key) {
        stats.put(key, stats.get(key) + 1);
    }

    private void assertCovered(Map<String, Integer> stats, String key) {
        assertTrue(stats.get(key) > 0, "算法未生成核心特性: " + key);
    }

    private void printReport(Map<String, Integer> stats) {
        int realTotal = stats.get("Total");
        System.out.println("====== LuaMutator Functional Coverage Report ======");
        System.out.println("Real Iterations: " + realTotal);
        System.out.println("---------------------------------------------------");
        System.out.printf("%-30s | %-10s | %-10s%n", "Feature / Attack", "Count", "Rate");
        System.out.println("---------------------------------------------------");

        String[] order = {
                "Predefined Payloads", "Function Definitions", "Table Constructors",
                "Coroutine Ops", "Metatable/setmetatable", "Bitwise Ops (5.3+)",
                "GC Stress (collectgarbage)", "Goto/Labels", "Complex Patterns (%b/%f)"
        };

        for (String k : order) {
            int v = stats.get(k);
            double rate = (realTotal > 0) ? (v * 100.0) / realTotal : 0.0;
            System.out.printf("%-30s | %-10d | %6.2f%%%n", k, v, rate);
        }
        System.out.println("===================================================");
    }

    @Test
    @DisplayName("Test 11: Nested Expression - 验证表达式递归深度是否合理")
    void testExpressionDepth() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        boolean foundDeep = false;
        while (iter.hasNext()) {
            String code = new String(iter.next().getData(), StandardCharsets.ISO_8859_1);
            // 通过计算括号嵌套来判断表达式复杂度
            int maxParens = 0;
            int current = 0;
            for (char c : code.toCharArray()) {
                if (c == '(') current++;
                if (c == ')') current--;
                maxParens = Math.max(maxParens, current);
            }
            if (maxParens > 5) { // 嵌套超过5层
                foundDeep = true;
                break;
            }
        }
        assertTrue(foundDeep, "生成器未能生成深层嵌套的算术/逻辑表达式");
    }

    @Test
    @DisplayName("Test 12: Memory Stress - 检查长字符串生成")
    void testStringStress() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        boolean foundLong = false;
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            if (data.length > 500) { // 变异器生成的脚本长度
                foundLong = true;
                break;
            }
        }
        assertTrue(foundLong, "生成器未能生成足够规模的 Lua 脚本");
    }
}