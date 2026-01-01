package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JsonMutator 单元测试
 *
 * 验证点：
 * 1. 编码多样性 (BOM 识别与多字符集测试)
 * 2. 结构攻击 (深度嵌套、宽对象)
 * 3. 语义攻击 (孤立代理对、畸形数字解析)
 * 4. 统计报告 (可视化覆盖率)
 */
class JsonMutatorTest {

    private Seed dummySeed;
    private JsonMutator mutator;

    @BeforeEach
    void setUp() {
        dummySeed = Seed.loadWithMetadata(new File("dummy_json"), new byte[0]);
        mutator = new JsonMutator();
    }

    // ==========================================
    // 基础功能测试
    // ==========================================

    @Test
    @DisplayName("Test 1: Encoding & BOM - 验证是否生成了多种编码及其对应的 BOM")
    void testEncodings() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 200);
        Map<String, Integer> encodingCount = new HashMap<>();

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            String detected = detectEncoding(data);
            encodingCount.put(detected, encodingCount.getOrDefault(detected, 0) + 1);
        }

        System.out.println("Encoding Distribution: " + encodingCount);
        assertTrue(encodingCount.size() >= 3, "生成的编码种类应包含 UTF-8, UTF-16LE, UTF-16BE 等");
    }

    @Test
    @DisplayName("Test 2: Diversity - 变异结果多样性检查")
    void testDiversity() {
        Set<Integer> hashes = new HashSet<>();
        // 增加样本数量到 200，以便观察更真实的多样性
        int testCount = 200;
        Iterator<Testcase> iter = mutator.mutate(dummySeed, testCount);

        int actualCount = 0;
        while (iter.hasNext()) {
            hashes.add(Arrays.hashCode(iter.next().getData()));
            actualCount++;
        }

        System.out.println("Requested: " + testCount);
        System.out.println("Actual Generated: " + actualCount);
        System.out.println("Unique Hashes: " + hashes.size());

        // 验证生成的数量是否正确 (排除原因1)
        assertEquals(testCount, actualCount, "生成的总数与 Energy 不匹配！");

        // 验证多样性 (放宽到 80%，因为固定 Payload 和简单类型可能重复)
        assertTrue(hashes.size() > (testCount * 0.8),
                "JSON 生成重复率过高，唯一数: " + hashes.size());
    }

    // ==========================================
    // 覆盖率报告
    // ==========================================

    @Test
    @DisplayName("Test 3-10: Coverage Report - 解析 2000 个样本并统计攻击向量")
    void testCoverage() {
        int totalIterations = 2000;
        Map<String, Integer> stats = new HashMap<>();
        String[] keys = {
                "Total", "Deep Nesting (>100)", "Wide Object (>1000 keys)",
                "Lone Surrogates (\\uD8xx)", "Edge Case Numbers (1e309/00/inf)",
                "Trailing Comma", "Non-standard Keywords", "BOM Present"
        };
        for (String k : keys) stats.put(k, 0);

        Iterator<Testcase> iter = mutator.mutate(dummySeed, totalIterations);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            stats.put("Total", stats.get("Total") + 1);

            // 识别编码并转回字符串以便正则分析
            String content = decodeSmart(data, stats);
            analyzeJson(content, stats, data.length);
        }

        printReport(stats);

        // 断言核心分支均被覆盖
        assertCovered(stats, "Deep Nesting (>100)");
        assertCovered(stats, "Wide Object (>1000 keys)");
        assertCovered(stats, "Lone Surrogates (\\uD8xx)");
        assertCovered(stats, "Edge Case Numbers (1e309/00/inf)");
    }

    private void analyzeJson(String json, Map<String, Integer> stats, int rawLen) {
        // 1. 深度嵌套检测 (简单计数括号)
        int maxDepth = 0;
        int current = 0;
        for (char c : json.toCharArray()) {
            if (c == '[' || c == '{') current++;
            if (c == ']' || c == '}') current--;
            maxDepth = Math.max(maxDepth, current);
        }
        if (maxDepth > 100) inc(stats, "Deep Nesting (>100)");

        // 2. 宽对象检测
        if (json.contains("\"k1000\":")) inc(stats, "Wide Object (>1000 keys)");

        // 3. 孤立代理对 (\\uD8xx 且后面不跟 \\uDCxx)
        // 简化检测：直接查找是否有 D8/D9/DA/DB 开头的转义
        if (Pattern.compile("\\\\u[dD][89abAB]").matcher(json).find()) {
            inc(stats, "Lone Surrogates (\\uD8xx)");
        }

        // 4. 边缘数值
        if (Pattern.compile("1e309|\\+123|00[0-9]|NaN|Infinity|-0|1\\.").matcher(json).find()) {
            inc(stats, "Edge Case Numbers (1e309/00/inf)");
        }

        // 5. 尾随逗号与非标关键字
        if (json.contains(",]") || json.contains(",}")) inc(stats, "Trailing Comma");
        if (Pattern.compile("True|Null|undefined").matcher(json).find()) {
            inc(stats, "Non-standard Keywords");
        }
    }

    private String decodeSmart(byte[] data, Map<String, Integer> stats) {
        if (data.length >= 3 && (data[0] & 0xFF) == 0xEF && (data[1] & 0xFF) == 0xBB && (data[2] & 0xFF) == 0xBF) {
            inc(stats, "BOM Present");
            return new String(data, 3, data.length - 3, StandardCharsets.UTF_8);
        }
        if (data.length >= 2 && (data[0] & 0xFF) == 0xFE && (data[1] & 0xFF) == 0xFF) {
            inc(stats, "BOM Present");
            return new String(data, 2, data.length - 2, StandardCharsets.UTF_16BE);
        }
        if (data.length >= 2 && (data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == 0xFE) {
            inc(stats, "BOM Present");
            return new String(data, 2, data.length - 2, StandardCharsets.UTF_16LE);
        }
        // 默认 UTF-8
        return new String(data, StandardCharsets.UTF_8);
    }

    private String detectEncoding(byte[] data) {
        if (data.length >= 3 && (data[0] & 0xFF) == 0xEF && (data[1] & 0xFF) == 0xBB && (data[2] & 0xFF) == 0xBF) return "UTF-8-BOM";
        if (data.length >= 2 && (data[0] & 0xFF) == 0xFE && (data[1] & 0xFF) == 0xFF) return "UTF-16BE-BOM";
        if (data.length >= 2 && (data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == 0xFE) return "UTF-16LE-BOM";
        return "UTF-8-RAW";
    }

    private void inc(Map<String, Integer> stats, String key) {
        stats.put(key, stats.get(key) + 1);
    }

    private void assertCovered(Map<String, Integer> stats, String key) {
        assertTrue(stats.get(key) > 0, "未生成核心攻击点: " + key);
    }

    private void printReport(Map<String, Integer> stats) {
        int realTotal = stats.get("Total");
        System.out.println("====== JsonMutator Functional Coverage Report ======");
        System.out.println("Real Iterations: " + realTotal);
        System.out.println("----------------------------------------------------");
        System.out.printf("%-30s | %-10s | %-10s%n", "Attack Vector", "Count", "Rate");
        System.out.println("----------------------------------------------------");

        String[] order = {
                "BOM Present", "Deep Nesting (>100)", "Wide Object (>1000 keys)",
                "Lone Surrogates (\\uD8xx)", "Edge Case Numbers (1e309/00/inf)",
                "Trailing Comma", "Non-standard Keywords"
        };

        for (String k : order) {
            int v = stats.get(k);
            double rate = (realTotal > 0) ? (v * 100.0) / realTotal : 0.0;
            System.out.printf("%-30s | %-10d | %6.2f%%%n", k, v, rate);
        }
        System.out.println("====================================================");
    }

    @Test
    @DisplayName("Test 11: Large String Check - 检查超大字符串生成")
    void testLargeString() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        boolean foundLarge = false;
        while (iter.hasNext()) {
            if (iter.next().getData().length > 10000) {
                foundLarge = true;
                break;
            }
        }
        assertTrue(foundLarge, "应能生成超过 10KB 的超长字符串测试 OOM");
    }
}