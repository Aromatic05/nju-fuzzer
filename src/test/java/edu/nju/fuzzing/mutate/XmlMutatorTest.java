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
 * XmlMutator 单元测试
 *
 * 验证点：
 * 1. 编码健壮性 (UTF-8/16/BOM 检测与解码)
 * 2. 核心攻击向量 (Billion Laughs, XXE, CDATA, DTD)
 * 3. 结构特征 (深度嵌套、混合内容、自闭合标签)
 * 4. 统计报告 (展示变异器的攻击性分布)
 */
class XmlMutatorTest {

    private Seed dummySeed;
    private XmlMutator mutator;

    @BeforeEach
    void setUp() {
        // 使用 Seed 类提供的静态工厂创建虚拟种子
        dummySeed = Seed.loadWithMetadata(new File("dummy_xml"), new byte[0]);
        mutator = new XmlMutator();
    }

    // ==========================================
    // 基础功能测试
    // ==========================================

    @Test
    @DisplayName("Test 1: XML Signature - 验证是否以 <?xml 或 < 开头")
    void testSignature() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            String content = decodeSmart(data, new HashMap<>()); // 临时解码
            assertTrue(content.trim().startsWith("<"), "XML 必须以标签或声明开头: " + content.substring(0, Math.min(20, content.length())));
        }
    }

    @Test
    @DisplayName("Test 2: Diversity - 变异结果多样性检查")
    void testDiversity() {
        Set<Integer> hashes = new HashSet<>();
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        while (iter.hasNext()) {
            hashes.add(Arrays.hashCode(iter.next().getData()));
        }
        assertTrue(hashes.size() > 85, "XML 生成重复率过高");
    }

    // ==========================================
    // 覆盖率报告
    // ==========================================

    @Test
    @DisplayName("Test 3-10: Coverage Report - 解析 2000 个样本并统计特征")
    void testCoverage() {
        int totalIterations = 2000;
        Map<String, Integer> stats = new HashMap<>();
        String[] keys = {
                "Total", "BOM / Multi-Encoding", "Billion Laughs (DoS)",
                "XXE (External Entity)", "Deep Nesting (>15 levels)",
                "Mixed Content (Text+Tag)", "CDATA Sections", "Malformed / Unclosed Tags",
                "DTD Declaration"
        };
        for (String k : keys) stats.put(k, 0);

        // 假设已经修改了 energy = count 逻辑
        Iterator<Testcase> iter = mutator.mutate(dummySeed, totalIterations);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            stats.put("Total", stats.get("Total") + 1);

            // 1. 解码 (识别 BOM 和编码)
            String xml = decodeSmart(data, stats);

            // 2. 分析结构
            analyzeXml(xml, stats);
        }

        printReport(stats);

        // 断言核心攻击向量被触发
        assertCovered(stats, "Billion Laughs (DoS)");
        assertCovered(stats, "XXE (External Entity)");
        assertCovered(stats, "Deep Nesting (>15 levels)");
        assertCovered(stats, "BOM / Multi-Encoding");
    }

    private void analyzeXml(String xml, Map<String, Integer> stats) {
        // 1. Billion Laughs: 特征是实体引用实体 (ENTITY ... &)
        if (Pattern.compile("<!ENTITY.*&.*;").matcher(xml).find()) {
            inc(stats, "Billion Laughs (DoS)");
        }

        // 2. XXE: 特征是 SYSTEM + file/http
        if (Pattern.compile("SYSTEM\\s+[\"'](file|http)").matcher(xml).find()) {
            inc(stats, "XXE (External Entity)");
        }

        // 3. DTD
        if (xml.contains("<!DOCTYPE")) inc(stats, "DTD Declaration");

        // 4. CDATA
        if (xml.contains("<![CDATA[")) inc(stats, "CDATA Sections");

        // 5. Mixed Content: 标签内包含文本和子标签
        if (Pattern.compile(">[^<\\s]+<[a-zA-Z]").matcher(xml).find()) {
            inc(stats, "Mixed Content (Text+Tag)");
        }

        // 6. Malformed: 只有开没有关，或者标签名不匹配 (简单启发式判断)
        if (xml.contains("<root") && !xml.contains("</root>")) {
            inc(stats, "Malformed / Unclosed Tags");
        }

        // 7. 深度嵌套检测
        int maxDepth = 0;
        int current = 0;
        // 简单正则匹配标签
        java.util.regex.Matcher m = Pattern.compile("<(/?[a-zA-Z0-9:]+)").matcher(xml);
        while (m.find()) {
            String tag = m.group(1);
            if (tag.startsWith("/")) current--;
            else if (!xml.substring(m.end()).trim().startsWith("/>")) current++; // 排除自闭合
            maxDepth = Math.max(maxDepth, current);
        }
        if (maxDepth > 15) inc(stats, "Deep Nesting (>15 levels)");
    }

    /**
     * XML 编码感知解码
     */
    private String decodeSmart(byte[] data, Map<String, Integer> stats) {
        if (data.length >= 3 && (data[0] & 0xFF) == 0xEF && (data[1] & 0xFF) == 0xBB && (data[2] & 0xFF) == 0xBF) {
            inc(stats, "BOM / Multi-Encoding");
            return new String(data, 3, data.length - 3, StandardCharsets.UTF_8);
        }
        if (data.length >= 2 && (data[0] & 0xFF) == 0xFE && (data[1] & 0xFF) == 0xFF) {
            inc(stats, "BOM / Multi-Encoding");
            return new String(data, 2, data.length - 2, StandardCharsets.UTF_16BE);
        }
        if (data.length >= 2 && (data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == 0xFE) {
            inc(stats, "BOM / Multi-Encoding");
            return new String(data, 2, data.length - 2, StandardCharsets.UTF_16LE);
        }
        // 检查是否有 UTF-16/32 的特征 (大量 null byte)
        return new String(data, StandardCharsets.UTF_8);
    }

    private void inc(Map<String, Integer> stats, String key) {
        if (stats.containsKey(key)) {
            stats.put(key, stats.get(key) + 1);
        }
    }

    private void assertCovered(Map<String, Integer> stats, String key) {
        assertTrue(stats.get(key) > 0, "算法未生成核心特征: " + key);
    }

    private void printReport(Map<String, Integer> stats) {
        int total = stats.get("Total");
        System.out.println("====== XmlMutator Functional Coverage Report ======");
        System.out.println("Real Iterations: " + total);
        System.out.println("---------------------------------------------------");
        System.out.printf("%-30s | %-10s | %-10s%n", "Attack Vector / Feature", "Count", "Rate");
        System.out.println("---------------------------------------------------");

        String[] order = {
                "BOM / Multi-Encoding", "Billion Laughs (DoS)", "XXE (External Entity)",
                "Deep Nesting (>15 levels)", "DTD Declaration", "CDATA Sections",
                "Mixed Content (Text+Tag)", "Malformed / Unclosed Tags"
        };

        for (String k : order) {
            int v = stats.getOrDefault(k, 0);
            double rate = (total > 0) ? (v * 100.0) / total : 0.0;
            System.out.printf("%-30s | %-10d | %6.2f%%%n", k, v, rate);
        }
        System.out.println("===================================================");
    }

    @Test
    @DisplayName("Test 11: Well-formed Balance - 检查标签闭合率")
    void testBalance() {
        // 在非 Malformed 模式下，生成的 XML 应该是平衡的
        // 抽取 100 个样本，统计闭合良好的比例
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        int balanced = 0;
        while (iter.hasNext()) {
            String xml = new String(iter.next().getData(), StandardCharsets.UTF_8);
            if (xml.contains("</") || xml.contains("/>")) balanced++;
        }
        assertTrue(balanced > 50, "生成的 XML 闭合标签太少，结构化变异可能失效");
    }
}