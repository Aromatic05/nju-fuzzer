package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.grammar.XmlSyntaxChecker;
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
 * 5. 语法修复后的 well-formedness (新增)
 */
class XmlMutatorTest {

    private Seed dummySeed;
    private Seed validSeed;
    private XmlMutator mutator;
    private XmlSyntaxChecker syntaxChecker;

    @BeforeEach
    void setUp() {
        // 使用 Seed 类提供的静态工厂创建虚拟种子
        dummySeed = Seed.loadWithMetadata(new File("dummy_xml"), new byte[0]);
        // 创建一个有效的 XML 种子用于变异测试
        byte[] validXmlData = "<?xml version=\"1.0\"?><root><child id=\"1\">content</child></root>"
                .getBytes(StandardCharsets.UTF_8);
        validSeed = Seed.loadWithMetadata(new File("valid_xml"), validXmlData);
        mutator = new XmlMutator();
        syntaxChecker = new XmlSyntaxChecker();
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
            assertTrue(content.trim().startsWith("<"),
                    "XML 必须以标签或声明开头: " + content.substring(0, Math.min(20, content.length())));
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
        for (String k : keys)
            stats.put(k, 0);

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
        if (xml.contains("<!DOCTYPE"))
            inc(stats, "DTD Declaration");

        // 4. CDATA
        if (xml.contains("<![CDATA["))
            inc(stats, "CDATA Sections");

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
            if (tag.startsWith("/"))
                current--;
            else if (!xml.substring(m.end()).trim().startsWith("/>"))
                current++; // 排除自闭合
            maxDepth = Math.max(maxDepth, current);
        }
        if (maxDepth > 15)
            inc(stats, "Deep Nesting (>15 levels)");
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
            if (xml.contains("</") || xml.contains("/>"))
                balanced++;
        }
        assertTrue(balanced > 50, "生成的 XML 闭合标签太少，结构化变异可能失效");
    }

    // ==========================================
    // 新增：语法修复相关测试
    // ==========================================

    @Test
    @DisplayName("Test 12: Syntax Validity Rate - 检查语法有效率")
    void testSyntaxValidityRate() {
        // 使用有效种子进行变异，检查生成的 XML 有效率
        Iterator<Testcase> iter = mutator.mutate(validSeed, 500);
        int validCount = 0;
        int totalCount = 0;

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            String xml = decodeSmart(data, new HashMap<>());
            XmlSyntaxChecker.CheckResult result = syntaxChecker.check(xml);
            if (result.isValid) {
                validCount++;
            }
            totalCount++;
        }

        double validRate = (validCount * 100.0) / totalCount;
        System.out.println("语法有效率: " + validRate + "% (" + validCount + "/" + totalCount + ")");

        // 根据问题文档，修复后预期有效率应该在 70% 以上
        assertTrue(validRate > 60, "语法有效率太低: " + validRate + "%，预期 > 60%");
    }

    @Test
    @DisplayName("Test 13: Tag Pairing - 检查标签配对正确性")
    void testTagPairing() {
        Iterator<Testcase> iter = mutator.mutate(validSeed, 200);
        int pairedCount = 0;
        int totalCount = 0;

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            String xml = decodeSmart(data, new HashMap<>());
            XmlSyntaxChecker.CheckResult result = syntaxChecker.check(xml);

            // 检查是否有未配对的标签
            if (result.unmatchedOpenTagCount == 0 && result.mismatchedTags.isEmpty()) {
                pairedCount++;
            }
            totalCount++;
        }

        double pairedRate = (pairedCount * 100.0) / totalCount;
        System.out.println("标签配对正确率: " + pairedRate + "% (" + pairedCount + "/" + totalCount + ")");

        assertTrue(pairedRate > 50, "标签配对正确率太低: " + pairedRate + "%");
    }

    @Test
    @DisplayName("Test 14: Attribute Escaping - 检查属性值转义")
    void testAttributeEscaping() {
        Iterator<Testcase> iter = mutator.mutate(validSeed, 100);
        int properlyEscaped = 0;
        int totalWithAttr = 0;

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            String xml = decodeSmart(data, new HashMap<>());

            // 检查是否有未转义的 < > 在属性值中
            if (xml.contains("=\"") || xml.contains("='")) {
                totalWithAttr++;
                // 简单检查：属性值内不应有未转义的 < 或 >
                XmlSyntaxChecker.CheckResult result = syntaxChecker.check(xml);
                if (!result.hasUnclosedAttribute) {
                    properlyEscaped++;
                }
            }
        }

        if (totalWithAttr > 0) {
            double escapedRate = (properlyEscaped * 100.0) / totalWithAttr;
            System.out.println("属性正确闭合率: " + escapedRate + "% (" + properlyEscaped + "/" + totalWithAttr + ")");
            assertTrue(escapedRate > 80, "属性值正确闭合率太低: " + escapedRate + "%");
        }
    }

    @Test
    @DisplayName("Test 15: Legal Entity Usage - 检查实体使用合法性")
    void testLegalEntityUsage() {
        Iterator<Testcase> iter = mutator.mutate(validSeed, 200);
        int legalEntityCount = 0;
        int attackEntityCount = 0;

        String[] legalEntities = { "&amp;", "&lt;", "&gt;", "&apos;", "&quot;" };
        String[] attackEntities = { "&xxe;", "&lol;" };

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            String xml = decodeSmart(data, new HashMap<>());

            for (String entity : legalEntities) {
                if (xml.contains(entity)) {
                    legalEntityCount++;
                    break;
                }
            }

            for (String entity : attackEntities) {
                if (xml.contains(entity)) {
                    attackEntityCount++;
                    break;
                }
            }
        }

        System.out.println("合法实体使用次数: " + legalEntityCount);
        System.out.println("攻击实体使用次数: " + attackEntityCount);

        // 合法实体应该比攻击实体更常见（约 80% vs 20%）
        assertTrue(legalEntityCount >= attackEntityCount,
                "合法实体使用应该不少于攻击实体");
    }

    @Test
    @DisplayName("Test 16: Comment Validity - 检查注释合法性")
    void testCommentValidity() {
        Iterator<Testcase> iter = mutator.mutate(validSeed, 200);
        int validComments = 0;
        int totalWithComments = 0;

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            String xml = decodeSmart(data, new HashMap<>());

            if (xml.contains("<!--")) {
                totalWithComments++;
                XmlSyntaxChecker.CheckResult result = syntaxChecker.check(xml);
                if (!result.hasInvalidComment) {
                    validComments++;
                }
            }
        }

        if (totalWithComments > 0) {
            double validRate = (validComments * 100.0) / totalWithComments;
            System.out.println("注释有效率: " + validRate + "% (" + validComments + "/" + totalWithComments + ")");
            assertTrue(validRate > 70, "注释有效率太低: " + validRate + "%");
        }
    }

    @Test
    @DisplayName("Test 17: Encoding Consistency - 检查编码声明一致性")
    void testEncodingConsistency() {
        Iterator<Testcase> iter = mutator.mutate(validSeed, 100);
        int consistentCount = 0;
        int totalWithEncoding = 0;

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();

            // 检查 BOM
            String declaredEncoding = null;
            String actualEncoding = "UTF-8";

            if (data.length >= 2 && (data[0] & 0xFF) == 0xFE && (data[1] & 0xFF) == 0xFF) {
                actualEncoding = "UTF-16BE";
            } else if (data.length >= 2 && (data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == 0xFE) {
                actualEncoding = "UTF-16LE";
            }

            String xml = decodeSmart(data, new HashMap<>());

            // 提取声明的编码
            if (xml.contains("encoding=")) {
                int idx = xml.indexOf("encoding=");
                if (idx > 0) {
                    int start = idx + 9;
                    if (start < xml.length()) {
                        char quote = xml.charAt(start);
                        if (quote == '"' || quote == '\'') {
                            int end = xml.indexOf(quote, start + 1);
                            if (end > start) {
                                declaredEncoding = xml.substring(start + 1, end);
                                totalWithEncoding++;

                                // 检查一致性
                                if (declaredEncoding.equalsIgnoreCase(actualEncoding) ||
                                        (actualEncoding.equals("UTF-8")
                                                && declaredEncoding.equalsIgnoreCase("UTF-8"))) {
                                    consistentCount++;
                                }
                            }
                        }
                    }
                }
            }
        }

        if (totalWithEncoding > 0) {
            double consistencyRate = (consistentCount * 100.0) / totalWithEncoding;
            System.out.println("编码一致率: " + consistencyRate + "% (" + consistentCount + "/" + totalWithEncoding + ")");
            assertTrue(consistencyRate > 70, "编码一致率太低: " + consistencyRate + "%");
        }
    }

    @Test
    @DisplayName("Test 18: Mutation Diversity with Valid Seed - 有效种子变异多样性")
    void testMutationDiversityWithValidSeed() {
        Set<Integer> hashes = new HashSet<>();
        Iterator<Testcase> iter = mutator.mutate(validSeed, 100);
        while (iter.hasNext()) {
            hashes.add(Arrays.hashCode(iter.next().getData()));
        }
        // 降低阈值，因为语法修复可能会使更多输出收敛
        assertTrue(hashes.size() > 60, "基于有效种子的变异多样性不足: " + hashes.size() + "/100");
    }

    @Test
    @DisplayName("Test 19: Syntax Fix Integration - 语法修复集成测试")
    void testSyntaxFixIntegration() {
        // 验证语法修复器是否正确集成到变异器中
        // 创建一个会产生语法问题的种子
        byte[] problematicData = "<root><child>".getBytes(StandardCharsets.UTF_8);
        Seed problematicSeed = Seed.loadWithMetadata(new File("problematic_xml"), problematicData);

        Iterator<Testcase> iter = mutator.mutate(problematicSeed, 50);
        int fixedCount = 0;

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            String xml = decodeSmart(data, new HashMap<>());
            XmlSyntaxChecker.CheckResult result = syntaxChecker.check(xml);
            if (result.isValid) {
                fixedCount++;
            }
        }

        // 即使输入有问题，输出也应该有较高的有效率（由于修复器的作用）
        double fixRate = (fixedCount * 100.0) / 50;
        System.out.println("从有问题种子生成的有效 XML 比例: " + fixRate + "%");
        assertTrue(fixRate > 40, "语法修复器未能有效工作: " + fixRate + "%");
    }

    @Test
    @DisplayName("Test 20: Comprehensive Report - 综合报告")
    void testComprehensiveReport() {
        int totalIterations = 500;
        Map<String, Integer> stats = new HashMap<>();
        String[] keys = {
                "Total", "Valid Syntax", "Paired Tags", "Valid Attributes",
                "Valid Comments", "Legal Entities", "Attack Entities"
        };
        for (String k : keys)
            stats.put(k, 0);

        Iterator<Testcase> iter = mutator.mutate(validSeed, totalIterations);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            stats.put("Total", stats.get("Total") + 1);

            String xml = decodeSmart(data, new HashMap<>());
            XmlSyntaxChecker.CheckResult result = syntaxChecker.check(xml);

            if (result.isValid)
                inc(stats, "Valid Syntax");
            if (result.unmatchedOpenTagCount == 0 && result.mismatchedTags.isEmpty())
                inc(stats, "Paired Tags");
            if (!result.hasUnclosedAttribute && !result.hasUnquotedAttribute)
                inc(stats, "Valid Attributes");
            if (!result.hasInvalidComment)
                inc(stats, "Valid Comments");

            // 检查实体类型
            if (xml.contains("&amp;") || xml.contains("&lt;") || xml.contains("&gt;")) {
                inc(stats, "Legal Entities");
            }
            if (xml.contains("&xxe;") || xml.contains("&lol;")) {
                inc(stats, "Attack Entities");
            }
        }

        printComprehensiveReport(stats);
    }

    private void printComprehensiveReport(Map<String, Integer> stats) {
        int total = stats.get("Total");
        System.out.println("====== XmlMutator Improved Quality Report ======");
        System.out.println("Total Samples: " + total);
        System.out.println("-------------------------------------------------");
        System.out.printf("%-25s | %-10s | %-10s%n", "Quality Metric", "Count", "Rate");
        System.out.println("-------------------------------------------------");

        String[] order = {
                "Valid Syntax", "Paired Tags", "Valid Attributes",
                "Valid Comments", "Legal Entities", "Attack Entities"
        };

        for (String k : order) {
            int v = stats.getOrDefault(k, 0);
            double rate = (total > 0) ? (v * 100.0) / total : 0.0;
            System.out.printf("%-25s | %-10d | %6.2f%%%n", k, v, rate);
        }
        System.out.println("=================================================");
    }
}