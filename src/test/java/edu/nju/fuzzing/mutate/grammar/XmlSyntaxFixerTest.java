package edu.nju.fuzzing.mutate.grammar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

/**
 * XmlSyntaxFixer 测试
 * 
 * 验证 XML 语法修复功能：
 * - 标签配对修复
 * - 属性引号修复
 * - 注释修复
 * - 实体引用修复
 * - CDATA 修复
 */
public class XmlSyntaxFixerTest {

    private XmlSyntaxFixer fixer;
    private XmlSyntaxChecker checker;

    @BeforeEach
    void setUp() {
        checker = new XmlSyntaxChecker();
        fixer = new XmlSyntaxFixer(checker);
    }

    // ==========================================
    // 标签修复测试
    // ==========================================

    @Test
    void testFixMissingCloseTag() {
        String xml = "<root><child>";
        String fixed = fixer.fix(xml);

        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed XML should be valid: " + result.errorMessage);
        assertTrue(fixed.contains("</child>") || fixed.contains("</root>"),
                "Fixed XML should have closing tags");
    }

    @Test
    void testFixMultipleMissingCloseTags() {
        String xml = "<root><a><b><c>";
        String fixed = fixer.fix(xml);

        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed XML should be valid: " + result.errorMessage);
    }

    @Test
    void testFixMismatchedTags() {
        String xml = "<root><child></wrong></root>";
        String fixed = fixer.fix(xml);

        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed XML should be valid: " + result.errorMessage);
    }

    @Test
    void testValidXmlUnchanged() {
        String xml = "<root><child/></root>";
        String fixed = fixer.fix(xml);

        assertEquals(xml, fixed, "Valid XML should not be changed");
    }

    // ==========================================
    // 属性修复测试
    // ==========================================

    @Test
    void testFixUnquotedAttribute() {
        String xml = "<root id=value></root>";
        String fixed = fixer.fix(xml);

        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed XML should be valid: " + result.errorMessage);
        assertTrue(fixed.contains("id=\"") || fixed.contains("id='"),
                "Attribute should be quoted");
    }

    @Test
    void testFixUnclosedAttributeQuote() {
        String xml = "<root id=\"value></root>";
        String fixed = fixer.fix(xml);

        // 修复后应该是有效的或至少属性问题被解决
        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        assertFalse(result.hasUnclosedAttribute, "Attribute quote should be fixed");
    }

    @Test
    void testFixMultipleUnquotedAttributes() {
        String xml = "<root id=1 class=test name=foo></root>";
        String fixed = fixer.fix(xml);

        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed XML should be valid: " + result.errorMessage);
    }

    // ==========================================
    // 注释修复测试
    // ==========================================

    @Test
    void testFixInvalidComment() {
        String xml = "<root><!-- has -- dash --></root>";
        String fixed = fixer.fix(xml);

        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed XML should be valid: " + result.errorMessage);
        // 注释内容中的 -- 应该被替换为 - -，但注释标记 <!-- --> 本身是允许的
        // 检查注释内部（去除标记后）不包含连续的 --
        int commentStart = fixed.indexOf("<!--");
        int commentEnd = fixed.indexOf("-->", commentStart);
        if (commentStart >= 0 && commentEnd > commentStart) {
            String commentContent = fixed.substring(commentStart + 4, commentEnd);
            assertFalse(commentContent.contains("--"),
                    "Comment content should not contain --: " + commentContent);
        }
    }

    @Test
    void testFixMultipleInvalidComments() {
        String xml = "<root><!-- a--b --><!-- c--d --></root>";
        String fixed = fixer.fix(xml);

        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed XML should be valid: " + result.errorMessage);
    }

    // ==========================================
    // 实体修复测试
    // ==========================================

    @Test
    void testFixUndefinedEntity() {
        String xml = "<root>&undefined;</root>";
        String fixed = fixer.fix(xml);

        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed XML should be valid: " + result.errorMessage);
        assertTrue(fixed.contains("&amp;undefined;"),
                "Undefined entity should be escaped");
    }

    @Test
    void testBuiltinEntitiesUnchanged() {
        String xml = "<root>&amp;&lt;&gt;</root>";
        String fixed = fixer.fix(xml);

        assertEquals(xml, fixed, "Built-in entities should not be changed");
    }

    // ==========================================
    // CDATA 修复测试
    // ==========================================

    @Test
    void testFixUnclosedCData() {
        String xml = "<root><![CDATA[content";
        String fixed = fixer.fix(xml);

        assertTrue(fixed.contains("]]>"), "CDATA should be closed");
    }

    // ==========================================
    // 复杂场景测试
    // ==========================================

    @Test
    void testFixMultipleIssues() {
        String xml = "<root id=unquoted><!-- has -- dash -->&undefined;<child>";
        String fixed = fixer.fix(xml);

        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        // 可能无法修复所有问题，但应该至少修复一些
        assertTrue(result.getTotalIssueCount() < 4, "Should fix at least some issues");
    }

    @Test
    void testFixPreservesContent() {
        String xml = "<root>Important content</root>";
        String fixed = fixer.fix(xml);

        assertEquals(xml, fixed, "Valid XML content should be preserved");
    }

    @Test
    void testFixNestedTags() {
        String xml = "<root><a><b><c></c></b>";
        String fixed = fixer.fix(xml);

        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed nested tags should be valid: " + result.errorMessage);
    }

    // ==========================================
    // Token 修复测试
    // ==========================================

    @Test
    void testFixTokens() {
        XmlTokenizer tokenizer = new XmlTokenizer();
        List<Token> tokens = tokenizer.tokenize("<root><child>".getBytes());

        List<Token> fixed = fixer.fixTokens(tokens);

        // 重新序列化并检查
        StringBuilder sb = new StringBuilder();
        for (Token t : fixed) {
            if (t.getValue() != null) {
                sb.append(t.getValue());
            }
        }

        XmlSyntaxChecker.CheckResult result = checker.check(sb.toString());
        assertTrue(result.isValid, "Fixed tokens should produce valid XML");
    }

    // ==========================================
    // 静态工具方法测试
    // ==========================================

    @Test
    void testEscapeXmlAttribute() {
        assertEquals("&amp;", XmlSyntaxFixer.escapeXmlAttribute("&"));
        assertEquals("&lt;", XmlSyntaxFixer.escapeXmlAttribute("<"));
        assertEquals("&gt;", XmlSyntaxFixer.escapeXmlAttribute(">"));
        assertEquals("&quot;", XmlSyntaxFixer.escapeXmlAttribute("\""));
        assertEquals("&apos;", XmlSyntaxFixer.escapeXmlAttribute("'"));
        assertEquals("&lt;script&gt;", XmlSyntaxFixer.escapeXmlAttribute("<script>"));
    }

    @Test
    void testEscapeXmlText() {
        assertEquals("&amp;", XmlSyntaxFixer.escapeXmlText("&"));
        assertEquals("&lt;", XmlSyntaxFixer.escapeXmlText("<"));
        assertEquals("&gt;", XmlSyntaxFixer.escapeXmlText(">"));
        assertEquals("&lt;tag&gt;", XmlSyntaxFixer.escapeXmlText("<tag>"));
    }

    @Test
    void testSanitizeComment() {
        assertEquals("a- -b", XmlSyntaxFixer.sanitizeComment("a--b"));
        assertEquals("- -- -", XmlSyntaxFixer.sanitizeComment("----"));
        assertEquals("- ->", XmlSyntaxFixer.sanitizeComment("-->"));
        assertEquals("no change", XmlSyntaxFixer.sanitizeComment("no change"));
    }

    // ==========================================
    // 边界情况测试
    // ==========================================

    @Test
    void testFixNullInput() {
        assertNull(fixer.fix(null), "Null input should return null");
    }

    @Test
    void testFixEmptyInput() {
        assertEquals("", fixer.fix(""), "Empty input should return empty");
    }

    @Test
    void testFixOnlyWhitespace() {
        String xml = "   ";
        String fixed = fixer.fix(xml);
        // 只有空白也是有效的
        XmlSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Whitespace only should be valid");
    }

    @Test
    void testMaxFixAttempts() {
        // 创建一个很难修复的 XML
        String xml = "<a><b><c><d><e>";
        String fixed = fixer.fix(xml);

        // 应该在有限次尝试后返回结果
        assertNotNull(fixed, "Should return result even if not fully fixed");
    }
}
