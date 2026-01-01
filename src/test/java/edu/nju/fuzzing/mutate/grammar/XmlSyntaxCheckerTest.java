package edu.nju.fuzzing.mutate.grammar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

/**
 * XmlSyntaxChecker 测试
 * 
 * 验证 XML 语法检查功能：
 * - 标签配对检查
 * - 属性引号检查
 * - 注释合法性检查
 * - 实体引用检查
 * - CDATA 结构检查
 */
public class XmlSyntaxCheckerTest {

    private XmlSyntaxChecker checker;

    @BeforeEach
    void setUp() {
        checker = new XmlSyntaxChecker();
    }

    // ==========================================
    // 有效 XML 测试
    // ==========================================

    @Test
    void testValidEmptyElement() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root/>");
        assertTrue(result.isValid, "Self-closing element should be valid");
    }

    @Test
    void testValidSimpleElement() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root></root>");
        assertTrue(result.isValid, "Simple element should be valid");
    }

    @Test
    void testValidElementWithContent() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root>Hello World</root>");
        assertTrue(result.isValid, "Element with text content should be valid");
    }

    @Test
    void testValidNestedElements() {
        XmlSyntaxChecker.CheckResult result = checker.check(
                "<root><child><grandchild/></child></root>");
        assertTrue(result.isValid, "Nested elements should be valid");
    }

    @Test
    void testValidWithAttributes() {
        XmlSyntaxChecker.CheckResult result = checker.check(
                "<root id=\"1\" class='test'>content</root>");
        assertTrue(result.isValid, "Element with attributes should be valid");
    }

    @Test
    void testValidWithXmlDeclaration() {
        XmlSyntaxChecker.CheckResult result = checker.check(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>");
        assertTrue(result.isValid, "XML with declaration should be valid");
    }

    @Test
    void testValidWithDoctype() {
        XmlSyntaxChecker.CheckResult result = checker.check(
                "<!DOCTYPE root [<!ENTITY test \"value\">]><root>&test;</root>");
        assertTrue(result.isValid, "XML with DOCTYPE and defined entity should be valid");
    }

    @Test
    void testValidWithCData() {
        XmlSyntaxChecker.CheckResult result = checker.check(
                "<root><![CDATA[<not>parsed</not>]]></root>");
        assertTrue(result.isValid, "XML with CDATA should be valid");
    }

    @Test
    void testValidWithComment() {
        XmlSyntaxChecker.CheckResult result = checker.check(
                "<root><!-- This is a comment --></root>");
        assertTrue(result.isValid, "XML with valid comment should be valid");
    }

    @Test
    void testValidWithBuiltinEntities() {
        XmlSyntaxChecker.CheckResult result = checker.check(
                "<root>&amp;&lt;&gt;&apos;&quot;</root>");
        assertTrue(result.isValid, "XML with built-in entities should be valid");
    }

    @Test
    void testValidNullInput() {
        XmlSyntaxChecker.CheckResult result = checker.check(null);
        assertTrue(result.isValid, "Null input should be valid");
    }

    @Test
    void testValidEmptyInput() {
        XmlSyntaxChecker.CheckResult result = checker.check("");
        assertTrue(result.isValid, "Empty input should be valid");
    }

    // ==========================================
    // 标签不匹配测试
    // ==========================================

    @Test
    void testMissingCloseTag() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root><child>");
        assertFalse(result.isValid, "Missing close tag should be invalid");
        assertTrue(result.unmatchedOpenTagCount > 0, "Should have unmatched open tags");
        assertTrue(result.unmatchedOpenTags.contains("child") || result.unmatchedOpenTags.contains("root"));
    }

    @Test
    void testExtraCloseTag() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root></root></extra>");
        assertFalse(result.isValid, "Extra close tag should be invalid");
        assertTrue(result.mismatchedTags.size() > 0, "Should have mismatched tags");
    }

    @Test
    void testMismatchedTags() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root><child></wrong></root>");
        assertFalse(result.isValid, "Mismatched tags should be invalid");
        assertTrue(result.mismatchedTags.size() > 0, "Should detect tag mismatch");
    }

    @Test
    void testNestedMismatch() {
        XmlSyntaxChecker.CheckResult result = checker.check("<a><b></a></b>");
        assertFalse(result.isValid, "Nested mismatched tags should be invalid");
    }

    // ==========================================
    // 属性问题测试
    // ==========================================

    @Test
    void testUnclosedAttributeQuote() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root id=\"value></root>");
        assertFalse(result.isValid, "Unclosed attribute quote should be invalid");
        assertTrue(result.hasUnclosedAttribute, "Should detect unclosed attribute");
    }

    @Test
    void testUnquotedAttribute() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root id=value></root>");
        assertFalse(result.isValid, "Unquoted attribute should be invalid in XML");
        assertTrue(result.hasUnquotedAttribute, "Should detect unquoted attribute");
    }

    // ==========================================
    // 注释问题测试
    // ==========================================

    @Test
    void testInvalidCommentWithDoubleDash() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root><!-- invalid -- comment --></root>");
        assertFalse(result.isValid, "Comment with -- should be invalid");
        assertTrue(result.hasInvalidComment, "Should detect invalid comment");
    }

    @Test
    void testUnclosedComment() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root><!-- unclosed comment");
        assertFalse(result.isValid, "Unclosed comment should be invalid");
        assertTrue(result.hasInvalidComment, "Should detect unclosed comment");
    }

    // ==========================================
    // 实体问题测试
    // ==========================================

    @Test
    void testUndefinedEntity() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root>&undefined;</root>");
        assertFalse(result.isValid, "Undefined entity should be invalid");
        assertTrue(result.undefinedEntities.contains("&undefined;"), "Should detect undefined entity");
    }

    @Test
    void testInvalidNumericEntity() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root>&#0;</root>");
        assertFalse(result.isValid, "Entity &#0; should be invalid");
        assertTrue(result.hasInvalidEntity, "Should detect invalid numeric entity");
    }

    @Test
    void testInvalidHexEntity() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root>&#x0;</root>");
        assertFalse(result.isValid, "Entity &#x0; should be invalid");
        assertTrue(result.hasInvalidEntity, "Should detect invalid hex entity");
    }

    @Test
    void testValidNumericEntity() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root>&#65;</root>");
        assertTrue(result.isValid, "Valid numeric entity &#65; should be valid");
    }

    @Test
    void testValidHexEntity() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root>&#x41;</root>");
        assertTrue(result.isValid, "Valid hex entity &#x41; should be valid");
    }

    // ==========================================
    // CDATA 问题测试
    // ==========================================

    @Test
    void testUnclosedCData() {
        XmlSyntaxChecker.CheckResult result = checker.check("<root><![CDATA[unclosed");
        assertFalse(result.isValid, "Unclosed CDATA should be invalid");
        assertTrue(result.hasUnclosedCData, "Should detect unclosed CDATA");
    }

    // ==========================================
    // 复杂场景测试
    // ==========================================

    @Test
    void testComplexValidXml() {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<!DOCTYPE root [\n" +
                "  <!ENTITY custom \"value\">\n" +
                "]>\n" +
                "<root xmlns:ns=\"http://example.com\" id=\"1\">\n" +
                "  <!-- Comment -->\n" +
                "  <ns:child attr='test'>\n" +
                "    <![CDATA[<raw>data</raw>]]>\n" +
                "    Text content &amp; entities\n" +
                "  </ns:child>\n" +
                "  <empty/>\n" +
                "</root>";

        XmlSyntaxChecker.CheckResult result = checker.check(xml);
        assertTrue(result.isValid, "Complex valid XML should be valid: " + result.errorMessage);
    }

    @Test
    void testMultipleIssues() {
        String xml = "<root id=unquoted><!-- has -- dash -->&undefined;<child>";
        XmlSyntaxChecker.CheckResult result = checker.check(xml);
        assertFalse(result.isValid, "XML with multiple issues should be invalid");
        assertTrue(result.getTotalIssueCount() > 1, "Should detect multiple issues");
    }

    // ==========================================
    // Token 列表检查测试
    // ==========================================

    @Test
    void testCheckTokens() {
        XmlTokenizer tokenizer = new XmlTokenizer();
        java.util.List<Token> tokens = tokenizer.tokenize("<root><child/></root>".getBytes());

        XmlSyntaxChecker.CheckResult result = checker.checkTokens(tokens);
        assertTrue(result.isValid, "Valid token list should pass check");
    }

    @Test
    void testCheckInvalidTokens() {
        XmlTokenizer tokenizer = new XmlTokenizer();
        java.util.List<Token> tokens = tokenizer.tokenize("<root><child>".getBytes());

        XmlSyntaxChecker.CheckResult result = checker.checkTokens(tokens);
        assertFalse(result.isValid, "Invalid token list should fail check");
    }
}
