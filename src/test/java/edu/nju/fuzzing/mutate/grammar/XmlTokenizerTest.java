package edu.nju.fuzzing.mutate.grammar;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * XmlTokenizer 单元测试
 */
class XmlTokenizerTest {

    private final XmlTokenizer tokenizer = new XmlTokenizer();

    // ==========================================
    // 基础功能测试
    // ==========================================

    @Test
    @DisplayName("Test 1: XML 声明")
    void testXmlDeclaration() {
        String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root/>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        assertTrue(hasTokenOfType(tokens, Token.Type.XML_DECL));
    }

    @Test
    @DisplayName("Test 2: 简单元素")
    void testSimpleElement() {
        String xml = "<root>content</root>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        assertTrue(hasTokenOfType(tokens, Token.Type.XML_TAG_OPEN));
        assertTrue(hasTokenOfType(tokens, Token.Type.XML_TAG_CLOSE));
    }

    @Test
    @DisplayName("Test 3: 自闭合标签")
    void testSelfClosingTag() {
        String xml = "<empty/>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        assertFalse(tokens.isEmpty());
        String combined = combineValues(tokens);
        assertTrue(combined.contains("empty"));
    }

    @Test
    @DisplayName("Test 4: 带属性的标签")
    void testTagWithAttributes() {
        String xml = "<div id=\"main\" class=\"container\">text</div>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        String combined = combineValues(tokens);
        assertTrue(combined.contains("id"));
        assertTrue(combined.contains("main"));
        assertTrue(combined.contains("class"));
    }

    @Test
    @DisplayName("Test 5: CDATA 区块")
    void testCDataSection() {
        String xml = "<root><![CDATA[<script>alert('xss')</script>]]></root>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        assertTrue(hasTokenOfType(tokens, Token.Type.XML_CDATA));

        Optional<Token> cdata = tokens.stream()
                .filter(t -> t.getType() == Token.Type.XML_CDATA)
                .findFirst();
        assertTrue(cdata.isPresent());
        assertTrue(cdata.get().getValue().contains("script"));
    }

    @Test
    @DisplayName("Test 6: XML 注释")
    void testXmlComment() {
        String xml = "<root><!-- this is a comment --><child/></root>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        String combined = combineValues(tokens);
        assertTrue(combined.contains("comment") || hasTokenOfType(tokens, Token.Type.COMMENT));
    }

    @Test
    @DisplayName("Test 7: DOCTYPE 声明")
    void testDoctype() {
        String xml = "<!DOCTYPE html><html></html>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        assertTrue(hasTokenOfType(tokens, Token.Type.XML_DOCTYPE));
    }

    @Test
    @DisplayName("Test 8: 实体引用")
    void testEntityReferences() {
        String xml = "<root>&lt;&gt;&amp;&quot;&apos;</root>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        String combined = combineValues(tokens);
        assertTrue(combined.contains("&lt;") || combined.contains("<") ||
                hasTokenOfType(tokens, Token.Type.XML_ENTITY));
    }

    @Test
    @DisplayName("Test 9: 嵌套元素")
    void testNestedElements() {
        String xml = "<root><parent><child>text</child></parent></root>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        long openTags = tokens.stream()
                .filter(t -> t.getType() == Token.Type.XML_TAG_OPEN)
                .count();
        long closeTags = tokens.stream()
                .filter(t -> t.getType() == Token.Type.XML_TAG_CLOSE)
                .count();

        assertTrue(openTags >= 3);
        assertTrue(closeTags >= 3);
    }

    @Test
    @DisplayName("Test 10: 命名空间")
    void testNamespaces() {
        String xml = "<ns:root xmlns:ns=\"http://example.com\"><ns:child/></ns:root>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        String combined = combineValues(tokens);
        assertTrue(combined.contains("ns:root") || combined.contains("ns:"));
        assertTrue(combined.contains("xmlns"));
    }

    @Test
    @DisplayName("Test 11: 处理指令")
    void testProcessingInstruction() {
        String xml = "<?xml-stylesheet type=\"text/xsl\" href=\"style.xsl\"?><root/>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        String combined = combineValues(tokens);
        assertTrue(combined.contains("xml-stylesheet") || combined.contains("style.xsl"));
    }

    @Test
    @DisplayName("Test 12: 容错 - 不完整的标签")
    void testIncompleteTag() {
        String xml = "<root><unclosed";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        assertFalse(tokens.isEmpty());
    }

    @Test
    @DisplayName("Test 13: 容错 - 未闭合的 CDATA")
    void testUnterminatedCData() {
        String xml = "<root><![CDATA[unterminated";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));

        assertFalse(tokens.isEmpty());
    }

    @Test
    @DisplayName("Test 14: 构建树")
    void testBuildTree() {
        String xml = "<root><child>text</child></root>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
        TokenNode tree = tokenizer.buildTree(tokens);

        assertNotNull(tree);
        assertEquals(TokenNode.NodeType.ROOT, tree.getNodeType());
    }

    @Test
    @DisplayName("Test 15: 完整解析流程")
    void testParse() {
        String xml = "<root attr=\"value\"/>";
        TokenNode tree = tokenizer.parse(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(tree);
        String serialized = tree.serialize();
        assertTrue(serialized.contains("root"));
    }

    @Test
    @DisplayName("Test 16: 空输入")
    void testEmptyInput() {
        List<Token> tokens = tokenizer.tokenize(new byte[0]);
        assertTrue(tokens.isEmpty());
    }

    // ==========================================
    // BOM 编码测试
    // ==========================================

    @Nested
    @DisplayName("BOM 编码测试")
    class BomEncodingTests {

        @Test
        @DisplayName("Test 17: UTF-8 BOM")
        void testUtf8Bom() {
            byte[] bom = { (byte) 0xEF, (byte) 0xBB, (byte) 0xBF };
            byte[] xml = "<root/>".getBytes(StandardCharsets.UTF_8);
            byte[] input = new byte[bom.length + xml.length];
            System.arraycopy(bom, 0, input, 0, bom.length);
            System.arraycopy(xml, 0, input, bom.length, xml.length);

            List<Token> tokens = tokenizer.tokenize(input);
            assertFalse(tokens.isEmpty());
            String combined = combineValues(tokens);
            assertTrue(combined.contains("root"));
        }

        @Test
        @DisplayName("Test 18: UTF-16BE BOM")
        void testUtf16BeBom() {
            byte[] bom = { (byte) 0xFE, (byte) 0xFF };
            String xmlStr = "<root/>";
            byte[] xml = xmlStr.getBytes(StandardCharsets.UTF_16BE);
            byte[] input = new byte[bom.length + xml.length];
            System.arraycopy(bom, 0, input, 0, bom.length);
            System.arraycopy(xml, 0, input, bom.length, xml.length);

            List<Token> tokens = tokenizer.tokenize(input);
            assertFalse(tokens.isEmpty());
        }

        @Test
        @DisplayName("Test 19: UTF-16LE BOM")
        void testUtf16LeBom() {
            byte[] bom = { (byte) 0xFF, (byte) 0xFE };
            String xmlStr = "<root/>";
            byte[] xml = xmlStr.getBytes(StandardCharsets.UTF_16LE);
            byte[] input = new byte[bom.length + xml.length];
            System.arraycopy(bom, 0, input, 0, bom.length);
            System.arraycopy(xml, 0, input, bom.length, xml.length);

            List<Token> tokens = tokenizer.tokenize(input);
            assertFalse(tokens.isEmpty());
        }
    }

    // ==========================================
    // DOCTYPE 复杂情况测试
    // ==========================================

    @Nested
    @DisplayName("DOCTYPE 测试")
    class DoctypeTests {

        @Test
        @DisplayName("Test 20: DOCTYPE 内部 DTD")
        void testDoctypeInternalDtd() {
            String xml = "<!DOCTYPE root [<!ELEMENT root (#PCDATA)>]><root/>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertTrue(hasTokenOfType(tokens, Token.Type.XML_DOCTYPE));
        }

        @Test
        @DisplayName("Test 21: DOCTYPE 带引号字符串")
        void testDoctypeWithQuotedStrings() {
            String xml = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1.dtd\"><html/>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertTrue(hasTokenOfType(tokens, Token.Type.XML_DOCTYPE));
        }

        @Test
        @DisplayName("Test 22: DOCTYPE 嵌套括号")
        void testDoctypeNestedBrackets() {
            String xml = "<!DOCTYPE root [<!ENTITY test \"[test]\">]><root/>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertTrue(hasTokenOfType(tokens, Token.Type.XML_DOCTYPE));
        }

        @Test
        @DisplayName("Test 23: DOCTYPE 未闭合")
        void testDoctypeUnclosed() {
            String xml = "<!DOCTYPE root [<!ELEMENT root";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertFalse(tokens.isEmpty());
        }
    }

    // ==========================================
    // 属性测试
    // ==========================================

    @Nested
    @DisplayName("属性测试")
    class AttributeTests {

        @Test
        @DisplayName("Test 24: 无引号属性值")
        void testUnquotedAttributeValue() {
            String xml = "<input type=text name=field>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            String combined = combineValues(tokens);
            assertTrue(combined.contains("type") && combined.contains("text"));
        }

        @Test
        @DisplayName("Test 25: 单引号属性值")
        void testSingleQuoteAttribute() {
            String xml = "<div class='container' id='main'/>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            String combined = combineValues(tokens);
            assertTrue(combined.contains("container"));
        }

        @Test
        @DisplayName("Test 26: 属性值中的特殊字符")
        void testAttributeWithSpecialChars() {
            String xml = "<a href=\"http://example.com?a=1&amp;b=2\">link</a>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertFalse(tokens.isEmpty());
        }

        @Test
        @DisplayName("Test 27: 无值属性")
        void testAttributeWithoutValue() {
            String xml = "<input disabled readonly/>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            String combined = combineValues(tokens);
            assertTrue(combined.contains("disabled"));
        }

        @Test
        @DisplayName("Test 28: 属性等号周围有空格")
        void testAttributeWithSpaces() {
            String xml = "<div id = \"main\" class  =  'container'/>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            String combined = combineValues(tokens);
            assertTrue(combined.contains("id") && combined.contains("main"));
        }
    }

    // ==========================================
    // 边界情况测试
    // ==========================================

    @Nested
    @DisplayName("边界情况测试")
    class EdgeCaseTests {

        @Test
        @DisplayName("Test 29: null 输入")
        void testNullInput() {
            List<Token> tokens = tokenizer.tokenize((byte[]) null);
            assertTrue(tokens.isEmpty());
        }

        @Test
        @DisplayName("Test 30: 未闭合注释")
        void testUnterminatedComment() {
            String xml = "<root><!-- comment without end";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertFalse(tokens.isEmpty());
        }

        @Test
        @DisplayName("Test 31: 未闭合 XML 声明")
        void testUnterminatedXmlDecl() {
            String xml = "<?xml version=\"1.0\"";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertFalse(tokens.isEmpty());
        }

        @Test
        @DisplayName("Test 32: 未闭合处理指令")
        void testUnterminatedPI() {
            String xml = "<?php echo 'test'";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertFalse(tokens.isEmpty());
        }

        @Test
        @DisplayName("Test 33: 孤立的 & 符号")
        void testLoneAmpersand() {
            String xml = "<root>test & value</root>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertFalse(tokens.isEmpty());
        }

        @Test
        @DisplayName("Test 34: 不完整实体引用")
        void testIncompleteEntity() {
            String xml = "<root>&incomplete</root>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertFalse(tokens.isEmpty());
        }

        @Test
        @DisplayName("Test 35: 只有 < 符号")
        void testLoneOpenBracket() {
            String xml = "<";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertFalse(tokens.isEmpty());
        }

        @Test
        @DisplayName("Test 36: 畸形标签 </")
        void testMalformedCloseTag() {
            String xml = "</";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertFalse(tokens.isEmpty());
        }

        @Test
        @DisplayName("Test 37: 数字实体引用")
        void testNumericEntity() {
            String xml = "<root>&#65;&#x41;</root>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertTrue(hasTokenOfType(tokens, Token.Type.XML_ENTITY) ||
                    combineValues(tokens).contains("&#"));
        }

        @Test
        @DisplayName("Test 38: 换行和空白处理")
        void testWhitespaceHandling() {
            String xml = "<root>\n  <child>\r\n    text\t</child>\n</root>";
            List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
            assertTrue(hasTokenOfType(tokens, Token.Type.WHITESPACE) ||
                    hasTokenOfType(tokens, Token.Type.NEWLINE));
        }
    }

    // ==========================================
    // 接口默认方法测试
    // ==========================================

    @Nested
    @DisplayName("接口默认方法测试")
    class InterfaceDefaultMethodTests {

        @Test
        @DisplayName("Test 39: tokenize(String) 默认方法")
        void testTokenizeString() {
            String xml = "<root>text</root>";
            List<Token> tokens = tokenizer.tokenize(xml);
            assertFalse(tokens.isEmpty());
            assertTrue(hasTokenOfType(tokens, Token.Type.XML_TAG_OPEN));
        }

        @Test
        @DisplayName("Test 40: parse(String) 默认方法")
        void testParseString() {
            String xml = "<root><child/></root>";
            TokenNode tree = tokenizer.parse(xml);
            assertNotNull(tree);
            assertEquals(TokenNode.NodeType.ROOT, tree.getNodeType());
        }

        @Test
        @DisplayName("Test 41: parse(byte[]) 默认方法")
        void testParseBytes() {
            byte[] xml = "<root><child/></root>".getBytes(StandardCharsets.UTF_8);
            TokenNode tree = tokenizer.parse(xml);
            assertNotNull(tree);
        }

        @Test
        @DisplayName("Test 42: buildTree 空列表")
        void testBuildTreeEmptyList() {
            TokenNode tree = tokenizer.buildTree(java.util.Collections.emptyList());
            assertNotNull(tree);
            assertEquals(TokenNode.NodeType.ROOT, tree.getNodeType());
        }

        @Test
        @DisplayName("Test 43: buildTree null 列表")
        void testBuildTreeNullList() {
            TokenNode tree = tokenizer.buildTree(null);
            assertNotNull(tree);
        }
    }

    // ==========================================
    // 辅助方法
    // ==========================================

    private boolean hasTokenOfType(List<Token> tokens, Token.Type type) {
        return tokens.stream().anyMatch(t -> t.getType() == type);
    }

    private String combineValues(List<Token> tokens) {
        StringBuilder sb = new StringBuilder();
        for (Token t : tokens) {
            if (t.getValue() != null) {
                sb.append(t.getValue());
            }
        }
        return sb.toString();
    }
}
