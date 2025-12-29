package edu.nju.fuzzing.mutate.grammar;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * XmlTokenizer 单元测试
 */
class XmlTokenizerTest {

    private final XmlTokenizer tokenizer = new XmlTokenizer();

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
        // 应该有某种标签 token
        String combined = combineValues(tokens);
        assertTrue(combined.contains("empty"));
    }

    @Test
    @DisplayName("Test 4: 带属性的标签")
    void testTagWithAttributes() {
        String xml = "<div id=\"main\" class=\"container\">text</div>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
        
        // 应该包含属性相关的 token
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
        
        // 注释可能被识别为 COMMENT 类型或包含在组合值中
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
        
        // 应该有实体引用 token 或文本中包含这些实体
        String combined = combineValues(tokens);
        assertTrue(combined.contains("&lt;") || combined.contains("<") || 
                   hasTokenOfType(tokens, Token.Type.XML_ENTITY));
    }

    @Test
    @DisplayName("Test 9: 嵌套元素")
    void testNestedElements() {
        String xml = "<root><parent><child>text</child></parent></root>";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
        
        // 应该有多个开标签和闭标签
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
        
        // 应该有处理指令相关内容
        String combined = combineValues(tokens);
        assertTrue(combined.contains("xml-stylesheet") || combined.contains("style.xsl"));
    }

    @Test
    @DisplayName("Test 12: 容错 - 不完整的标签")
    void testIncompleteTag() {
        String xml = "<root><unclosed";
        List<Token> tokens = tokenizer.tokenize(xml.getBytes(StandardCharsets.UTF_8));
        
        // 应该不崩溃，返回部分结果
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
