package edu.nju.fuzzing.mutate.grammar;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * MjsTokenizer 单元测试
 */
class MjsTokenizerTest {

    private final MjsTokenizer tokenizer = new MjsTokenizer();

    @Test
    @DisplayName("Test 1: 简单对象分词")
    void testSimpleObject() {
        String mjs = "{\"key\": 123}";
        List<Token> tokens = tokenizer.tokenize(mjs.getBytes(StandardCharsets.UTF_8));
        
        assertFalse(tokens.isEmpty());
        
        // 验证包含关键 token
        assertTrue(hasTokenOfType(tokens, Token.Type.LBRACE));
        assertTrue(hasTokenOfType(tokens, Token.Type.STRING));
        assertTrue(hasTokenOfType(tokens, Token.Type.COLON));
        assertTrue(hasTokenOfType(tokens, Token.Type.NUMBER));
        assertTrue(hasTokenOfType(tokens, Token.Type.RBRACE));
    }

    @Test
    @DisplayName("Test 2: 简单数组分词")
    void testSimpleArray() {
        String mjs = "[1, 2, 3]";
        List<Token> tokens = tokenizer.tokenize(mjs.getBytes(StandardCharsets.UTF_8));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.LBRACKET));
        assertTrue(hasTokenOfType(tokens, Token.Type.RBRACKET));
        assertTrue(hasTokenOfType(tokens, Token.Type.COMMA));
        
        // 应有3个数字
        long numberCount = tokens.stream()
            .filter(t -> t.getType() == Token.Type.NUMBER)
            .count();
        assertEquals(3, numberCount);
    }

    @Test
    @DisplayName("Test 3: 字符串带转义")
    void testStringWithEscapes() {
        String mjs = "{\"msg\": \"hello\\nworld\\t!\"}";
        List<Token> tokens = tokenizer.tokenize(mjs.getBytes(StandardCharsets.UTF_8));
        
        Optional<Token> strToken = tokens.stream()
            .filter(t -> t.getType() == Token.Type.STRING && t.getValue().contains("hello"))
            .findFirst();
        
        assertTrue(strToken.isPresent());
        assertTrue(strToken.get().getValue().contains("\\n"));
    }

    @Test
    @DisplayName("Test 4: 关键字识别")
    void testKeywords() {
        String mjs = "[true, false, null]";
        List<Token> tokens = tokenizer.tokenize(mjs.getBytes(StandardCharsets.UTF_8));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.BOOLEAN));
        assertTrue(hasTokenOfType(tokens, Token.Type.NULL));
        
        // 两个布尔值
        long boolCount = tokens.stream()
            .filter(t -> t.getType() == Token.Type.BOOLEAN)
            .count();
        assertEquals(2, boolCount);
    }

    @Test
    @DisplayName("Test 5: 数字格式 - 整数、小数、科学计数法")
    void testNumberFormats() {
        String mjs = "[42, -3.14, 1.5e10, -2E-5]";
        List<Token> tokens = tokenizer.tokenize(mjs.getBytes(StandardCharsets.UTF_8));
        
        List<String> numbers = new ArrayList<>();
        for (Token t : tokens) {
            if (t.getType() == Token.Type.NUMBER) {
                numbers.add(t.getValue());
            }
        }
        
        assertEquals(4, numbers.size());
        assertTrue(numbers.contains("42"));
        assertTrue(numbers.contains("-3.14"));
    }

    @Test
    @DisplayName("Test 6: UTF-8 BOM 检测")
    void testUtf8Bom() {
        byte[] bom = {(byte)0xEF, (byte)0xBB, (byte)0xBF};
        byte[] mjs = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);
        byte[] withBom = new byte[bom.length + mjs.length];
        System.arraycopy(bom, 0, withBom, 0, bom.length);
        System.arraycopy(mjs, 0, withBom, bom.length, mjs.length);
        
        List<Token> tokens = tokenizer.tokenize(withBom);
        
        assertFalse(tokens.isEmpty());
        assertTrue(hasTokenOfType(tokens, Token.Type.LBRACE));
    }

    @Test
    @DisplayName("Test 7: UTF-16BE BOM 检测")
    void testUtf16BeBom() {
        byte[] bom = {(byte)0xFE, (byte)0xFF};
        String mjs = "{\"a\":1}";
        byte[] mjsBytes = mjs.getBytes(StandardCharsets.UTF_16BE);
        byte[] withBom = new byte[bom.length + mjsBytes.length];
        System.arraycopy(bom, 0, withBom, 0, bom.length);
        System.arraycopy(mjsBytes, 0, withBom, bom.length, mjsBytes.length);
        
        List<Token> tokens = tokenizer.tokenize(withBom);
        
        assertFalse(tokens.isEmpty());
    }

    @Test
    @DisplayName("Test 8: 空白字符处理")
    void testWhitespace() {
        String mjs = "{\n  \"key\" : \t 123 \n}";
        List<Token> tokens = tokenizer.tokenize(mjs.getBytes(StandardCharsets.UTF_8));
        
        // 空白可能被保留为 WHITESPACE token，也可能被跳过
        // 关键是核心 token 都在
        assertTrue(hasTokenOfType(tokens, Token.Type.LBRACE));
        assertTrue(hasTokenOfType(tokens, Token.Type.STRING));
        assertTrue(hasTokenOfType(tokens, Token.Type.NUMBER));
        assertTrue(hasTokenOfType(tokens, Token.Type.RBRACE));
    }

    @Test
    @DisplayName("Test 9: 嵌套结构")
    void testNestedStructure() {
        String mjs = "{\"obj\": {\"arr\": [1, 2]}}";
        List<Token> tokens = tokenizer.tokenize(mjs.getBytes(StandardCharsets.UTF_8));
        
        // 应该有2个 { 和 2个 }
        long openBraceCount = tokens.stream()
            .filter(t -> t.getType() == Token.Type.LBRACE)
            .count();
        long closeBraceCount = tokens.stream()
            .filter(t -> t.getType() == Token.Type.RBRACE)
            .count();
        
        assertEquals(2, openBraceCount);
        assertEquals(2, closeBraceCount);
    }

    @Test
    @DisplayName("Test 10: 容错 - 不完整的字符串")
    void testIncompleteString() {
        String mjs = "{\"unterminated";
        List<Token> tokens = tokenizer.tokenize(mjs.getBytes(StandardCharsets.UTF_8));
        
        // 应该仍能分词，不会崩溃
        assertFalse(tokens.isEmpty());
    }

    @Test
    @DisplayName("Test 11: 容错 - 非法字符")
    void testIllegalCharacters() {
        String mjs = "{\"key\": @#$%}";
        List<Token> tokens = tokenizer.tokenize(mjs.getBytes(StandardCharsets.UTF_8));
        
        // 应该包含 UNKNOWN 或 RAW token
        assertFalse(tokens.isEmpty());
    }

    @Test
    @DisplayName("Test 12: 构建树")
    void testBuildTree() {
        String mjs = "{\"a\": [1, 2]}";
        List<Token> tokens = tokenizer.tokenize(mjs.getBytes(StandardCharsets.UTF_8));
        TokenNode tree = tokenizer.buildTree(tokens);
        
        assertNotNull(tree);
        assertEquals(TokenNode.NodeType.ROOT, tree.getNodeType());
        assertFalse(tree.getChildren().isEmpty());
    }

    @Test
    @DisplayName("Test 13: 完整解析流程")
    void testParse() {
        String mjs = "[true, null]";
        TokenNode tree = tokenizer.parse(mjs.getBytes(StandardCharsets.UTF_8));
        
        assertNotNull(tree);
        String serialized = tree.serialize();
        // 序列化后应保留结构
        assertTrue(serialized.contains("["));
        assertTrue(serialized.contains("]"));
        assertTrue(serialized.contains("true"));
        assertTrue(serialized.contains("null"));
    }

    @Test
    @DisplayName("Test 14: 空输入")
    void testEmptyInput() {
        List<Token> tokens = tokenizer.tokenize(new byte[0]);
        assertTrue(tokens.isEmpty());
        
        TokenNode tree = tokenizer.parse(new byte[0]);
        assertNotNull(tree);
        assertTrue(tree.getChildren().isEmpty());
    }

    private boolean hasTokenOfType(List<Token> tokens, Token.Type type) {
        return tokens.stream().anyMatch(t -> t.getType() == type);
    }
}
