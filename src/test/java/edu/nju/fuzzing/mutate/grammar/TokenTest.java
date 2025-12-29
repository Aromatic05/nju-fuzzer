package edu.nju.fuzzing.mutate.grammar;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Token 类单元测试
 */
class TokenTest {

    @Test
    @DisplayName("Test 1: Token 基本创建与属性")
    void testTokenCreation() {
        Token token = new Token(Token.Type.STRING, "\"hello\"", 0, 7);
        
        assertEquals(Token.Type.STRING, token.getType());
        assertEquals("\"hello\"", token.getValue());
        assertEquals(0, token.getStartPos());
        assertEquals(7, token.getEndPos());
    }

    @Test
    @DisplayName("Test 2: Token 简化构造函数")
    void testSimpleConstructor() {
        Token token = new Token(Token.Type.NUMBER, "123");
        
        assertEquals(Token.Type.NUMBER, token.getType());
        assertEquals("123", token.getValue());
        assertEquals(-1, token.getStartPos());
        assertEquals(-1, token.getEndPos());
    }

    @Test
    @DisplayName("Test 3: Token withValue 不可变性")
    void testWithValue() {
        Token original = new Token(Token.Type.STRING, "\"old\"", 10, 15);
        Token modified = original.withValue("\"new\"");
        
        // 原始 token 不变
        assertEquals("\"old\"", original.getValue());
        // 新 token 有新值
        assertEquals("\"new\"", modified.getValue());
        // 类型和位置保持不变
        assertEquals(Token.Type.STRING, modified.getType());
        assertEquals(10, modified.getStartPos());
        assertEquals(15, modified.getEndPos());
    }

    @Test
    @DisplayName("Test 4: Token withType 不可变性")
    void testWithType() {
        Token original = new Token(Token.Type.STRING, "123");
        Token modified = original.withType(Token.Type.NUMBER);
        
        assertEquals(Token.Type.STRING, original.getType());
        assertEquals(Token.Type.NUMBER, modified.getType());
        assertEquals("123", modified.getValue());
    }

    @Test
    @DisplayName("Test 5: 分隔符检测")
    void testDelimiterDetection() {
        Token openBrace = new Token(Token.Type.LBRACE, "{");
        Token closeBrace = new Token(Token.Type.RBRACE, "}");
        Token openBracket = new Token(Token.Type.LBRACKET, "[");
        Token closeBracket = new Token(Token.Type.RBRACKET, "]");
        Token string = new Token(Token.Type.STRING, "\"test\"");
        
        assertTrue(openBrace.isDelimiter());
        assertTrue(closeBrace.isDelimiter());
        assertTrue(openBracket.isDelimiter());
        assertTrue(closeBracket.isDelimiter());
        assertFalse(string.isDelimiter());
        
        assertTrue(openBrace.isOpenDelimiter());
        assertTrue(openBracket.isOpenDelimiter());
        assertFalse(closeBrace.isOpenDelimiter());
        assertFalse(closeBracket.isOpenDelimiter());
    }

    @Test
    @DisplayName("Test 6: Token Type 枚举覆盖")
    void testTokenTypes() {
        // 确保所有重要类型都存在
        assertNotNull(Token.Type.RAW);
        assertNotNull(Token.Type.UNKNOWN);
        assertNotNull(Token.Type.WHITESPACE);
        assertNotNull(Token.Type.STRING);
        assertNotNull(Token.Type.NUMBER);
        assertNotNull(Token.Type.BOOLEAN);
        assertNotNull(Token.Type.NULL);
        assertNotNull(Token.Type.LBRACE);
        assertNotNull(Token.Type.RBRACE);
        assertNotNull(Token.Type.LBRACKET);
        assertNotNull(Token.Type.RBRACKET);
        assertNotNull(Token.Type.COMMA);
        assertNotNull(Token.Type.COLON);
        
        // XML 特有类型
        assertNotNull(Token.Type.XML_DECL);
        assertNotNull(Token.Type.XML_TAG_OPEN);
        assertNotNull(Token.Type.XML_TAG_CLOSE);
        assertNotNull(Token.Type.XML_CDATA);
        
        // CXX 特有类型
        assertNotNull(Token.Type.CXX_PREFIX);
        assertNotNull(Token.Type.CXX_TYPE);
        assertNotNull(Token.Type.CXX_NAME);
        assertNotNull(Token.Type.CXX_TEMPLATE);
    }

    @Test
    @DisplayName("Test 7: Token toString")
    void testToString() {
        Token token = new Token(Token.Type.STRING, "\"hello\"");
        String str = token.toString();
        
        assertTrue(str.contains("STRING"));
        assertTrue(str.contains("hello"));
    }
}
