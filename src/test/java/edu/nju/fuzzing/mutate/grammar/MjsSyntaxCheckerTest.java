package edu.nju.fuzzing.mutate.grammar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.ArrayList;

/**
 * MjsSyntaxChecker 测试
 */
public class MjsSyntaxCheckerTest {

    private MjsSyntaxChecker checker;

    @BeforeEach
    void setUp() {
        checker = new MjsSyntaxChecker();
    }

    // ==========================================
    // 有效 JSON/MJS 测试
    // ==========================================

    @Test
    void testValidEmptyObject() {
        MjsSyntaxChecker.CheckResult result = checker.check("{}");
        assertTrue(result.isValid, "Empty object should be valid");
    }

    @Test
    void testValidEmptyArray() {
        MjsSyntaxChecker.CheckResult result = checker.check("[]");
        assertTrue(result.isValid, "Empty array should be valid");
    }

    @Test
    void testValidSimpleObject() {
        MjsSyntaxChecker.CheckResult result = checker.check("{\"key\": \"value\"}");
        assertTrue(result.isValid, "Simple object should be valid");
    }

    @Test
    void testValidNestedObject() {
        MjsSyntaxChecker.CheckResult result = checker.check(
            "{\"a\": {\"b\": {\"c\": 1}}}"
        );
        assertTrue(result.isValid, "Nested object should be valid");
    }

    @Test
    void testValidArrayWithMixedTypes() {
        MjsSyntaxChecker.CheckResult result = checker.check(
            "[1, \"string\", true, null, {\"key\": [1,2,3]}]"
        );
        assertTrue(result.isValid, "Array with mixed types should be valid");
    }

    @Test
    void testValidComplexJson() {
        String json = "{\n" +
            "  \"name\": \"test\",\n" +
            "  \"values\": [1, 2, 3],\n" +
            "  \"nested\": {\n" +
            "    \"flag\": true,\n" +
            "    \"data\": null\n" +
            "  }\n" +
            "}";
        MjsSyntaxChecker.CheckResult result = checker.check(json);
        assertTrue(result.isValid, "Complex JSON should be valid");
    }

    @Test
    void testValidNullInput() {
        MjsSyntaxChecker.CheckResult result = checker.check(null);
        assertTrue(result.isValid, "Null input should be valid");
    }

    @Test
    void testValidEmptyInput() {
        MjsSyntaxChecker.CheckResult result = checker.check("");
        assertTrue(result.isValid, "Empty input should be valid");
    }

    // ==========================================
    // 括号不平衡测试
    // ==========================================

    @Test
    void testMissingClosingBrace() {
        MjsSyntaxChecker.CheckResult result = checker.check("{\"key\": \"value\"");
        assertFalse(result.isValid, "Missing closing brace should be invalid");
        assertEquals(1, result.missingBraceCount, "Should have 1 missing brace");
    }

    @Test
    void testMissingClosingBracket() {
        MjsSyntaxChecker.CheckResult result = checker.check("[1, 2, 3");
        assertFalse(result.isValid, "Missing closing bracket should be invalid");
        assertEquals(1, result.missingBracketCount, "Should have 1 missing bracket");
    }

    @Test
    void testExtraClosingBrace() {
        MjsSyntaxChecker.CheckResult result = checker.check("{}}");
        assertFalse(result.isValid, "Extra closing brace should be invalid");
        assertEquals(1, result.extraBraceCount, "Should have 1 extra brace");
    }

    @Test
    void testExtraClosingBracket() {
        MjsSyntaxChecker.CheckResult result = checker.check("[]]");
        assertFalse(result.isValid, "Extra closing bracket should be invalid");
        assertEquals(1, result.extraBracketCount, "Should have 1 extra bracket");
    }

    @Test
    void testMultipleMissingBrackets() {
        MjsSyntaxChecker.CheckResult result = checker.check("[[{");
        assertFalse(result.isValid, "Multiple missing brackets should be invalid");
        assertEquals(1, result.missingBraceCount);
        assertEquals(2, result.missingBracketCount);
    }

    @Test
    void testMismatchedBrackets() {
        MjsSyntaxChecker.CheckResult result = checker.check("{]");
        assertFalse(result.isValid, "Mismatched brackets should be invalid");
        // 预期 { 未闭合，] 多余
        assertTrue(result.missingBraceCount > 0 || result.extraBracketCount > 0);
    }

    // ==========================================
    // 字符串问题测试
    // ==========================================

    @Test
    void testUnclosedDoubleQuoteString() {
        MjsSyntaxChecker.CheckResult result = checker.check("{\"key: \"value\"}");
        // 这可能被解析为两个独立的问题
        assertFalse(result.isValid, "Unclosed string should be invalid");
    }

    @Test
    void testUnclosedSingleQuoteString() {
        MjsSyntaxChecker.CheckResult result = checker.check("{'key': 'value}");
        assertFalse(result.isValid, "Unclosed single quote string should be invalid");
        assertTrue(result.hasUnclosedString);
    }

    @Test
    void testValidEscapedQuotes() {
        MjsSyntaxChecker.CheckResult result = checker.check("{\"key\": \"value with \\\"quotes\\\"\"}");
        assertTrue(result.isValid, "Escaped quotes should be valid");
    }

    // ==========================================
    // 尾随逗号测试
    // ==========================================

    @Test
    void testTrailingCommaInObject() {
        MjsSyntaxChecker.CheckResult result = checker.check("{\"a\": 1,}");
        assertFalse(result.isValid, "Trailing comma in object should be invalid");
        assertTrue(result.hasTrailingComma);
    }

    @Test
    void testTrailingCommaInArray() {
        MjsSyntaxChecker.CheckResult result = checker.check("[1, 2, 3,]");
        assertFalse(result.isValid, "Trailing comma in array should be invalid");
        assertTrue(result.hasTrailingComma);
    }

    @Test
    void testTrailingCommaWithWhitespace() {
        MjsSyntaxChecker.CheckResult result = checker.check("{\"a\": 1,   }");
        assertFalse(result.isValid, "Trailing comma with whitespace should be invalid");
        assertTrue(result.hasTrailingComma);
    }

    // ==========================================
    // 缺少值测试
    // ==========================================

    @Test
    void testMissingValueAfterColon() {
        MjsSyntaxChecker.CheckResult result = checker.check("{\"key\":}");
        assertFalse(result.isValid, "Missing value after colon should be invalid");
        assertTrue(result.hasMissingValue);
    }

    @Test
    void testMissingValueAfterColonWithWhitespace() {
        MjsSyntaxChecker.CheckResult result = checker.check("{\"key\":  }");
        assertFalse(result.isValid);
        assertTrue(result.hasMissingValue);
    }

    // ==========================================
    // 辅助方法测试
    // ==========================================

    @Test
    void testGetTotalMissingClose() {
        MjsSyntaxChecker.CheckResult result = checker.check("{[((");
        assertFalse(result.isValid);
        int expected = result.missingBraceCount + result.missingBracketCount + result.missingParenCount;
        assertEquals(expected, result.getTotalMissingClose());
    }

    @Test
    void testGetTotalExtraClose() {
        MjsSyntaxChecker.CheckResult result = checker.check("}])");
        assertFalse(result.isValid);
        int expected = result.extraBraceCount + result.extraBracketCount + result.extraParenCount;
        assertEquals(expected, result.getTotalExtraClose());
    }

    // ==========================================
    // Token 检查测试
    // ==========================================

    @Test
    void testCheckTokensEmpty() {
        MjsSyntaxChecker.CheckResult result = checker.checkTokens(new ArrayList<>());
        assertTrue(result.isValid, "Empty token list should be valid");
    }

    @Test
    void testCheckTokensNull() {
        MjsSyntaxChecker.CheckResult result = checker.checkTokens(null);
        assertTrue(result.isValid, "Null token list should be valid");
    }

    @Test
    void testCheckTokensValidBrackets() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.LBRACE, "{"));
        tokens.add(new Token(Token.Type.STRING, "\"key\""));
        tokens.add(new Token(Token.Type.COLON, ":"));
        tokens.add(new Token(Token.Type.NUMBER, "123"));
        tokens.add(new Token(Token.Type.RBRACE, "}"));
        
        MjsSyntaxChecker.CheckResult result = checker.checkTokens(tokens);
        assertTrue(result.isValid, "Valid tokens should pass check");
    }

    @Test
    void testCheckTokensMissingClose() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.LBRACE, "{"));
        tokens.add(new Token(Token.Type.STRING, "\"key\""));
        tokens.add(new Token(Token.Type.COLON, ":"));
        tokens.add(new Token(Token.Type.LBRACKET, "["));
        tokens.add(new Token(Token.Type.NUMBER, "1"));
        // 缺少 ] 和 }
        
        MjsSyntaxChecker.CheckResult result = checker.checkTokens(tokens);
        assertFalse(result.isValid);
        assertEquals(1, result.missingBraceCount);
        assertEquals(1, result.missingBracketCount);
    }

    @Test
    void testCheckTokensTrailingComma() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.LBRACE, "{"));
        tokens.add(new Token(Token.Type.STRING, "\"a\""));
        tokens.add(new Token(Token.Type.COLON, ":"));
        tokens.add(new Token(Token.Type.NUMBER, "1"));
        tokens.add(new Token(Token.Type.COMMA, ","));
        tokens.add(new Token(Token.Type.RBRACE, "}"));
        
        MjsSyntaxChecker.CheckResult result = checker.checkTokens(tokens);
        assertFalse(result.isValid);
        assertTrue(result.hasTrailingComma);
    }

    // ==========================================
    // 边界情况测试
    // ==========================================

    @Test
    void testDeeplyNested() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 50; i++) {
            sb.append("{\"a\":");
        }
        sb.append("1");
        for (int i = 0; i < 50; i++) {
            sb.append("}");
        }
        
        MjsSyntaxChecker.CheckResult result = checker.check(sb.toString());
        assertTrue(result.isValid, "Deeply nested JSON should be valid");
    }

    @Test
    void testLargeArray() {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < 1000; i++) {
            if (i > 0) sb.append(",");
            sb.append(i);
        }
        sb.append("]");
        
        MjsSyntaxChecker.CheckResult result = checker.check(sb.toString());
        assertTrue(result.isValid, "Large array should be valid");
    }

    @Test
    void testWithComments() {
        String code = "{\n" +
            "  // this is a comment\n" +
            "  \"key\": \"value\"\n" +
            "}";
        MjsSyntaxChecker.CheckResult result = checker.check(code);
        assertTrue(result.isValid, "JSON with comments should be valid (MJS supports comments)");
    }
}
