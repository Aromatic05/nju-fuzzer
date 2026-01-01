package edu.nju.fuzzing.mutate.grammar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.ArrayList;

/**
 * MjsSyntaxFixer 测试
 */
public class MjsSyntaxFixerTest {

    private MjsSyntaxFixer fixer;
    private MjsSyntaxChecker checker;

    @BeforeEach
    void setUp() {
        checker = new MjsSyntaxChecker();
        fixer = new MjsSyntaxFixer(checker);
    }

    // ==========================================
    // 括号修复测试
    // ==========================================

    @Test
    void testFixMissingClosingBrace() {
        String input = "{\"key\": \"value\"";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid");
        assertTrue(fixed.endsWith("}"), "Should end with closing brace");
    }

    @Test
    void testFixMissingClosingBracket() {
        String input = "[1, 2, 3";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid");
        assertTrue(fixed.endsWith("]"), "Should end with closing bracket");
    }

    @Test
    void testFixMultipleMissingBrackets() {
        String input = "{\"a\": [1, 2";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid");
        assertTrue(fixed.contains("]") && fixed.contains("}"), "Should have both closings");
    }

    @Test
    void testFixExtraClosingBrace() {
        String input = "{}}";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid");
        assertEquals("{}", fixed, "Should be just {}");
    }

    @Test
    void testFixExtraClosingBracket() {
        String input = "[]]";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid");
        assertEquals("[]", fixed, "Should be just []");
    }

    @Test
    void testFixNestedMissingBrackets() {
        String input = "{\"a\": {\"b\": [1, 2, {\"c\": 3";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid: " + result.errorMessage);
    }

    // ==========================================
    // 字符串修复测试
    // ==========================================

    @Test
    void testFixUnclosedDoubleQuoteString() {
        String input = "{\"key: \"value\"}";
        String fixed = fixer.fix(input);
        
        // 应该尝试闭合字符串
        assertNotNull(fixed);
    }

    @Test
    void testFixUnclosedSingleQuoteString() {
        String input = "{'key': 'value}";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid: " + result.errorMessage);
    }

    @Test
    void testFixMultipleUnclosedStrings() {
        String input = "{\"a\": \"test, \"b\": 2}";
        String fixed = fixer.fix(input);
        
        assertNotNull(fixed);
    }

    // ==========================================
    // 尾随逗号修复测试
    // ==========================================

    @Test
    void testFixTrailingCommaInObject() {
        String input = "{\"a\": 1,}";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid");
        assertEquals("{\"a\": 1}", fixed, "Trailing comma should be removed");
    }

    @Test
    void testFixTrailingCommaInArray() {
        String input = "[1, 2, 3,]";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid");
        assertEquals("[1, 2, 3]", fixed, "Trailing comma should be removed");
    }

    @Test
    void testFixTrailingCommaWithWhitespace() {
        String input = "{\"a\": 1,   }";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid");
        assertFalse(fixed.contains(",}") || fixed.contains(", }"), 
                   "Trailing comma should be removed");
    }

    @Test
    void testFixNestedTrailingCommas() {
        String input = "{\"a\": [1, 2,], \"b\": {\"c\": 3,},}";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid: " + result.errorMessage);
    }

    // ==========================================
    // 缺少值修复测试
    // ==========================================

    @Test
    void testFixMissingValueAfterColon() {
        String input = "{\"key\":}";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed code should be valid: " + result.errorMessage);
        assertTrue(fixed.contains("null"), "Should add null as placeholder");
    }

    @Test
    void testFixMissingValueAfterComma() {
        String input = "{\"a\": 1, \"b\":,}";
        String fixed = fixer.fix(input);
        
        // 应该修复多个问题
        assertNotNull(fixed);
    }

    // ==========================================
    // Token 修复测试
    // ==========================================

    @Test
    void testFixTokensMissingClose() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.LBRACE, "{"));
        tokens.add(new Token(Token.Type.STRING, "\"key\""));
        tokens.add(new Token(Token.Type.COLON, ":"));
        tokens.add(new Token(Token.Type.LBRACKET, "["));
        tokens.add(new Token(Token.Type.NUMBER, "1"));
        // 缺少 ] 和 }
        
        List<Token> fixed = fixer.fixTokens(tokens);
        MjsSyntaxChecker.CheckResult result = checker.checkTokens(fixed);
        assertTrue(result.isValid, "Fixed tokens should be valid: " + result.errorMessage);
        
        // 应该添加了闭合括号
        assertTrue(fixed.size() > tokens.size(), "Should add closing tokens");
    }

    @Test
    void testFixTokensExtraClose() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.LBRACE, "{"));
        tokens.add(new Token(Token.Type.RBRACE, "}"));
        tokens.add(new Token(Token.Type.RBRACE, "}"));  // 多余
        
        List<Token> fixed = fixer.fixTokens(tokens);
        MjsSyntaxChecker.CheckResult result = checker.checkTokens(fixed);
        assertTrue(result.isValid, "Fixed tokens should be valid");
        
        // 应该移除多余的括号
        assertEquals(2, fixed.size(), "Should remove extra closing");
    }

    @Test
    void testFixTokensTrailingComma() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.LBRACE, "{"));
        tokens.add(new Token(Token.Type.STRING, "\"a\""));
        tokens.add(new Token(Token.Type.COLON, ":"));
        tokens.add(new Token(Token.Type.NUMBER, "1"));
        tokens.add(new Token(Token.Type.COMMA, ","));
        tokens.add(new Token(Token.Type.RBRACE, "}"));
        
        List<Token> fixed = fixer.fixTokens(tokens);
        MjsSyntaxChecker.CheckResult result = checker.checkTokens(fixed);
        assertTrue(result.isValid, "Fixed tokens should be valid: " + result.errorMessage);
    }

    @Test
    void testFixTokensUnclosedString() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.LBRACE, "{"));
        tokens.add(new Token(Token.Type.STRING, "\"key"));  // 未闭合
        tokens.add(new Token(Token.Type.COLON, ":"));
        tokens.add(new Token(Token.Type.NUMBER, "1"));
        tokens.add(new Token(Token.Type.RBRACE, "}"));
        
        List<Token> fixed = fixer.fixTokens(tokens);
        
        // 查找修复后的字符串 token
        Token stringToken = fixed.stream()
            .filter(t -> t.getType() == Token.Type.STRING)
            .findFirst()
            .orElse(null);
        
        assertNotNull(stringToken);
        String val = stringToken.getValue();
        assertTrue(val.endsWith("\""), "String should be closed: " + val);
    }

    // ==========================================
    // 边界情况和 quickFix 测试
    // ==========================================

    @Test
    void testFixNullInput() {
        String fixed = fixer.fix(null);
        assertNull(fixed, "Null input should return null");
    }

    @Test
    void testFixEmptyInput() {
        String fixed = fixer.fix("");
        assertEquals("", fixed, "Empty input should return empty");
    }

    @Test
    void testFixValidInput() {
        String input = "{\"key\": \"value\"}";
        String fixed = fixer.fix(input);
        
        assertEquals(input, fixed, "Valid input should be unchanged");
    }

    @Test
    void testQuickFix() {
        String input = "{\"key\": [1, 2, 3";
        String fixed = fixer.quickFix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Quick fix should produce valid JSON: " + result.errorMessage);
    }

    @Test
    void testQuickFixWithTrim() {
        String input = "   {\"a\": 1}   ";
        String fixed = fixer.quickFix(input);
        
        assertNotNull(fixed);
        assertFalse(fixed.startsWith(" "), "Should be trimmed");
    }

    @Test
    void testFixComplexBrokenJson() {
        String input = "{\"users\": [{\"name\": \"Alice\", \"age\": 30,}, {\"name\": \"Bob\", \"age\":";
        String fixed = fixer.fix(input);
        
        MjsSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Complex broken JSON should be fixed: " + result.errorMessage);
    }

    @Test
    void testMaxFixAttempts() {
        // 非常破碎的输入，可能需要多次尝试
        String input = "{{{{[[[";
        String fixed = fixer.fix(input);
        
        // 即使无法完全修复，也不应该抛出异常
        assertNotNull(fixed);
    }
}
