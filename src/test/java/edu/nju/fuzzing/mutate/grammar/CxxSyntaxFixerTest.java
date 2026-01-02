package edu.nju.fuzzing.mutate.grammar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;

/**
 * CxxSyntaxFixer 测试
 */
public class CxxSyntaxFixerTest {

    private CxxSyntaxFixer fixer;
    private CxxSyntaxChecker checker;

    @BeforeEach
    void setUp() {
        checker = new CxxSyntaxChecker();
        fixer = new CxxSyntaxFixer(checker);
    }

    // ==========================================
    // 前缀修复测试
    // ==========================================

    @Test
    void testFixMissingPrefix() {
        String input = "4funcv";
        String fixed = fixer.fix(input);
        
        assertTrue(fixed.startsWith("_Z"), "Should start with _Z prefix");
        CxxSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.hasValidPrefix);
    }

    @Test
    void testFixPartialPrefix() {
        String input = "_4funcv";
        String fixed = fixer.fix(input);
        
        assertTrue(fixed.startsWith("_Z"), "Should have proper _Z prefix");
    }

    // ==========================================
    // NUL 字符修复测试
    // ==========================================

    @Test
    void testRemoveNullCharacters() {
        String input = "_Z4func\0v";
        String fixed = fixer.fix(input);
        
        assertFalse(fixed.contains("\0"), "Should not contain NUL");
        CxxSyntaxChecker.CheckResult result = checker.check(fixed);
        assertFalse(result.hasNullCharacter);
    }

    @Test
    void testRemoveMultipleNullCharacters() {
        String input = "_Z\04\0func\0v";
        String fixed = fixer.fix(input);
        
        assertFalse(fixed.contains("\0"), "Should not contain any NUL");
    }

    // ==========================================
    // N/E 配对修复测试
    // ==========================================

    @Test
    void testFixMissingNestedE() {
        String input = "_ZN3foo3barv";
        String fixed = fixer.fix(input);
        
        CxxSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid, "Fixed should be valid: " + result.errorMessage);
        assertEquals(0, result.missingNestedE);
    }

    @Test
    void testFixMultipleMissingE() {
        String input = "_ZNN3foo3bar";
        String fixed = fixer.fix(input);
        
        CxxSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid || result.missingNestedE == 0, 
                "Should fix missing E: " + result.errorMessage);
    }

    @Test
    void testFixExtraE() {
        String input = "_ZN3fooEEv";
        String fixed = fixer.fix(input);
        
        CxxSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid || result.extraE == 0, 
                "Should fix extra E: " + result.errorMessage);
    }

    // ==========================================
    // I/E 模板配对修复测试
    // ==========================================

    @Test
    void testFixMissingTemplateE() {
        String input = "_Z4funcIiv";
        String fixed = fixer.fix(input);
        
        CxxSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid || result.missingTemplateE == 0, 
                "Should fix missing template E: " + result.errorMessage);
    }

    @Test
    void testFixNestedTemplateMissingE() {
        String input = "_ZN3stdIi4sizeEv";
        String fixed = fixer.fix(input);
        
        CxxSyntaxChecker.CheckResult result = checker.check(fixed);
        assertEquals(0, result.getTotalMissingE(), "Should fix all missing E");
    }

    // ==========================================
    // 长度-名称修复测试
    // ==========================================

    @Test
    void testFixLengthNameMismatch() {
        // 声明长度 10，实际名称 foo (长度 3)
        String input = "_Z10foov";
        String fixed = fixer.fix(input);
        
        CxxSyntaxChecker.CheckResult result = checker.check(fixed);
        // 修复后长度应该匹配
        assertFalse(result.hasLengthMismatch, "Should fix length mismatch: " + result.errorMessage);
    }

    @Test
    void testFixLengthOverflow() {
        String input = "_Z99999999999999funcv";
        String fixed = fixer.fix(input);
        
        // 应该用合理的长度替换
        assertNotNull(fixed);
        assertTrue(fixed.startsWith("_Z"));
    }

    // ==========================================
    // Token 修复测试
    // ==========================================

    @Test
    void testFixTokensNull() {
        List<Token> fixed = fixer.fixTokens(null);
        assertNotNull(fixed);
        assertFalse(fixed.isEmpty());
        assertEquals(Token.Type.CXX_PREFIX, fixed.get(0).getType());
    }

    @Test
    void testFixTokensEmpty() {
        List<Token> fixed = fixer.fixTokens(new ArrayList<>());
        assertNotNull(fixed);
        assertFalse(fixed.isEmpty());
        assertEquals(Token.Type.CXX_PREFIX, fixed.get(0).getType());
    }

    @Test
    void testFixTokensMissingPrefix() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.CXX_LENGTH, "4"));
        tokens.add(new Token(Token.Type.CXX_NAME, "func"));
        tokens.add(new Token(Token.Type.CXX_TYPE, "v"));
        
        List<Token> fixed = fixer.fixTokens(tokens);
        assertEquals(Token.Type.CXX_PREFIX, fixed.get(0).getType());
    }

    @Test
    void testFixTokensMissingE() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.CXX_PREFIX, "_Z"));
        tokens.add(new Token(Token.Type.CXX_NESTED, "N"));
        tokens.add(new Token(Token.Type.CXX_LENGTH, "3"));
        tokens.add(new Token(Token.Type.CXX_NAME, "foo"));
        tokens.add(new Token(Token.Type.CXX_TYPE, "v"));
        // 缺少 E
        
        List<Token> fixed = fixer.fixTokens(tokens);
        CxxSyntaxChecker.CheckResult result = checker.checkTokens(fixed);
        assertEquals(0, result.missingNestedE, "Should add missing E");
    }

    @Test
    void testFixTokensLengthMismatch() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.CXX_PREFIX, "_Z"));
        tokens.add(new Token(Token.Type.CXX_LENGTH, "10"));  // 声明长度 10
        tokens.add(new Token(Token.Type.CXX_NAME, "foo"));   // 实际长度 3
        tokens.add(new Token(Token.Type.CXX_TYPE, "v"));
        
        List<Token> fixed = fixer.fixTokens(tokens);
        CxxSyntaxChecker.CheckResult result = checker.checkTokens(fixed);
        assertFalse(result.hasLengthMismatch, "Should fix length mismatch");
    }

    @Test
    void testFixTokensExtraE() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.CXX_PREFIX, "_Z"));
        tokens.add(new Token(Token.Type.CXX_NESTED, "N"));
        tokens.add(new Token(Token.Type.CXX_LENGTH, "3"));
        tokens.add(new Token(Token.Type.CXX_NAME, "foo"));
        tokens.add(new Token(Token.Type.CXX_NESTED, "E"));
        tokens.add(new Token(Token.Type.CXX_NESTED, "E"));  // 多余
        tokens.add(new Token(Token.Type.CXX_TYPE, "v"));
        
        List<Token> fixed = fixer.fixTokens(tokens);
        CxxSyntaxChecker.CheckResult result = checker.checkTokens(fixed);
        assertEquals(0, result.extraE, "Should remove extra E");
    }

    @Test
    void testFixTokensNullCharacter() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.CXX_PREFIX, "_Z"));
        tokens.add(new Token(Token.Type.CXX_LENGTH, "4"));
        tokens.add(new Token(Token.Type.CXX_NAME, "fu\0nc"));  // 包含 NUL
        tokens.add(new Token(Token.Type.CXX_TYPE, "v"));
        
        List<Token> fixed = fixer.fixTokens(tokens);
        for (Token t : fixed) {
            if (t.getValue() != null) {
                assertFalse(t.getValue().contains("\0"), "Should remove NUL from token");
            }
        }
    }

    // ==========================================
    // 工具方法测试
    // ==========================================

    @Test
    void testFindLengthNamePairs() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.CXX_PREFIX, "_Z"));
        tokens.add(new Token(Token.Type.CXX_LENGTH, "4"));
        tokens.add(new Token(Token.Type.CXX_NAME, "func"));
        tokens.add(new Token(Token.Type.CXX_LENGTH, "3"));
        tokens.add(new Token(Token.Type.CXX_NAME, "bar"));
        tokens.add(new Token(Token.Type.CXX_TYPE, "v"));
        
        List<int[]> pairs = CxxSyntaxFixer.findLengthNamePairs(tokens);
        assertEquals(2, pairs.size());
        assertArrayEquals(new int[]{1, 2}, pairs.get(0));
        assertArrayEquals(new int[]{3, 4}, pairs.get(1));
    }

    @Test
    void testSyncLengthName() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.CXX_PREFIX, "_Z"));
        tokens.add(new Token(Token.Type.CXX_LENGTH, "4"));
        tokens.add(new Token(Token.Type.CXX_NAME, "func"));
        tokens.add(new Token(Token.Type.CXX_TYPE, "v"));
        
        CxxSyntaxFixer.syncLengthName(tokens, 1, "newfunction");
        
        assertEquals("11", tokens.get(1).getValue());
        assertEquals("newfunction", tokens.get(2).getValue());
    }

    // ==========================================
    // 边界情况测试
    // ==========================================

    @Test
    void testFixValidInput() {
        String input = "_Z4funcv";
        String fixed = fixer.fix(input);
        
        assertEquals(input, fixed, "Valid input should be unchanged");
    }

    @Test
    void testFixComplexBroken() {
        String input = "_ZNN3fooIIi3barv";  // 多处问题
        String fixed = fixer.fix(input);
        
        CxxSyntaxChecker.CheckResult result = checker.check(fixed);
        assertTrue(result.isValid || result.getTotalMissingE() == 0, 
                "Should fix all issues: " + result.errorMessage);
        // 即使无法完全修复，也不应该抛出异常
        assertNotNull(fixed);
        assertTrue(fixed.startsWith("_Z"));
    }

    @Test
    void testMaxFixAttempts() {
        String input = "NNNIIIIII";  // 非常破碎的输入
        String fixed = fixer.fix(input);
        
        assertNotNull(fixed);
        assertTrue(fixed.startsWith("_Z"));
    }

    // ==========================================
    // 综合测试
    // ==========================================

    @Test
    void testFixMultipleIssues() {
        // 缺少前缀 + 缺少 E + NUL
        String input = "N3foo\0v";
        String fixed = fixer.fix(input);
        
        assertTrue(fixed.startsWith("_Z"));
        assertFalse(fixed.contains("\0"));
    }

    @Test
    void testFixPreservesStructure() {
        String input = "_ZN3foo3bar";  // 只缺少 E
        String fixed = fixer.fix(input);
        
        assertTrue(fixed.contains("foo"));
        assertTrue(fixed.contains("bar"));
        assertTrue(fixed.endsWith("E") || fixed.contains("Ev"));
    }
}
