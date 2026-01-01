package edu.nju.fuzzing.mutate.grammar;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;

/**
 * CxxSyntaxChecker 测试
 */
public class CxxSyntaxCheckerTest {

    private CxxSyntaxChecker checker;

    @BeforeEach
    void setUp() {
        checker = new CxxSyntaxChecker();
    }

    // ==========================================
    // 有效 mangled name 测试
    // ==========================================

    @Test
    void testValidSimpleFunction() {
        CxxSyntaxChecker.CheckResult result = checker.check("_Z4funcv");
        assertTrue(result.isValid, "Simple function should be valid: " + result.errorMessage);
        assertTrue(result.hasValidPrefix);
    }

    @Test
    void testValidFunctionWithIntParam() {
        CxxSyntaxChecker.CheckResult result = checker.check("_Z4funci");
        assertTrue(result.isValid, "Function with int param should be valid");
    }

    @Test
    void testValidNestedNamespace() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZN3foo3barEv");
        assertTrue(result.isValid, "Nested namespace should be valid: " + result.errorMessage);
    }

    @Test
    void testValidTemplate() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZN3std6vectorIiE4sizeEv");
        assertTrue(result.isValid, "Template should be valid: " + result.errorMessage);
    }

    @Test
    void testValidConstructor() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZN3FooC1Ev");
        assertTrue(result.isValid, "Constructor should be valid: " + result.errorMessage);
    }

    @Test
    void testValidDestructor() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZN3FooD1Ev");
        assertTrue(result.isValid, "Destructor should be valid: " + result.errorMessage);
    }

    @Test
    void testValidPointerType() {
        CxxSyntaxChecker.CheckResult result = checker.check("_Z4funcPi");
        assertTrue(result.isValid, "Pointer type should be valid: " + result.errorMessage);
    }

    @Test
    void testValidConstRef() {
        CxxSyntaxChecker.CheckResult result = checker.check("_Z4funcRKi");
        assertTrue(result.isValid, "Const ref should be valid: " + result.errorMessage);
    }

    // ==========================================
    // 前缀检查测试
    // ==========================================

    @Test
    void testMissingPrefix() {
        CxxSyntaxChecker.CheckResult result = checker.check("4funcv");
        assertFalse(result.isValid, "Missing prefix should be invalid");
        assertFalse(result.hasValidPrefix);
    }

    @Test
    void testWrongPrefix() {
        CxxSyntaxChecker.CheckResult result = checker.check("_Y4funcv");
        assertFalse(result.isValid, "Wrong prefix should be invalid");
        assertFalse(result.hasValidPrefix);
    }

    @Test
    void testEmptyInput() {
        CxxSyntaxChecker.CheckResult result = checker.check("");
        assertFalse(result.isValid, "Empty input should be invalid");
    }

    @Test
    void testNullInput() {
        CxxSyntaxChecker.CheckResult result = checker.check(null);
        assertFalse(result.isValid, "Null input should be invalid");
    }

    // ==========================================
    // N/E 配对测试
    // ==========================================

    @Test
    void testMissingNestedE() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZN3foo3barv");
        assertFalse(result.isValid, "Missing nested E should be invalid");
        assertEquals(1, result.missingNestedE);
    }

    @Test
    void testMultipleMissingE() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZNN3foo3bar");
        assertFalse(result.isValid, "Multiple missing E should be invalid");
        assertTrue(result.missingNestedE >= 2);
    }

    @Test
    void testExtraE() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZN3fooEEv");
        assertFalse(result.isValid, "Extra E should be invalid");
        assertEquals(1, result.extraE);
    }

    // ==========================================
    // I/E 模板配对测试
    // ==========================================

    @Test
    void testMissingTemplateE() {
        CxxSyntaxChecker.CheckResult result = checker.check("_Z4funcIiv");
        assertFalse(result.isValid, "Missing template E should be invalid");
        assertEquals(1, result.missingTemplateE);
    }

    @Test
    void testNestedTemplate() {
        CxxSyntaxChecker.CheckResult result = checker.check("_Z4funcIIiEEv");
        assertTrue(result.isValid, "Nested template should be valid: " + result.errorMessage);
    }

    @Test
    void testMixedNesting() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZN3stdIiE4funcEv");
        assertTrue(result.isValid, "Mixed nesting should be valid: " + result.errorMessage);
    }

    // ==========================================
    // NUL 字符测试
    // ==========================================

    @Test
    void testNullCharacter() {
        CxxSyntaxChecker.CheckResult result = checker.check("_Z4func\0v");
        assertFalse(result.isValid, "NUL character should be invalid");
        assertTrue(result.hasNullCharacter);
    }

    // ==========================================
    // 长度-名称匹配测试
    // ==========================================

    @Test
    void testValidLengthName() {
        CxxSyntaxChecker.CheckResult result = checker.check("_Z4mainv");
        assertTrue(result.isValid, "Valid length-name should pass: " + result.errorMessage);
        assertFalse(result.hasLengthMismatch);
    }

    @Test
    void testLengthOverflow() {
        CxxSyntaxChecker.CheckResult result = checker.check("_Z99999999999999funcv");
        assertFalse(result.isValid, "Length overflow should be invalid");
        assertTrue(result.hasLengthMismatch);
    }

    // ==========================================
    // 替换引用测试
    // ==========================================

    @Test
    void testValidSubstitution() {
        // S_ 是第一个替换，总是有效的
        CxxSyntaxChecker.CheckResult result = checker.check("_ZN3foo3barES_v");
        assertTrue(result.isValid, "Valid substitution should pass: " + result.errorMessage);
    }

    @Test
    void testStandardSubstitution() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZSt4cout");
        assertTrue(result.isValid, "Standard substitution should be valid: " + result.errorMessage);
    }

    // ==========================================
    // Token 检查测试
    // ==========================================

    @Test
    void testCheckTokensEmpty() {
        CxxSyntaxChecker.CheckResult result = checker.checkTokens(new ArrayList<>());
        assertFalse(result.isValid, "Empty token list should be invalid");
    }

    @Test
    void testCheckTokensNull() {
        CxxSyntaxChecker.CheckResult result = checker.checkTokens(null);
        assertFalse(result.isValid, "Null token list should be invalid");
    }

    @Test
    void testCheckTokensValidSimple() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.CXX_PREFIX, "_Z"));
        tokens.add(new Token(Token.Type.CXX_LENGTH, "4"));
        tokens.add(new Token(Token.Type.CXX_NAME, "func"));
        tokens.add(new Token(Token.Type.CXX_TYPE, "v"));
        
        CxxSyntaxChecker.CheckResult result = checker.checkTokens(tokens);
        assertTrue(result.isValid, "Valid tokens should pass: " + result.errorMessage);
    }

    @Test
    void testCheckTokensMissingE() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.CXX_PREFIX, "_Z"));
        tokens.add(new Token(Token.Type.CXX_NESTED, "N"));
        tokens.add(new Token(Token.Type.CXX_LENGTH, "3"));
        tokens.add(new Token(Token.Type.CXX_NAME, "foo"));
        tokens.add(new Token(Token.Type.CXX_TYPE, "v"));
        // 缺少 E
        
        CxxSyntaxChecker.CheckResult result = checker.checkTokens(tokens);
        assertFalse(result.isValid);
        assertEquals(1, result.missingNestedE);
    }

    @Test
    void testCheckTokensLengthMismatch() {
        List<Token> tokens = new ArrayList<>();
        tokens.add(new Token(Token.Type.CXX_PREFIX, "_Z"));
        tokens.add(new Token(Token.Type.CXX_LENGTH, "10"));  // 声明长度 10
        tokens.add(new Token(Token.Type.CXX_NAME, "foo"));   // 实际长度 3
        tokens.add(new Token(Token.Type.CXX_TYPE, "v"));
        
        CxxSyntaxChecker.CheckResult result = checker.checkTokens(tokens);
        assertFalse(result.isValid);
        assertTrue(result.hasLengthMismatch);
    }

    // ==========================================
    // 辅助方法测试
    // ==========================================

    @Test
    void testGetTotalMissingE() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZNIi");
        assertFalse(result.isValid);
        int expected = result.missingNestedE + result.missingTemplateE;
        assertEquals(expected, result.getTotalMissingE());
    }

    @Test
    void testIsBasicValid() {
        assertTrue(checker.isBasicValid("_Z4funcv"));
        assertTrue(checker.isBasicValid("_ZN3fooEv"));
        assertFalse(checker.isBasicValid("Z4funcv"));  // 缺少 _
        assertFalse(checker.isBasicValid("_Z"));       // 太短
        assertFalse(checker.isBasicValid(null));
        assertFalse(checker.isBasicValid(""));
        assertFalse(checker.isBasicValid("_Z\0v"));    // 包含 NUL
        assertFalse(checker.isBasicValid("_ZN3foo"));  // 缺少 E
    }

    // ==========================================
    // 复杂案例测试
    // ==========================================

    @Test
    void testComplexTemplate() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZN3std6vectorIiSaIiEE9push_backERKi");
        assertTrue(result.isValid, "Complex template should be valid: " + result.errorMessage);
    }

    @Test
    void testOperatorOverload() {
        CxxSyntaxChecker.CheckResult result = checker.check("_ZNK3FooplERKS_");
        assertTrue(result.isValid, "Operator overload should be valid: " + result.errorMessage);
    }

    @Test
    void testFunctionPointer() {
        CxxSyntaxChecker.CheckResult result = checker.check("_Z4funcPFviE");
        assertTrue(result.isValid, "Function pointer should be valid: " + result.errorMessage);
    }

    @Test
    void testDeepNesting() {
        StringBuilder sb = new StringBuilder("_Z");
        for (int i = 0; i < 50; i++) {
            String name = "ns" + i;
            sb.append("N").append(name.length()).append(name);
        }
        for (int i = 0; i < 50; i++) {
            sb.append("E");
        }
        sb.append("v");
        
        CxxSyntaxChecker.CheckResult result = checker.check(sb.toString());
        assertTrue(result.isValid, "Deep nesting should be valid: " + result.errorMessage);
    }
}
