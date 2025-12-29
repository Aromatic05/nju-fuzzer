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
 * CxxTokenizer 单元测试 (C++ Itanium ABI Mangled Name)
 */
class CxxTokenizerTest {

    private final CxxTokenizer tokenizer = new CxxTokenizer();

    @Test
    @DisplayName("Test 1: 识别 _Z 前缀")
    void testPrefix() {
        String mangled = "_Z4mainiPPc";
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.CXX_PREFIX));
        
        Optional<Token> prefix = tokens.stream()
            .filter(t -> t.getType() == Token.Type.CXX_PREFIX)
            .findFirst();
        assertTrue(prefix.isPresent());
        assertEquals("_Z", prefix.get().getValue());
    }

    @Test
    @DisplayName("Test 2: 长度前缀的名称")
    void testLengthPrefixedName() {
        String mangled = "_Z4mainv";  // main()
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        // 应该有长度 token 和名称 token
        assertTrue(hasTokenOfType(tokens, Token.Type.CXX_LENGTH) || hasTokenOfType(tokens, Token.Type.CXX_NAME));
        
        String combined = combineValues(tokens);
        assertTrue(combined.contains("main"));
    }

    @Test
    @DisplayName("Test 3: 基本类型")
    void testBasicTypes() {
        String mangled = "_Z3fooidfb";  // foo(int, double, float, bool)
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.CXX_TYPE));
        
        // 应该有 i(int), d(double), f(float), b(bool)
        long typeCount = tokens.stream()
            .filter(t -> t.getType() == Token.Type.CXX_TYPE)
            .count();
        assertTrue(typeCount >= 4);
    }

    @Test
    @DisplayName("Test 4: 指针修饰符")
    void testPointerModifier() {
        String mangled = "_Z3fooPiPPc";  // foo(int*, char**)
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.CXX_MODIFIER));
        
        long pCount = tokens.stream()
            .filter(t -> t.getType() == Token.Type.CXX_MODIFIER && "P".equals(t.getValue()))
            .count();
        assertTrue(pCount >= 1);
    }

    @Test
    @DisplayName("Test 5: 引用修饰符")
    void testReferenceModifier() {
        String mangled = "_Z3barRiOd";  // bar(int&, double&&)
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        // R = lvalue reference, O = rvalue reference
        String combined = combineValues(tokens);
        assertTrue(combined.contains("R") || combined.contains("O"));
    }

    @Test
    @DisplayName("Test 6: const/volatile 修饰符")
    void testCvModifiers() {
        String mangled = "_Z3bazKPKi";  // baz(const int* const)
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        // K = const
        boolean hasConst = tokens.stream().anyMatch(t -> 
            t.getType() == Token.Type.CXX_MODIFIER && "K".equals(t.getValue()));
        assertTrue(hasConst);
    }

    @Test
    @DisplayName("Test 7: 嵌套名称 N...E")
    void testNestedName() {
        String mangled = "_ZN3foo3barEv";  // foo::bar()
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.CXX_NESTED));
        
        // 检查 N 和 E
        boolean hasN = tokens.stream().anyMatch(t -> 
            t.getType() == Token.Type.CXX_NESTED && "N".equals(t.getValue()));
        boolean hasE = tokens.stream().anyMatch(t -> 
            t.getType() == Token.Type.CXX_NESTED && "E".equals(t.getValue()));
        assertTrue(hasN);
        assertTrue(hasE);
    }

    @Test
    @DisplayName("Test 8: 模板 I...E")
    void testTemplate() {
        String mangled = "_Z3fooIiEvT_";  // foo<int>(T)
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.CXX_TEMPLATE));
        
        boolean hasI = tokens.stream().anyMatch(t -> 
            (t.getType() == Token.Type.CXX_TEMPLATE || t.getType() == Token.Type.CXX_NESTED) 
            && "I".equals(t.getValue()));
        assertTrue(hasI);
    }

    @Test
    @DisplayName("Test 9: 替换 S_")
    void testSubstitution() {
        String mangled = "_Z3fooS_S0_";
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.CXX_SUBST));
    }

    @Test
    @DisplayName("Test 10: 标准替换 St, Sa, Sb, Ss")
    void testStandardSubstitutions() {
        String mangled = "_ZNSt3fooEv";  // std::foo()
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        String combined = combineValues(tokens);
        assertTrue(combined.contains("St"));
    }

    @Test
    @DisplayName("Test 11: 数组类型 A")
    void testArrayType() {
        String mangled = "_Z3fooA10_i";  // foo(int[10])
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        String combined = combineValues(tokens);
        assertTrue(combined.contains("A"));
        assertTrue(combined.contains("10"));
    }

    @Test
    @DisplayName("Test 12: 函数指针")
    void testFunctionPointer() {
        String mangled = "_Z3fooPFivE";  // foo(int(*)())
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        String combined = combineValues(tokens);
        assertTrue(combined.contains("PF"));
    }

    @Test
    @DisplayName("Test 13: 构造函数/析构函数")
    void testCtorDtor() {
        String mangled = "_ZN3fooC1Ev";  // foo::foo()
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        String combined = combineValues(tokens);
        assertTrue(combined.contains("C1") || combined.contains("C2") || combined.contains("D"));
    }

    @Test
    @DisplayName("Test 14: 操作符重载")
    void testOperators() {
        String mangled = "_ZN3fooplERS_";  // foo::operator+(foo&)
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.CXX_OPERATOR));
        
        Optional<Token> op = tokens.stream()
            .filter(t -> t.getType() == Token.Type.CXX_OPERATOR)
            .findFirst();
        assertTrue(op.isPresent());
        assertEquals("pl", op.get().getValue());
    }

    @Test
    @DisplayName("Test 15: 复杂嵌套模板")
    void testComplexTemplate() {
        String mangled = "_ZN3std6vectorIiSaIiEEC1Ev";  // std::vector<int, std::allocator<int>>::vector()
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        assertFalse(tokens.isEmpty());
        assertTrue(hasTokenOfType(tokens, Token.Type.CXX_NESTED));
        assertTrue(hasTokenOfType(tokens, Token.Type.CXX_TEMPLATE) || 
                   tokens.stream().anyMatch(t -> "I".equals(t.getValue())));
    }

    @Test
    @DisplayName("Test 16: 容错 - 无效前缀")
    void testInvalidPrefix() {
        String invalid = "not_a_mangled_name";
        List<Token> tokens = tokenizer.tokenize(invalid.getBytes(StandardCharsets.ISO_8859_1));
        
        // 应该返回 RAW token 或空
        // 不应该崩溃
        assertNotNull(tokens);
    }

    @Test
    @DisplayName("Test 17: 容错 - 截断的名称")
    void testTruncatedName() {
        String truncated = "_Z10ver";  // 声明长度10但只有3个字符
        List<Token> tokens = tokenizer.tokenize(truncated.getBytes(StandardCharsets.ISO_8859_1));
        
        // 应该优雅处理
        assertNotNull(tokens);
        assertFalse(tokens.isEmpty());
    }

    @Test
    @DisplayName("Test 18: 构建树")
    void testBuildTree() {
        String mangled = "_ZN3foo3barEv";
        List<Token> tokens = tokenizer.tokenize(mangled.getBytes(StandardCharsets.ISO_8859_1));
        TokenNode tree = tokenizer.buildTree(tokens);
        
        assertNotNull(tree);
        assertEquals(TokenNode.NodeType.ROOT, tree.getNodeType());
    }

    @Test
    @DisplayName("Test 19: 完整解析流程")
    void testParse() {
        String mangled = "_Z4testii";
        TokenNode tree = tokenizer.parse(mangled.getBytes(StandardCharsets.ISO_8859_1));
        
        assertNotNull(tree);
        String serialized = tree.serialize();
        assertTrue(serialized.startsWith("_Z"));
    }

    @Test
    @DisplayName("Test 20: 空输入")
    void testEmptyInput() {
        List<Token> tokens = tokenizer.tokenize(new byte[0]);
        assertTrue(tokens.isEmpty());
    }

    @Test
    @DisplayName("Test 21: 序列化后与原始一致")
    void testSerializationRoundTrip() {
        String[] samples = {
            "_Z4mainv",
            "_Z3fooi",
            "_ZN3std4coutE"
        };
        
        for (String mangled : samples) {
            TokenNode tree = tokenizer.parse(mangled.getBytes(StandardCharsets.ISO_8859_1));
            String serialized = tree.serialize();
            assertEquals(mangled, serialized, "序列化应与原始一致: " + mangled);
        }
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
