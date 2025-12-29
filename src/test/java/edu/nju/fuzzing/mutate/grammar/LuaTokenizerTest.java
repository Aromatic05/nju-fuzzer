package edu.nju.fuzzing.mutate.grammar;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * LuaTokenizer 单元测试
 */
class LuaTokenizerTest {

    private final LuaTokenizer tokenizer = new LuaTokenizer();

    @Test
    @DisplayName("Test 1: 关键字识别")
    void testKeywords() {
        String lua = "local function if then else end";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        long keywordCount = tokens.stream()
            .filter(t -> t.getType() == Token.Type.KEYWORD)
            .count();
        
        assertTrue(keywordCount >= 5, "应识别 local, function, if, then, else, end");
    }

    @Test
    @DisplayName("Test 2: 标识符")
    void testIdentifiers() {
        String lua = "myVar = someFunction(arg1, arg2)";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.IDENTIFIER));
        
        // myVar, someFunction, arg1, arg2 都应该是标识符
        long idCount = tokens.stream()
            .filter(t -> t.getType() == Token.Type.IDENTIFIER)
            .count();
        assertTrue(idCount >= 4);
    }

    @Test
    @DisplayName("Test 3: 字符串 - 单引号")
    void testSingleQuoteString() {
        String lua = "local s = 'hello world'";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        Optional<Token> str = tokens.stream()
            .filter(t -> t.getType() == Token.Type.STRING)
            .findFirst();
        
        assertTrue(str.isPresent());
        assertTrue(str.get().getValue().contains("hello"));
    }

    @Test
    @DisplayName("Test 4: 字符串 - 双引号")
    void testDoubleQuoteString() {
        String lua = "local s = \"hello\\nworld\"";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.STRING));
    }

    @Test
    @DisplayName("Test 5: 长字符串 [[...]]")
    void testLongString() {
        String lua = "local s = [[multiline\nstring\nhere]]";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        Optional<Token> longStr = tokens.stream()
            .filter(t -> t.getType() == Token.Type.STRING && t.getValue().contains("[["))
            .findFirst();
        
        assertTrue(longStr.isPresent());
        assertTrue(longStr.get().getValue().contains("multiline"));
    }

    @Test
    @DisplayName("Test 6: 带等号的长字符串 [=[...]=]")
    void testLongStringWithEquals() {
        String lua = "local s = [==[nested [[brackets]] ok]==]";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.STRING));
        String combined = combineValues(tokens);
        assertTrue(combined.contains("nested"));
    }

    @Test
    @DisplayName("Test 7: 数字 - 整数")
    void testIntegerNumbers() {
        String lua = "local a = 42 local b = -123";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.NUMBER));
    }

    @Test
    @DisplayName("Test 8: 数字 - 十六进制")
    void testHexNumbers() {
        String lua = "local h = 0xFF local h2 = 0x1A2B";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        List<Token> numbers = new ArrayList<>();
        for (Token t : tokens) {
            if (t.getType() == Token.Type.NUMBER) {
                numbers.add(t);
            }
        }
        
        assertTrue(numbers.size() >= 2);
        boolean hasHex = numbers.stream().anyMatch(t -> 
            t.getValue().contains("0x") || t.getValue().contains("0X"));
        assertTrue(hasHex);
    }

    @Test
    @DisplayName("Test 9: 数字 - 浮点数")
    void testFloatNumbers() {
        String lua = "local f = 3.14 local e = 1.5e10";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        String combined = combineValues(tokens);
        assertTrue(combined.contains("3.14"));
        assertTrue(combined.contains("1.5e10") || combined.contains("1.5"));
    }

    @Test
    @DisplayName("Test 10: 单行注释")
    void testSingleLineComment() {
        String lua = "local x = 1 -- this is a comment\nlocal y = 2";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.COMMENT));
    }

    @Test
    @DisplayName("Test 11: 多行注释")
    void testMultiLineComment() {
        String lua = "local x = 1 --[[multi\nline\ncomment]] local y = 2";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.COMMENT));
    }

    @Test
    @DisplayName("Test 12: 操作符")
    void testOperators() {
        String lua = "a + b - c * d / e % f ^ g == h ~= i <= j >= k < l > m and n or not o";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        assertTrue(hasTokenOfType(tokens, Token.Type.OPERATOR));
        
        // 验证各种操作符都被识别
        String combined = combineValues(tokens);
        assertTrue(combined.contains("+"));
        assertTrue(combined.contains("-"));
        assertTrue(combined.contains("*"));
        assertTrue(combined.contains("=="));
        assertTrue(combined.contains("~="));
    }

    @Test
    @DisplayName("Test 13: Lua 5.3 位运算符")
    void testBitwiseOperators() {
        String lua = "a & b | c ~ d << e >> f";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        String combined = combineValues(tokens);
        assertTrue(combined.contains("&"));
        assertTrue(combined.contains("|"));
        assertTrue(combined.contains("<<"));
        assertTrue(combined.contains(">>"));
    }

    @Test
    @DisplayName("Test 14: 分隔符")
    void testDelimiters() {
        String lua = "function foo(a, b) return {x=1, y=2} end";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        // 检查括号、花括号、逗号等
        String combined = combineValues(tokens);
        assertTrue(combined.contains("("));
        assertTrue(combined.contains(")"));
        assertTrue(combined.contains("{"));
        assertTrue(combined.contains("}"));
        assertTrue(combined.contains(","));
    }

    @Test
    @DisplayName("Test 15: 完整函数定义")
    void testFunctionDefinition() {
        String lua = "function factorial(n)\n  if n <= 1 then\n    return 1\n  else\n    return n * factorial(n - 1)\n  end\nend";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        // 应该识别所有关键字
        Map<String, Boolean> found = new HashMap<>();
        found.put("function", false);
        found.put("if", false);
        found.put("then", false);
        found.put("return", false);
        found.put("else", false);
        found.put("end", false);
        
        for (Token t : tokens) {
            if (t.getType() == Token.Type.KEYWORD) {
                found.put(t.getValue(), true);
            }
        }
        
        for (Map.Entry<String, Boolean> e : found.entrySet()) {
            assertTrue(e.getValue(), "未识别关键字: " + e.getKey());
        }
    }

    @Test
    @DisplayName("Test 16: 容错 - 不完整的字符串")
    void testIncompleteString() {
        String lua = "local s = \"unterminated";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        // 应该不崩溃
        assertFalse(tokens.isEmpty());
    }

    @Test
    @DisplayName("Test 17: 容错 - 不完整的长字符串")
    void testIncompleteLongString() {
        String lua = "local s = [[unterminated";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        
        assertFalse(tokens.isEmpty());
    }

    @Test
    @DisplayName("Test 18: 构建树")
    void testBuildTree() {
        String lua = "if true then print('hello') end";
        List<Token> tokens = tokenizer.tokenize(lua.getBytes(StandardCharsets.UTF_8));
        TokenNode tree = tokenizer.buildTree(tokens);
        
        assertNotNull(tree);
        assertEquals(TokenNode.NodeType.ROOT, tree.getNodeType());
    }

    @Test
    @DisplayName("Test 19: 完整解析流程")
    void testParse() {
        String lua = "local t = {1, 2, 3}";
        TokenNode tree = tokenizer.parse(lua.getBytes(StandardCharsets.UTF_8));
        
        assertNotNull(tree);
        String serialized = tree.serialize();
        assertTrue(serialized.contains("local"));
        assertTrue(serialized.contains("{"));
    }

    @Test
    @DisplayName("Test 20: 空输入")
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
