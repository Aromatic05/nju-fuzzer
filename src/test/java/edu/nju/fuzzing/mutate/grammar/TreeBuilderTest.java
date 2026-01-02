package edu.nju.fuzzing.mutate.grammar;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * TreeBuilder 类单元测试
 */
class TreeBuilderTest {

    @Test
    @DisplayName("Test 1: 空 token 列表返回空根节点")
    void testEmptyTokens() {
        TokenNode root = TreeBuilder.build(Arrays.asList());
        assertEquals(0, root.getChildren().size());
        assertNotNull(root);
        
        assertEquals(TokenNode.NodeType.ROOT, root.getNodeType());
        assertTrue(root.getChildren().isEmpty());
    }

    @Test
    @DisplayName("Test 2: 单个 token 创建叶子节点")
    void testSingleToken() {
        List<Token> tokens = Arrays.asList(
            new Token(Token.Type.STRING, "\"hello\"")
        );
        
        TokenNode root = TreeBuilder.build(tokens);
        assertNotNull(root);
        
        assertEquals(1, root.getChildren().size());
        assertEquals(TokenNode.NodeType.LEAF, root.getChildren().get(0).getNodeType());
        assertEquals("\"hello\"", root.getChildren().get(0).getToken().getValue());
    }

    @Test
    @DisplayName("Test 3: 匹配的大括号创建块节点")
    void testMatchedBraces() {
        List<Token> tokens = Arrays.asList(
            new Token(Token.Type.LBRACE, "{"),
            new Token(Token.Type.STRING, "\"key\""),
            new Token(Token.Type.COLON, ":"),
            new Token(Token.Type.NUMBER, "123"),
            new Token(Token.Type.RBRACE, "}")
        );
        
        TokenNode root = TreeBuilder.build(tokens);
        
        assertEquals(1, root.getChildren().size());
        TokenNode block = root.getChildren().get(0);
        assertEquals(TokenNode.NodeType.BLOCK, block.getNodeType());
        assertEquals(3, block.getChildren().size()); // "key", :, 123
    }

    @Test
    @DisplayName("Test 4: 嵌套结构")
    void testNestedStructure() {
        List<Token> tokens = Arrays.asList(
            new Token(Token.Type.LBRACE, "{"),
            new Token(Token.Type.STRING, "\"arr\""),
            new Token(Token.Type.COLON, ":"),
            new Token(Token.Type.LBRACKET, "["),
            new Token(Token.Type.NUMBER, "1"),
            new Token(Token.Type.COMMA, ","),
            new Token(Token.Type.NUMBER, "2"),
            new Token(Token.Type.RBRACKET, "]"),
            new Token(Token.Type.RBRACE, "}")
        );
        
        TokenNode root = TreeBuilder.build(tokens);
        
        assertEquals(1, root.getChildren().size());
        TokenNode outerBlock = root.getChildren().get(0);
        assertEquals(TokenNode.NodeType.BLOCK, outerBlock.getNodeType());
        
        // 找到内层数组块
        TokenNode innerBlock = null;
        for (TokenNode child : outerBlock.getChildren()) {
            if (child.getNodeType() == TokenNode.NodeType.BLOCK) {
                innerBlock = child;
                break;
            }
        }
        assertNotNull(innerBlock);
    }

    @Test
    @DisplayName("Test 5: 未匹配的开括号 - 容错处理")
    void testUnmatchedOpenBrace() {
        List<Token> tokens = Arrays.asList(
            new Token(Token.Type.LBRACE, "{"),
            new Token(Token.Type.STRING, "\"key\""),
            new Token(Token.Type.COLON, ":"),
            new Token(Token.Type.NUMBER, "123")
            // 缺少 }
        );
        
        TokenNode root = TreeBuilder.build(tokens);
        
        // 应该仍然能构建树，未闭合的块也会被添加
        assertNotNull(root);
        assertFalse(root.getChildren().isEmpty());
    }

    @Test
    @DisplayName("Test 6: 未匹配的闭括号 - 容错处理")
    void testUnmatchedCloseBrace() {
        List<Token> tokens = Arrays.asList(
            new Token(Token.Type.STRING, "\"value\""),
            new Token(Token.Type.RBRACE, "}")  // 孤立的 }
        );
        
        TokenNode root = TreeBuilder.build(tokens);
        
        // 应该将孤立的 } 作为叶子节点或片段处理
        assertNotNull(root);
        assertEquals(2, root.getChildren().size());
    }

    @Test
    @DisplayName("Test 7: 混合括号类型")
    void testMixedBrackets() {
        List<Token> tokens = Arrays.asList(
            new Token(Token.Type.LBRACKET, "["),
            new Token(Token.Type.LBRACE, "{"),
            new Token(Token.Type.STRING, "\"a\""),
            new Token(Token.Type.RBRACE, "}"),
            new Token(Token.Type.RBRACKET, "]")
        );
        
        TokenNode root = TreeBuilder.build(tokens);
        
        assertEquals(1, root.getChildren().size());
        TokenNode arrayBlock = root.getChildren().get(0);
        
        // 内部应有一个对象块
        boolean hasObjectBlock = false;
        for (TokenNode child : arrayBlock.getChildren()) {
            if (child.getNodeType() == TokenNode.NodeType.BLOCK) {
                hasObjectBlock = true;
                break;
            }
        }
        assertTrue(hasObjectBlock);
    }

    @Test
    @DisplayName("Test 8: XML 风格的尖括号")
    void testAngleBrackets() {
        List<Token> tokens = Arrays.asList(
            new Token(Token.Type.LANGLE, "<"),
            new Token(Token.Type.RAW, "tag"),
            new Token(Token.Type.RANGLE, ">"),
            new Token(Token.Type.RAW, "content")
        );
        
        TokenNode root = TreeBuilder.build(tokens);
        
        assertNotNull(root);
        assertFalse(root.getChildren().isEmpty());
    }

    @Test
    @DisplayName("Test 9: 序列化后与原始匹配")
    void testSerializationRoundTrip() {
        List<Token> tokens = Arrays.asList(
            new Token(Token.Type.LBRACE, "{"),
            new Token(Token.Type.STRING, "\"x\""),
            new Token(Token.Type.COLON, ":"),
            new Token(Token.Type.NUMBER, "42"),
            new Token(Token.Type.RBRACE, "}")
        );
        
        TokenNode root = TreeBuilder.build(tokens);
        String serialized = root.serialize();
        
        assertEquals("{\"x\":42}", serialized);
    }

    @Test
    @DisplayName("Test 10: 深度嵌套")
    void testDeepNesting() {
        // 创建 [[[1]]]
        List<Token> tokens = Arrays.asList(
            new Token(Token.Type.LBRACKET, "["),
            new Token(Token.Type.LBRACKET, "["),
            new Token(Token.Type.LBRACKET, "["),
            new Token(Token.Type.NUMBER, "1"),
            new Token(Token.Type.RBRACKET, "]"),
            new Token(Token.Type.RBRACKET, "]"),
            new Token(Token.Type.RBRACKET, "]")
        );
        
        TokenNode root = TreeBuilder.build(tokens);
        String serialized = root.serialize();
        
        assertEquals("[[[1]]]", serialized);
        
        // 验证嵌套深度
        int depth = 0;
        TokenNode current = root.getChildren().get(0);
        while (current.getNodeType() == TokenNode.NodeType.BLOCK) {
            depth++;
            if (current.getChildren().isEmpty()) break;
            TokenNode nextBlock = null;
            for (TokenNode child : current.getChildren()) {
                if (child.getNodeType() == TokenNode.NodeType.BLOCK) {
                    nextBlock = child;
                    break;
                }
            }
            if (nextBlock == null) break;
            current = nextBlock;
        }
        assertEquals(3, depth);
    }
}
