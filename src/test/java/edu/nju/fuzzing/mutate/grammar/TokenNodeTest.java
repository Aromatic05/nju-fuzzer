package edu.nju.fuzzing.mutate.grammar;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * TokenNode 类单元测试
 */
class TokenNodeTest {

    @Test
    @DisplayName("Test 1: 创建根节点")
    void testCreateRoot() {
        TokenNode root = TokenNode.createRoot();
        
        assertEquals(TokenNode.NodeType.ROOT, root.getNodeType());
        assertNull(root.getToken());
        assertNull(root.getParent());
        assertTrue(root.getChildren().isEmpty());
    }

    @Test
    @DisplayName("Test 2: 创建叶子节点")
    void testCreateLeaf() {
        Token token = new Token(Token.Type.STRING, "\"value\"");
        TokenNode leaf = TokenNode.createLeaf(token);
        
        assertEquals(TokenNode.NodeType.LEAF, leaf.getNodeType());
        assertEquals(token, leaf.getToken());
    }

    @Test
    @DisplayName("Test 3: 创建块节点")
    void testCreateBlock() {
        Token openToken = new Token(Token.Type.LBRACE, "{");
        TokenNode block = TokenNode.createBlock(openToken);
        
        assertEquals(TokenNode.NodeType.BLOCK, block.getNodeType());
    }

    @Test
    @DisplayName("Test 4: 添加子节点并建立父子关系")
    void testAddChild() {
        TokenNode root = TokenNode.createRoot();
        Token token = new Token(Token.Type.NUMBER, "42");
        TokenNode child = TokenNode.createLeaf(token);
        
        root.addChild(child);
        
        assertEquals(1, root.getChildren().size());
        assertEquals(root, child.getParent());
        assertEquals(child, root.getChildren().get(0));
    }

    @Test
    @DisplayName("Test 5: 插入子节点")
    void testInsertChild() {
        TokenNode root = TokenNode.createRoot();
        TokenNode child1 = TokenNode.createLeaf(new Token(Token.Type.NUMBER, "1"));
        TokenNode child2 = TokenNode.createLeaf(new Token(Token.Type.NUMBER, "2"));
        TokenNode child3 = TokenNode.createLeaf(new Token(Token.Type.NUMBER, "3"));
        
        root.addChild(child1);
        root.addChild(child3);
        root.insertChild(1, child2);  // 在位置1插入
        
        assertEquals(3, root.getChildren().size());
        assertEquals("1", root.getChildren().get(0).getToken().getValue());
        assertEquals("2", root.getChildren().get(1).getToken().getValue());
        assertEquals("3", root.getChildren().get(2).getToken().getValue());
    }

    @Test
    @DisplayName("Test 6: 替换子节点")
    void testReplaceChild() {
        TokenNode root = TokenNode.createRoot();
        TokenNode original = TokenNode.createLeaf(new Token(Token.Type.NUMBER, "old"));
        TokenNode replacement = TokenNode.createLeaf(new Token(Token.Type.NUMBER, "new"));
        
        root.addChild(original);
        root.replaceChild(0, replacement);
        
        assertEquals(1, root.getChildren().size());
        assertEquals("new", root.getChildren().get(0).getToken().getValue());
        assertEquals(root, replacement.getParent());
    }

    @Test
    @DisplayName("Test 7: 深拷贝")
    void testDeepCopy() {
        TokenNode root = TokenNode.createRoot();
        TokenNode block = TokenNode.createBlock(new Token(Token.Type.LBRACE, "{"));
        TokenNode leaf = TokenNode.createLeaf(new Token(Token.Type.STRING, "\"test\""));
        
        block.addChild(leaf);
        root.addChild(block);
        
        TokenNode copy = root.deepCopy();
        
        // 验证结构相同
        assertEquals(1, copy.getChildren().size());
        assertEquals(TokenNode.NodeType.BLOCK, copy.getChildren().get(0).getNodeType());
        assertEquals(1, copy.getChildren().get(0).getChildren().size());
        
        // 验证是独立对象
        assertNotSame(root, copy);
        assertNotSame(block, copy.getChildren().get(0));
        assertNotSame(leaf, copy.getChildren().get(0).getChildren().get(0));
    }

    @Test
    @DisplayName("Test 8: 序列化")
    void testSerialize() {
        TokenNode root = TokenNode.createRoot();
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.LBRACE, "{")));
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.STRING, "\"key\"")));
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.COLON, ":")));
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "123")));
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.RBRACE, "}")));
        
        String result = root.serialize();
        
        assertEquals("{\"key\":123}", result);
    }

    @Test
    @DisplayName("Test 9: 序列化嵌套结构")
    void testSerializeNested() {
        TokenNode root = TokenNode.createRoot();
        TokenNode block = TokenNode.createBlock(new Token(Token.Type.LBRACKET, "["));
        block.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "1")));
        block.addChild(TokenNode.createLeaf(new Token(Token.Type.COMMA, ",")));
        block.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "2")));
        block.setCloseDelimiter(new Token(Token.Type.RBRACKET, "]"));
        root.addChild(block);
        
        String result = root.serialize();
        
        assertEquals("[1,2]", result);
    }

    @Test
    @DisplayName("Test 10: 带缺失闭合符号的序列化")
    void testSerializeWithMissingClose() {
        TokenNode root = TokenNode.createRoot();
        TokenNode block = TokenNode.createBlock(new Token(Token.Type.LBRACE, "{"));
        block.addChild(TokenNode.createLeaf(new Token(Token.Type.STRING, "\"a\"")));
        block.addChild(TokenNode.createLeaf(new Token(Token.Type.COLON, ":")));
        block.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "1")));
        block.setCloseDelimiter(new Token(Token.Type.RBRACE, "}"));
        root.addChild(block);
        
        // 100% 概率移除闭合符号
        String result = root.serializeWithMissingClose(ThreadLocalRandom.current(), 1.0);
        
        assertEquals("{\"a\":1", result);
    }

    @Test
    @DisplayName("Test 11: 收集所有叶子节点")
    void testCollectLeaves() {
        TokenNode root = TokenNode.createRoot();
        TokenNode block = TokenNode.createBlock(new Token(Token.Type.LBRACE, "{"));
        TokenNode leaf1 = TokenNode.createLeaf(new Token(Token.Type.STRING, "\"a\""));
        TokenNode leaf2 = TokenNode.createLeaf(new Token(Token.Type.NUMBER, "1"));
        
        block.addChild(leaf1);
        block.addChild(leaf2);
        root.addChild(block);
        
        List<TokenNode> leaves = root.collectLeaves();
        
        assertEquals(2, leaves.size());
        assertTrue(leaves.contains(leaf1));
        assertTrue(leaves.contains(leaf2));
    }

    @Test
    @DisplayName("Test 12: 收集所有块节点")
    void testCollectBlocks() {
        TokenNode root = TokenNode.createRoot();
        TokenNode block1 = TokenNode.createBlock(new Token(Token.Type.LBRACE, "{"));
        TokenNode block2 = TokenNode.createBlock(new Token(Token.Type.LBRACKET, "["));
        
        block1.addChild(block2);
        root.addChild(block1);
        
        List<TokenNode> blocks = root.collectBlocks();
        
        assertEquals(2, blocks.size());
        assertTrue(blocks.contains(block1));
        assertTrue(blocks.contains(block2));
    }

    @Test
    @DisplayName("Test 13: 随机获取块/叶子节点")
    void testRandomBlockAndLeaf() {
        TokenNode root = TokenNode.createRoot();
        TokenNode block = TokenNode.createBlock(new Token(Token.Type.LBRACE, "{"));
        TokenNode leaf = TokenNode.createLeaf(new Token(Token.Type.STRING, "\"test\""));
        
        block.addChild(leaf);
        root.addChild(block);
        
        ThreadLocalRandom rand = ThreadLocalRandom.current();
        
        TokenNode randomBlock = root.randomBlock(rand);
        assertNotNull(randomBlock);
        assertEquals(TokenNode.NodeType.BLOCK, randomBlock.getNodeType());
        
        TokenNode randomLeaf = root.randomLeaf(rand);
        assertNotNull(randomLeaf);
        assertEquals(TokenNode.NodeType.LEAF, randomLeaf.getNodeType());
    }

    @Test
    @DisplayName("Test 14: 空树返回 null")
    void testEmptyTreeRandomAccess() {
        TokenNode root = TokenNode.createRoot();
        ThreadLocalRandom rand = ThreadLocalRandom.current();
        
        assertNull(root.randomBlock(rand));
        assertNull(root.randomLeaf(rand));
    }
}
