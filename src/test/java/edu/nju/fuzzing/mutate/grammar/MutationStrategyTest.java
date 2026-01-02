package edu.nju.fuzzing.mutate.grammar;

import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * MutationStrategy 单元测试
 */
class MutationStrategyTest {

    private final ThreadLocalRandom rand = ThreadLocalRandom.current();

    @Test
    @DisplayName("Test 1: duplicateSubtree - 复制子树")
    void testDuplicateSubtree() {
        TokenNode root = createSampleTree();
        int originalBlockCount = root.collectBlocks().size();
        assertTrue(originalBlockCount > 0, "Sample tree should have at least one block node");
        MutationStrategy.duplicateSubtree(root, 3, rand);
        
        // 复制后应该有更多内容
        String serialized = root.serialize();
        assertNotNull(serialized);
    }

    @Test
    @DisplayName("Test 2: deleteNodes - 删除节点")
    void testDeleteNodes() {
        TokenNode root = createSampleTree();
        int originalLeafCount = root.collectLeaves().size();
        
        // 删除 50% 的节点
        MutationStrategy.deleteNodes(root, 0.5, rand);
        
        int newLeafCount = root.collectLeaves().size();
        // 应该删除了一些节点（除非运气不好全部保留）
        assertTrue(newLeafCount <= originalLeafCount);
    }

    @Test
    @DisplayName("Test 3: swapNodes - 交换节点")
    void testSwapNodes() {
        TokenNode root = createSampleTree();
        String before = root.serialize();
        assertNotNull(before);
        
        // 多次交换以增加变化概率
        for (int i = 0; i < 5; i++) {
            MutationStrategy.swapNodes(root, rand);
        }
        
        // 结构可能改变
        String after = root.serialize();
        assertNotNull(after);
    }

    @Test
    @DisplayName("Test 4: injectPayload - 注入攻击载荷")
    void testInjectPayload() {
        TokenNode root = createSampleTree();
        String[] payloads = {"PAYLOAD1", "PAYLOAD2", "PAYLOAD3"};
        
        // 多次注入
        for (int i = 0; i < 10; i++) {
            MutationStrategy.injectPayload(root, payloads, rand);
        }
        
        String serialized = root.serialize();
        assertNotNull(serialized);
    }

    @Test
    @DisplayName("Test 5: typeConfusion - 类型混淆")
    void testTypeConfusion() {
        TokenNode root = TokenNode.createRoot();
        TokenNode leaf = TokenNode.createLeaf(new Token(Token.Type.STRING, "\"test\""));
        root.addChild(leaf);
        
        // 多次尝试类型混淆
        for (int i = 0; i < 10; i++) {
            MutationStrategy.typeConfusion(root, rand);
        }
        
        // 验证不崩溃，可能类型已改变
        assertNotNull(root.serialize());
    }

    @Test
    @DisplayName("Test 6: replaceKeywords - 关键字替换")
    void testReplaceKeywords() {
        TokenNode root = TokenNode.createRoot();
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.BOOLEAN, "true")));
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.NULL, "null")));
        
        String[][] replacements = {
            {"true", "false"},
            {"null", "undefined"}
        };
        
        // 100% 概率替换
        for (int i = 0; i < 20; i++) {
            MutationStrategy.replaceKeywords(root, replacements, rand);
        }
        
        String serialized = root.serialize();
        assertNotNull(serialized);
    }

    @Test
    @DisplayName("Test 7: mutateNumbers - 数字变异")
    void testMutateNumbers() {
        TokenNode root = TokenNode.createRoot();
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "42")));
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "3.14")));
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "100")));
        
        String before = root.serialize();
        assertNotNull(before);
        
        // 多次变异数字
        for (int i = 0; i < 10; i++) {
            MutationStrategy.mutateNumbers(root, rand);
        }
        
        String after = root.serialize();
        assertNotNull(after);
    }

    @Test
    @DisplayName("Test 8: 空树操作不崩溃")
    void testEmptyTree() {
        TokenNode root = TokenNode.createRoot();
        
        // 所有操作都不应该崩溃
        assertDoesNotThrow(() -> MutationStrategy.duplicateSubtree(root, 3, rand));
        assertDoesNotThrow(() -> MutationStrategy.deleteNodes(root, 0.5, rand));
        assertDoesNotThrow(() -> MutationStrategy.swapNodes(root, rand));
        assertDoesNotThrow(() -> MutationStrategy.injectPayload(root, new String[]{"x"}, rand));
        assertDoesNotThrow(() -> MutationStrategy.typeConfusion(root, rand));
        assertDoesNotThrow(() -> MutationStrategy.replaceKeywords(root, new String[][]{{"a", "b"}}, rand));
        assertDoesNotThrow(() -> MutationStrategy.mutateNumbers(root, rand));
    }

    @Test
    @DisplayName("Test 9: 只有叶子的树")
    void testLeafOnlyTree() {
        TokenNode root = TokenNode.createRoot();
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.STRING, "\"a\"")));
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "1")));
        root.addChild(TokenNode.createLeaf(new Token(Token.Type.BOOLEAN, "true")));
        
        // 所有操作都不应该崩溃
        assertDoesNotThrow(() -> MutationStrategy.duplicateSubtree(root, 2, rand));
        assertDoesNotThrow(() -> MutationStrategy.deleteNodes(root, 0.3, rand));
        assertDoesNotThrow(() -> MutationStrategy.swapNodes(root, rand));
    }

    @Test
    @DisplayName("Test 10: 深度嵌套树")
    void testDeeplyNestedTree() {
        TokenNode root = TokenNode.createRoot();
        TokenNode current = root;
        
        // 创建 10 层嵌套
        for (int i = 0; i < 10; i++) {
            TokenNode block = TokenNode.createBlock(new Token(Token.Type.LBRACE, "{"));
            current.addChild(block);
            current = block;
        }
        current.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "42")));
        
        // 操作不应该崩溃
        assertDoesNotThrow(() -> MutationStrategy.duplicateSubtree(root, 3, rand));
        assertDoesNotThrow(() -> MutationStrategy.deleteNodes(root, 0.2, rand));
    }

    @Test
    @DisplayName("Test 11: 常见攻击载荷数组")
    void testCommonPayloads() {
        // 验证 MutationStrategy 包含常见攻击载荷
        String[] payloads = MutationStrategy.COMMON_PAYLOADS;
        
        assertNotNull(payloads);
        assertTrue(payloads.length > 0);
        
        // 检查一些典型的攻击载荷
        boolean hasNullByte = false;
        boolean hasPathTraversal = false;
        boolean hasFormatString = false;
        
        for (String p : payloads) {
            if (p.contains("\\x00") || p.contains("\\0") || p.contains("\0")) hasNullByte = true;
            if (p.contains("../")) hasPathTraversal = true;
            if (p.contains("%s") || p.contains("%x") || p.contains("%n")) hasFormatString = true;
        }
        
        assertTrue(hasNullByte || hasPathTraversal || hasFormatString, 
            "应包含至少一种常见攻击载荷");
    }

    /**
     * 创建一个示例树用于测试
     * 结构: { "key": [1, 2, 3] }
     */
    private TokenNode createSampleTree() {
        TokenNode root = TokenNode.createRoot();
        
        TokenNode obj = TokenNode.createBlock(new Token(Token.Type.LBRACE, "{"));
        obj.setCloseDelimiter(new Token(Token.Type.RBRACE, "}"));
        
        obj.addChild(TokenNode.createLeaf(new Token(Token.Type.STRING, "\"key\"")));
        obj.addChild(TokenNode.createLeaf(new Token(Token.Type.COLON, ":")));
        
        TokenNode arr = TokenNode.createBlock(new Token(Token.Type.LBRACKET, "["));
        arr.setCloseDelimiter(new Token(Token.Type.RBRACKET, "]"));
        arr.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "1")));
        arr.addChild(TokenNode.createLeaf(new Token(Token.Type.COMMA, ",")));
        arr.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "2")));
        arr.addChild(TokenNode.createLeaf(new Token(Token.Type.COMMA, ",")));
        arr.addChild(TokenNode.createLeaf(new Token(Token.Type.NUMBER, "3")));
        
        obj.addChild(arr);
        root.addChild(obj);
        
        return root;
    }
}
