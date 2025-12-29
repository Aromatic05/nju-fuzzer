package edu.nju.fuzzing.mutate.grammar;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * 轻量级结构构建器 (Tree Builder)
 * 
 * 功能：基于 Token 流构建松散的树状结构
 * 
 * 关键点：
 * 1. 不进行严格语法校验
 * 2. 使用栈根据界定符推断层级
 * 3. 括号不匹配时强制生成"尽可能合理"的树
 */
public class TreeBuilder {

    /**
     * 从 Token 流构建树
     * 
     * @param tokens Token 列表
     * @return 根节点
     */
    public static TokenNode build(List<Token> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return TokenNode.createRoot();
        }

        TokenNode root = TokenNode.createRoot();
        Deque<TokenNode> stack = new ArrayDeque<>();
        stack.push(root);

        for (Token token : tokens) {
            TokenNode current = stack.peek();

            if (token.isOpenDelimiter()) {
                // 遇到开放界定符，创建新 BLOCK 并入栈
                TokenNode block = TokenNode.createBlock(token);
                current.addChild(block);
                stack.push(block);
            } else if (token.isCloseDelimiter()) {
                // 遇到闭合界定符
                Token.Type expectedOpen = token.getMatchingDelimiter();
                
                // 尝试找到匹配的开放界定符
                TokenNode matchingBlock = findMatchingBlock(stack, expectedOpen);
                
                if (matchingBlock != null) {
                    // 找到匹配，关闭该 BLOCK
                    matchingBlock.setCloseDelimiter(token);
                    
                    // 弹出栈直到（包括）匹配的 BLOCK
                    while (stack.peek() != matchingBlock) {
                        stack.pop();
                    }
                    stack.pop();
                    
                    // 确保栈不为空
                    if (stack.isEmpty()) {
                        stack.push(root);
                    }
                } else {
                    // 没有匹配的开放界定符，作为 LEAF 添加
                    current.addChild(TokenNode.createLeaf(token));
                }
            } else {
                // 其他 Token 作为 LEAF 添加
                current.addChild(TokenNode.createLeaf(token));
            }
        }

        // 处理未闭合的 BLOCK（保持为未闭合状态，不强制添加闭合符）
        // 这是故意的设计：让变异器可以检测到未闭合的结构

        return root;
    }

    /**
     * 在栈中查找匹配的开放界定符
     * 
     * @param stack 当前栈
     * @param expectedOpen 期望的开放界定符类型
     * @return 匹配的 BLOCK 节点，如果没有则返回 null
     */
    private static TokenNode findMatchingBlock(Deque<TokenNode> stack, Token.Type expectedOpen) {
        for (TokenNode node : stack) {
            if (node.getNodeType() == TokenNode.NodeType.BLOCK) {
                Token open = node.getOpenDelimiter();
                if (open != null && open.getType() == expectedOpen) {
                    return node;
                }
            }
        }
        return null;
    }

    /**
     * 构建扁平的 Token 列表（当结构过于混乱时使用）
     * 
     * @param tokens Token 列表
     * @return 包含所有 Token 作为 LEAF 的根节点
     */
    public static TokenNode buildFlat(List<Token> tokens) {
        TokenNode root = TokenNode.createRoot();
        if (tokens != null) {
            for (Token token : tokens) {
                root.addChild(TokenNode.createLeaf(token));
            }
        }
        return root;
    }
}
