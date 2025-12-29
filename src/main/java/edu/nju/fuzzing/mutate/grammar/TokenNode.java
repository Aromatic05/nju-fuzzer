package edu.nju.fuzzing.mutate.grammar;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * TokenNode - 轻量级树状结构节点
 * 
 * 用于表示 Token 流的层级结构，基于界定符（括号、花括号等）推断层级。
 * 设计特点：
 * 1. 松散结构：即使括号不匹配也能构建树
 * 2. 支持子树操作：复制、删除、替换
 * 3. 可序列化回字符串
 */
public class TokenNode {

    /**
     * 节点类型
     */
    public enum NodeType {
        ROOT,       // 根节点
        BLOCK,      // 由界定符包围的块 { }, [ ], ( ), < >
        LEAF,       // 叶子节点（单个 Token）
        FRAGMENT    // 片段（多个连续 Token，无显式结构）
    }

    private NodeType nodeType;
    private Token token;                    // 对于 LEAF 节点，存储单个 Token
    private Token openDelimiter;            // 对于 BLOCK 节点，开始界定符
    private Token closeDelimiter;           // 对于 BLOCK 节点，结束界定符（可能为 null = 未闭合）
    private List<TokenNode> children;       // 子节点列表
    private TokenNode parent;               // 父节点引用

    // === 构造器 ===

    /**
     * 创建根节点
     */
    public static TokenNode createRoot() {
        TokenNode node = new TokenNode();
        node.nodeType = NodeType.ROOT;
        node.children = new ArrayList<>();
        return node;
    }

    /**
     * 创建叶子节点
     */
    public static TokenNode createLeaf(Token token) {
        TokenNode node = new TokenNode();
        node.nodeType = NodeType.LEAF;
        node.token = token;
        return node;
    }

    /**
     * 创建块节点
     */
    public static TokenNode createBlock(Token openDelimiter) {
        TokenNode node = new TokenNode();
        node.nodeType = NodeType.BLOCK;
        node.openDelimiter = openDelimiter;
        node.children = new ArrayList<>();
        return node;
    }

    /**
     * 创建片段节点
     */
    public static TokenNode createFragment() {
        TokenNode node = new TokenNode();
        node.nodeType = NodeType.FRAGMENT;
        node.children = new ArrayList<>();
        return node;
    }

    private TokenNode() {}

    // === 树操作 ===

    public void addChild(TokenNode child) {
        if (children == null) {
            children = new ArrayList<>();
        }
        child.parent = this;
        children.add(child);
    }

    public void insertChild(int index, TokenNode child) {
        if (children == null) {
            children = new ArrayList<>();
        }
        child.parent = this;
        children.add(Math.min(index, children.size()), child);
    }

    public boolean removeChild(TokenNode child) {
        if (children != null) {
            child.parent = null;
            return children.remove(child);
        }
        return false;
    }

    public TokenNode removeChildAt(int index) {
        if (children != null && index >= 0 && index < children.size()) {
            TokenNode removed = children.remove(index);
            removed.parent = null;
            return removed;
        }
        return null;
    }

    public void replaceChild(int index, TokenNode newChild) {
        if (children != null && index >= 0 && index < children.size()) {
            TokenNode old = children.get(index);
            old.parent = null;
            newChild.parent = this;
            children.set(index, newChild);
        }
    }

    public void setCloseDelimiter(Token closeDelimiter) {
        this.closeDelimiter = closeDelimiter;
    }

    // === Getters ===

    public NodeType getNodeType() {
        return nodeType;
    }

    public Token getToken() {
        return token;
    }

    public Token getOpenDelimiter() {
        return openDelimiter;
    }

    public Token getCloseDelimiter() {
        return closeDelimiter;
    }

    public List<TokenNode> getChildren() {
        return children != null ? children : List.of();
    }

    public TokenNode getParent() {
        return parent;
    }

    public int getChildCount() {
        return children != null ? children.size() : 0;
    }

    public boolean hasChildren() {
        return children != null && !children.isEmpty();
    }

    public boolean isClosed() {
        return nodeType != NodeType.BLOCK || closeDelimiter != null;
    }

    // === 深度操作 ===

    /**
     * 计算此节点的深度（从根开始）
     */
    public int getDepth() {
        int depth = 0;
        TokenNode current = parent;
        while (current != null) {
            depth++;
            current = current.parent;
        }
        return depth;
    }

    /**
     * 计算子树的最大深度
     */
    public int getMaxDepth() {
        if (children == null || children.isEmpty()) {
            return 0;
        }
        int maxChildDepth = 0;
        for (TokenNode child : children) {
            maxChildDepth = Math.max(maxChildDepth, child.getMaxDepth());
        }
        return maxChildDepth + 1;
    }

    /**
     * 深拷贝此节点及其所有子节点
     */
    public TokenNode deepCopy() {
        TokenNode copy = new TokenNode();
        copy.nodeType = this.nodeType;
        copy.token = this.token;
        copy.openDelimiter = this.openDelimiter;
        copy.closeDelimiter = this.closeDelimiter;

        if (this.children != null) {
            copy.children = new ArrayList<>(this.children.size());
            for (TokenNode child : this.children) {
                TokenNode childCopy = child.deepCopy();
                childCopy.parent = copy;
                copy.children.add(childCopy);
            }
        }
        return copy;
    }

    // === 遍历辅助 ===

    /**
     * 收集所有 BLOCK 类型的子节点（递归）
     */
    public List<TokenNode> collectBlocks() {
        List<TokenNode> blocks = new ArrayList<>();
        collectBlocksRecursive(this, blocks);
        return blocks;
    }

    private void collectBlocksRecursive(TokenNode node, List<TokenNode> result) {
        if (node.nodeType == NodeType.BLOCK) {
            result.add(node);
        }
        if (node.children != null) {
            for (TokenNode child : node.children) {
                collectBlocksRecursive(child, result);
            }
        }
    }

    /**
     * 收集所有 LEAF 类型的子节点（递归）
     */
    public List<TokenNode> collectLeaves() {
        List<TokenNode> leaves = new ArrayList<>();
        collectLeavesRecursive(this, leaves);
        return leaves;
    }

    private void collectLeavesRecursive(TokenNode node, List<TokenNode> result) {
        if (node.nodeType == NodeType.LEAF) {
            result.add(node);
        }
        if (node.children != null) {
            for (TokenNode child : node.children) {
                collectLeavesRecursive(child, result);
            }
        }
    }

    /**
     * 随机选择一个 BLOCK 子节点
     */
    public TokenNode randomBlock(ThreadLocalRandom rand) {
        List<TokenNode> blocks = collectBlocks();
        if (blocks.isEmpty()) return null;
        return blocks.get(rand.nextInt(blocks.size()));
    }

    /**
     * 随机选择一个 LEAF 子节点
     */
    public TokenNode randomLeaf(ThreadLocalRandom rand) {
        List<TokenNode> leaves = collectLeaves();
        if (leaves.isEmpty()) return null;
        return leaves.get(rand.nextInt(leaves.size()));
    }

    // === 序列化 ===

    /**
     * 将此节点及其子节点序列化回字符串
     */
    public String serialize() {
        StringBuilder sb = new StringBuilder();
        serializeRecursive(this, sb);
        return sb.toString();
    }

    private void serializeRecursive(TokenNode node, StringBuilder sb) {
        switch (node.nodeType) {
            case ROOT:
            case FRAGMENT:
                if (node.children != null) {
                    for (TokenNode child : node.children) {
                        serializeRecursive(child, sb);
                    }
                }
                break;

            case LEAF:
                if (node.token != null && node.token.getValue() != null) {
                    sb.append(node.token.getValue());
                }
                break;

            case BLOCK:
                // 开始界定符
                if (node.openDelimiter != null && node.openDelimiter.getValue() != null) {
                    sb.append(node.openDelimiter.getValue());
                }
                // 子节点
                if (node.children != null) {
                    for (TokenNode child : node.children) {
                        serializeRecursive(child, sb);
                    }
                }
                // 结束界定符（可能缺失）
                if (node.closeDelimiter != null && node.closeDelimiter.getValue() != null) {
                    sb.append(node.closeDelimiter.getValue());
                }
                break;
        }
    }

    /**
     * 序列化时故意省略一些闭合符号（用于测试 EOF 处理）
     * @param skipCloseProb 省略闭合符号的概率 [0.0, 1.0]
     */
    public String serializeWithMissingClose(ThreadLocalRandom rand, double skipCloseProb) {
        StringBuilder sb = new StringBuilder();
        serializeWithMissingCloseRecursive(this, sb, rand, skipCloseProb);
        return sb.toString();
    }

    private void serializeWithMissingCloseRecursive(TokenNode node, StringBuilder sb, 
            ThreadLocalRandom rand, double skipCloseProb) {
        switch (node.nodeType) {
            case ROOT:
            case FRAGMENT:
                if (node.children != null) {
                    for (TokenNode child : node.children) {
                        serializeWithMissingCloseRecursive(child, sb, rand, skipCloseProb);
                    }
                }
                break;

            case LEAF:
                if (node.token != null && node.token.getValue() != null) {
                    sb.append(node.token.getValue());
                }
                break;

            case BLOCK:
                if (node.openDelimiter != null && node.openDelimiter.getValue() != null) {
                    sb.append(node.openDelimiter.getValue());
                }
                if (node.children != null) {
                    for (TokenNode child : node.children) {
                        serializeWithMissingCloseRecursive(child, sb, rand, skipCloseProb);
                    }
                }
                // 根据概率决定是否省略闭合符号
                if (node.closeDelimiter != null && node.closeDelimiter.getValue() != null) {
                    if (rand.nextDouble() >= skipCloseProb) {
                        sb.append(node.closeDelimiter.getValue());
                    }
                }
                break;
        }
    }

    @Override
    public String toString() {
        return String.format("TokenNode(%s, children=%d, depth=%d)", 
            nodeType, getChildCount(), getDepth());
    }
}
