package edu.nju.fuzzing.mutate.grammar;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 语法感知变异策略 (Grammar-Aware Mutation Strategies)
 * 
 * 提供通用的变异操作，可被各格式特定的 Mutator 使用
 */
public class MutationStrategy {

    // === 结构变异 ===

    /**
     * 子树复制（制造深层嵌套）
     * 选择一个 BLOCK 节点，将其内容复制并嵌套
     * 
     * @param root 树根节点
     * @param depth 复制嵌套的深度
     * @param rand 随机数生成器
     * @return 修改后的树（直接修改原树）
     */
    public static TokenNode duplicateSubtree(TokenNode root, int depth, ThreadLocalRandom rand) {
        List<TokenNode> blocks = root.collectBlocks();
        if (blocks.isEmpty()) return root;

        TokenNode target = blocks.get(rand.nextInt(blocks.size()));
        
        for (int i = 0; i < depth; i++) {
            // 创建新的包装块
            TokenNode wrapper = TokenNode.createBlock(target.getOpenDelimiter());
            
            // 将原有子节点移动到包装块中
            for (TokenNode child : target.getChildren()) {
                wrapper.addChild(child.deepCopy());
            }
            
            if (target.getCloseDelimiter() != null) {
                wrapper.setCloseDelimiter(target.getCloseDelimiter());
            }
            
            // 清空原节点，将包装块作为唯一子节点
            target.getChildren().clear();
            target.addChild(wrapper);
        }
        
        return root;
    }

    /**
     * 节点删除
     * 随机删除一些子节点
     * 
     * @param root 树根节点
     * @param deleteProb 删除概率 [0.0, 1.0]
     * @param rand 随机数生成器
     * @return 修改后的树
     */
    public static TokenNode deleteNodes(TokenNode root, double deleteProb, ThreadLocalRandom rand) {
        deleteNodesRecursive(root, deleteProb, rand);
        return root;
    }

    private static void deleteNodesRecursive(TokenNode node, double deleteProb, ThreadLocalRandom rand) {
        List<TokenNode> children = node.getChildren();
        if (children == null || children.isEmpty()) return;

        // 从后向前遍历以安全删除
        for (int i = children.size() - 1; i >= 0; i--) {
            TokenNode child = children.get(i);
            
            // 递归处理子节点
            deleteNodesRecursive(child, deleteProb, rand);
            
            // 按概率删除（但保留至少一个子节点）
            if (children.size() > 1 && rand.nextDouble() < deleteProb) {
                node.removeChildAt(i);
            }
        }
    }

    /**
     * 节点交换
     * 随机交换两个兄弟节点的位置
     */
    public static TokenNode swapNodes(TokenNode root, ThreadLocalRandom rand) {
        swapNodesRecursive(root, rand);
        return root;
    }

    private static void swapNodesRecursive(TokenNode node, ThreadLocalRandom rand) {
        List<TokenNode> children = node.getChildren();
        if (children == null || children.size() < 2) return;

        // 有 20% 概率在这一层进行交换
        if (rand.nextInt(5) == 0) {
            int i = rand.nextInt(children.size());
            int j = rand.nextInt(children.size());
            if (i != j) {
                TokenNode temp = children.get(i);
                children.set(i, children.get(j));
                children.set(j, temp);
            }
        }

        // 递归处理子节点
        for (TokenNode child : children) {
            swapNodesRecursive(child, rand);
        }
    }

    // === Token 值变异 ===

    /**
     * 字符串注入
     * 在字符串类型的 Token 中注入特殊 payload
     */
    public static TokenNode injectPayload(TokenNode root, String[] payloads, ThreadLocalRandom rand) {
        List<TokenNode> leaves = root.collectLeaves();
        
        for (TokenNode leaf : leaves) {
            if (leaf.getToken() != null && leaf.getToken().getType() == Token.Type.STRING) {
                if (rand.nextInt(5) == 0) { // 20% 概率注入
                    String original = leaf.getToken().getValue();
                    String payload = payloads[rand.nextInt(payloads.length)];
                    
                    // 在字符串中间插入 payload
                    if (original.length() > 2) {
                        int insertPos = 1 + rand.nextInt(original.length() - 2);
                        String newValue = original.substring(0, insertPos) + payload + 
                                         original.substring(insertPos);
                        Token newToken = leaf.getToken().withValue(newValue);
                        // 创建新的 leaf 节点来替换
                        TokenNode parent = leaf.getParent();
                        if (parent != null) {
                            int idx = parent.getChildren().indexOf(leaf);
                            if (idx >= 0) {
                                parent.replaceChild(idx, TokenNode.createLeaf(newToken));
                            }
                        }
                    }
                }
            }
        }
        
        return root;
    }

    /**
     * 类型混淆
     * 将数字改成字符串，将布尔值改成数字等
     */
    public static TokenNode typeConfusion(TokenNode root, ThreadLocalRandom rand) {
        List<TokenNode> leaves = root.collectLeaves();
        
        for (TokenNode leaf : leaves) {
            if (leaf.getToken() == null) continue;
            
            if (rand.nextInt(10) == 0) { // 10% 概率混淆
                Token token = leaf.getToken();
                Token newToken = null;
                
                switch (token.getType()) {
                    case NUMBER:
                        // 数字 -> 字符串
                        newToken = token.withTypeAndValue(Token.Type.STRING, 
                            "\"" + token.getValue() + "\"");
                        break;
                    case BOOLEAN:
                        // 布尔 -> 数字
                        String val = "true".equalsIgnoreCase(token.getValue()) ? "1" : "0";
                        newToken = token.withTypeAndValue(Token.Type.NUMBER, val);
                        break;
                    case STRING:
                        // 字符串 -> 数字（如果可能）或 null
                        newToken = token.withTypeAndValue(Token.Type.NULL, "null");
                        break;
                    case NULL:
                        // null -> 空对象/数组标记
                        newToken = token.withTypeAndValue(Token.Type.STRING, "\"\"");
                        break;
                    default:
                        break;
                }
                
                if (newToken != null) {
                    TokenNode parent = leaf.getParent();
                    if (parent != null) {
                        int idx = parent.getChildren().indexOf(leaf);
                        if (idx >= 0) {
                            parent.replaceChild(idx, TokenNode.createLeaf(newToken));
                        }
                    }
                }
            }
        }
        
        return root;
    }

    /**
     * 关键词替换
     * 将关键字替换为类似但可能导致解析错误的关键字
     */
    public static TokenNode replaceKeywords(TokenNode root, String[][] replacements, 
                                           ThreadLocalRandom rand) {
        List<TokenNode> leaves = root.collectLeaves();
        
        for (TokenNode leaf : leaves) {
            if (leaf.getToken() == null) continue;
            Token token = leaf.getToken();
            
            if (token.getType() == Token.Type.KEYWORD || 
                token.getType() == Token.Type.IDENTIFIER) {
                
                for (String[] pair : replacements) {
                    if (pair.length >= 2 && pair[0].equals(token.getValue())) {
                        if (rand.nextInt(3) == 0) { // 33% 概率替换
                            Token newToken = token.withValue(pair[1]);
                            TokenNode parent = leaf.getParent();
                            if (parent != null) {
                                int idx = parent.getChildren().indexOf(leaf);
                                if (idx >= 0) {
                                    parent.replaceChild(idx, TokenNode.createLeaf(newToken));
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
        
        return root;
    }

    /**
     * 数字边界值变异
     * 将数字替换为边界值（MAX_INT, MIN_INT, 0, -1 等）
     * 注意：Lua 不支持 NaN、Infinity 字面量，需要使用表达式
     */
    public static TokenNode mutateNumbers(TokenNode root, ThreadLocalRandom rand) {
        String[] boundaryValues = {
            "0", "-1", "1", 
            "2147483647", "-2147483648",       // INT32 边界
            "9223372036854775807", "-9223372036854775808", // INT64 边界
            "1.7976931348623157E308",          // Double MAX
            "4.9E-324",                        // Double MIN
            "0/0",                             // NaN (Lua 兼容)
            "math.huge", "-math.huge",         // Infinity (Lua 兼容)
            "1e308",                           // 接近最大值
            "0.0", "-0.0", "0e0"
        };
        
        List<TokenNode> leaves = root.collectLeaves();
        
        for (TokenNode leaf : leaves) {
            if (leaf.getToken() != null && leaf.getToken().getType() == Token.Type.NUMBER) {
                if (rand.nextInt(5) == 0) { // 20% 概率变异
                    String newValue = boundaryValues[rand.nextInt(boundaryValues.length)];
                    Token newToken = leaf.getToken().withValue(newValue);
                    TokenNode parent = leaf.getParent();
                    if (parent != null) {
                        int idx = parent.getChildren().indexOf(leaf);
                        if (idx >= 0) {
                            parent.replaceChild(idx, TokenNode.createLeaf(newToken));
                        }
                    }
                }
            }
        }
        
        return root;
    }

    // === 常用 Payload ===
    
    public static final String[] COMMON_PAYLOADS = {
        "\\x00",           // Null byte
        "\\0",             // Null terminator
        "%s%s%s%s%s",      // Format string
        "%n%n%n%n",        // Format string (write)
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "<script>alert(1)</script>",
        "{{7*7}}",         // Template injection
        "${7*7}",          // Expression injection
        "$(id)",           // Command injection
        "`id`",            // Command injection
        "' OR '1'='1",     // SQL injection
        "\" OR \"1\"=\"1", 
        "\\uD800",         // Lone surrogate
        "\\uDFFF",         // Lone surrogate
        "\r\n\r\n",        // HTTP injection
        "AAAA" + "A".repeat(1000), // Buffer overflow attempt
    };
}
