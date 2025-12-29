package edu.nju.fuzzing.mutate.grammar;

import java.util.List;

/**
 * 容错分词器接口 (Robust Tokenizer)
 * 
 * 设计原则：
 * 1. 绝不抛出异常 - 遇到无法识别的字符标记为 RAW/UNKNOWN
 * 2. 尽可能识别有意义的 Token
 * 3. 保留原始位置信息以便后续定位
 */
public interface Tokenizer {

    /**
     * 将原始字节流切分为 Token 流
     * 
     * @param input 原始字节数组
     * @return Token 列表（绝不为 null，可能为空）
     */
    List<Token> tokenize(byte[] input);

    /**
     * 将字符串输入切分为 Token 流
     * 
     * @param input 字符串输入
     * @return Token 列表
     */
    default List<Token> tokenize(String input) {
        return tokenize(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * 基于 Token 流构建松散的树状结构
     * 
     * 使用栈来根据界定符推断层级：
     * - 遇到开放界定符（如 { [ ( <）入栈，创建新 BLOCK 节点
     * - 遇到闭合界定符（如 } ] ) >）出栈，关闭当前 BLOCK
     * - 其他 Token 作为 LEAF 加入当前节点
     * - 括号不匹配时强制生成"尽可能合理"的树
     * 
     * @param tokens Token 列表
     * @return TokenNode 根节点
     */
    default TokenNode buildTree(List<Token> tokens) {
        return TreeBuilder.build(tokens);
    }

    /**
     * 便捷方法：直接从字节流构建树
     */
    default TokenNode parse(byte[] input) {
        return buildTree(tokenize(input));
    }

    /**
     * 便捷方法：直接从字符串构建树
     */
    default TokenNode parse(String input) {
        return buildTree(tokenize(input));
    }
}
