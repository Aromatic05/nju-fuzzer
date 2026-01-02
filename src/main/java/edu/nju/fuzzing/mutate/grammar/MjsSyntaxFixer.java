package edu.nju.fuzzing.mutate.grammar;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * MJS/JSON 语法修复器
 * 
 * 自动修复常见的语法问题：
 * - 未闭合的字符串引号
 * - 缺少的闭合括号 ({}, [], ())
 * - 多余的闭合括号
 * - 尾随逗号
 * - 缺少逗号分隔
 * - 缺少值
 * 
 * 设计原则：尽量保持原始结构，最小化修改
 */
public class MjsSyntaxFixer {

    private final MjsSyntaxChecker checker;
    private static final int MAX_FIX_ATTEMPTS = 5;

    public MjsSyntaxFixer() {
        this.checker = new MjsSyntaxChecker();
    }

    public MjsSyntaxFixer(MjsSyntaxChecker checker) {
        this.checker = checker;
    }

    /**
     * 修复代码，返回修复后的代码
     * 
     * @param code 原始代码
     * @return 修复后的代码，如果无法修复则返回原代码
     */
    public String fix(String code) {
        if (code == null || code.isEmpty()) {
            return code;
        }

        String fixed = code;
        int attempts = 0;

        while (attempts < MAX_FIX_ATTEMPTS) {
            MjsSyntaxChecker.CheckResult result = checker.check(fixed);
            
            if (result.isValid) {
                return fixed;
            }

            String before = fixed;

            // 按优先级修复
            if (result.hasUnclosedString) {
                fixed = fixUnclosedStrings(fixed);
            }
            
            if (result.extraBraceCount > 0 || result.extraBracketCount > 0 || result.extraParenCount > 0) {
                fixed = fixExtraBrackets(fixed, result);
            }

            if (result.missingBraceCount > 0 || result.missingBracketCount > 0 || result.missingParenCount > 0) {
                fixed = fixMissingBrackets(fixed, result);
            }

            if (result.hasTrailingComma) {
                fixed = fixTrailingCommas(fixed);
            }

            if (result.hasMissingValue) {
                fixed = fixMissingValues(fixed);
            }

            // 如果没有任何改变，退出循环
            if (fixed.equals(before)) {
                break;
            }

            attempts++;
        }

        return fixed;
    }

    /**
     * 基于 Token 列表修复
     * 
     * @param tokens 原始 Token 列表
     * @return 修复后的 Token 列表
     */
    public List<Token> fixTokens(List<Token> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return tokens;
        }

        List<Token> fixed = new ArrayList<>(tokens);
        int attempts = 0;

        while (attempts < MAX_FIX_ATTEMPTS) {
            MjsSyntaxChecker.CheckResult result = checker.checkTokens(fixed);
            
            if (result.isValid) {
                return fixed;
            }

            int sizeBefore = fixed.size();

            // 按优先级修复
            if (result.hasUnclosedString) {
                fixed = fixUnclosedStringTokens(fixed);
            }
            
            if (result.extraBraceCount > 0 || result.extraBracketCount > 0 || result.extraParenCount > 0) {
                fixed = fixExtraBracketTokens(fixed, result);
            }

            if (result.missingBraceCount > 0 || result.missingBracketCount > 0 || result.missingParenCount > 0) {
                fixed = fixMissingBracketTokens(fixed, result);
            }

            if (result.hasTrailingComma) {
                fixed = fixTrailingCommaTokens(fixed);
            }

            // 如果没有任何改变，退出循环
            if (fixed.size() == sizeBefore) {
                break;
            }

            attempts++;
        }

        return fixed;
    }

    // === 字符串修复 ===

    /**
     * 修复未闭合的字符串
     */
    private String fixUnclosedStrings(String code) {
        StringBuilder result = new StringBuilder();
        int len = code.length();
        int i = 0;

        while (i < len) {
            char c = code.charAt(i);

            if (c == '"' || c == '\'') {
                char quote = c;
                result.append(quote);
                i++;
                boolean closed = false;

                while (i < len) {
                    char curr = code.charAt(i);
                    if (curr == '\\' && i + 1 < len) {
                        result.append(curr);
                        result.append(code.charAt(i + 1));
                        i += 2;
                        continue;
                    }
                    if (curr == quote) {
                        result.append(quote);
                        i++;
                        closed = true;
                        break;
                    }
                    // 换行符结束字符串（JavaScript 字符串不能跨行）
                    if (curr == '\n' || curr == '\r') {
                        result.append(quote);  // 在换行前闭合
                        result.append(curr);
                        i++;
                        closed = true;
                        break;
                    }
                    result.append(curr);
                    i++;
                }

                if (!closed) {
                    result.append(quote);  // 在末尾闭合
                }
            } else {
                result.append(c);
                i++;
            }
        }

        return result.toString();
    }

    /**
     * 修复 Token 中未闭合的字符串
     */
    private List<Token> fixUnclosedStringTokens(List<Token> tokens) {
        List<Token> result = new ArrayList<>();

        for (Token token : tokens) {
            if (token.getType() == Token.Type.STRING) {
                String val = token.getValue();
                if (val != null && val.length() >= 1) {
                    char quote = val.charAt(0);
                    if ((quote == '"' || quote == '\'') && 
                        (val.length() < 2 || val.charAt(val.length() - 1) != quote)) {
                        // 添加闭合引号
                        result.add(new Token(Token.Type.STRING, val + quote));
                        continue;
                    }
                }
            }
            result.add(token);
        }

        return result;
    }

    // === 括号修复 ===

    /**
     * 修复缺少的闭合括号
     */
    private String fixMissingBrackets(String code, MjsSyntaxChecker.CheckResult result) {
        StringBuilder sb = new StringBuilder(code);

        // 分析结构找到最佳插入位置
        List<InsertPosition> positions = findBracketInsertPositions(code, result);

        // 从后往前插入，避免位置偏移
        for (int i = positions.size() - 1; i >= 0; i--) {
            InsertPosition pos = positions.get(i);
            sb.insert(pos.position, pos.bracket);
        }

        return sb.toString();
    }

    /**
     * 修复多余的闭合括号
     */
    private String fixExtraBrackets(String code, MjsSyntaxChecker.CheckResult result) {
        StringBuilder sb = new StringBuilder();
        Deque<Character> stack = new ArrayDeque<>();
        int extraBrace = result.extraBraceCount;
        int extraBracket = result.extraBracketCount;
        int extraParen = result.extraParenCount;

        boolean inString = false;
        char stringChar = 0;

        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);

            // 处理字符串
            if (!inString && (c == '"' || c == '\'')) {
                inString = true;
                stringChar = c;
                sb.append(c);
                continue;
            }
            if (inString) {
                if (c == '\\' && i + 1 < code.length()) {
                    sb.append(c);
                    sb.append(code.charAt(i + 1));
                    i++;
                    continue;
                }
                if (c == stringChar) {
                    inString = false;
                }
                sb.append(c);
                continue;
            }

            // 处理括号
            switch (c) {
                case '{':
                case '[':
                case '(':
                    stack.push(c);
                    sb.append(c);
                    break;
                case '}':
                    if (!stack.isEmpty() && stack.peek() == '{') {
                        stack.pop();
                        sb.append(c);
                    } else if (extraBrace > 0) {
                        extraBrace--;  // 跳过多余的括号
                    } else {
                        sb.append(c);
                    }
                    break;
                case ']':
                    if (!stack.isEmpty() && stack.peek() == '[') {
                        stack.pop();
                        sb.append(c);
                    } else if (extraBracket > 0) {
                        extraBracket--;
                    } else {
                        sb.append(c);
                    }
                    break;
                case ')':
                    if (!stack.isEmpty() && stack.peek() == '(') {
                        stack.pop();
                        sb.append(c);
                    } else if (extraParen > 0) {
                        extraParen--;
                    } else {
                        sb.append(c);
                    }
                    break;
                default:
                    sb.append(c);
            }
        }

        return sb.toString();
    }

    /**
     * 修复 Token 中缺少的闭合括号
     */
    private List<Token> fixMissingBracketTokens(List<Token> tokens, MjsSyntaxChecker.CheckResult result) {
        List<Token> fixed = new ArrayList<>(tokens);

        // 在末尾添加缺少的闭合括号（按正确顺序）
        Deque<Character> unclosed = new ArrayDeque<>();
        
        for (Token token : tokens) {
            Token.Type type = token.getType();
            switch (type) {
                case LBRACE:
                    unclosed.push('{');
                    break;
                case RBRACE:
                    if (!unclosed.isEmpty() && unclosed.peek() == '{') {
                        unclosed.pop();
                    }
                    break;
                case LBRACKET:
                    unclosed.push('[');
                    break;
                case RBRACKET:
                    if (!unclosed.isEmpty() && unclosed.peek() == '[') {
                        unclosed.pop();
                    }
                    break;
                case LPAREN:
                    unclosed.push('(');
                    break;
                case RPAREN:
                    if (!unclosed.isEmpty() && unclosed.peek() == '(') {
                        unclosed.pop();
                    }
                    break;
                default:
                    break;
            }
        }

        // 添加闭合括号
        while (!unclosed.isEmpty()) {
            char c = unclosed.pop();
            switch (c) {
                case '{':
                    fixed.add(new Token(Token.Type.RBRACE, "}"));
                    break;
                case '[':
                    fixed.add(new Token(Token.Type.RBRACKET, "]"));
                    break;
                case '(':
                    fixed.add(new Token(Token.Type.RPAREN, ")"));
                    break;
            }
        }

        return fixed;
    }

    /**
     * 修复 Token 中多余的闭合括号
     */
    private List<Token> fixExtraBracketTokens(List<Token> tokens, MjsSyntaxChecker.CheckResult result) {
        List<Token> fixed = new ArrayList<>();
        Deque<Character> stack = new ArrayDeque<>();
        int extraBrace = result.extraBraceCount;
        int extraBracket = result.extraBracketCount;
        int extraParen = result.extraParenCount;

        for (Token token : tokens) {
            Token.Type type = token.getType();

            switch (type) {
                case LBRACE:
                    stack.push('{');
                    fixed.add(token);
                    break;
                case RBRACE:
                    if (!stack.isEmpty() && stack.peek() == '{') {
                        stack.pop();
                        fixed.add(token);
                    } else if (extraBrace > 0) {
                        extraBrace--;  // 跳过
                    } else {
                        fixed.add(token);
                    }
                    break;
                case LBRACKET:
                    stack.push('[');
                    fixed.add(token);
                    break;
                case RBRACKET:
                    if (!stack.isEmpty() && stack.peek() == '[') {
                        stack.pop();
                        fixed.add(token);
                    } else if (extraBracket > 0) {
                        extraBracket--;
                    } else {
                        fixed.add(token);
                    }
                    break;
                case LPAREN:
                    stack.push('(');
                    fixed.add(token);
                    break;
                case RPAREN:
                    if (!stack.isEmpty() && stack.peek() == '(') {
                        stack.pop();
                        fixed.add(token);
                    } else if (extraParen > 0) {
                        extraParen--;
                    } else {
                        fixed.add(token);
                    }
                    break;
                default:
                    fixed.add(token);
            }
        }

        return fixed;
    }

    // === 逗号修复 ===

    /**
     * 修复尾随逗号
     */
    private String fixTrailingCommas(String code) {
        // 移除 ,} 和 ,] 中的逗号（考虑空白）
        String fixed = code;
        
        // 使用正则替换 ", 后跟空白和 } 或 ]" 的模式
        fixed = fixed.replaceAll(",\\s*}", "}");
        fixed = fixed.replaceAll(",\\s*]", "]");
        
        return fixed;
    }

    /**
     * 修复 Token 中的尾随逗号
     */
    private List<Token> fixTrailingCommaTokens(List<Token> tokens) {
        List<Token> fixed = new ArrayList<>();
        
        for (int i = 0; i < tokens.size(); i++) {
            Token token = tokens.get(i);
            
            if (token.getType() == Token.Type.COMMA) {
                // 查找下一个有意义的 token
                Token nextSignificant = null;
                for (int j = i + 1; j < tokens.size(); j++) {
                    Token next = tokens.get(j);
                    if (next.getType() != Token.Type.WHITESPACE && 
                        next.getType() != Token.Type.NEWLINE &&
                        next.getType() != Token.Type.COMMENT) {
                        nextSignificant = next;
                        break;
                    }
                }
                
                // 如果下一个有意义的 token 是闭合括号，跳过这个逗号
                if (nextSignificant != null && 
                    (nextSignificant.getType() == Token.Type.RBRACE || 
                     nextSignificant.getType() == Token.Type.RBRACKET ||
                     nextSignificant.getType() == Token.Type.RPAREN)) {
                    continue;  // 跳过尾随逗号
                }
            }
            
            fixed.add(token);
        }
        
        return fixed;
    }

    // === 缺失值修复 ===

    /**
     * 修复缺失的值
     */
    private String fixMissingValues(String code) {
        // 修复 ":}" -> ":null}"
        // 修复 ":]" -> ":null]"
        // 修复 ":," -> ":null,"
        String fixed = code;
        
        fixed = fixed.replaceAll(":\\s*}", ": null}");
        fixed = fixed.replaceAll(":\\s*]", ": null]");
        fixed = fixed.replaceAll(":\\s*,", ": null,");
        
        return fixed;
    }

    // === 辅助方法 ===

    private static class InsertPosition implements Comparable<InsertPosition> {
        int position;
        char bracket;

        InsertPosition(int position, char bracket) {
            this.position = position;
            this.bracket = bracket;
        }

        @Override
        public int compareTo(InsertPosition other) {
            return Integer.compare(this.position, other.position);
        }
    }

    /**
     * 分析代码结构，找到括号的最佳插入位置
     */
    private List<InsertPosition> findBracketInsertPositions(String code, MjsSyntaxChecker.CheckResult result) {
        List<InsertPosition> positions = new ArrayList<>();
        Deque<BracketInfo> stack = new ArrayDeque<>();

        boolean inString = false;
        char stringChar = 0;

        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);

            // 处理字符串
            if (!inString && (c == '"' || c == '\'')) {
                inString = true;
                stringChar = c;
                continue;
            }
            if (inString) {
                if (c == '\\' && i + 1 < code.length()) {
                    i++;
                    continue;
                }
                if (c == stringChar) {
                    inString = false;
                }
                continue;
            }

            // 记录括号位置
            switch (c) {
                case '{':
                case '[':
                case '(':
                    stack.push(new BracketInfo(c, i));
                    break;
                case '}':
                case ']':
                case ')':
                    if (!stack.isEmpty()) {
                        BracketInfo info = stack.peek();
                        if ((info.bracket == '{' && c == '}') ||
                            (info.bracket == '[' && c == ']') ||
                            (info.bracket == '(' && c == ')')) {
                            stack.pop();
                        }
                    }
                    break;
            }
        }

        // 为每个未闭合的括号在末尾添加闭合
        int insertPos = code.length();
        
        // 先按位置排序，然后逆序闭合
        List<BracketInfo> unclosed = new ArrayList<>(stack);
        
        for (BracketInfo info : unclosed) {
            char close = info.bracket == '{' ? '}' : (info.bracket == '[' ? ']' : ')');
            positions.add(new InsertPosition(insertPos, close));
        }

        return positions;
    }

    private static class BracketInfo {
        char bracket;
        int position;

        BracketInfo(char bracket, int position) {
            this.bracket = bracket;
            this.position = position;
        }
    }

    /**
     * 快速检查并修复简单问题
     * 
     * @param code 原始代码
     * @return 修复后的代码
     */
    public String quickFix(String code) {
        if (code == null || code.isEmpty()) {
            return code;
        }

        String fixed = code.trim();

        // 确保以有效的 JSON/MJS 结构开始
        if (!fixed.startsWith("{") && !fixed.startsWith("[") && 
            !fixed.startsWith("\"") && !fixed.startsWith("'") &&
            !fixed.matches("^\\d.*") && !fixed.startsWith("true") && 
            !fixed.startsWith("false") && !fixed.startsWith("null")) {
            // 可能是无效的开始，尝试包装成对象
            if (fixed.contains(":")) {
                fixed = "{" + fixed + "}";
            }
        }

        return fix(fixed);
    }
}
