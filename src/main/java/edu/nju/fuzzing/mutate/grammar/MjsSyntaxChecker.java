package edu.nju.fuzzing.mutate.grammar;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * 轻量级 MJS/JSON 语法检查器
 * 
 * 检查基本的语法结构平衡：
 * - 括号配对 ({}, [], ())
 * - 字符串引号配对 ("", '')
 * - 冒号和逗号的合理使用
 * - 值的基本完整性
 * 
 * 这是一个快速检查器，不做完整的语法分析，仅验证结构平衡性
 */
public class MjsSyntaxChecker {

    /**
     * 语法检查结果
     */
    public static class CheckResult {
        public final boolean isValid;
        public final String errorMessage;
        public final int missingBraceCount;      // 缺少的 }
        public final int missingBracketCount;    // 缺少的 ]
        public final int missingParenCount;      // 缺少的 )
        public final int extraBraceCount;        // 多余的 }
        public final int extraBracketCount;      // 多余的 ]
        public final int extraParenCount;        // 多余的 )
        public final boolean hasUnclosedString;
        public final boolean hasTrailingComma;
        public final boolean hasMissingColon;
        public final boolean hasMissingValue;

        public CheckResult(boolean isValid, String errorMessage,
                          int missingBraceCount, int missingBracketCount, int missingParenCount,
                          int extraBraceCount, int extraBracketCount, int extraParenCount,
                          boolean hasUnclosedString, boolean hasTrailingComma,
                          boolean hasMissingColon, boolean hasMissingValue) {
            this.isValid = isValid;
            this.errorMessage = errorMessage;
            this.missingBraceCount = missingBraceCount;
            this.missingBracketCount = missingBracketCount;
            this.missingParenCount = missingParenCount;
            this.extraBraceCount = extraBraceCount;
            this.extraBracketCount = extraBracketCount;
            this.extraParenCount = extraParenCount;
            this.hasUnclosedString = hasUnclosedString;
            this.hasTrailingComma = hasTrailingComma;
            this.hasMissingColon = hasMissingColon;
            this.hasMissingValue = hasMissingValue;
        }

        public static CheckResult valid() {
            return new CheckResult(true, null, 0, 0, 0, 0, 0, 0, false, false, false, false);
        }

        public static CheckResult invalid(String message,
                                         int missingBrace, int missingBracket, int missingParen,
                                         int extraBrace, int extraBracket, int extraParen,
                                         boolean unclosedString, boolean trailingComma,
                                         boolean missingColon, boolean missingValue) {
            return new CheckResult(false, message,
                    missingBrace, missingBracket, missingParen,
                    extraBrace, extraBracket, extraParen,
                    unclosedString, trailingComma, missingColon, missingValue);
        }
        
        /**
         * 返回需要添加的闭合括号数量
         */
        public int getTotalMissingClose() {
            return missingBraceCount + missingBracketCount + missingParenCount;
        }
        
        /**
         * 返回多余的闭合括号数量
         */
        public int getTotalExtraClose() {
            return extraBraceCount + extraBracketCount + extraParenCount;
        }
    }

    /**
     * 检查代码的语法结构是否平衡
     * 
     * @param code MJS/JSON 代码
     * @return 检查结果
     */
    public CheckResult check(String code) {
        if (code == null || code.isEmpty()) {
            return CheckResult.valid();
        }

        // 移除注释，简化检查
        String stripped = stripComments(code);
        
        // 检查字符串引号配对
        StringCheckResult stringResult = checkStrings(stripped);
        if (stringResult.hasUnclosed) {
            return CheckResult.invalid("Unclosed string", 0, 0, 0, 0, 0, 0, true, false, false, false);
        }

        // 使用移除字符串内容后的代码检查括号
        String noStrings = stringResult.strippedCode;
        
        // 检查括号配对
        BracketBalance balance = checkBrackets(noStrings);

        // 检查结构完整性
        StructureCheck structure = checkStructure(noStrings);

        boolean isValid = balance.missingBrace == 0 && balance.missingBracket == 0 && balance.missingParen == 0 &&
                         balance.extraBrace == 0 && balance.extraBracket == 0 && balance.extraParen == 0 &&
                         !structure.hasTrailingComma && !structure.hasMissingColon && !structure.hasMissingValue;

        if (isValid) {
            return CheckResult.valid();
        }

        StringBuilder errorMsg = new StringBuilder();
        if (balance.missingBrace > 0) errorMsg.append("Missing ").append(balance.missingBrace).append(" '}'. ");
        if (balance.missingBracket > 0) errorMsg.append("Missing ").append(balance.missingBracket).append(" ']'. ");
        if (balance.missingParen > 0) errorMsg.append("Missing ").append(balance.missingParen).append(" ')'. ");
        if (balance.extraBrace > 0) errorMsg.append("Extra ").append(balance.extraBrace).append(" '}'. ");
        if (balance.extraBracket > 0) errorMsg.append("Extra ").append(balance.extraBracket).append(" ']'. ");
        if (balance.extraParen > 0) errorMsg.append("Extra ").append(balance.extraParen).append(" ')'. ");
        if (structure.hasTrailingComma) errorMsg.append("Trailing comma before closing bracket. ");
        if (structure.hasMissingColon) errorMsg.append("Missing ':' in object. ");
        if (structure.hasMissingValue) errorMsg.append("Missing value after ':' or ','. ");

        return CheckResult.invalid(errorMsg.toString().trim(),
                balance.missingBrace, balance.missingBracket, balance.missingParen,
                balance.extraBrace, balance.extraBracket, balance.extraParen,
                false, structure.hasTrailingComma, structure.hasMissingColon, structure.hasMissingValue);
    }

    /**
     * 基于 Token 列表检查语法
     */
    public CheckResult checkTokens(List<Token> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return CheckResult.valid();
        }

        // 检查括号配对
        Deque<Character> stack = new ArrayDeque<>();
        int extraBrace = 0, extraBracket = 0, extraParen = 0;
        boolean hasUnclosedString = false;
        boolean hasTrailingComma = false;
        boolean hasMissingColon = false;
        boolean hasMissingValue = false;

        Token prevSignificant = null;

        for (Token token : tokens) {
            Token.Type type = token.getType();

            // 跳过空白和注释
            if (type == Token.Type.WHITESPACE || type == Token.Type.NEWLINE || type == Token.Type.COMMENT) {
                continue;
            }

            switch (type) {
                case LBRACE:
                    stack.push('{');
                    break;
                case RBRACE:
                    if (!stack.isEmpty() && stack.peek() == '{') {
                        stack.pop();
                    } else {
                        extraBrace++;
                    }
                    // 检查尾随逗号
                    if (prevSignificant != null && prevSignificant.getType() == Token.Type.COMMA) {
                        hasTrailingComma = true;
                    }
                    break;
                case LBRACKET:
                    stack.push('[');
                    break;
                case RBRACKET:
                    if (!stack.isEmpty() && stack.peek() == '[') {
                        stack.pop();
                    } else {
                        extraBracket++;
                    }
                    // 检查尾随逗号
                    if (prevSignificant != null && prevSignificant.getType() == Token.Type.COMMA) {
                        hasTrailingComma = true;
                    }
                    break;
                case LPAREN:
                    stack.push('(');
                    break;
                case RPAREN:
                    if (!stack.isEmpty() && stack.peek() == '(') {
                        stack.pop();
                    } else {
                        extraParen++;
                    }
                    break;
                case STRING:
                    String val = token.getValue();
                    if (val != null && val.length() >= 1) {
                        char quote = val.charAt(0);
                        if ((quote == '"' || quote == '\'') && 
                            (val.length() < 2 || val.charAt(val.length() - 1) != quote)) {
                            hasUnclosedString = true;
                        }
                    }
                    break;
                default:
                    break;
            }

            prevSignificant = token;
        }

        // 统计缺少的括号
        int missingBrace = 0, missingBracket = 0, missingParen = 0;
        while (!stack.isEmpty()) {
            char c = stack.pop();
            switch (c) {
                case '{': missingBrace++; break;
                case '[': missingBracket++; break;
                case '(': missingParen++; break;
            }
        }

        boolean isValid = missingBrace == 0 && missingBracket == 0 && missingParen == 0 &&
                         extraBrace == 0 && extraBracket == 0 && extraParen == 0 &&
                         !hasUnclosedString && !hasTrailingComma;

        if (isValid) {
            return CheckResult.valid();
        }

        StringBuilder errorMsg = new StringBuilder();
        if (missingBrace > 0) errorMsg.append("Missing ").append(missingBrace).append(" '}'. ");
        if (missingBracket > 0) errorMsg.append("Missing ").append(missingBracket).append(" ']'. ");
        if (missingParen > 0) errorMsg.append("Missing ").append(missingParen).append(" ')'. ");
        if (extraBrace > 0) errorMsg.append("Extra ").append(extraBrace).append(" '}'. ");
        if (extraBracket > 0) errorMsg.append("Extra ").append(extraBracket).append(" ']'. ");
        if (extraParen > 0) errorMsg.append("Extra ").append(extraParen).append(" ')'. ");
        if (hasUnclosedString) errorMsg.append("Unclosed string. ");
        if (hasTrailingComma) errorMsg.append("Trailing comma. ");

        return CheckResult.invalid(errorMsg.toString().trim(),
                missingBrace, missingBracket, missingParen,
                extraBrace, extraBracket, extraParen,
                hasUnclosedString, hasTrailingComma, hasMissingColon, hasMissingValue);
    }

    // === 辅助类 ===

    private static class StringCheckResult {
        boolean hasUnclosed;
        String strippedCode;

        StringCheckResult(boolean hasUnclosed, String strippedCode) {
            this.hasUnclosed = hasUnclosed;
            this.strippedCode = strippedCode;
        }
    }

    private static class BracketBalance {
        int missingBrace = 0;
        int missingBracket = 0;
        int missingParen = 0;
        int extraBrace = 0;
        int extraBracket = 0;
        int extraParen = 0;
    }

    private static class StructureCheck {
        boolean hasTrailingComma = false;
        boolean hasMissingColon = false;
        boolean hasMissingValue = false;
    }

    // === 辅助方法 ===

    /**
     * 移除注释 (行注释 // 和 块注释)
     */
    private String stripComments(String code) {
        StringBuilder result = new StringBuilder();
        int len = code.length();
        int i = 0;

        while (i < len) {
            char c = code.charAt(i);

            // 跳过字符串（不处理其中的 //）
            if (c == '"' || c == '\'') {
                int end = skipString(code, i);
                result.append(code, i, end);
                i = end;
                continue;
            }

            // 行注释 //
            if (c == '/' && i + 1 < len && code.charAt(i + 1) == '/') {
                while (i < len && code.charAt(i) != '\n') i++;
                result.append(' ');  // 用空格替代
                continue;
            }

            // 块注释 /* */
            if (c == '/' && i + 1 < len && code.charAt(i + 1) == '*') {
                i += 2;
                while (i + 1 < len) {
                    if (code.charAt(i) == '*' && code.charAt(i + 1) == '/') {
                        i += 2;
                        break;
                    }
                    i++;
                }
                result.append(' ');
                continue;
            }

            result.append(c);
            i++;
        }

        return result.toString();
    }

    /**
     * 检查字符串引号配对，并返回移除字符串内容后的代码
     */
    private StringCheckResult checkStrings(String code) {
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
                        i += 2;  // 跳过转义
                        continue;
                    }
                    if (curr == quote) {
                        result.append(quote);  // 保留引号对
                        i++;
                        closed = true;
                        break;
                    }
                    i++;
                }

                if (!closed) {
                    return new StringCheckResult(true, null);
                }
            } else {
                result.append(c);
                i++;
            }
        }

        return new StringCheckResult(false, result.toString());
    }

    /**
     * 检查括号配对
     */
    private BracketBalance checkBrackets(String code) {
        BracketBalance balance = new BracketBalance();
        Deque<Character> stack = new ArrayDeque<>();

        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);

            switch (c) {
                case '{':
                case '[':
                case '(':
                    stack.push(c);
                    break;
                case '}':
                    if (!stack.isEmpty() && stack.peek() == '{') {
                        stack.pop();
                    } else {
                        balance.extraBrace++;
                    }
                    break;
                case ']':
                    if (!stack.isEmpty() && stack.peek() == '[') {
                        stack.pop();
                    } else {
                        balance.extraBracket++;
                    }
                    break;
                case ')':
                    if (!stack.isEmpty() && stack.peek() == '(') {
                        stack.pop();
                    } else {
                        balance.extraParen++;
                    }
                    break;
            }
        }

        // 统计未闭合的括号
        while (!stack.isEmpty()) {
            char c = stack.pop();
            switch (c) {
                case '{': balance.missingBrace++; break;
                case '[': balance.missingBracket++; break;
                case '(': balance.missingParen++; break;
            }
        }

        return balance;
    }

    /**
     * 检查结构完整性
     */
    private StructureCheck checkStructure(String code) {
        StructureCheck check = new StructureCheck();
        
        // 简化检查：查找尾随逗号模式
        // 模式: , 后面紧跟 } 或 ]（忽略空白）
        String trimmed = code.replaceAll("\\s+", "");
        
        if (trimmed.contains(",}") || trimmed.contains(",]")) {
            check.hasTrailingComma = true;
        }
        
        // 检查缺少冒号：对象中的 "key" "value" 模式（应该是 "key": "value"）
        // 这是一个简化检查
        if (trimmed.matches(".*\"[^\"]*\"\\s*\"[^\"]*\".*")) {
            // 两个连续字符串没有冒号分隔，可能缺少冒号
            // 但这也可能是数组，所以只是一个启发式检查
        }
        
        // 检查冒号后缺少值：": }" 或 ": ]" 或 ": ," 模式
        if (trimmed.contains(":}") || trimmed.contains(":]") || trimmed.contains(":,")) {
            check.hasMissingValue = true;
        }

        return check;
    }

    /**
     * 跳过字符串
     */
    private int skipString(String code, int pos) {
        char quote = code.charAt(pos);
        pos++;
        while (pos < code.length()) {
            char c = code.charAt(pos);
            if (c == '\\' && pos + 1 < code.length()) {
                pos += 2;
                continue;
            }
            if (c == quote) {
                return pos + 1;
            }
            pos++;
        }
        return pos;
    }
}
