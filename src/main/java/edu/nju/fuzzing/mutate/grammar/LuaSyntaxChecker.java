package edu.nju.fuzzing.mutate.grammar;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * 轻量级 Lua 语法检查器
 * 
 * 检查基本的语法结构平衡：
 * - 块结构平衡 (do-end, if-then-end, function-end, while-do-end, for-do-end, repeat-until)
 * - 括号配对 ((), [], {})
 * - 字符串引号配对
 * 
 * 这是一个快速检查器，不做完整的语法分析，仅验证结构平衡性
 */
public class LuaSyntaxChecker {

    /**
     * 语法检查结果
     */
    public static class CheckResult {
        public final boolean isValid;
        public final String errorMessage;
        public final int missingEndCount;
        public final int extraEndCount;
        public final int missingParenCount;    // 缺少的 )
        public final int missingBracketCount;  // 缺少的 ]
        public final int missingBraceCount;    // 缺少的 }
        public final boolean hasUnclosedString;
        public final boolean hasMissingThen;
        public final boolean hasMissingUntil;

        public CheckResult(boolean isValid, String errorMessage, int missingEndCount, int extraEndCount,
                          int missingParenCount, int missingBracketCount, int missingBraceCount,
                          boolean hasUnclosedString, boolean hasMissingThen, boolean hasMissingUntil) {
            this.isValid = isValid;
            this.errorMessage = errorMessage;
            this.missingEndCount = missingEndCount;
            this.extraEndCount = extraEndCount;
            this.missingParenCount = missingParenCount;
            this.missingBracketCount = missingBracketCount;
            this.missingBraceCount = missingBraceCount;
            this.hasUnclosedString = hasUnclosedString;
            this.hasMissingThen = hasMissingThen;
            this.hasMissingUntil = hasMissingUntil;
        }

        public static CheckResult valid() {
            return new CheckResult(true, null, 0, 0, 0, 0, 0, false, false, false);
        }

        public static CheckResult invalid(String message, int missingEnd, int extraEnd,
                                         int missingParen, int missingBracket, int missingBrace,
                                         boolean unclosedString, boolean missingThen, boolean missingUntil) {
            return new CheckResult(false, message, missingEnd, extraEnd,
                    missingParen, missingBracket, missingBrace, unclosedString, missingThen, missingUntil);
        }
    }

    /**
     * 检查代码的语法结构是否平衡
     * 
     * @param code Lua 代码
     * @return 检查结果
     */
    public CheckResult check(String code) {
        if (code == null || code.isEmpty()) {
            return CheckResult.valid();
        }

        // 移除注释和字符串内容，简化检查
        String stripped = stripCommentsAndStrings(code);
        if (stripped == null) {
            // 有未闭合的字符串
            return CheckResult.invalid("Unclosed string", 0, 0, 0, 0, 0, true, false, false);
        }

        // 检查括号配对
        int[] parenBalance = checkParentheses(stripped);
        int missingParen = Math.max(0, parenBalance[0]);
        int missingBracket = Math.max(0, parenBalance[1]);
        int missingBrace = Math.max(0, parenBalance[2]);

        // 检查块结构平衡
        BlockBalance blockBalance = checkBlockBalance(stripped);

        boolean hasMissingThen = blockBalance.unclosedIf > 0;
        boolean hasMissingUntil = blockBalance.unclosedRepeat > 0;

        int missingEnd = blockBalance.missingEnd;
        int extraEnd = blockBalance.extraEnd;

        boolean isValid = missingEnd == 0 && extraEnd == 0 &&
                         missingParen == 0 && missingBracket == 0 && missingBrace == 0 &&
                         !hasMissingThen && !hasMissingUntil;

        if (isValid) {
            return CheckResult.valid();
        }

        StringBuilder errorMsg = new StringBuilder();
        if (missingEnd > 0) errorMsg.append("Missing ").append(missingEnd).append(" 'end'. ");
        if (extraEnd > 0) errorMsg.append("Extra ").append(extraEnd).append(" 'end'. ");
        if (missingParen > 0) errorMsg.append("Missing ").append(missingParen).append(" ')'. ");
        if (missingBracket > 0) errorMsg.append("Missing ").append(missingBracket).append(" ']'. ");
        if (missingBrace > 0) errorMsg.append("Missing ").append(missingBrace).append(" '}'. ");
        if (hasMissingThen) errorMsg.append("Missing 'then' after 'if'. ");
        if (hasMissingUntil) errorMsg.append("Missing 'until' after 'repeat'. ");

        return CheckResult.invalid(errorMsg.toString().trim(), missingEnd, extraEnd,
                missingParen, missingBracket, missingBrace, false, hasMissingThen, hasMissingUntil);
    }

    /**
     * 移除注释和字符串内容，保留结构关键字
     * 
     * @return 处理后的代码，如果有未闭合字符串则返回 null
     */
    private String stripCommentsAndStrings(String code) {
        StringBuilder result = new StringBuilder();
        int len = code.length();
        int i = 0;

        while (i < len) {
            char c = code.charAt(i);

            // 跳过行注释 --
            if (c == '-' && i + 1 < len && code.charAt(i + 1) == '-') {
                // 检查是否是长注释 --[[
                if (i + 2 < len && code.charAt(i + 2) == '[') {
                    int eqCount = countEquals(code, i + 3);
                    if (i + 3 + eqCount < len && code.charAt(i + 3 + eqCount) == '[') {
                        // 长注释，跳过直到找到对应的闭合
                        i = skipLongBracket(code, i + 2, eqCount);
                        continue;
                    }
                }
                // 行注释，跳过到行尾
                while (i < len && code.charAt(i) != '\n') i++;
                continue;
            }

            // 跳过长字符串 [[ 或 [=[
            if (c == '[') {
                int eqCount = countEquals(code, i + 1);
                if (i + 1 + eqCount < len && code.charAt(i + 1 + eqCount) == '[') {
                    int end = skipLongBracket(code, i, eqCount);
                    if (end < 0) return null; // 未闭合
                    result.append(" \"\" "); // 用空字符串占位
                    i = end;
                    continue;
                }
            }

            // 跳过普通字符串 " 或 '
            if (c == '"' || c == '\'') {
                int end = skipString(code, i, c);
                if (end < 0) return null; // 未闭合
                result.append(" \"\" "); // 用空字符串占位
                i = end;
                continue;
            }

            result.append(c);
            i++;
        }

        return result.toString();
    }

    private int countEquals(String code, int pos) {
        int count = 0;
        while (pos + count < code.length() && code.charAt(pos + count) == '=') {
            count++;
        }
        return count;
    }

    private int skipLongBracket(String code, int start, int eqCount) {
        // 从 [=*[ 开始，找到对应的 ]=*]
        int i = start + 2 + eqCount; // 跳过 [=*[
        String closing = "]" + "=".repeat(eqCount) + "]";
        int idx = code.indexOf(closing, i);
        if (idx < 0) return -1;
        return idx + closing.length();
    }

    private int skipString(String code, int start, char quote) {
        int i = start + 1;
        while (i < code.length()) {
            char c = code.charAt(i);
            if (c == '\\') {
                i += 2; // 跳过转义
                continue;
            }
            if (c == quote) {
                return i + 1;
            }
            if (c == '\n') {
                // 普通字符串不能跨行
                return -1;
            }
            i++;
        }
        return -1; // 未闭合
    }

    private int[] checkParentheses(String code) {
        int paren = 0;   // ()
        int bracket = 0; // []
        int brace = 0;   // {}

        for (char c : code.toCharArray()) {
            switch (c) {
                case '(': paren++; break;
                case ')': paren--; break;
                case '[': bracket++; break;
                case ']': bracket--; break;
                case '{': brace++; break;
                case '}': brace--; break;
            }
        }

        return new int[]{paren, bracket, brace};
    }

    private static class BlockBalance {
        int missingEnd = 0;
        int extraEnd = 0;
        int unclosedIf = 0;
        int unclosedRepeat = 0;
    }

    private BlockBalance checkBlockBalance(String code) {
        BlockBalance result = new BlockBalance();
        
        // 使用简单的计数方法
        // 需要 end 的: do, function, if...then, while...do, for...do
        // 需要 until 的: repeat
        
        Deque<String> stack = new ArrayDeque<>();
        
        // 简单的词法分析
        String[] words = code.split("\\s+|(?=[{}()\\[\\];,])|(?<=[{}()\\[\\];,])");
        
        boolean expectThen = false; // 在 if/elseif 后期待 then
        boolean isFirstThenForIf = false; // 标记是否是 if 的第一个 then（需要压栈）
        
        for (String word : words) {
            word = word.trim();
            if (word.isEmpty()) continue;
            
            switch (word) {
                case "do":
                case "function":
                    stack.push("end");
                    expectThen = false;
                    isFirstThenForIf = false;
                    break;
                    
                case "if":
                    expectThen = true;
                    isFirstThenForIf = true; // if 的 then 需要压栈
                    break;
                    
                case "elseif":
                    // elseif 是 if 结构的一部分，不需要额外的 end
                    expectThen = true;
                    isFirstThenForIf = false; // elseif 的 then 不压栈
                    break;
                    
                case "else":
                    // else 也是 if 结构的一部分，不需要额外的 end
                    expectThen = false;
                    isFirstThenForIf = false;
                    break;
                    
                case "then":
                    if (expectThen) {
                        if (isFirstThenForIf) {
                            // 只有 if 后的第一个 then 才压栈
                            stack.push("end");
                        }
                        expectThen = false;
                        isFirstThenForIf = false;
                    }
                    break;
                    
                case "while":
                case "for":
                    // while/for 后面需要 do，do 会处理压栈
                    break;
                    
                case "repeat":
                    stack.push("until");
                    break;
                    
                case "until":
                    if (!stack.isEmpty() && "until".equals(stack.peek())) {
                        stack.pop();
                    }
                    break;
                    
                case "end":
                    if (!stack.isEmpty() && "end".equals(stack.peek())) {
                        stack.pop();
                    } else if (!stack.isEmpty() && "until".equals(stack.peek())) {
                        // 用 end 关闭 repeat？这是错误的
                        result.extraEnd++;
                    } else {
                        result.extraEnd++;
                    }
                    break;
            }
            
            // 检查未闭合的 if (期待 then 但遇到其他关键字)
            if (expectThen && !word.equals("if") && !word.equals("elseif") && 
                !word.equals("then") && isBlockKeyword(word)) {
                result.unclosedIf++;
                expectThen = false;
                isFirstThenForIf = false;
            }
        }
        
        // 栈中剩余的是未闭合的
        for (String remaining : stack) {
            if ("end".equals(remaining)) {
                result.missingEnd++;
            } else if ("until".equals(remaining)) {
                result.unclosedRepeat++;
            }
        }
        
        if (expectThen) {
            result.unclosedIf++;
        }
        
        return result;
    }
    
    private boolean isBlockKeyword(String word) {
        switch (word) {
            case "do":
            case "function":
            case "if":
            case "while":
            case "for":
            case "repeat":
            case "end":
            case "until":
            case "else":
            case "elseif":
                return true;
            default:
                return false;
        }
    }

    /**
     * 使用 Token 列表进行检查（更精确）
     */
    public CheckResult checkTokens(List<Token> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return CheckResult.valid();
        }

        int parenDepth = 0;
        int bracketDepth = 0;
        int braceDepth = 0;
        Deque<String> blockStack = new ArrayDeque<>();
        boolean expectThen = false;
        int unclosedIf = 0;
        int extraEnd = 0;

        for (Token token : tokens) {
            if (token.getType() == Token.Type.WHITESPACE || 
                token.getType() == Token.Type.NEWLINE ||
                token.getType() == Token.Type.COMMENT) {
                continue;
            }

            String value = token.getValue();
            Token.Type type = token.getType();

            // 括号
            if (type == Token.Type.LPAREN) parenDepth++;
            else if (type == Token.Type.RPAREN) parenDepth--;
            else if (type == Token.Type.LBRACKET) bracketDepth++;
            else if (type == Token.Type.RBRACKET) bracketDepth--;
            else if (type == Token.Type.LBRACE) braceDepth++;
            else if (type == Token.Type.RBRACE) braceDepth--;

            // 块关键字
            if (type == Token.Type.KEYWORD) {
                switch (value) {
                    case "do":
                    case "function":
                        blockStack.push("end");
                        expectThen = false;
                        break;
                    case "if":
                        expectThen = true;
                        break;
                    case "elseif":
                        expectThen = true;
                        break;
                    case "then":
                        if (expectThen) {
                            blockStack.push("end");
                            expectThen = false;
                        }
                        break;
                    case "repeat":
                        blockStack.push("until");
                        break;
                    case "until":
                        if (!blockStack.isEmpty() && "until".equals(blockStack.peek())) {
                            blockStack.pop();
                        }
                        break;
                    case "end":
                        if (!blockStack.isEmpty() && "end".equals(blockStack.peek())) {
                            blockStack.pop();
                        } else {
                            extraEnd++;
                        }
                        break;
                }
            }
        }

        int missingEnd = 0;
        int unclosedRepeat = 0;
        for (String remaining : blockStack) {
            if ("end".equals(remaining)) missingEnd++;
            else if ("until".equals(remaining)) unclosedRepeat++;
        }
        if (expectThen) unclosedIf++;

        int missingParen = Math.max(0, parenDepth);
        int missingBracket = Math.max(0, bracketDepth);
        int missingBrace = Math.max(0, braceDepth);

        boolean isValid = missingEnd == 0 && extraEnd == 0 &&
                         missingParen == 0 && missingBracket == 0 && missingBrace == 0 &&
                         unclosedIf == 0 && unclosedRepeat == 0;

        if (isValid) {
            return CheckResult.valid();
        }

        StringBuilder msg = new StringBuilder();
        if (missingEnd > 0) msg.append("Missing ").append(missingEnd).append(" 'end'. ");
        if (extraEnd > 0) msg.append("Extra ").append(extraEnd).append(" 'end'. ");
        if (missingParen > 0) msg.append("Unclosed ").append(missingParen).append(" '('. ");
        if (missingBracket > 0) msg.append("Unclosed ").append(missingBracket).append(" '['. ");
        if (missingBrace > 0) msg.append("Unclosed ").append(missingBrace).append(" '{'. ");
        if (unclosedIf > 0) msg.append("Missing 'then'. ");
        if (unclosedRepeat > 0) msg.append("Missing 'until'. ");

        return CheckResult.invalid(msg.toString().trim(), missingEnd, extraEnd,
                missingParen, missingBracket, missingBrace, false, unclosedIf > 0, unclosedRepeat > 0);
    }
}
