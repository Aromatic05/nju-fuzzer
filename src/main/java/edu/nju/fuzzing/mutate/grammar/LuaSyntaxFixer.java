package edu.nju.fuzzing.mutate.grammar;

/**
 * Lua 语义修复后处理器
 * 
 * 自动补全缺失的语法结构，尽可能将变异后的代码修复为合法 Lua 代码：
 * - 自动补全缺失的 end
 * - 自动补全缺失的 then
 * - 自动补全缺失的 until
 * - 自动闭合未闭合的括号 (), [], {}
 * - 自动闭合未闭合的字符串
 * 
 * 这个后处理器与 LuaSyntaxChecker 配合使用
 */
public class LuaSyntaxFixer {

    private final LuaSyntaxChecker checker = new LuaSyntaxChecker();

    /**
     * 修复代码的语法问题
     * 
     * @param code 原始代码
     * @return 修复后的代码
     */
    public String fix(String code) {
        if (code == null || code.isEmpty()) {
            return code;
        }

        // 先检查
        LuaSyntaxChecker.CheckResult result = checker.check(code);
        if (result.isValid) {
            return code;
        }

        StringBuilder fixed = new StringBuilder(code);

        // 1. 修复未闭合的字符串
        if (result.hasUnclosedString) {
            fixed = new StringBuilder(fixUnclosedStrings(fixed.toString()));
        }

        // 2. 修复缺失的 then（在 if/elseif 后）
        if (result.hasMissingThen) {
            fixed = new StringBuilder(fixMissingThen(fixed.toString()));
        }

        // 3. 修复缺失的 until（在 repeat 后）
        if (result.hasMissingUntil) {
            fixed = new StringBuilder(fixMissingUntil(fixed.toString()));
        }

        // 4. 在末尾补全缺失的 end
        if (result.missingEndCount > 0) {
            for (int i = 0; i < result.missingEndCount; i++) {
                fixed.append("\nend");
            }
        }

        // 5. 移除多余的 end（从末尾开始）
        if (result.extraEndCount > 0) {
            String s = fixed.toString();
            for (int i = 0; i < result.extraEndCount; i++) {
                s = removeLastEnd(s);
            }
            fixed = new StringBuilder(s);
        }

        // 6. 补全括号
        if (result.missingParenCount > 0) {
            for (int i = 0; i < result.missingParenCount; i++) {
                fixed.append(")");
            }
        }
        if (result.missingBracketCount > 0) {
            for (int i = 0; i < result.missingBracketCount; i++) {
                fixed.append("]");
            }
        }
        if (result.missingBraceCount > 0) {
            for (int i = 0; i < result.missingBraceCount; i++) {
                fixed.append("}");
            }
        }

        return fixed.toString();
    }

    /**
     * 迭代修复，直到代码合法或达到最大尝试次数
     * 
     * @param code 原始代码
     * @param maxIterations 最大迭代次数
     * @return 修复后的代码
     */
    public String fixIteratively(String code, int maxIterations) {
        String current = code;
        for (int i = 0; i < maxIterations; i++) {
            LuaSyntaxChecker.CheckResult result = checker.check(current);
            if (result.isValid) {
                return current;
            }
            String fixed = fix(current);
            if (fixed.equals(current)) {
                // 无法继续修复
                break;
            }
            current = fixed;
        }
        return current;
    }

    /**
     * 修复未闭合的字符串
     */
    private String fixUnclosedStrings(String code) {
        StringBuilder result = new StringBuilder();
        int len = code.length();
        int i = 0;

        while (i < len) {
            char c = code.charAt(i);

            // 跳过注释
            if (c == '-' && i + 1 < len && code.charAt(i + 1) == '-') {
                int start = i;
                if (i + 2 < len && code.charAt(i + 2) == '[') {
                    int eqCount = countEquals(code, i + 3);
                    if (i + 3 + eqCount < len && code.charAt(i + 3 + eqCount) == '[') {
                        // 长注释
                        int end = findLongBracketEnd(code, i + 2, eqCount);
                        if (end < 0) {
                            // 未闭合的长注释，补全它
                            result.append(code.substring(start));
                            result.append("]").append("=".repeat(eqCount)).append("]");
                            return result.toString();
                        }
                        result.append(code, start, end);
                        i = end;
                        continue;
                    }
                }
                // 行注释，找到行尾
                while (i < len && code.charAt(i) != '\n') {
                    result.append(code.charAt(i));
                    i++;
                }
                continue;
            }

            // 处理长字符串 [[
            if (c == '[') {
                int eqCount = countEquals(code, i + 1);
                if (i + 1 + eqCount < len && code.charAt(i + 1 + eqCount) == '[') {
                    int end = findLongBracketEnd(code, i, eqCount);
                    if (end < 0) {
                        // 未闭合，补全
                        result.append(code.substring(i));
                        result.append("]").append("=".repeat(eqCount)).append("]");
                        return result.toString();
                    }
                    result.append(code, i, end);
                    i = end;
                    continue;
                }
            }

            // 处理普通字符串
            if (c == '"' || c == '\'') {
                int start = i;
                i++;
                while (i < len) {
                    char sc = code.charAt(i);
                    if (sc == '\\' && i + 1 < len) {
                        i += 2;
                        continue;
                    }
                    if (sc == c) {
                        i++;
                        break;
                    }
                    if (sc == '\n') {
                        // 字符串被换行打断，插入闭合引号
                        result.append(code, start, i);
                        result.append(c);
                        break;
                    }
                    i++;
                }
                if (i >= len) {
                    // 到达文件尾，未闭合
                    result.append(code.substring(start));
                    result.append(c);
                    return result.toString();
                }
                result.append(code, start, i);
                continue;
            }

            result.append(c);
            i++;
        }

        return result.toString();
    }

    /**
     * 修复缺失的 then
     * 
     * 在 if/elseif 表达式后如果直接跟语句而不是 then，插入 then
     */
    private String fixMissingThen(String code) {
        // 简化实现：查找 if/elseif 后没有 then 的情况
        // 使用正则替换有风险，这里使用简单的词法分析
        
        StringBuilder result = new StringBuilder();
        String[] tokens = code.split("((?<=\\s)|(?=\\s)|(?<=[{}()\\[\\];,])|(?=[{}()\\[\\];,]))");
        
        boolean needThen = false;
        int parenDepth = 0;
        
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i];
            result.append(token);
            
            if ("if".equals(token.trim()) || "elseif".equals(token.trim())) {
                needThen = true;
                parenDepth = 0;
            } else if (needThen) {
                String trimmed = token.trim();
                if ("(".equals(trimmed)) parenDepth++;
                else if (")".equals(trimmed)) parenDepth--;
                else if ("then".equals(trimmed)) {
                    needThen = false;
                } else if (parenDepth == 0 && isStatementStart(trimmed)) {
                    // 遇到语句开始但没有 then，插入 then
                    result.insert(result.length() - token.length(), " then ");
                    needThen = false;
                }
            }
        }
        
        // 如果文件结尾还需要 then
        if (needThen) {
            result.append(" then true end");
        }
        
        return result.toString();
    }

    /**
     * 修复缺失的 until
     */
    private String fixMissingUntil(String code) {
        // 检查 repeat 后是否有对应的 until
        // 简化处理：在文件末尾添加 until true
        
        int repeatCount = countOccurrences(code, "\\brepeat\\b");
        int untilCount = countOccurrences(code, "\\buntil\\b");
        
        StringBuilder result = new StringBuilder(code);
        int missing = repeatCount - untilCount;
        for (int i = 0; i < missing; i++) {
            result.append("\nuntil true");
        }
        
        return result.toString();
    }

    private int countOccurrences(String text, String regex) {
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(regex);
        java.util.regex.Matcher matcher = pattern.matcher(text);
        int count = 0;
        while (matcher.find()) count++;
        return count;
    }

    private boolean isStatementStart(String token) {
        switch (token) {
            case "local":
            case "function":
            case "if":
            case "while":
            case "for":
            case "repeat":
            case "do":
            case "return":
            case "break":
            case "goto":
                return true;
            default:
                return false;
        }
    }

    private String removeLastEnd(String code) {
        // 从后向前查找最后一个独立的 end 并移除
        int lastEnd = code.lastIndexOf("end");
        if (lastEnd < 0) return code;
        
        // 检查是不是独立的 end（前后是边界或空白）
        boolean validBefore = lastEnd == 0 || !Character.isLetterOrDigit(code.charAt(lastEnd - 1));
        boolean validAfter = lastEnd + 3 >= code.length() || 
                            !Character.isLetterOrDigit(code.charAt(lastEnd + 3));
        
        if (validBefore && validAfter) {
            return code.substring(0, lastEnd) + code.substring(lastEnd + 3);
        }
        
        // 继续向前找
        String prefix = code.substring(0, lastEnd);
        String suffix = code.substring(lastEnd + 3);
        String fixedPrefix = removeLastEnd(prefix);
        if (!fixedPrefix.equals(prefix)) {
            return fixedPrefix + "end" + suffix;
        }
        
        return code;
    }

    private int countEquals(String code, int pos) {
        int count = 0;
        while (pos + count < code.length() && code.charAt(pos + count) == '=') {
            count++;
        }
        return count;
    }

    private int findLongBracketEnd(String code, int start, int eqCount) {
        String closing = "]" + "=".repeat(eqCount) + "]";
        int idx = code.indexOf(closing, start + 2 + eqCount);
        if (idx < 0) return -1;
        return idx + closing.length();
    }

    /**
     * 快速修复常见的语法错误
     * 
     * @param code 原始代码
     * @return 修复后的代码，如果无法修复则返回 null
     */
    public String quickFix(String code) {
        if (code == null) return null;
        
        LuaSyntaxChecker.CheckResult result = checker.check(code);
        if (result.isValid) {
            return code;
        }

        // 只处理简单的修复情况
        // 复杂的错误（如多个问题组合）可能无法正确修复
        int totalIssues = result.missingEndCount + result.extraEndCount +
                         result.missingParenCount + result.missingBracketCount + 
                         result.missingBraceCount +
                         (result.hasMissingThen ? 1 : 0) + (result.hasMissingUntil ? 1 : 0);
        
        if (totalIssues > 5) {
            // 问题太多，放弃修复
            return null;
        }

        return fixIteratively(code, 3);
    }
}
