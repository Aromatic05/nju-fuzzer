package edu.nju.fuzzing.mutate.grammar;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * C++ Mangled Name 语法修复器
 * 
 * 自动修复常见的 mangled name 语法问题：
 * - 闭合未配对的 N/E 和 I/E
 * - 同步长度前缀与名称实际长度
 * - 修复替换引用超出范围
 * - 移除非法字符（NUL）
 * - 添加缺失的 _Z 前缀
 * 
 * 设计原则：尽量保持原始结构，最小化修改
 */
public class CxxSyntaxFixer {

    private final CxxSyntaxChecker checker;
    private static final int MAX_FIX_ATTEMPTS = 5;
    
    // 长度-名称模式
    private static final Pattern LENGTH_NAME_PATTERN = Pattern.compile("(\\d+)([a-zA-Z_][a-zA-Z0-9_]*)");
    
    // 替换模式
    private static final Pattern SUBST_PATTERN = Pattern.compile("S([0-9A-Z]+)_");

    public CxxSyntaxFixer() {
        this.checker = new CxxSyntaxChecker();
    }

    public CxxSyntaxFixer(CxxSyntaxChecker checker) {
        this.checker = checker;
    }

    /**
     * 修复 mangled name，返回修复后的结果
     * 
     * @param mangledName 原始 mangled name
     * @return 修复后的 mangled name
     */
    public String fix(String mangledName) {
        if (mangledName == null || mangledName.isEmpty()) {
            return "_Zv";  // 返回最简单的有效 mangled name (void)
        }

        String fixed = mangledName;
        int attempts = 0;

        while (attempts < MAX_FIX_ATTEMPTS) {
            CxxSyntaxChecker.CheckResult result = checker.check(fixed);
            
            if (result.isValid) {
                return fixed;
            }

            String before = fixed;

            // 按优先级修复
            if (!result.hasValidPrefix) {
                fixed = fixPrefix(fixed);
            }

            if (result.hasNullCharacter) {
                fixed = removeNullCharacters(fixed);
            }

            if (result.hasLengthMismatch) {
                fixed = fixLengthNames(fixed);
            }

            if (result.missingNestedE > 0 || result.missingTemplateE > 0) {
                fixed = fixMissingE(fixed, result);
            }

            if (result.extraE > 0) {
                fixed = fixExtraE(fixed);
            }

            if (result.hasInvalidSubstitution) {
                fixed = fixSubstitutions(fixed);
            }

            // 如果没有改变，退出循环
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
            List<Token> result = new ArrayList<>();
            result.add(new Token(Token.Type.CXX_PREFIX, "_Z"));
            result.add(new Token(Token.Type.CXX_TYPE, "v"));
            return result;
        }

        List<Token> fixed = new ArrayList<>(tokens);
        int attempts = 0;

        while (attempts < MAX_FIX_ATTEMPTS) {
            CxxSyntaxChecker.CheckResult result = checker.checkTokens(fixed);
            
            if (result.isValid) {
                return fixed;
            }

            int sizeBefore = fixed.size();

            // 按优先级修复
            if (!result.hasValidPrefix) {
                fixed = fixTokenPrefix(fixed);
            }

            if (result.hasNullCharacter) {
                fixed = removeNullCharacterTokens(fixed);
            }

            if (result.hasLengthMismatch) {
                fixed = fixTokenLengthNames(fixed);
            }

            if (result.missingNestedE > 0 || result.missingTemplateE > 0) {
                fixed = fixTokenMissingE(fixed, result);
            }

            if (result.extraE > 0) {
                fixed = fixTokenExtraE(fixed);
            }

            if (result.hasInvalidSubstitution) {
                fixed = fixTokenSubstitutions(fixed);
            }

            // 如果没有改变，退出循环
            if (fixed.size() == sizeBefore) {
                break;
            }

            attempts++;
        }

        return fixed;
    }

    // === 字符串修复方法 ===

    /**
     * 修复缺失的 _Z 前缀
     */
    private String fixPrefix(String mangledName) {
        if (!mangledName.startsWith("_Z")) {
            if (mangledName.startsWith("_")) {
                return "_Z" + mangledName.substring(1);
            }
            return "_Z" + mangledName;
        }
        return mangledName;
    }

    /**
     * 移除 NUL 字符
     */
    private String removeNullCharacters(String mangledName) {
        return mangledName.replace("\0", "");
    }

    /**
     * 修复长度-名称不匹配
     */
    private String fixLengthNames(String mangledName) {
        StringBuilder result = new StringBuilder();
        int pos = 0;

        while (pos < mangledName.length()) {
            if (Character.isDigit(mangledName.charAt(pos))) {
                // 找到长度前缀
                int numStart = pos;
                while (pos < mangledName.length() && Character.isDigit(mangledName.charAt(pos))) {
                    pos++;
                }
                
                try {
                    int declaredLen = Integer.parseInt(mangledName.substring(numStart, pos));
                    
                    // 提取名称（直到非标识符字符或达到声明长度）
                    int nameStart = pos;
                    int actualLen = 0;
                    
                    while (pos < mangledName.length() && actualLen < declaredLen) {
                        char c = mangledName.charAt(pos);
                        if (!Character.isLetterOrDigit(c) && c != '_') {
                            break;
                        }
                        pos++;
                        actualLen++;
                    }
                    
                    String name = mangledName.substring(nameStart, pos);
                    
                    // 用实际长度替换声明长度
                    if (name.length() > 0) {
                        result.append(name.length());
                        result.append(name);
                    } else {
                        // 空名称，保留原样
                        result.append(mangledName.substring(numStart, pos));
                    }
                    
                } catch (NumberFormatException e) {
                    // 数字溢出，简化处理
                    result.append("4func");
                    while (pos < mangledName.length() && 
                           (Character.isLetterOrDigit(mangledName.charAt(pos)) || 
                            mangledName.charAt(pos) == '_')) {
                        pos++;
                    }
                }
            } else {
                result.append(mangledName.charAt(pos));
                pos++;
            }
        }

        return result.toString();
    }

    /**
     * 修复缺失的 E
     */
    private String fixMissingE(String mangledName, CxxSyntaxChecker.CheckResult checkResult) {
        StringBuilder sb = new StringBuilder(mangledName);
        
        // 在末尾添加缺少的 E
        int totalMissing = checkResult.missingNestedE + checkResult.missingTemplateE;
        for (int i = 0; i < totalMissing; i++) {
            sb.append("E");
        }
        
        return sb.toString();
    }

    /**
     * 修复多余的 E
     */
    private String fixExtraE(String mangledName) {
        StringBuilder result = new StringBuilder();
        Deque<Character> stack = new ArrayDeque<>();

        int pos = 0;
        // 保留前缀
        if (mangledName.startsWith("_Z")) {
            result.append("_Z");
            pos = 2;
        }

        while (pos < mangledName.length()) {
            char c = mangledName.charAt(pos);

            // 跳过长度前缀名称
            if (Character.isDigit(c)) {
                int numStart = pos;
                while (pos < mangledName.length() && Character.isDigit(mangledName.charAt(pos))) {
                    pos++;
                }
                result.append(mangledName.substring(numStart, pos));
                
                // 添加名称
                int numEnd = pos;
                try {
                    int len = Integer.parseInt(mangledName.substring(numStart, numEnd));
                    int nameEnd = Math.min(pos + len, mangledName.length());
                    result.append(mangledName.substring(pos, nameEnd));
                    pos = nameEnd;
                } catch (NumberFormatException e) {
                    // 继续处理
                }
                continue;
            }

            if (c == 'N' || c == 'I') {
                stack.push(c);
                result.append(c);
            } else if (c == 'E') {
                if (!stack.isEmpty()) {
                    stack.pop();
                    result.append(c);
                }
                // 多余的 E 被跳过
            } else {
                result.append(c);
            }

            pos++;
        }

        return result.toString();
    }

    /**
     * 修复无效的替换引用
     */
    private String fixSubstitutions(String mangledName) {
        // 统计替换候选数量
        int maxSubst = countSubstitutionCandidates(mangledName);
        
        StringBuffer result = new StringBuffer();
        Matcher matcher = SUBST_PATTERN.matcher(mangledName);

        while (matcher.find()) {
            String seqStr = matcher.group(1);
            int seq = parseBase36(seqStr);
            
            if (seq >= maxSubst) {
                // 替换为有效的引用
                int validSeq = Math.max(0, maxSubst - 1);
                String replacement = "S" + (validSeq == 0 ? "" : toBase36(validSeq - 1)) + "_";
                matcher.appendReplacement(result, replacement);
            }
        }
        matcher.appendTail(result);

        return result.toString();
    }

    // === Token 修复方法 ===

    /**
     * 修复 Token 前缀
     */
    private List<Token> fixTokenPrefix(List<Token> tokens) {
        List<Token> result = new ArrayList<>();
        
        // 检查第一个是否是前缀
        if (tokens.isEmpty() || tokens.get(0).getType() != Token.Type.CXX_PREFIX) {
            result.add(new Token(Token.Type.CXX_PREFIX, "_Z"));
        }
        result.addAll(tokens);
        return result;
    }

    /**
     * 移除包含 NUL 的 Token
     */
    private List<Token> removeNullCharacterTokens(List<Token> tokens) {
        List<Token> result = new ArrayList<>();
        for (Token token : tokens) {
            String val = token.getValue();
            if (val != null && val.contains("\0")) {
                // 移除 NUL 字符
                result.add(token.withValue(val.replace("\0", "")));
            } else {
                result.add(token);
            }
        }
        return result;
    }

    /**
     * 修复 Token 长度-名称不匹配
     */
    private List<Token> fixTokenLengthNames(List<Token> tokens) {
        List<Token> result = new ArrayList<>();

        for (int i = 0; i < tokens.size(); i++) {
            Token token = tokens.get(i);

            if (token.getType() == Token.Type.CXX_LENGTH && 
                i + 1 < tokens.size() && 
                tokens.get(i + 1).getType() == Token.Type.CXX_NAME) {
                
                Token nameToken = tokens.get(i + 1);
                String name = nameToken.getValue();
                int actualLen = name != null ? name.length() : 0;
                
                // 更新长度以匹配名称
                result.add(token.withValue(String.valueOf(actualLen)));
                result.add(nameToken);
                i++; // 跳过名称 token
            } else {
                result.add(token);
            }
        }

        return result;
    }

    /**
     * 修复 Token 缺失的 E
     */
    private List<Token> fixTokenMissingE(List<Token> tokens, CxxSyntaxChecker.CheckResult result) {
        List<Token> fixed = new ArrayList<>(tokens);
        
        // 分析当前未闭合的结构
        Deque<Character> stack = new ArrayDeque<>();
        for (Token token : tokens) {
            String val = token.getValue();
            if (val == null) continue;
            
            if (token.getType() == Token.Type.CXX_NESTED && "N".equals(val)) {
                stack.push('N');
            } else if (token.getType() == Token.Type.CXX_TEMPLATE && "I".equals(val)) {
                stack.push('I');
            } else if (token.getType() == Token.Type.CXX_NESTED && "E".equals(val)) {
                if (!stack.isEmpty()) {
                    stack.pop();
                }
            }
        }

        // 添加缺失的 E（按正确顺序）
        while (!stack.isEmpty()) {
            stack.pop();
            fixed.add(new Token(Token.Type.CXX_NESTED, "E"));
        }

        return fixed;
    }

    /**
     * 修复 Token 多余的 E
     */
    private List<Token> fixTokenExtraE(List<Token> tokens) {
        List<Token> result = new ArrayList<>();
        Deque<Character> stack = new ArrayDeque<>();

        for (Token token : tokens) {
            String val = token.getValue();
            Token.Type type = token.getType();

            if (type == Token.Type.CXX_NESTED && "N".equals(val)) {
                stack.push('N');
                result.add(token);
            } else if (type == Token.Type.CXX_TEMPLATE && "I".equals(val)) {
                stack.push('I');
                result.add(token);
            } else if (type == Token.Type.CXX_NESTED && "E".equals(val)) {
                if (!stack.isEmpty()) {
                    stack.pop();
                    result.add(token);
                }
                // 多余的 E 被跳过
            } else {
                result.add(token);
            }
        }

        return result;
    }

    /**
     * 修复 Token 无效替换
     */
    private List<Token> fixTokenSubstitutions(List<Token> tokens) {
        // 统计替换候选
        int maxSubst = countTokenSubstitutionCandidates(tokens);
        
        List<Token> result = new ArrayList<>();
        for (Token token : tokens) {
            if (token.getType() == Token.Type.CXX_SUBST) {
                String val = token.getValue();
                if (val != null) {
                    Matcher matcher = SUBST_PATTERN.matcher(val);
                    if (matcher.matches()) {
                        String seqStr = matcher.group(1);
                        int seq = parseBase36(seqStr);
                        
                        if (seq >= maxSubst) {
                            // 替换为有效引用
                            int validSeq = Math.max(0, maxSubst - 1);
                            String replacement = "S" + (validSeq == 0 ? "" : toBase36(validSeq - 1)) + "_";
                            result.add(token.withValue(replacement));
                            continue;
                        }
                    }
                }
            }
            result.add(token);
        }

        return result;
    }

    // === 辅助方法 ===

    /**
     * 统计替换候选数量
     */
    private int countSubstitutionCandidates(String mangledName) {
        int count = 0;
        Matcher matcher = LENGTH_NAME_PATTERN.matcher(mangledName);
        while (matcher.find()) {
            count++;
        }
        for (int i = 0; i < mangledName.length(); i++) {
            if (mangledName.charAt(i) == 'I') count++;
        }
        return Math.max(1, count);
    }

    /**
     * 统计 Token 替换候选
     */
    private int countTokenSubstitutionCandidates(List<Token> tokens) {
        int count = 0;
        for (Token token : tokens) {
            Token.Type type = token.getType();
            if (type == Token.Type.CXX_NAME || type == Token.Type.CXX_TYPE ||
                type == Token.Type.CXX_TEMPLATE) {
                count++;
            }
        }
        return Math.max(1, count);
    }

    /**
     * 解析 base-36 序号
     */
    private int parseBase36(String s) {
        if (s == null || s.isEmpty()) return 0;
        int result = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int digit;
            if (Character.isDigit(c)) {
                digit = c - '0';
            } else {
                digit = c - 'A' + 10;
            }
            result = result * 36 + digit;
        }
        return result;
    }

    /**
     * 转换为 base-36 字符串
     */
    private String toBase36(int n) {
        if (n == 0) return "";
        StringBuilder sb = new StringBuilder();
        while (n > 0) {
            int digit = n % 36;
            if (digit < 10) {
                sb.insert(0, (char)('0' + digit));
            } else {
                sb.insert(0, (char)('A' + digit - 10));
            }
            n /= 36;
        }
        return sb.toString();
    }

    /**
     * 同步更新长度和名称
     * 这是一个工具方法，用于在变异时保持长度-名称同步
     */
    public static void syncLengthName(List<Token> tokens, int lengthIdx, String newName) {
        if (lengthIdx >= 0 && lengthIdx < tokens.size()) {
            tokens.set(lengthIdx, tokens.get(lengthIdx).withValue(String.valueOf(newName.length())));
        }
        if (lengthIdx + 1 < tokens.size()) {
            tokens.set(lengthIdx + 1, tokens.get(lengthIdx + 1).withValue(newName));
        }
    }

    /**
     * 查找所有长度-名称配对的索引
     */
    public static List<int[]> findLengthNamePairs(List<Token> tokens) {
        List<int[]> pairs = new ArrayList<>();
        for (int i = 0; i < tokens.size() - 1; i++) {
            if (tokens.get(i).getType() == Token.Type.CXX_LENGTH &&
                tokens.get(i + 1).getType() == Token.Type.CXX_NAME) {
                pairs.add(new int[]{i, i + 1});
            }
        }
        return pairs;
    }
}
