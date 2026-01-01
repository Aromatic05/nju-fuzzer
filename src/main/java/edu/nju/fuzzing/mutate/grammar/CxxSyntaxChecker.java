package edu.nju.fuzzing.mutate.grammar;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * C++ Mangled Name 语法检查器
 * 
 * 检查 Itanium C++ ABI Name Mangling 的语法正确性：
 * - _Z 前缀存在
 * - N...E 嵌套结构配对
 * - I...E 模板结构配对
 * - 长度前缀与名称实际长度匹配
 * - 替换引用 S<n>_ 在有效范围内
 * - 基础类型编码合法
 * 
 * 这是一个快速检查器，用于验证变异后的 mangled name 基本合法性
 */
public class CxxSyntaxChecker {

    // 有效的基础类型
    private static final String VALID_BASE_TYPES = "vwbcahstijlmxynofdeqz";

    // 有效的修饰符
    private static final String VALID_MODIFIERS = "PROKVUO";

    // 标准替换
    private static final String[] STD_SUBSTITUTIONS = { "St", "Sa", "Sb", "Ss", "Si", "So", "Sd" };

    // 长度-名称模式
    private static final Pattern LENGTH_NAME_PATTERN = Pattern.compile("(\\d+)([a-zA-Z_][a-zA-Z0-9_]*)");

    // 替换模式
    private static final Pattern SUBST_PATTERN = Pattern.compile("S([0-9A-Z]*)_");

    /**
     * 检查结果
     */
    public static class CheckResult {
        public final boolean isValid;
        public final String errorMessage;
        public final int missingNestedE; // 缺少的嵌套 E
        public final int missingTemplateE; // 缺少的模板 E
        public final int extraE; // 多余的 E
        public final boolean hasValidPrefix;
        public final boolean hasLengthMismatch;
        public final boolean hasInvalidSubstitution;
        public final boolean hasNullCharacter;
        public final boolean hasInvalidType;
        public final List<String> lengthMismatches; // 长度不匹配的详情
        public final List<String> invalidSubstitutions; // 无效替换的详情

        public CheckResult(boolean isValid, String errorMessage,
                int missingNestedE, int missingTemplateE, int extraE,
                boolean hasValidPrefix, boolean hasLengthMismatch,
                boolean hasInvalidSubstitution, boolean hasNullCharacter,
                boolean hasInvalidType,
                List<String> lengthMismatches, List<String> invalidSubstitutions) {
            this.isValid = isValid;
            this.errorMessage = errorMessage;
            this.missingNestedE = missingNestedE;
            this.missingTemplateE = missingTemplateE;
            this.extraE = extraE;
            this.hasValidPrefix = hasValidPrefix;
            this.hasLengthMismatch = hasLengthMismatch;
            this.hasInvalidSubstitution = hasInvalidSubstitution;
            this.hasNullCharacter = hasNullCharacter;
            this.hasInvalidType = hasInvalidType;
            this.lengthMismatches = lengthMismatches != null ? lengthMismatches : new ArrayList<>();
            this.invalidSubstitutions = invalidSubstitutions != null ? invalidSubstitutions : new ArrayList<>();
        }

        public static CheckResult valid() {
            return new CheckResult(true, null, 0, 0, 0, true, false, false, false, false, null, null);
        }

        public static CheckResult invalid(String message, int missingNested, int missingTemplate, int extraE,
                boolean validPrefix, boolean lengthMismatch, boolean invalidSubst,
                boolean nullChar, boolean invalidType,
                List<String> lengthDetails, List<String> substDetails) {
            return new CheckResult(false, message, missingNested, missingTemplate, extraE,
                    validPrefix, lengthMismatch, invalidSubst, nullChar, invalidType,
                    lengthDetails, substDetails);
        }

        /**
         * 返回需要添加的 E 数量
         */
        public int getTotalMissingE() {
            return missingNestedE + missingTemplateE;
        }
    }

    /**
     * 检查 mangled name 的语法
     * 
     * @param mangledName 要检查的 mangled name
     * @return 检查结果
     */
    public CheckResult check(String mangledName) {
        if (mangledName == null || mangledName.isEmpty()) {
            return CheckResult.invalid("Empty mangled name", 0, 0, 0, false, false, false, false, false, null, null);
        }

        List<String> errors = new ArrayList<>();
        List<String> lengthMismatches = new ArrayList<>();
        List<String> invalidSubstitutions = new ArrayList<>();

        // 1. 检查前缀
        boolean hasValidPrefix = mangledName.startsWith("_Z");
        if (!hasValidPrefix) {
            errors.add("Missing _Z prefix");
        }

        // 2. 检查 NUL 字符
        boolean hasNullChar = mangledName.contains("\0");
        if (hasNullChar) {
            errors.add("Contains NUL character");
        }

        // 3. 检查 N/E 和 I/E 配对
        NestingResult nesting = checkNesting(mangledName);
        if (nesting.missingNestedE > 0) {
            errors.add("Missing " + nesting.missingNestedE + " nested E");
        }
        if (nesting.missingTemplateE > 0) {
            errors.add("Missing " + nesting.missingTemplateE + " template E");
        }
        if (nesting.extraE > 0) {
            errors.add("Extra " + nesting.extraE + " E");
        }

        // 4. 检查长度-名称匹配
        boolean hasLengthMismatch = !checkLengthNames(mangledName, lengthMismatches);
        if (hasLengthMismatch) {
            errors.add("Length-name mismatch");
        }

        // 5. 检查替换引用
        int substitutionCount = countSubstitutionCandidates(mangledName);
        boolean hasInvalidSubst = !checkSubstitutions(mangledName, substitutionCount, invalidSubstitutions);
        if (hasInvalidSubst) {
            errors.add("Invalid substitution reference");
        }

        // 6. 检查类型编码（简化检查）
        boolean hasInvalidType = false; // 当前不做严格类型检查

        boolean isValid = errors.isEmpty();
        String errorMessage = isValid ? null : String.join("; ", errors);

        return new CheckResult(isValid, errorMessage,
                nesting.missingNestedE, nesting.missingTemplateE, nesting.extraE,
                hasValidPrefix, hasLengthMismatch, hasInvalidSubst, hasNullChar, hasInvalidType,
                lengthMismatches, invalidSubstitutions);
    }

    /**
     * 基于 Token 列表检查语法
     */
    public CheckResult checkTokens(List<Token> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return CheckResult.invalid("Empty token list", 0, 0, 0, false, false, false, false, false, null, null);
        }

        List<String> errors = new ArrayList<>();
        List<String> lengthMismatches = new ArrayList<>();
        List<String> invalidSubstitutions = new ArrayList<>();

        // 1. 检查前缀
        boolean hasValidPrefix = !tokens.isEmpty() && tokens.get(0).getType() == Token.Type.CXX_PREFIX;
        if (!hasValidPrefix) {
            errors.add("Missing _Z prefix");
        }

        // 2. 检查 NUL 字符
        boolean hasNullChar = false;
        for (Token token : tokens) {
            if (token.getValue() != null && token.getValue().contains("\0")) {
                hasNullChar = true;
                errors.add("Contains NUL character");
                break;
            }
        }

        // 3. 检查 N/E 和 I/E 配对
        NestingResult nesting = checkTokenNesting(tokens);
        if (nesting.missingNestedE > 0) {
            errors.add("Missing " + nesting.missingNestedE + " nested E");
        }
        if (nesting.missingTemplateE > 0) {
            errors.add("Missing " + nesting.missingTemplateE + " template E");
        }
        if (nesting.extraE > 0) {
            errors.add("Extra " + nesting.extraE + " E");
        }

        // 4. 检查长度-名称匹配
        boolean hasLengthMismatch = !checkTokenLengthNames(tokens, lengthMismatches);
        if (hasLengthMismatch) {
            errors.add("Length-name mismatch");
        }

        // 5. 检查替换引用
        int substitutionCount = countTokenSubstitutionCandidates(tokens);
        boolean hasInvalidSubst = !checkTokenSubstitutions(tokens, substitutionCount, invalidSubstitutions);
        if (hasInvalidSubst) {
            errors.add("Invalid substitution reference");
        }

        boolean isValid = errors.isEmpty();
        String errorMessage = isValid ? null : String.join("; ", errors);

        return new CheckResult(isValid, errorMessage,
                nesting.missingNestedE, nesting.missingTemplateE, nesting.extraE,
                hasValidPrefix, hasLengthMismatch, hasInvalidSubst, hasNullChar, false,
                lengthMismatches, invalidSubstitutions);
    }

    // === 辅助类 ===

    private static class NestingResult {
        int missingNestedE = 0;
        int missingTemplateE = 0;
        int extraE = 0;
    }

    // === 检查方法 ===

    /**
     * 检查 N/E 和 I/E 嵌套配对
     */
    private NestingResult checkNesting(String mangledName) {
        NestingResult result = new NestingResult();
        Deque<Character> stack = new ArrayDeque<>();

        // 跳过 _Z 前缀
        int start = mangledName.startsWith("_Z") ? 2 : 0;
        int i = start;
        char prevChar = '\0';

        while (i < mangledName.length()) {
            char c = mangledName.charAt(i);

            // 特殊处理构造/析构函数编码: C1, C2, C3, D0, D1, D2
            // 这些后面的数字不是长度前缀
            if ((prevChar == 'C' || prevChar == 'D') && Character.isDigit(c)) {
                prevChar = c;
                i++;
                continue;
            }

            // 跳过长度前缀名称
            if (Character.isDigit(c)) {
                int[] skipResult = skipLengthName(mangledName, i);
                i = skipResult[1];
                prevChar = '\0';
                continue;
            }

            // 跳过替换
            if (c == 'S') {
                i = skipSubstitution(mangledName, i);
                prevChar = '\0';
                continue;
            }

            if (c == 'N') {
                stack.push('N');
            } else if (c == 'I') {
                stack.push('I');
            } else if (c == 'F') {
                // F...E 函数类型编码
                stack.push('F');
            } else if (c == 'E') {
                if (stack.isEmpty()) {
                    result.extraE++;
                } else {
                    char top = stack.pop();
                    // F...E 函数类型的 E 不计入嵌套配对统计
                    // 只检查 N 和 I 的配对
                    if (top == 'F') {
                        // 函数类型正确闭合，不计入错误
                    }
                }
            }

            prevChar = c;
            i++;
        }

        // 统计未闭合的结构
        while (!stack.isEmpty()) {
            char c = stack.pop();
            if (c == 'N') {
                result.missingNestedE++;
            } else if (c == 'I') {
                result.missingTemplateE++;
            }
        }

        return result;
    }

    /**
     * 基于 Token 检查嵌套配对
     */
    private NestingResult checkTokenNesting(List<Token> tokens) {
        NestingResult result = new NestingResult();
        Deque<Character> stack = new ArrayDeque<>();

        for (Token token : tokens) {
            String val = token.getValue();
            if (val == null)
                continue;

            Token.Type type = token.getType();

            if (type == Token.Type.CXX_NESTED && "N".equals(val)) {
                stack.push('N');
            } else if (type == Token.Type.CXX_TEMPLATE && "I".equals(val)) {
                stack.push('I');
            } else if (type == Token.Type.CXX_NESTED && "E".equals(val)) {
                if (stack.isEmpty()) {
                    result.extraE++;
                } else {
                    stack.pop();
                }
            }
        }

        while (!stack.isEmpty()) {
            char c = stack.pop();
            if (c == 'N') {
                result.missingNestedE++;
            } else if (c == 'I') {
                result.missingTemplateE++;
            }
        }

        return result;
    }

    /**
     * 检查长度-名称匹配
     */
    private boolean checkLengthNames(String mangledName, List<String> mismatches) {
        boolean allMatch = true;
        Matcher matcher = LENGTH_NAME_PATTERN.matcher(mangledName);

        while (matcher.find()) {
            String lengthStr = matcher.group(1);
            String name = matcher.group(2);

            try {
                int declaredLen = Integer.parseInt(lengthStr);
                int actualLen = name.length();

                // 只取声明长度的字符
                if (declaredLen > 0 && declaredLen != actualLen) {
                    // 这可能是正常的，因为名称后面可能有其他内容
                    // 只有当声明长度大于实际可用字符时才是错误
                    if (declaredLen > actualLen) {
                        mismatches
                                .add(lengthStr + name + " (declared=" + declaredLen + ", available=" + actualLen + ")");
                        allMatch = false;
                    }
                }
            } catch (NumberFormatException e) {
                // 数字太大
                mismatches.add(lengthStr + " (length overflow)");
                allMatch = false;
            }
        }

        return allMatch;
    }

    /**
     * 基于 Token 检查长度-名称匹配
     */
    private boolean checkTokenLengthNames(List<Token> tokens, List<String> mismatches) {
        boolean allMatch = true;

        for (int i = 0; i < tokens.size() - 1; i++) {
            Token lenToken = tokens.get(i);
            Token nameToken = tokens.get(i + 1);

            if (lenToken.getType() == Token.Type.CXX_LENGTH &&
                    nameToken.getType() == Token.Type.CXX_NAME) {

                try {
                    int declaredLen = Integer.parseInt(lenToken.getValue());
                    String name = nameToken.getValue();
                    int actualLen = name != null ? name.length() : 0;

                    if (declaredLen != actualLen) {
                        mismatches.add(lenToken.getValue() + nameToken.getValue() +
                                " (declared=" + declaredLen + ", actual=" + actualLen + ")");
                        allMatch = false;
                    }
                } catch (NumberFormatException e) {
                    mismatches.add(lenToken.getValue() + " (length overflow)");
                    allMatch = false;
                }
            }
        }

        return allMatch;
    }

    /**
     * 统计替换候选数量（名称和类型）
     */
    private int countSubstitutionCandidates(String mangledName) {
        int count = 0;
        Matcher matcher = LENGTH_NAME_PATTERN.matcher(mangledName);
        while (matcher.find()) {
            count++;
        }
        // 简化：每个模板也算一个候选
        for (int i = 0; i < mangledName.length(); i++) {
            if (mangledName.charAt(i) == 'I')
                count++;
        }
        return Math.max(1, count);
    }

    /**
     * 基于 Token 统计替换候选
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
     * 检查替换引用是否有效
     */
    private boolean checkSubstitutions(String mangledName, int maxSubst, List<String> invalid) {
        boolean allValid = true;
        Matcher matcher = SUBST_PATTERN.matcher(mangledName);

        while (matcher.find()) {
            String seqStr = matcher.group(1);
            if (seqStr.isEmpty()) {
                // S_ 是 S0 的简写，总是有效
                continue;
            }

            try {
                // 替换序号使用 base-36 编码
                int seq = parseBase36(seqStr) + 1;
                if (seq > maxSubst) {
                    invalid.add("S" + seqStr + "_ (seq=" + seq + ", max=" + maxSubst + ")");
                    allValid = false;
                }
            } catch (NumberFormatException e) {
                invalid.add("S" + seqStr + "_ (invalid sequence)");
                allValid = false;
            }
        }

        return allValid;
    }

    /**
     * 基于 Token 检查替换
     */
    private boolean checkTokenSubstitutions(List<Token> tokens, int maxSubst, List<String> invalid) {
        boolean allValid = true;

        for (Token token : tokens) {
            if (token.getType() == Token.Type.CXX_SUBST) {
                String val = token.getValue();
                if (val == null)
                    continue;

                // 标准替换总是有效
                for (String std : STD_SUBSTITUTIONS) {
                    if (val.equals(std)) {
                        continue;
                    }
                }

                Matcher matcher = SUBST_PATTERN.matcher(val);
                if (matcher.matches()) {
                    String seqStr = matcher.group(1);
                    if (!seqStr.isEmpty()) {
                        try {
                            int seq = parseBase36(seqStr) + 1;
                            if (seq > maxSubst) {
                                invalid.add(val + " (seq=" + seq + ", max=" + maxSubst + ")");
                                allValid = false;
                            }
                        } catch (NumberFormatException e) {
                            invalid.add(val + " (invalid sequence)");
                            allValid = false;
                        }
                    }
                }
            }
        }

        return allValid;
    }

    // === 辅助方法 ===

    /**
     * 跳过长度前缀名称，返回 [名称开始位置, 名称结束位置]
     */
    private int[] skipLengthName(String text, int pos) {
        int numStart = pos;
        while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
            pos++;
        }

        if (pos == numStart) {
            return new int[] { numStart, numStart };
        }

        try {
            // 防止数字过长导致溢出，限制最多读取 9 位数字
            String numStr = text.substring(numStart, pos);
            if (numStr.length() > 9) {
                // 超长数字，只跳过数字本身
                return new int[] { numStart, pos };
            }
            int len = Integer.parseInt(numStr);
            // 防止 len 为负数或过大
            if (len < 0 || len > text.length()) {
                return new int[] { numStart, pos };
            }
            int nameEnd = Math.min(pos + len, text.length());
            return new int[] { pos, nameEnd };
        } catch (NumberFormatException e) {
            return new int[] { numStart, pos };
        }
    }

    /**
     * 跳过替换引用
     */
    private int skipSubstitution(String text, int pos) {
        pos++; // 跳过 S
        if (pos >= text.length())
            return pos;

        char c = text.charAt(pos);
        // 标准替换
        if ("tabiods".indexOf(c) >= 0) {
            return pos + 1;
        }
        // S_ 或 S<seq>_
        if (c == '_') {
            return pos + 1;
        }
        while (pos < text.length() && (Character.isDigit(text.charAt(pos)) ||
                (text.charAt(pos) >= 'A' && text.charAt(pos) <= 'Z'))) {
            pos++;
        }
        if (pos < text.length() && text.charAt(pos) == '_') {
            return pos + 1;
        }
        return pos;
    }

    /**
     * 解析 base-36 序号
     */
    private int parseBase36(String s) {
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
     * 快速检查 mangled name 是否基本有效
     */
    public boolean isBasicValid(String mangledName) {
        if (mangledName == null || mangledName.length() < 2) {
            return false;
        }
        if (!mangledName.startsWith("_Z")) {
            return false;
        }
        // 仅有前缀时不视为有效
        if (mangledName.length() <= 2) {
            return false;
        }
        if (mangledName.contains("\0")) {
            return false;
        }

        // 检查嵌套配对
        NestingResult nesting = checkNesting(mangledName);
        return nesting.missingNestedE == 0 && nesting.missingTemplateE == 0 && nesting.extraE == 0;
    }
}
