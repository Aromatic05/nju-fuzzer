package edu.nju.fuzzing.mutate.grammar;

import java.util.*;

/**
 * 轻量级 XML 语法检查器
 * 
 * 检查基本的语法结构：
 * - 标签配对 (开始标签与结束标签匹配)
 * - 属性引号配对 ("" 或 '')
 * - 注释合法性 (不包含 --)
 * - 实体引用合法性
 * - CDATA 结构完整性
 * - 编码声明与实际编码一致性
 * 
 * 这是一个快速检查器，验证 XML well-formedness
 */
public class XmlSyntaxChecker {

    /**
     * 语法检查结果
     */
    public static class CheckResult {
        public final boolean isValid;
        public final String errorMessage;
        public final int unmatchedOpenTagCount; // 未闭合的开始标签数
        public final int unmatchedCloseTagCount; // 多余的结束标签数
        public final List<String> unmatchedOpenTags; // 未闭合的开始标签名
        public final List<String> mismatchedTags; // 不匹配的标签对
        public final boolean hasUnclosedAttribute; // 属性引号未闭合
        public final boolean hasInvalidComment; // 注释包含 --
        public final boolean hasInvalidEntity; // 无效的实体引用
        public final boolean hasUnclosedCData; // CDATA 未闭合
        public final boolean hasUnquotedAttribute; // 属性值无引号
        public final boolean hasEncodingMismatch; // 编码声明不匹配
        public final List<String> undefinedEntities; // 未定义的实体

        public CheckResult(boolean isValid, String errorMessage,
                int unmatchedOpenTagCount, int unmatchedCloseTagCount,
                List<String> unmatchedOpenTags, List<String> mismatchedTags,
                boolean hasUnclosedAttribute, boolean hasInvalidComment,
                boolean hasInvalidEntity, boolean hasUnclosedCData,
                boolean hasUnquotedAttribute, boolean hasEncodingMismatch,
                List<String> undefinedEntities) {
            this.isValid = isValid;
            this.errorMessage = errorMessage;
            this.unmatchedOpenTagCount = unmatchedOpenTagCount;
            this.unmatchedCloseTagCount = unmatchedCloseTagCount;
            this.unmatchedOpenTags = unmatchedOpenTags != null ? unmatchedOpenTags : new ArrayList<>();
            this.mismatchedTags = mismatchedTags != null ? mismatchedTags : new ArrayList<>();
            this.hasUnclosedAttribute = hasUnclosedAttribute;
            this.hasInvalidComment = hasInvalidComment;
            this.hasInvalidEntity = hasInvalidEntity;
            this.hasUnclosedCData = hasUnclosedCData;
            this.hasUnquotedAttribute = hasUnquotedAttribute;
            this.hasEncodingMismatch = hasEncodingMismatch;
            this.undefinedEntities = undefinedEntities != null ? undefinedEntities : new ArrayList<>();
        }

        public static CheckResult valid() {
            return new CheckResult(true, null, 0, 0,
                    new ArrayList<>(), new ArrayList<>(),
                    false, false, false, false, false, false,
                    new ArrayList<>());
        }

        public static CheckResult invalid(String message,
                int unmatchedOpen, int unmatchedClose,
                List<String> openTags, List<String> mismatched,
                boolean unclosedAttr, boolean invalidComment,
                boolean invalidEntity, boolean unclosedCData,
                boolean unquotedAttr, boolean encodingMismatch,
                List<String> undefinedEntities) {
            return new CheckResult(false, message,
                    unmatchedOpen, unmatchedClose, openTags, mismatched,
                    unclosedAttr, invalidComment, invalidEntity, unclosedCData,
                    unquotedAttr, encodingMismatch, undefinedEntities);
        }

        /**
         * 返回所有问题的总数
         */
        public int getTotalIssueCount() {
            int count = unmatchedOpenTagCount + unmatchedCloseTagCount + mismatchedTags.size();
            if (hasUnclosedAttribute)
                count++;
            if (hasInvalidComment)
                count++;
            if (hasInvalidEntity)
                count++;
            if (hasUnclosedCData)
                count++;
            if (hasUnquotedAttribute)
                count++;
            if (hasEncodingMismatch)
                count++;
            count += undefinedEntities.size();
            return count;
        }
    }

    // XML 内置实体
    private static final Set<String> BUILTIN_ENTITIES = new HashSet<>(Arrays.asList(
            "amp", "lt", "gt", "apos", "quot"));

    /**
     * 检查 XML 代码的语法结构
     * 
     * @param xml XML 代码
     * @return 检查结果
     */
    public CheckResult check(String xml) {
        if (xml == null || xml.isEmpty()) {
            return CheckResult.valid();
        }

        Deque<String> tagStack = new ArrayDeque<>();
        List<String> unmatchedOpenTags = new ArrayList<>();
        List<String> mismatchedTags = new ArrayList<>();
        List<String> undefinedEntities = new ArrayList<>();
        Set<String> definedEntities = new HashSet<>(BUILTIN_ENTITIES);

        boolean hasUnclosedAttribute = false;
        boolean hasInvalidComment = false;
        boolean hasInvalidEntity = false;
        boolean hasUnclosedCData = false;
        boolean hasUnquotedAttribute = false;
        boolean hasEncodingMismatch = false;

        int pos = 0;
        int len = xml.length();

        // 检测声明的编码
        String declaredEncoding = null;
        int xmlDeclEnd = xml.indexOf("?>");
        if (xml.startsWith("<?xml") && xmlDeclEnd > 0) {
            String decl = xml.substring(0, xmlDeclEnd);
            int encIdx = decl.indexOf("encoding");
            if (encIdx > 0) {
                int eqIdx = decl.indexOf('=', encIdx);
                if (eqIdx > 0) {
                    int quoteStart = eqIdx + 1;
                    while (quoteStart < decl.length() && Character.isWhitespace(decl.charAt(quoteStart))) {
                        quoteStart++;
                    }
                    if (quoteStart < decl.length()) {
                        char quote = decl.charAt(quoteStart);
                        if (quote == '"' || quote == '\'') {
                            int quoteEnd = decl.indexOf(quote, quoteStart + 1);
                            if (quoteEnd > quoteStart) {
                                declaredEncoding = decl.substring(quoteStart + 1, quoteEnd);
                            }
                        }
                    }
                }
            }
        }

        // 收集 DOCTYPE 中定义的实体
        int doctypeStart = xml.indexOf("<!DOCTYPE");
        if (doctypeStart >= 0) {
            int doctypeEnd = findDoctypeEnd(xml, doctypeStart);
            String doctypeContent = xml.substring(doctypeStart, doctypeEnd);
            collectDefinedEntities(doctypeContent, definedEntities);
        }

        while (pos < len) {
            char c = xml.charAt(pos);

            // 处理 < 开头的各种结构
            if (c == '<') {
                if (pos + 1 >= len) {
                    pos++;
                    continue;
                }

                char next = xml.charAt(pos + 1);

                // XML 声明 <?xml ... ?>
                if (next == '?') {
                    int end = xml.indexOf("?>", pos);
                    if (end < 0) {
                        // 未闭合的 XML 声明，但不是致命错误
                    }
                    pos = (end >= 0) ? end + 2 : len;
                    continue;
                }

                // DOCTYPE
                if (next == '!' && xml.regionMatches(true, pos, "<!DOCTYPE", 0, 9)) {
                    pos = findDoctypeEnd(xml, pos);
                    continue;
                }

                // CDATA
                if (next == '!' && xml.regionMatches(pos, "<![CDATA[", 0, 9)) {
                    int end = xml.indexOf("]]>", pos);
                    if (end < 0) {
                        hasUnclosedCData = true;
                        pos = len;
                    } else {
                        pos = end + 3;
                    }
                    continue;
                }

                // 注释
                if (next == '!' && xml.regionMatches(pos, "<!--", 0, 4)) {
                    int end = xml.indexOf("-->", pos + 4);
                    if (end >= 0) {
                        String comment = xml.substring(pos + 4, end);
                        // 检查注释内容是否包含 --
                        if (comment.contains("--")) {
                            hasInvalidComment = true;
                        }
                        pos = end + 3;
                    } else {
                        hasInvalidComment = true;
                        pos = len;
                    }
                    continue;
                }

                // 结束标签
                if (next == '/') {
                    int tagEnd = xml.indexOf('>', pos);
                    if (tagEnd < 0) {
                        pos = len;
                        continue;
                    }
                    String tagContent = xml.substring(pos + 2, tagEnd).trim();
                    String tagName = extractTagName(tagContent);

                    if (tagStack.isEmpty()) {
                        mismatchedTags.add("Unexpected close tag: </" + tagName + ">");
                    } else {
                        String expected = tagStack.peek();
                        if (tagName.equals(expected)) {
                            tagStack.pop();
                        } else {
                            // 标签不匹配
                            mismatchedTags.add("Expected </" + expected + ">, got </" + tagName + ">");
                            // 尝试找到匹配的开始标签
                            if (tagStack.contains(tagName)) {
                                while (!tagStack.isEmpty() && !tagStack.peek().equals(tagName)) {
                                    unmatchedOpenTags.add(tagStack.pop());
                                }
                                if (!tagStack.isEmpty()) {
                                    tagStack.pop();
                                }
                            }
                        }
                    }
                    pos = tagEnd + 1;
                    continue;
                }

                // 开始标签
                int[] tagResult = parseOpenTag(xml, pos);
                int tagEnd = tagResult[0];
                boolean isSelfClosing = tagResult[1] == 1;
                boolean hasAttrIssue = tagResult[2] == 1;
                boolean hasUnquoted = tagResult[3] == 1;

                if (hasAttrIssue) {
                    hasUnclosedAttribute = true;
                }
                if (hasUnquoted) {
                    hasUnquotedAttribute = true;
                }

                String tagContent = xml.substring(pos + 1, Math.min(tagEnd, len));
                String tagName = extractTagName(tagContent);

                if (!isSelfClosing && !tagName.isEmpty()) {
                    tagStack.push(tagName);
                }

                pos = Math.min(tagEnd + 1, len);
                continue;
            }

            // 实体引用
            if (c == '&') {
                int semiPos = xml.indexOf(';', pos);
                if (semiPos > pos && semiPos - pos < 20) {
                    String entityRef = xml.substring(pos + 1, semiPos);
                    if (entityRef.startsWith("#")) {
                        // 数字实体引用，检查格式
                        if (entityRef.startsWith("#x") || entityRef.startsWith("#X")) {
                            // 十六进制
                            String hex = entityRef.substring(2);
                            if (!hex.matches("[0-9a-fA-F]+")) {
                                hasInvalidEntity = true;
                            } else {
                                try {
                                    int code = Integer.parseInt(hex, 16);
                                    // XML 1.0 禁止的字符 (除了 #x9, #xA, #xD)
                                    if (code == 0) {
                                        hasInvalidEntity = true;
                                    }
                                } catch (NumberFormatException e) {
                                    hasInvalidEntity = true;
                                }
                            }
                        } else {
                            // 十进制
                            String dec = entityRef.substring(1);
                            if (!dec.matches("[0-9]+")) {
                                hasInvalidEntity = true;
                            } else {
                                try {
                                    int code = Integer.parseInt(dec);
                                    if (code == 0) {
                                        hasInvalidEntity = true;
                                    }
                                } catch (NumberFormatException e) {
                                    hasInvalidEntity = true;
                                }
                            }
                        }
                    } else {
                        // 命名实体引用
                        if (!definedEntities.contains(entityRef)) {
                            undefinedEntities.add("&" + entityRef + ";");
                        }
                    }
                    pos = semiPos + 1;
                    continue;
                }
            }

            pos++;
        }

        // 检查未闭合的标签
        while (!tagStack.isEmpty()) {
            unmatchedOpenTags.add(tagStack.pop());
        }

        // 汇总结果
        boolean isValid = unmatchedOpenTags.isEmpty()
                && mismatchedTags.isEmpty()
                && !hasUnclosedAttribute
                && !hasInvalidComment
                && !hasInvalidEntity
                && !hasUnclosedCData
                && !hasUnquotedAttribute
                && !hasEncodingMismatch
                && undefinedEntities.isEmpty();

        if (isValid) {
            return CheckResult.valid();
        }

        StringBuilder errMsg = new StringBuilder();
        if (!unmatchedOpenTags.isEmpty()) {
            errMsg.append("Unclosed tags: ").append(unmatchedOpenTags).append("; ");
        }
        if (!mismatchedTags.isEmpty()) {
            errMsg.append("Mismatched tags: ").append(mismatchedTags).append("; ");
        }
        if (hasUnclosedAttribute)
            errMsg.append("Unclosed attribute quote; ");
        if (hasInvalidComment)
            errMsg.append("Invalid comment (contains --); ");
        if (hasInvalidEntity)
            errMsg.append("Invalid entity reference; ");
        if (hasUnclosedCData)
            errMsg.append("Unclosed CDATA section; ");
        if (hasUnquotedAttribute)
            errMsg.append("Unquoted attribute value; ");
        if (!undefinedEntities.isEmpty()) {
            errMsg.append("Undefined entities: ").append(undefinedEntities).append("; ");
        }

        return CheckResult.invalid(errMsg.toString(),
                unmatchedOpenTags.size(), mismatchedTags.size(),
                unmatchedOpenTags, mismatchedTags,
                hasUnclosedAttribute, hasInvalidComment,
                hasInvalidEntity, hasUnclosedCData,
                hasUnquotedAttribute, hasEncodingMismatch,
                undefinedEntities);
    }

    /**
     * 检查 Token 列表
     */
    public CheckResult checkTokens(List<Token> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return CheckResult.valid();
        }
        StringBuilder sb = new StringBuilder();
        for (Token token : tokens) {
            if (token.getValue() != null) {
                sb.append(token.getValue());
            }
        }
        return check(sb.toString());
    }

    /**
     * 解析开始标签，返回 [endPos, isSelfClosing, hasAttrIssue, hasUnquoted]
     */
    private int[] parseOpenTag(String xml, int pos) {
        int len = xml.length();
        pos++; // 跳过 <

        boolean isSelfClosing = false;
        boolean hasAttrIssue = false;
        boolean hasUnquoted = false;
        boolean inAttrValue = false;
        char attrQuote = 0;

        while (pos < len) {
            char c = xml.charAt(pos);

            if (inAttrValue) {
                if (c == attrQuote) {
                    inAttrValue = false;
                    attrQuote = 0;
                }
                pos++;
                continue;
            }

            if (c == '"' || c == '\'') {
                inAttrValue = true;
                attrQuote = c;
                pos++;
                continue;
            }

            if (c == '/' && pos + 1 < len && xml.charAt(pos + 1) == '>') {
                isSelfClosing = true;
                return new int[] { pos + 1, 1, hasAttrIssue ? 1 : 0, hasUnquoted ? 1 : 0 };
            }

            if (c == '>') {
                if (inAttrValue) {
                    hasAttrIssue = true;
                }
                return new int[] { pos, isSelfClosing ? 1 : 0, hasAttrIssue ? 1 : 0, hasUnquoted ? 1 : 0 };
            }

            // 检测无引号的属性值
            if (c == '=') {
                int nextPos = pos + 1;
                while (nextPos < len && Character.isWhitespace(xml.charAt(nextPos))) {
                    nextPos++;
                }
                if (nextPos < len) {
                    char nextChar = xml.charAt(nextPos);
                    if (nextChar != '"' && nextChar != '\'' && nextChar != '>' && nextChar != '/') {
                        hasUnquoted = true;
                    }
                }
            }

            pos++;
        }

        // 未闭合的标签
        if (inAttrValue) {
            hasAttrIssue = true;
        }
        return new int[] { len - 1, isSelfClosing ? 1 : 0, hasAttrIssue ? 1 : 0, hasUnquoted ? 1 : 0 };
    }

    /**
     * 从标签内容中提取标签名
     */
    private String extractTagName(String tagContent) {
        if (tagContent == null || tagContent.isEmpty()) {
            return "";
        }
        // 去除开头可能的 /
        String content = tagContent.trim();
        if (content.startsWith("/")) {
            content = content.substring(1);
        }

        // 提取标签名（到空格或 / 或 > 为止）
        int end = 0;
        while (end < content.length()) {
            char c = content.charAt(end);
            if (Character.isWhitespace(c) || c == '/' || c == '>') {
                break;
            }
            end++;
        }
        return content.substring(0, end);
    }

    /**
     * 查找 DOCTYPE 结束位置
     */
    private int findDoctypeEnd(String xml, int pos) {
        int depth = 0;
        boolean inString = false;
        char stringChar = 0;
        int len = xml.length();

        for (int i = pos; i < len; i++) {
            char c = xml.charAt(i);

            if (inString) {
                if (c == stringChar)
                    inString = false;
                continue;
            }

            if (c == '"' || c == '\'') {
                inString = true;
                stringChar = c;
            } else if (c == '[') {
                depth++;
            } else if (c == ']') {
                depth--;
            } else if (c == '>' && depth == 0) {
                return i + 1;
            }
        }
        return len;
    }

    /**
     * 从 DOCTYPE 中收集定义的实体
     */
    private void collectDefinedEntities(String doctype, Set<String> entities) {
        int pos = 0;
        while (true) {
            int entityIdx = doctype.indexOf("<!ENTITY", pos);
            if (entityIdx < 0)
                break;

            int nameStart = entityIdx + 8;
            while (nameStart < doctype.length() && Character.isWhitespace(doctype.charAt(nameStart))) {
                nameStart++;
            }

            // 跳过参数实体 (%)
            if (nameStart < doctype.length() && doctype.charAt(nameStart) == '%') {
                nameStart++;
                while (nameStart < doctype.length() && Character.isWhitespace(doctype.charAt(nameStart))) {
                    nameStart++;
                }
            }

            int nameEnd = nameStart;
            while (nameEnd < doctype.length() && !Character.isWhitespace(doctype.charAt(nameEnd))) {
                nameEnd++;
            }

            if (nameEnd > nameStart) {
                entities.add(doctype.substring(nameStart, nameEnd));
            }

            pos = nameEnd;
        }
    }
}
