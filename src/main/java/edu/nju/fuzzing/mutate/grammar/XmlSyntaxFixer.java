package edu.nju.fuzzing.mutate.grammar;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * XML 语法修复器
 * 
 * 自动修复常见的语法问题：
 * - 未闭合的标签（添加缺失的结束标签）
 * - 不匹配的标签（修正标签名）
 * - 属性值中的特殊字符未转义
 * - 未引用的属性值
 * - 注释中的 -- 序列
 * - 未定义的实体引用
 * - 未闭合的 CDATA
 * 
 * 设计原则：尽量保持原始结构，最小化修改
 */
public class XmlSyntaxFixer {

    private final XmlSyntaxChecker checker;
    private static final int MAX_FIX_ATTEMPTS = 5;

    // 预编译的正则表达式
    private static final Pattern COMMENT_PATTERN = Pattern.compile("<!--([^>]*?)-->");
    private static final Pattern UNQUOTED_ATTR_PATTERN = Pattern.compile("(\\s)(\\w+)=([^\"'\\s>][^\\s>]*)");
    private static final Pattern OPEN_TAG_PATTERN = Pattern.compile("<([a-zA-Z][a-zA-Z0-9_:-]*)([^>]*?)(/?)>");
    private static final Pattern CLOSE_TAG_PATTERN = Pattern.compile("</([a-zA-Z][a-zA-Z0-9_:-]*)\\s*>");

    public XmlSyntaxFixer() {
        this.checker = new XmlSyntaxChecker();
    }

    public XmlSyntaxFixer(XmlSyntaxChecker checker) {
        this.checker = checker;
    }

    /**
     * 修复 XML 代码，返回修复后的代码
     * 
     * @param xml 原始 XML
     * @return 修复后的 XML，如果无法修复则返回原代码
     */
    public String fix(String xml) {
        if (xml == null || xml.isEmpty()) {
            return xml;
        }

        String fixed = xml;
        int attempts = 0;

        while (attempts < MAX_FIX_ATTEMPTS) {
            XmlSyntaxChecker.CheckResult result = checker.check(fixed);

            if (result.isValid) {
                return fixed;
            }

            String before = fixed;

            // 按优先级修复
            if (result.hasInvalidComment) {
                fixed = fixInvalidComments(fixed);
            }

            if (result.hasUnquotedAttribute) {
                fixed = fixUnquotedAttributes(fixed);
            }

            if (result.hasUnclosedAttribute) {
                fixed = fixUnclosedAttributes(fixed);
            }

            if (result.hasUnclosedCData) {
                fixed = fixUnclosedCData(fixed);
            }

            if (!result.undefinedEntities.isEmpty()) {
                fixed = fixUndefinedEntities(fixed, result.undefinedEntities);
            }

            if (!result.mismatchedTags.isEmpty()) {
                fixed = fixMismatchedTags(fixed);
            }

            if (!result.unmatchedOpenTags.isEmpty()) {
                fixed = fixUnmatchedOpenTags(fixed, result.unmatchedOpenTags);
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
     */
    public List<Token> fixTokens(List<Token> tokens) {
        if (tokens == null || tokens.isEmpty()) {
            return tokens;
        }

        // 转换为字符串进行修复
        StringBuilder sb = new StringBuilder();
        for (Token token : tokens) {
            if (token.getValue() != null) {
                sb.append(token.getValue());
            }
        }

        String fixed = fix(sb.toString());

        // 重新分词
        XmlTokenizer tokenizer = new XmlTokenizer();
        return tokenizer.tokenize(fixed.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * 转义 XML 属性值中的特殊字符
     */
    public static String escapeXmlAttribute(String value) {
        if (value == null)
            return null;
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    /**
     * 转义 XML 文本中的特殊字符
     */
    public static String escapeXmlText(String value) {
        if (value == null)
            return null;
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    /**
     * 清理注释内容，移除非法的 -- 序列
     */
    public static String sanitizeComment(String content) {
        if (content == null)
            return null;
        // 将 -- 替换为 - -
        return content.replace("--", "- -");
    }

    // ==========================================
    // 修复方法
    // ==========================================

    /**
     * 修复注释中的 -- 序列
     */
    private String fixInvalidComments(String xml) {
        StringBuilder result = new StringBuilder();
        int pos = 0;

        while (pos < xml.length()) {
            int commentStart = xml.indexOf("<!--", pos);
            if (commentStart < 0) {
                result.append(xml.substring(pos));
                break;
            }

            result.append(xml, pos, commentStart);

            int commentEnd = xml.indexOf("-->", commentStart + 4);
            if (commentEnd < 0) {
                // 未闭合的注释，添加结束符
                String content = xml.substring(commentStart + 4);
                result.append("<!--").append(sanitizeComment(content)).append("-->");
                break;
            }

            String content = xml.substring(commentStart + 4, commentEnd);
            result.append("<!--").append(sanitizeComment(content)).append("-->");
            pos = commentEnd + 3;
        }

        return result.toString();
    }

    /**
     * 修复无引号的属性值
     */
    private String fixUnquotedAttributes(String xml) {
        Matcher matcher = UNQUOTED_ATTR_PATTERN.matcher(xml);
        StringBuffer sb = new StringBuffer();

        while (matcher.find()) {
            String ws = matcher.group(1);
            String attrName = matcher.group(2);
            String attrValue = matcher.group(3);
            // 添加引号
            matcher.appendReplacement(sb, ws + attrName + "=\"" + escapeXmlAttribute(attrValue) + "\"");
        }
        matcher.appendTail(sb);

        return sb.toString();
    }

    /**
     * 修复未闭合的属性引号
     */
    private String fixUnclosedAttributes(String xml) {
        StringBuilder result = new StringBuilder();
        int pos = 0;
        int len = xml.length();

        while (pos < len) {
            char c = xml.charAt(pos);

            if (c == '<') {
                int tagEnd = findTagEnd(xml, pos);
                String tag = xml.substring(pos, Math.min(tagEnd + 1, len));
                result.append(fixTagAttributes(tag));
                pos = Math.min(tagEnd + 1, len);
                continue;
            }

            result.append(c);
            pos++;
        }

        return result.toString();
    }

    /**
     * 修复单个标签中的属性问题
     */
    private String fixTagAttributes(String tag) {
        if (!tag.startsWith("<") || tag.startsWith("<!") || tag.startsWith("<?") || tag.startsWith("</")) {
            return tag;
        }

        StringBuilder result = new StringBuilder();
        int pos = 0;
        int len = tag.length();
        boolean inQuote = false;
        char quoteChar = 0;

        while (pos < len) {
            char c = tag.charAt(pos);

            if (inQuote) {
                if (c == quoteChar) {
                    inQuote = false;
                    quoteChar = 0;
                } else if (c == '>' || (c == '/' && pos + 1 < len && tag.charAt(pos + 1) == '>')) {
                    // 在标签结束前引号未闭合
                    result.append(quoteChar);
                    inQuote = false;
                    quoteChar = 0;
                    continue; // 不增加 pos，让外层处理 > 或 />
                }
                result.append(c);
            } else {
                if (c == '"' || c == '\'') {
                    inQuote = true;
                    quoteChar = c;
                }
                result.append(c);
            }
            pos++;
        }

        // 如果到达末尾仍在引号内
        if (inQuote) {
            // 检查最后一个字符是否是 > 或 />
            String res = result.toString();
            if (res.endsWith("/>")) {
                result = new StringBuilder(res.substring(0, res.length() - 2));
                result.append(quoteChar).append("/>");
            } else if (res.endsWith(">")) {
                result = new StringBuilder(res.substring(0, res.length() - 1));
                result.append(quoteChar).append(">");
            } else {
                result.append(quoteChar);
            }
        }

        return result.toString();
    }

    /**
     * 修复未闭合的 CDATA
     */
    private String fixUnclosedCData(String xml) {
        int cdataStart = xml.lastIndexOf("<![CDATA[");
        if (cdataStart < 0) {
            return xml;
        }

        int cdataEnd = xml.indexOf("]]>", cdataStart);
        if (cdataEnd < 0) {
            // 添加闭合
            return xml + "]]>";
        }

        return xml;
    }

    /**
     * 修复未定义的实体引用
     */
    private String fixUndefinedEntities(String xml, List<String> undefinedEntities) {
        String result = xml;
        for (String entity : undefinedEntities) {
            // 将未定义的实体转义
            String escaped = entity.replace("&", "&amp;");
            result = result.replace(entity, escaped);
        }
        return result;
    }

    /**
     * 修复不匹配的标签
     */
    private String fixMismatchedTags(String xml) {
        // 收集所有标签及其位置
        List<TagInfo> tags = collectTags(xml);
        Deque<TagInfo> stack = new ArrayDeque<>();
        List<TagFix> fixes = new ArrayList<>();

        for (TagInfo tag : tags) {
            if (tag.isOpen && !tag.isSelfClosing) {
                stack.push(tag);
            } else if (tag.isClose) {
                if (stack.isEmpty()) {
                    // 多余的结束标签，删除
                    fixes.add(new TagFix(tag.start, tag.end, ""));
                } else {
                    TagInfo openTag = stack.peek();
                    if (openTag.name.equals(tag.name)) {
                        stack.pop();
                    } else {
                        // 不匹配，修改结束标签名
                        fixes.add(new TagFix(tag.start, tag.end, "</" + openTag.name + ">"));
                        stack.pop();
                    }
                }
            }
        }

        // 应用修复（从后往前）
        StringBuilder result = new StringBuilder(xml);
        fixes.sort((a, b) -> b.start - a.start);
        for (TagFix fix : fixes) {
            result.replace(fix.start, fix.end, fix.replacement);
        }

        return result.toString();
    }

    /**
     * 修复未闭合的开始标签
     */
    private String fixUnmatchedOpenTags(String xml, List<String> unmatchedOpenTags) {
        StringBuilder result = new StringBuilder(xml);

        // 在末尾添加缺失的结束标签（逆序添加）
        for (int i = unmatchedOpenTags.size() - 1; i >= 0; i--) {
            String tagName = unmatchedOpenTags.get(i);
            result.append("</").append(tagName).append(">");
        }

        return result.toString();
    }

    // ==========================================
    // 辅助类和方法
    // ==========================================

    private static class TagInfo {
        final String name;
        final int start;
        final int end;
        final boolean isOpen;
        final boolean isClose;
        final boolean isSelfClosing;

        TagInfo(String name, int start, int end, boolean isOpen, boolean isClose, boolean isSelfClosing) {
            this.name = name;
            this.start = start;
            this.end = end;
            this.isOpen = isOpen;
            this.isClose = isClose;
            this.isSelfClosing = isSelfClosing;
        }
    }

    private static class TagFix {
        final int start;
        final int end;
        final String replacement;

        TagFix(int start, int end, String replacement) {
            this.start = start;
            this.end = end;
            this.replacement = replacement;
        }
    }

    private List<TagInfo> collectTags(String xml) {
        List<TagInfo> tags = new ArrayList<>();
        int pos = 0;
        int len = xml.length();

        while (pos < len) {
            int tagStart = xml.indexOf('<', pos);
            if (tagStart < 0)
                break;

            if (tagStart + 1 >= len)
                break;

            char next = xml.charAt(tagStart + 1);

            // 跳过特殊标签
            if (next == '?' || next == '!') {
                pos = skipSpecialTag(xml, tagStart);
                continue;
            }

            // 结束标签
            if (next == '/') {
                int tagEnd = xml.indexOf('>', tagStart);
                if (tagEnd < 0)
                    break;
                String name = extractTagName(xml.substring(tagStart + 2, tagEnd));
                tags.add(new TagInfo(name, tagStart, tagEnd + 1, false, true, false));
                pos = tagEnd + 1;
                continue;
            }

            // 开始标签
            int tagEnd = findTagEnd(xml, tagStart);
            if (tagEnd < 0 || tagEnd >= len)
                break;

            String tagContent = xml.substring(tagStart + 1, tagEnd);
            String name = extractTagName(tagContent);
            boolean isSelfClosing = tagContent.endsWith("/") ||
                    (tagEnd > 0 && tagEnd - 1 >= tagStart && xml.charAt(tagEnd - 1) == '/');

            // 检查标签结束前是否有 /
            if (!isSelfClosing && tagEnd > tagStart) {
                String fullTag = xml.substring(tagStart, tagEnd + 1);
                isSelfClosing = fullTag.endsWith("/>");
            }

            tags.add(new TagInfo(name, tagStart, tagEnd + 1, true, false, isSelfClosing));
            pos = tagEnd + 1;
        }

        return tags;
    }

    private int skipSpecialTag(String xml, int pos) {
        char next = xml.charAt(pos + 1);

        // XML 声明
        if (next == '?') {
            int end = xml.indexOf("?>", pos);
            return (end >= 0) ? end + 2 : xml.length();
        }

        // CDATA
        if (xml.regionMatches(pos, "<![CDATA[", 0, 9)) {
            int end = xml.indexOf("]]>", pos);
            return (end >= 0) ? end + 3 : xml.length();
        }

        // 注释
        if (xml.regionMatches(pos, "<!--", 0, 4)) {
            int end = xml.indexOf("-->", pos);
            return (end >= 0) ? end + 3 : xml.length();
        }

        // DOCTYPE
        if (xml.regionMatches(true, pos, "<!DOCTYPE", 0, 9)) {
            return findDoctypeEnd(xml, pos);
        }

        // 其他 <!...>
        int end = xml.indexOf('>', pos);
        return (end >= 0) ? end + 1 : xml.length();
    }

    private int findTagEnd(String xml, int pos) {
        boolean inQuote = false;
        char quoteChar = 0;
        int len = xml.length();

        for (int i = pos + 1; i < len; i++) {
            char c = xml.charAt(i);

            if (inQuote) {
                if (c == quoteChar) {
                    inQuote = false;
                }
                continue;
            }

            if (c == '"' || c == '\'') {
                inQuote = true;
                quoteChar = c;
            } else if (c == '>') {
                return i;
            }
        }

        return len - 1;
    }

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

    private String extractTagName(String content) {
        if (content == null || content.isEmpty()) {
            return "";
        }
        content = content.trim();
        if (content.startsWith("/")) {
            content = content.substring(1);
        }

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
}
