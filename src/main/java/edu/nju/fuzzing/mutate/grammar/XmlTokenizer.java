package edu.nju.fuzzing.mutate.grammar;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * XML 容错分词器
 * 
 * 识别 XML 的基本结构：
 * - XML 声明: <?xml ... ?>
 * - DOCTYPE: <!DOCTYPE ...>
 * - CDATA: <![CDATA[ ... ]]>
 * - 注释: <!-- ... -->
 * - 标签: <tag>, </tag>, <tag/>
 * - 属性: name="value"
 * - 实体引用: &xxx;
 * - 文本内容
 * 
 * 容错策略：无法识别的内容标记为 RAW/UNKNOWN
 */
public class XmlTokenizer implements Tokenizer {

    @Override
    public List<Token> tokenize(byte[] input) {
        List<Token> tokens = new ArrayList<>();
        if (input == null || input.length == 0) {
            return tokens;
        }

        String text;
        try {
            text = decodeWithBom(input);
        } catch (Exception e) {
            text = new String(input, StandardCharsets.ISO_8859_1);
        }

        int pos = 0;
        int len = text.length();

        while (pos < len) {
            char c = text.charAt(pos);
            int start = pos;

            // 处理 < 开头的各种结构
            if (c == '<') {
                if (pos + 1 < len) {
                    char next = text.charAt(pos + 1);

                    // XML 声明 <?xml ... ?>
                    if (next == '?' && text.regionMatches(true, pos, "<?xml", 0, 5)) {
                        int end = scanXmlDecl(text, pos);
                        tokens.add(new Token(Token.Type.XML_DECL, text.substring(start, end), start, end));
                        pos = end;
                        continue;
                    }

                    // 处理指令 <?...?>
                    if (next == '?') {
                        int end = scanPI(text, pos);
                        tokens.add(new Token(Token.Type.XML_DECL, text.substring(start, end), start, end));
                        pos = end;
                        continue;
                    }

                    // DOCTYPE <!DOCTYPE ...>
                    if (next == '!' && text.regionMatches(true, pos, "<!DOCTYPE", 0, 9)) {
                        int end = scanDoctype(text, pos);
                        tokens.add(new Token(Token.Type.XML_DOCTYPE, text.substring(start, end), start, end));
                        pos = end;
                        continue;
                    }

                    // CDATA <![CDATA[ ... ]]>
                    if (next == '!' && text.regionMatches(pos, "<![CDATA[", 0, 9)) {
                        int end = scanCData(text, pos);
                        tokens.add(new Token(Token.Type.XML_CDATA, text.substring(start, end), start, end));
                        pos = end;
                        continue;
                    }

                    // 注释 <!-- ... -->
                    if (next == '!' && text.regionMatches(pos, "<!--", 0, 4)) {
                        int end = scanComment(text, pos);
                        tokens.add(new Token(Token.Type.COMMENT, text.substring(start, end), start, end));
                        pos = end;
                        continue;
                    }

                    // 闭合标签 </tag>
                    if (next == '/') {
                        int end = scanCloseTag(text, pos);
                        tokens.add(new Token(Token.Type.XML_TAG_CLOSE, text.substring(start, end), start, end));
                        pos = end;
                        continue;
                    }
                }

                // 开放标签 <tag ...>
                int[] tagEnd = scanOpenTag(text, pos, tokens);
                pos = tagEnd[0];
                continue;
            }

            // 实体引用 &xxx;
            if (c == '&') {
                int end = scanEntity(text, pos);
                if (end > pos + 1) {
                    tokens.add(new Token(Token.Type.XML_ENTITY, text.substring(start, end), start, end));
                    pos = end;
                    continue;
                }
            }

            // 空白
            if (Character.isWhitespace(c)) {
                pos = skipWhitespace(text, pos);
                Token.Type type = (c == '\n' || c == '\r') ? Token.Type.NEWLINE : Token.Type.WHITESPACE;
                tokens.add(new Token(type, text.substring(start, pos), start, pos));
                continue;
            }

            // 文本内容（直到下一个 < 或 &）
            int end = scanText(text, pos);
            if (end > pos) {
                tokens.add(new Token(Token.Type.XML_TEXT, text.substring(start, end), start, end));
                pos = end;
                continue;
            }

            // 无法识别的字符
            tokens.add(new Token(Token.Type.UNKNOWN, String.valueOf(c), pos, pos + 1));
            pos++;
        }

        return tokens;
    }

    // === 扫描方法 ===

    private int scanXmlDecl(String text, int pos) {
        int end = text.indexOf("?>", pos);
        return (end >= 0) ? end + 2 : text.length();
    }

    private int scanPI(String text, int pos) {
        int end = text.indexOf("?>", pos);
        return (end >= 0) ? end + 2 : text.length();
    }

    private int scanDoctype(String text, int pos) {
        int depth = 0;
        boolean inString = false;
        char stringChar = 0;

        for (int i = pos; i < text.length(); i++) {
            char c = text.charAt(i);
            
            if (inString) {
                if (c == stringChar) inString = false;
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
        return text.length();
    }

    private int scanCData(String text, int pos) {
        int end = text.indexOf("]]>", pos);
        return (end >= 0) ? end + 3 : text.length();
    }

    private int scanComment(String text, int pos) {
        int end = text.indexOf("-->", pos);
        return (end >= 0) ? end + 3 : text.length();
    }

    private int scanCloseTag(String text, int pos) {
        int end = text.indexOf('>', pos);
        return (end >= 0) ? end + 1 : text.length();
    }

    /**
     * 扫描开放标签，同时提取属性
     * @return [endPos] 
     */
    private int[] scanOpenTag(String text, int pos, List<Token> tokens) {
        int start = pos;
        pos++; // 跳过 <

        // 提取标签名
        int nameStart = pos;
        while (pos < text.length() && isNameChar(text.charAt(pos))) {
            pos++;
        }
        String tagName = text.substring(nameStart, pos);
        
        // 添加开放标签 token
        StringBuilder tagBuilder = new StringBuilder("<").append(tagName);

        // 扫描属性和结束
        while (pos < text.length()) {
            char c = text.charAt(pos);

            // 空白
            if (Character.isWhitespace(c)) {
                int wsEnd = skipWhitespace(text, pos);
                tagBuilder.append(text, pos, wsEnd);
                pos = wsEnd;
                continue;
            }

            // 自闭合 />
            if (c == '/' && pos + 1 < text.length() && text.charAt(pos + 1) == '>') {
                tagBuilder.append("/>");
                tokens.add(new Token(Token.Type.XML_TAG_OPEN, tagBuilder.toString(), start, pos + 2));
                return new int[]{pos + 2};
            }

            // 标签结束 >
            if (c == '>') {
                tagBuilder.append(">");
                tokens.add(new Token(Token.Type.XML_TAG_OPEN, tagBuilder.toString(), start, pos + 1));
                return new int[]{pos + 1};
            }

            // 属性名
            if (isNameStartChar(c)) {
                int attrNameStart = pos;
                while (pos < text.length() && isNameChar(text.charAt(pos))) {
                    pos++;
                }
                String attrName = text.substring(attrNameStart, pos);
                tagBuilder.append(attrName);

                // 跳过空白
                while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
                    tagBuilder.append(text.charAt(pos));
                    pos++;
                }

                // = 号
                if (pos < text.length() && text.charAt(pos) == '=') {
                    tagBuilder.append('=');
                    pos++;

                    // 跳过空白
                    while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
                        tagBuilder.append(text.charAt(pos));
                        pos++;
                    }

                    // 属性值
                    if (pos < text.length()) {
                        char quote = text.charAt(pos);
                        if (quote == '"' || quote == '\'') {
                            int valueEnd = scanQuotedValue(text, pos);
                            tagBuilder.append(text, pos, valueEnd);
                            pos = valueEnd;
                        } else {
                            // 无引号的属性值
                            int valueEnd = scanUnquotedValue(text, pos);
                            tagBuilder.append(text, pos, valueEnd);
                            pos = valueEnd;
                        }
                    }
                }
                continue;
            }

            // 无法识别的字符，追加并继续
            tagBuilder.append(c);
            pos++;
        }

        // 未闭合的标签
        tokens.add(new Token(Token.Type.XML_TAG_OPEN, tagBuilder.toString(), start, pos));
        return new int[]{pos};
    }

    private int scanQuotedValue(String text, int pos) {
        char quote = text.charAt(pos);
        pos++; // 跳过开始引号
        while (pos < text.length()) {
            if (text.charAt(pos) == quote) {
                return pos + 1;
            }
            pos++;
        }
        return pos;
    }

    private int scanUnquotedValue(String text, int pos) {
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (Character.isWhitespace(c) || c == '>' || c == '/') {
                break;
            }
            pos++;
        }
        return pos;
    }

    private int scanEntity(String text, int pos) {
        pos++; // 跳过 &
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (c == ';') {
                return pos + 1;
            }
            if (!Character.isLetterOrDigit(c) && c != '#') {
                break;
            }
            pos++;
        }
        return pos;
    }

    private int scanText(String text, int pos) {
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (c == '<' || c == '&') {
                break;
            }
            pos++;
        }
        return pos;
    }

    private int skipWhitespace(String text, int pos) {
        while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
            pos++;
        }
        return pos;
    }

    private boolean isNameStartChar(char c) {
        return Character.isLetter(c) || c == '_' || c == ':';
    }

    private boolean isNameChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == ':' || c == '-' || c == '.';
    }

    private String decodeWithBom(byte[] input) {
        if (input.length >= 3 && 
            (input[0] & 0xFF) == 0xEF && 
            (input[1] & 0xFF) == 0xBB && 
            (input[2] & 0xFF) == 0xBF) {
            return new String(input, 3, input.length - 3, StandardCharsets.UTF_8);
        }
        if (input.length >= 2) {
            if ((input[0] & 0xFF) == 0xFE && (input[1] & 0xFF) == 0xFF) {
                return new String(input, 2, input.length - 2, StandardCharsets.UTF_16BE);
            }
            if ((input[0] & 0xFF) == 0xFF && (input[1] & 0xFF) == 0xFE) {
                return new String(input, 2, input.length - 2, StandardCharsets.UTF_16LE);
            }
        }
        return new String(input, StandardCharsets.UTF_8);
    }
}
