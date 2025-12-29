package edu.nju.fuzzing.mutate.grammar;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * JSON 容错分词器
 * 
 * 识别 JSON 的基本结构：
 * - 界定符: { } [ ] , :
 * - 字符串: "..." 或 '...'（非标准但常见）
 * - 数字: 整数、浮点数、科学计数法
 * - 关键字: true, false, null
 * - 空白和注释（非标准但某些解析器支持）
 * 
 * 容错策略：无法识别的字符标记为 UNKNOWN，不中断解析
 */
public class JsonTokenizer implements Tokenizer {

    @Override
    public List<Token> tokenize(byte[] input) {
        List<Token> tokens = new ArrayList<>();
        if (input == null || input.length == 0) {
            return tokens;
        }

        String text;
        try {
            // 尝试检测 BOM 并解码
            text = decodeWithBom(input);
        } catch (Exception e) {
            // 解码失败，使用 ISO-8859-1 保留所有字节
            text = new String(input, StandardCharsets.ISO_8859_1);
        }

        int pos = 0;
        int len = text.length();

        while (pos < len) {
            char c = text.charAt(pos);
            int start = pos;

            // 空白
            if (Character.isWhitespace(c)) {
                pos = skipWhitespace(text, pos);
                Token.Type type = (c == '\n' || c == '\r') ? Token.Type.NEWLINE : Token.Type.WHITESPACE;
                tokens.add(new Token(type, text.substring(start, pos), start, pos));
                continue;
            }

            // 界定符
            switch (c) {
                case '{':
                    tokens.add(new Token(Token.Type.LBRACE, "{", pos, pos + 1));
                    pos++;
                    continue;
                case '}':
                    tokens.add(new Token(Token.Type.RBRACE, "}", pos, pos + 1));
                    pos++;
                    continue;
                case '[':
                    tokens.add(new Token(Token.Type.LBRACKET, "[", pos, pos + 1));
                    pos++;
                    continue;
                case ']':
                    tokens.add(new Token(Token.Type.RBRACKET, "]", pos, pos + 1));
                    pos++;
                    continue;
                case ',':
                    tokens.add(new Token(Token.Type.COMMA, ",", pos, pos + 1));
                    pos++;
                    continue;
                case ':':
                    tokens.add(new Token(Token.Type.COLON, ":", pos, pos + 1));
                    pos++;
                    continue;
            }

            // 字符串 ("..." 或 '...')
            if (c == '"' || c == '\'') {
                int end = scanString(text, pos);
                tokens.add(new Token(Token.Type.STRING, text.substring(start, end), start, end));
                pos = end;
                continue;
            }

            // 数字（包括负数）
            if (c == '-' || c == '+' || Character.isDigit(c) || c == '.') {
                int end = scanNumber(text, pos);
                if (end > pos) {
                    tokens.add(new Token(Token.Type.NUMBER, text.substring(start, end), start, end));
                    pos = end;
                    continue;
                }
            }

            // 关键字 (true, false, null) 或标识符
            if (Character.isLetter(c) || c == '_') {
                int end = scanIdentifier(text, pos);
                String word = text.substring(start, end);
                Token.Type type = classifyKeyword(word);
                tokens.add(new Token(type, word, start, end));
                pos = end;
                continue;
            }

            // 注释 (非标准，但某些 JSON 解析器支持)
            if (c == '/') {
                if (pos + 1 < len) {
                    char next = text.charAt(pos + 1);
                    if (next == '/') {
                        // 单行注释
                        int end = scanLineComment(text, pos);
                        tokens.add(new Token(Token.Type.COMMENT, text.substring(start, end), start, end));
                        pos = end;
                        continue;
                    } else if (next == '*') {
                        // 多行注释
                        int end = scanBlockComment(text, pos);
                        tokens.add(new Token(Token.Type.COMMENT, text.substring(start, end), start, end));
                        pos = end;
                        continue;
                    }
                }
            }

            // 无法识别的字符
            tokens.add(new Token(Token.Type.UNKNOWN, String.valueOf(c), pos, pos + 1));
            pos++;
        }

        return tokens;
    }

    // === 辅助扫描方法 ===

    private int skipWhitespace(String text, int pos) {
        while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
            pos++;
        }
        return pos;
    }

    private int scanString(String text, int pos) {
        char quote = text.charAt(pos);
        pos++; // 跳过开始引号
        
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (c == quote) {
                return pos + 1; // 包含结束引号
            }
            if (c == '\\' && pos + 1 < text.length()) {
                pos += 2; // 跳过转义字符
                continue;
            }
            pos++;
        }
        
        return pos; // 未闭合的字符串，返回到末尾
    }

    private int scanNumber(String text, int pos) {
        int start = pos;
        int len = text.length();
        
        // 可选的符号
        if (pos < len && (text.charAt(pos) == '-' || text.charAt(pos) == '+')) {
            pos++;
        }
        
        // 整数部分
        boolean hasDigits = false;
        while (pos < len && Character.isDigit(text.charAt(pos))) {
            pos++;
            hasDigits = true;
        }
        
        // 小数部分
        if (pos < len && text.charAt(pos) == '.') {
            pos++;
            while (pos < len && Character.isDigit(text.charAt(pos))) {
                pos++;
                hasDigits = true;
            }
        }
        
        // 如果没有数字，只有符号或点，返回起始位置
        if (!hasDigits) {
            return start;
        }
        
        // 指数部分
        if (pos < len && (text.charAt(pos) == 'e' || text.charAt(pos) == 'E')) {
            int expStart = pos;
            pos++;
            if (pos < len && (text.charAt(pos) == '-' || text.charAt(pos) == '+')) {
                pos++;
            }
            boolean hasExpDigits = false;
            while (pos < len && Character.isDigit(text.charAt(pos))) {
                pos++;
                hasExpDigits = true;
            }
            if (!hasExpDigits) {
                // 无效的指数，回退
                return expStart;
            }
        }
        
        return pos;
    }

    private int scanIdentifier(String text, int pos) {
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (Character.isLetterOrDigit(c) || c == '_') {
                pos++;
            } else {
                break;
            }
        }
        return pos;
    }

    private int scanLineComment(String text, int pos) {
        while (pos < text.length() && text.charAt(pos) != '\n') {
            pos++;
        }
        return pos;
    }

    private int scanBlockComment(String text, int pos) {
        pos += 2; // 跳过 /*
        while (pos + 1 < text.length()) {
            if (text.charAt(pos) == '*' && text.charAt(pos + 1) == '/') {
                return pos + 2;
            }
            pos++;
        }
        return text.length(); // 未闭合的注释
    }

    private Token.Type classifyKeyword(String word) {
        String lower = word.toLowerCase();
        switch (lower) {
            case "true":
            case "false":
                return Token.Type.BOOLEAN;
            case "null":
                return Token.Type.NULL;
            case "nan":
            case "infinity":
                return Token.Type.NUMBER; // 非标准但常见
            case "undefined":
                return Token.Type.KEYWORD; // JavaScript 混入
            default:
                return Token.Type.IDENTIFIER;
        }
    }

    private String decodeWithBom(byte[] input) {
        // 检测 BOM
        if (input.length >= 3 && 
            (input[0] & 0xFF) == 0xEF && 
            (input[1] & 0xFF) == 0xBB && 
            (input[2] & 0xFF) == 0xBF) {
            // UTF-8 BOM
            return new String(input, 3, input.length - 3, StandardCharsets.UTF_8);
        }
        if (input.length >= 2) {
            if ((input[0] & 0xFF) == 0xFE && (input[1] & 0xFF) == 0xFF) {
                // UTF-16BE BOM
                return new String(input, 2, input.length - 2, StandardCharsets.UTF_16BE);
            }
            if ((input[0] & 0xFF) == 0xFF && (input[1] & 0xFF) == 0xFE) {
                // UTF-16LE BOM
                return new String(input, 2, input.length - 2, StandardCharsets.UTF_16LE);
            }
        }
        // 默认 UTF-8
        return new String(input, StandardCharsets.UTF_8);
    }
}
