package edu.nju.fuzzing.mutate.grammar;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Lua 容错分词器
 * 
 * 识别 Lua 的基本结构：
 * - 关键字: if, then, else, elseif, end, function, local, return, do, while, for, repeat, until, in, and, or, not, nil, true, false, goto, break
 * - 界定符: { } [ ] ( )
 * - 运算符: + - * / % ^ # & | ~ << >> // == ~= <= >= < > = .. ...
 * - 字符串: "...", '...', [[...]], [=[...]=]
 * - 数字: 整数、浮点数、十六进制
 * - 注释: -- 和 --[[ ]]
 * - 标识符
 * 
 * 容错策略：无法识别的字符标记为 UNKNOWN
 */
public class LuaTokenizer implements Tokenizer {

    private static final Set<String> KEYWORDS = new HashSet<>();
    static {
        KEYWORDS.add("and");
        KEYWORDS.add("break");
        KEYWORDS.add("do");
        KEYWORDS.add("else");
        KEYWORDS.add("elseif");
        KEYWORDS.add("end");
        KEYWORDS.add("false");
        KEYWORDS.add("for");
        KEYWORDS.add("function");
        KEYWORDS.add("goto");
        KEYWORDS.add("if");
        KEYWORDS.add("in");
        KEYWORDS.add("local");
        KEYWORDS.add("nil");
        KEYWORDS.add("not");
        KEYWORDS.add("or");
        KEYWORDS.add("repeat");
        KEYWORDS.add("return");
        KEYWORDS.add("then");
        KEYWORDS.add("true");
        KEYWORDS.add("until");
        KEYWORDS.add("while");
    }

    @Override
    public List<Token> tokenize(byte[] input) {
        List<Token> tokens = new ArrayList<>();
        if (input == null || input.length == 0) {
            return tokens;
        }

        String text;
        try {
            text = new String(input, StandardCharsets.UTF_8);
        } catch (Exception e) {
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

            // 注释 -- 或 --[[...]]
            if (c == '-' && pos + 1 < len && text.charAt(pos + 1) == '-') {
                int end;
                if (pos + 2 < len && text.charAt(pos + 2) == '[') {
                    // 可能是长注释 --[[...]] 或 --[=[...]=]
                    int eqCount = countEquals(text, pos + 3);
                    if (pos + 3 + eqCount < len && text.charAt(pos + 3 + eqCount) == '[') {
                        end = scanLongString(text, pos + 2, eqCount);
                    } else {
                        end = scanLineComment(text, pos);
                    }
                } else {
                    end = scanLineComment(text, pos);
                }
                tokens.add(new Token(Token.Type.COMMENT, text.substring(start, end), start, end));
                pos = end;
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
                    // 检查是否是长字符串 [[...]] 或 [=[...]=]
                    int eqCount = countEquals(text, pos + 1);
                    if (pos + 1 + eqCount < len && text.charAt(pos + 1 + eqCount) == '[') {
                        int end = scanLongString(text, pos, eqCount);
                        tokens.add(new Token(Token.Type.STRING, text.substring(start, end), start, end));
                        pos = end;
                        continue;
                    }
                    tokens.add(new Token(Token.Type.LBRACKET, "[", pos, pos + 1));
                    pos++;
                    continue;
                case ']':
                    tokens.add(new Token(Token.Type.RBRACKET, "]", pos, pos + 1));
                    pos++;
                    continue;
                case '(':
                    tokens.add(new Token(Token.Type.LPAREN, "(", pos, pos + 1));
                    pos++;
                    continue;
                case ')':
                    tokens.add(new Token(Token.Type.RPAREN, ")", pos, pos + 1));
                    pos++;
                    continue;
                case ',':
                    tokens.add(new Token(Token.Type.COMMA, ",", pos, pos + 1));
                    pos++;
                    continue;
                case ';':
                    tokens.add(new Token(Token.Type.SEMICOLON, ";", pos, pos + 1));
                    pos++;
                    continue;
            }

            // 标签 ::label::
            if (c == ':' && pos + 1 < len && text.charAt(pos + 1) == ':') {
                int end = pos + 2;
                while (end < len && isIdentChar(text.charAt(end))) {
                    end++;
                }
                if (end + 1 < len && text.charAt(end) == ':' && text.charAt(end + 1) == ':') {
                    end += 2;
                    tokens.add(new Token(Token.Type.KEYWORD, text.substring(start, end), start, end));
                    pos = end;
                    continue;
                }
            }

            // 冒号
            if (c == ':') {
                tokens.add(new Token(Token.Type.COLON, ":", pos, pos + 1));
                pos++;
                continue;
            }

            // 字符串 "..." 或 '...'
            if (c == '"' || c == '\'') {
                int end = scanShortString(text, pos);
                tokens.add(new Token(Token.Type.STRING, text.substring(start, end), start, end));
                pos = end;
                continue;
            }

            // 数字
            if (Character.isDigit(c) || (c == '.' && pos + 1 < len && Character.isDigit(text.charAt(pos + 1)))) {
                int end = scanNumber(text, pos);
                tokens.add(new Token(Token.Type.NUMBER, text.substring(start, end), start, end));
                pos = end;
                continue;
            }

            // 运算符
            int opEnd = scanOperator(text, pos);
            if (opEnd > pos) {
                String op = text.substring(start, opEnd);
                Token.Type type = classifyOperator(op);
                tokens.add(new Token(type, op, start, opEnd));
                pos = opEnd;
                continue;
            }

            // 标识符或关键字
            if (isIdentStartChar(c)) {
                int end = scanIdentifier(text, pos);
                String word = text.substring(start, end);
                Token.Type type = KEYWORDS.contains(word) ? Token.Type.KEYWORD : Token.Type.IDENTIFIER;
                
                // 特殊处理布尔和 nil
                if ("true".equals(word) || "false".equals(word)) {
                    type = Token.Type.BOOLEAN;
                } else if ("nil".equals(word)) {
                    type = Token.Type.NULL;
                }
                
                tokens.add(new Token(type, word, start, end));
                pos = end;
                continue;
            }

            // 无法识别的字符
            tokens.add(new Token(Token.Type.UNKNOWN, String.valueOf(c), pos, pos + 1));
            pos++;
        }

        return tokens;
    }

    // === 辅助方法 ===

    private int skipWhitespace(String text, int pos) {
        while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
            pos++;
        }
        return pos;
    }

    private int scanLineComment(String text, int pos) {
        while (pos < text.length() && text.charAt(pos) != '\n') {
            pos++;
        }
        return pos;
    }

    private int countEquals(String text, int pos) {
        int count = 0;
        while (pos < text.length() && text.charAt(pos) == '=') {
            count++;
            pos++;
        }
        return count;
    }

    private int scanLongString(String text, int pos, int eqCount) {
        // 跳过 [=*[
        pos += 2 + eqCount;
        
        // 寻找匹配的 ]=*]
        String closer = "]" + "=".repeat(eqCount) + "]";
        int closePos = text.indexOf(closer, pos);
        return (closePos >= 0) ? closePos + closer.length() : text.length();
    }

    private int scanShortString(String text, int pos) {
        char quote = text.charAt(pos);
        pos++;
        
        while (pos < text.length()) {
            char c = text.charAt(pos);
            if (c == quote) {
                return pos + 1;
            }
            if (c == '\\' && pos + 1 < text.length()) {
                pos += 2;
                continue;
            }
            if (c == '\n' || c == '\r') {
                // 短字符串不能跨行（除非转义）
                break;
            }
            pos++;
        }
        return pos;
    }

    private int scanNumber(String text, int pos) {
        int len = text.length();
        
        // 十六进制 0x 或 0X
        if (pos + 1 < len && text.charAt(pos) == '0' && 
            (text.charAt(pos + 1) == 'x' || text.charAt(pos + 1) == 'X')) {
            pos += 2;
            while (pos < len && isHexDigit(text.charAt(pos))) {
                pos++;
            }
            // 十六进制小数点
            if (pos < len && text.charAt(pos) == '.') {
                pos++;
                while (pos < len && isHexDigit(text.charAt(pos))) {
                    pos++;
                }
            }
            // 十六进制指数 p/P
            if (pos < len && (text.charAt(pos) == 'p' || text.charAt(pos) == 'P')) {
                pos++;
                if (pos < len && (text.charAt(pos) == '+' || text.charAt(pos) == '-')) {
                    pos++;
                }
                while (pos < len && Character.isDigit(text.charAt(pos))) {
                    pos++;
                }
            }
            return pos;
        }
        
        // 十进制
        while (pos < len && Character.isDigit(text.charAt(pos))) {
            pos++;
        }
        
        // 小数部分
        if (pos < len && text.charAt(pos) == '.') {
            pos++;
            while (pos < len && Character.isDigit(text.charAt(pos))) {
                pos++;
            }
        }
        
        // 指数部分
        if (pos < len && (text.charAt(pos) == 'e' || text.charAt(pos) == 'E')) {
            pos++;
            if (pos < len && (text.charAt(pos) == '+' || text.charAt(pos) == '-')) {
                pos++;
            }
            while (pos < len && Character.isDigit(text.charAt(pos))) {
                pos++;
            }
        }
        
        return pos;
    }

    private int scanOperator(String text, int pos) {
        if (pos >= text.length()) return pos;
        
        char c = text.charAt(pos);
        int len = text.length();
        
        // 三字符运算符
        if (pos + 2 < len) {
            String three = text.substring(pos, pos + 3);
            if ("...".equals(three)) {
                return pos + 3;
            }
        }
        
        // 双字符运算符
        if (pos + 1 < len) {
            String two = text.substring(pos, pos + 2);
            switch (two) {
                case "==":
                case "~=":
                case "<=":
                case ">=":
                case "<<":
                case ">>":
                case "//":
                case "..":
                    return pos + 2;
            }
        }
        
        // 单字符运算符
        switch (c) {
            case '+':
            case '-':
            case '*':
            case '/':
            case '%':
            case '^':
            case '#':
            case '&':
            case '|':
            case '~':
            case '<':
            case '>':
            case '=':
            case '.':
                return pos + 1;
        }
        
        return pos;
    }

    private Token.Type classifyOperator(String op) {
        if ("=".equals(op)) {
            return Token.Type.EQUALS;
        }
        if (".".equals(op)) {
            return Token.Type.DOT;
        }
        return Token.Type.OPERATOR;
    }

    private int scanIdentifier(String text, int pos) {
        while (pos < text.length() && isIdentChar(text.charAt(pos))) {
            pos++;
        }
        return pos;
    }

    private boolean isIdentStartChar(char c) {
        return Character.isLetter(c) || c == '_';
    }

    private boolean isIdentChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }

    private boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}
