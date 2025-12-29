package edu.nju.fuzzing.mutate.grammar;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * C++ Mangled Name 容错分词器
 * 
 * 识别 Itanium C++ ABI Name Mangling 的结构：
 * - 前缀: _Z
 * - 嵌套名称: N...E
 * - 模板: I...E
 * - 类型: 基础类型(i, l, d...)、修饰符(P, R, K...)
 * - 替换: S_, S0_, S1_...
 * - 操作符: nw, na, dl, pl...
 * - 长度+名称: 4main, 6printf...
 * 
 * 容错策略：无法识别的字符标记为 UNKNOWN
 */
public class CxxTokenizer implements Tokenizer {

    // 基础类型编码
    private static final String BASE_TYPES = "vwbcahstijlmxynofdeqz";
    
    // 修饰符
    private static final String MODIFIERS = "PROKVUO";

    @Override
    public List<Token> tokenize(byte[] input) {
        List<Token> tokens = new ArrayList<>();
        if (input == null || input.length == 0) {
            return tokens;
        }

        String text;
        try {
            text = new String(input, StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            text = new String(input, StandardCharsets.US_ASCII);
        }

        int pos = 0;
        int len = text.length();

        // 检查 _Z 前缀
        if (len >= 2 && text.charAt(0) == '_' && text.charAt(1) == 'Z') {
            tokens.add(new Token(Token.Type.CXX_PREFIX, "_Z", 0, 2));
            pos = 2;
        }

        while (pos < len) {
            char c = text.charAt(pos);
            int start = pos;

            // 嵌套名称开始 N
            if (c == 'N') {
                tokens.add(new Token(Token.Type.CXX_NESTED, "N", pos, pos + 1));
                pos++;
                continue;
            }

            // 嵌套/模板结束 E
            if (c == 'E') {
                tokens.add(new Token(Token.Type.CXX_NESTED, "E", pos, pos + 1));
                pos++;
                continue;
            }

            // 模板开始 I
            if (c == 'I') {
                tokens.add(new Token(Token.Type.CXX_TEMPLATE, "I", pos, pos + 1));
                pos++;
                continue;
            }

            // 替换 S_, S0_, S1_...
            if (c == 'S') {
                int end = scanSubstitution(text, pos);
                tokens.add(new Token(Token.Type.CXX_SUBST, text.substring(start, end), start, end));
                pos = end;
                continue;
            }

            // 修饰符
            if (MODIFIERS.indexOf(c) >= 0) {
                tokens.add(new Token(Token.Type.CXX_MODIFIER, String.valueOf(c), pos, pos + 1));
                pos++;
                continue;
            }

            // 数组类型 A
            if (c == 'A') {
                int end = scanArrayType(text, pos);
                tokens.add(new Token(Token.Type.CXX_TYPE, text.substring(start, end), start, end));
                pos = end;
                continue;
            }

            // 函数类型 F...E
            if (c == 'F') {
                tokens.add(new Token(Token.Type.CXX_TYPE, "F", pos, pos + 1));
                pos++;
                continue;
            }

            // 扩展类型 D (Da, Dc, Dd, Df, Dh, Di, Dn, Ds)
            if (c == 'D') {
                int end = scanExtendedType(text, pos);
                tokens.add(new Token(Token.Type.CXX_TYPE, text.substring(start, end), start, end));
                pos = end;
                continue;
            }

            // Decltype Dt...E 或 DT...E
            if (c == 'D' && pos + 1 < len && (text.charAt(pos + 1) == 't' || text.charAt(pos + 1) == 'T')) {
                tokens.add(new Token(Token.Type.CXX_TYPE, "Dt", pos, pos + 2));
                pos += 2;
                continue;
            }

            // 基础类型 (单字符)
            if (BASE_TYPES.indexOf(Character.toLowerCase(c)) >= 0) {
                tokens.add(new Token(Token.Type.CXX_TYPE, String.valueOf(c), pos, pos + 1));
                pos++;
                continue;
            }

            // 长度前缀 + 名称 (如 4main, 6printf)
            if (Character.isDigit(c)) {
                int[] result = scanLengthPrefixedName(text, pos);
                int numEnd = result[0];
                int nameEnd = result[1];
                
                if (numEnd > pos) {
                    // 添加长度 token
                    tokens.add(new Token(Token.Type.CXX_LENGTH, text.substring(start, numEnd), start, numEnd));
                    
                    // 添加名称 token（如果存在）
                    if (nameEnd > numEnd) {
                        tokens.add(new Token(Token.Type.CXX_NAME, text.substring(numEnd, nameEnd), numEnd, nameEnd));
                    }
                    pos = nameEnd;
                    continue;
                }
            }

            // 构造函数 C1, C2, C3
            if (c == 'C' && pos + 1 < len && Character.isDigit(text.charAt(pos + 1))) {
                tokens.add(new Token(Token.Type.CXX_OPERATOR, text.substring(pos, pos + 2), pos, pos + 2));
                pos += 2;
                continue;
            }

            // 析构函数 D0, D1, D2
            if (c == 'D' && pos + 1 < len && Character.isDigit(text.charAt(pos + 1))) {
                tokens.add(new Token(Token.Type.CXX_OPERATOR, text.substring(pos, pos + 2), pos, pos + 2));
                pos += 2;
                continue;
            }

            // 操作符 (双字符)
            if (pos + 1 < len) {
                String twoChar = text.substring(pos, pos + 2);
                if (isOperator(twoChar)) {
                    tokens.add(new Token(Token.Type.CXX_OPERATOR, twoChar, pos, pos + 2));
                    pos += 2;
                    continue;
                }
            }

            // Lambda Ul...E
            if (c == 'U' && pos + 1 < len && text.charAt(pos + 1) == 'l') {
                tokens.add(new Token(Token.Type.CXX_TYPE, "Ul", pos, pos + 2));
                pos += 2;
                continue;
            }

            // 未知字符
            tokens.add(new Token(Token.Type.UNKNOWN, String.valueOf(c), pos, pos + 1));
            pos++;
        }

        return tokens;
    }

    // === 辅助方法 ===

    private int scanSubstitution(String text, int pos) {
        pos++; // 跳过 S
        
        // 标准替换 St, Sa, Sb, Ss, Si, So, Sd
        if (pos < text.length()) {
            char c = text.charAt(pos);
            if (c == 't' || c == 'a' || c == 'b' || c == 's' || c == 'i' || c == 'o' || c == 'd') {
                return pos + 1;
            }
            
            // S_ 或 S<seq>_
            if (c == '_') {
                return pos + 1;
            }
            
            // S<数字/字母序列>_
            while (pos < text.length() && (Character.isDigit(text.charAt(pos)) || 
                   (text.charAt(pos) >= 'A' && text.charAt(pos) <= 'Z'))) {
                pos++;
            }
            if (pos < text.length() && text.charAt(pos) == '_') {
                return pos + 1;
            }
        }
        
        return pos;
    }

    private int scanArrayType(String text, int pos) {
        pos++; // 跳过 A
        
        // 可选的数组大小
        while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
            pos++;
        }
        
        // 下划线分隔
        if (pos < text.length() && text.charAt(pos) == '_') {
            pos++;
        }
        
        return pos;
    }

    private int scanExtendedType(String text, int pos) {
        pos++; // 跳过 D
        
        if (pos < text.length()) {
            char c = text.charAt(pos);
            // Da, Dc, Dd, Df, Dh, Di, Dn, Ds, De, Do, Dp, Du
            if ("acdfhinseopuTt".indexOf(c) >= 0) {
                return pos + 1;
            }
        }
        
        return pos;
    }

    private int[] scanLengthPrefixedName(String text, int pos) {
        int start = pos;
        
        // 扫描数字
        while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
            pos++;
        }
        
        int numEnd = pos;
        
        if (numEnd == start) {
            return new int[]{start, start};
        }
        
        // 解析长度
        int length;
        try {
            length = Integer.parseInt(text.substring(start, numEnd));
        } catch (NumberFormatException e) {
            // 数字太大，返回数字部分
            return new int[]{numEnd, numEnd};
        }
        
        // 读取名称
        int nameEnd = Math.min(numEnd + length, text.length());
        
        return new int[]{numEnd, nameEnd};
    }

    private boolean isOperator(String s) {
        switch (s) {
            case "nw": // new
            case "na": // new[]
            case "dl": // delete
            case "da": // delete[]
            case "ps": // + (unary)
            case "ng": // - (unary)
            case "ad": // & (unary)
            case "de": // * (unary)
            case "co": // ~
            case "pl": // +
            case "mi": // -
            case "ml": // *
            case "dv": // /
            case "rm": // %
            case "an": // &
            case "or": // |
            case "eo": // ^
            case "aS": // =
            case "pL": // +=
            case "mI": // -=
            case "mL": // *=
            case "dV": // /=
            case "rM": // %=
            case "aN": // &=
            case "oR": // |=
            case "eO": // ^=
            case "ls": // <<
            case "rs": // >>
            case "lS": // <<=
            case "rS": // >>=
            case "eq": // ==
            case "ne": // !=
            case "lt": // <
            case "gt": // >
            case "le": // <=
            case "ge": // >=
            case "nt": // !
            case "aa": // &&
            case "oo": // ||
            case "pp": // ++ (postfix)
            case "mm": // -- (postfix)
            case "cm": // ,
            case "pm": // ->*
            case "pt": // ->
            case "cl": // ()
            case "ix": // []
            case "qu": // ?
            case "cv": // (cast)
            case "li": // literal operator
                return true;
            default:
                return false;
        }
    }
}
