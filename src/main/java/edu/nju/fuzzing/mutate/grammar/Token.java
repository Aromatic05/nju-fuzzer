package edu.nju.fuzzing.mutate.grammar;

/**
 * 通用 Token 类 - 容错分词器的基础单元
 * 
 * 设计原则：
 * 1. 不变性：Token 一旦创建不可修改，变异时创建新 Token
 * 2. 容错性：包含 RAW/UNKNOWN 类型处理无法识别的字符
 * 3. 位置追踪：保留原始字节流中的位置信息
 */
public class Token {

    /**
     * Token 类型枚举 - 通用类型 + 格式特定类型
     */
    public enum Type {
        // === 通用类型 ===
        RAW,            // 原始字节（无法识别）
        UNKNOWN,        // 未知字符
        WHITESPACE,     // 空白符
        NEWLINE,        // 换行
        COMMENT,        // 注释
        
        // === 界定符 ===
        LBRACE,         // {
        RBRACE,         // }
        LBRACKET,       // [
        RBRACKET,       // ]
        LPAREN,         // (
        RPAREN,         // )
        LANGLE,         // <
        RANGLE,         // >
        
        // === 字面量 ===
        STRING,         // "..." 或 '...'
        NUMBER,         // 123, 3.14, 1e10
        BOOLEAN,        // true/false
        NULL,           // null/nil
        
        // === 运算符/标点 ===
        COLON,          // :
        COMMA,          // ,
        SEMICOLON,      // ;
        DOT,            // .
        EQUALS,         // =
        OPERATOR,       // +, -, *, /, etc.
        
        // === 标识符/关键字 ===
        IDENTIFIER,     // 变量名、函数名等
        KEYWORD,        // 保留关键字 (if, function, local, etc.)
        
        // === XML 特定 ===
        XML_DECL,       // <?xml ... ?>
        XML_DOCTYPE,    // <!DOCTYPE ...>
        XML_CDATA,      // <![CDATA[ ... ]]>
        XML_ENTITY,     // &xxx;
        XML_TAG_OPEN,   // <tagname
        XML_TAG_CLOSE,  // </tagname>
        XML_TAG_END,    // > 或 />
        XML_ATTR_NAME,  // 属性名
        XML_ATTR_VALUE, // 属性值
        XML_TEXT,       // 文本内容
        
        // === C++ Mangled Name 特定 ===
        CXX_PREFIX,     // _Z
        CXX_NESTED,     // N...E 嵌套名称
        CXX_TYPE,       // 类型编码
        CXX_MODIFIER,   // P, R, K, V 等修饰符
        CXX_SUBST,      // S0_, S_ 等替换
        CXX_TEMPLATE,   // I...E 模板参数
        CXX_OPERATOR,   // 操作符编码
        CXX_LENGTH,     // 数字长度前缀
        CXX_NAME,       // 名称部分
        
        // === 特殊 ===
        EOF             // 文件结束
    }

    private final Type type;
    private final String value;     // Token 的文本值
    private final byte[] rawBytes;  // 原始字节（用于二进制数据）
    private final int startPos;     // 在原始输入中的起始位置
    private final int endPos;       // 在原始输入中的结束位置

    // === 构造器 ===
    
    public Token(Type type, String value, int startPos, int endPos) {
        this.type = type;
        this.value = value;
        this.rawBytes = null;
        this.startPos = startPos;
        this.endPos = endPos;
    }

    public Token(Type type, byte[] rawBytes, int startPos, int endPos) {
        this.type = type;
        this.value = null;
        this.rawBytes = rawBytes;
        this.startPos = startPos;
        this.endPos = endPos;
    }

    public Token(Type type, String value) {
        this(type, value, -1, -1);
    }

    // === Getters ===
    
    public Type getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    public byte[] getRawBytes() {
        return rawBytes;
    }

    public int getStartPos() {
        return startPos;
    }

    public int getEndPos() {
        return endPos;
    }

    public int getLength() {
        if (endPos >= 0 && startPos >= 0) {
            return endPos - startPos;
        }
        return value != null ? value.length() : (rawBytes != null ? rawBytes.length : 0);
    }

    // === 工厂方法 ===
    
    /**
     * 创建一个修改后的 Token（保留位置信息）
     */
    public Token withValue(String newValue) {
        return new Token(this.type, newValue, this.startPos, this.endPos);
    }

    public Token withType(Type newType) {
        return new Token(newType, this.value, this.startPos, this.endPos);
    }

    public Token withTypeAndValue(Type newType, String newValue) {
        return new Token(newType, newValue, this.startPos, this.endPos);
    }

    // === 辅助方法 ===
    
    public boolean isDelimiter() {
        switch (type) {
            case LBRACE:
            case RBRACE:
            case LBRACKET:
            case RBRACKET:
            case LPAREN:
            case RPAREN:
            case LANGLE:
            case RANGLE:
                return true;
            default:
                return false;
        }
    }

    public boolean isOpenDelimiter() {
        switch (type) {
            case LBRACE:
            case LBRACKET:
            case LPAREN:
            case LANGLE:
                return true;
            default:
                return false;
        }
    }

    public boolean isCloseDelimiter() {
        switch (type) {
            case RBRACE:
            case RBRACKET:
            case RPAREN:
            case RANGLE:
                return true;
            default:
                return false;
        }
    }

    public Type getMatchingDelimiter() {
        switch (type) {
            case LBRACE: return Type.RBRACE;
            case RBRACE: return Type.LBRACE;
            case LBRACKET: return Type.RBRACKET;
            case RBRACKET: return Type.LBRACKET;
            case LPAREN: return Type.RPAREN;
            case RPAREN: return Type.LPAREN;
            case LANGLE: return Type.RANGLE;
            case RANGLE: return Type.LANGLE;
            default: return null;
        }
    }

    public boolean isLiteral() {
        switch (type) {
            case STRING:
            case NUMBER:
            case BOOLEAN:
            case NULL:
                return true;
            default:
                return false;
        }
    }

    public boolean isTrivia() {
        switch (type) {
            case WHITESPACE:
            case NEWLINE:
            case COMMENT:
                return true;
            default:
                return false;
        }
    }

    @Override
    public String toString() {
        return String.format("Token(%s, \"%s\", %d-%d)", 
            type, 
            value != null ? value.substring(0, Math.min(20, value.length())) : "<bytes>",
            startPos, 
            endPos);
    }
}
