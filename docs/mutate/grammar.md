# 语法感知变异框架 (Grammar-Aware Mutation)

## 1. 概述

语法感知变异框架位于 `edu.nju.fuzzing.mutate.grammar` 包中，提供了一套完整的**文本格式解析与变异引擎**。与盲目的字节级变异不同，该框架能够理解输入的语法结构，生成在语法层面"看起来合理"但在语义层面"存在问题"的测试用例。

### 核心价值

*   **绕过初级检查**：生成的用例能通过格式验证、语法解析等早期检查
*   **触达深层逻辑**：使 Fuzzer 能够测试业务逻辑、状态机、类型系统等深层代码
*   **保持可读性**：变异后的数据仍可作为调试用例使用

---

## 2. 架构组件

### 2.1 核心类图

```
Tokenizer (接口)
    ├── XmlTokenizer    (XML 分词器)
    ├── LuaTokenizer    (Lua 分词器)
    ├── CxxTokenizer    (C++ Mangled Name 分词器)
    └── MjsTokenizer    (JavaScript/MJS 分词器)

Token
    ├── type            (Token 类型)
    ├── value           (文本值)
    ├── startPos        (起始位置)
    └── endPos          (结束位置)

TokenNode
    ├── nodeType        (节点类型: ROOT/BLOCK/LEAF/FRAGMENT)
    ├── token           (关联的 Token)
    ├── children        (子节点列表)
    └── openDelimiter   (开放界定符)

TreeBuilder             (Token 流转树结构)
MutationStrategy        (通用变异策略)

*SyntaxChecker         (语法检查器: Xml/Lua/Cxx/Mjs)
*SyntaxFixer           (语法修复器: Xml/Lua/Cxx/Mjs)
```

### 2.2 处理流程

```
原始数据 --> Tokenizer.tokenize() --> Token 流
                                        |
                                        v
                              TreeBuilder.build()
                                        |
                                        v
                                   TokenNode 树
                                        |
                                        v
                            MutationStrategy.* 变异操作
                                        |
                                        v
                              TokenNode.serialize()
                                        |
                                        v
                              SyntaxFixer.fix()
                                        |
                                        v
                                   变异后数据
```

---

## 3. Token 系统

### 3.1 Token 类型枚举

`Token.Type` 定义了所有可识别的 Token 类型：

#### 通用类型

| 类型 | 描述 | 示例 |
| :--- | :--- | :--- |
| `RAW` | 原始字节（无法识别） | 二进制数据 |
| `UNKNOWN` | 未知字符 | 乱码 |
| `WHITESPACE` | 空白符 | 空格、Tab |
| `NEWLINE` | 换行 | `\n`, `\r\n` |
| `COMMENT` | 注释 | `// ...`, `/* ... */` |

#### 界定符

| 类型 | 描述 | 匹配 |
| :--- | :--- | :--- |
| `LBRACE` / `RBRACE` | 花括号 | `{` / `}` |
| `LBRACKET` / `RBRACKET` | 方括号 | `[` / `]` |
| `LPAREN` / `RPAREN` | 圆括号 | `(` / `)` |
| `LANGLE` / `RANGLE` | 尖括号 | `<` / `>` |

#### 字面量

| 类型 | 描述 | 示例 |
| :--- | :--- | :--- |
| `STRING` | 字符串 | `"hello"`, `'world'` |
| `NUMBER` | 数字 | `123`, `3.14`, `1e10` |
| `BOOLEAN` | 布尔值 | `true`, `false` |
| `NULL` | 空值 | `null`, `nil` |

#### XML 特定类型

| 类型 | 描述 | 示例 |
| :--- | :--- | :--- |
| `XML_DECL` | XML 声明 | `<?xml version="1.0"?>` |
| `XML_DOCTYPE` | DOCTYPE | `<!DOCTYPE html>` |
| `XML_CDATA` | CDATA 区块 | `<![CDATA[...]]>` |
| `XML_ENTITY` | 实体引用 | `&amp;`, `&#123;` |
| `XML_TAG_OPEN` | 开始标签 | `<div` |
| `XML_TAG_CLOSE` | 结束标签 | `</div>` |
| `XML_TEXT` | 文本内容 | `Hello World` |

#### C++ Mangled Name 特定类型

| 类型 | 描述 | 示例 |
| :--- | :--- | :--- |
| `CXX_PREFIX` | 前缀 | `_Z` |
| `CXX_NESTED` | 嵌套名称 | `N...E` |
| `CXX_TYPE` | 类型编码 | `i`, `d`, `v` |
| `CXX_MODIFIER` | 修饰符 | `P` (指针), `R` (引用) |
| `CXX_TEMPLATE` | 模板参数 | `I...E` |

### 3.2 Token 不变性

Token 一旦创建不可修改。变异时使用工厂方法创建新 Token：

```java
// 修改值
Token newToken = token.withValue("new_value");

// 修改类型
Token newToken = token.withType(Token.Type.STRING);

// 同时修改
Token newToken = token.withTypeAndValue(Token.Type.NUMBER, "42");
```

---

## 4. 分词器 (Tokenizer)

### 4.1 接口定义

```java
public interface Tokenizer {
    /**
     * 将原始字节流切分为 Token 流
     */
    List<Token> tokenize(byte[] input);
    
    /**
     * 便捷方法：直接从字节流构建树
     */
    default TokenNode parse(byte[] input) {
        return buildTree(tokenize(input));
    }
}
```

### 4.2 容错设计原则

所有分词器遵循以下原则：

1. **绝不抛出异常**：遇到无法识别的字符标记为 `RAW` 或 `UNKNOWN`
2. **尽可能识别有意义的 Token**：即使在错误上下文中也尝试识别
3. **保留位置信息**：每个 Token 记录在原始输入中的起始和结束位置

### 4.3 已实现的分词器

#### XmlTokenizer

识别 XML 的所有基本结构：

```java
XmlTokenizer tokenizer = new XmlTokenizer();
List<Token> tokens = tokenizer.tokenize(xmlBytes);
// 识别: XML声明, DOCTYPE, CDATA, 注释, 标签, 属性, 实体引用, 文本
```

#### LuaTokenizer

识别 Lua 脚本的语法元素：

*   关键字：`function`, `local`, `if`, `then`, `end`, `for`, `while`, `return`...
*   字符串：`"..."`, `'...'`, `[[...]]` (长字符串)
*   注释：`--...`, `--[[...]]`
*   操作符和标点

#### CxxTokenizer

识别 Itanium C++ ABI 符号修饰：

*   前缀：`_Z`
*   类型编码：`i` (int), `d` (double), `v` (void)...
*   修饰符：`P` (指针), `R` (引用), `K` (const)...
*   嵌套名称：`N...E`
*   模板参数：`I...E`

#### MjsTokenizer

识别 JavaScript/ES Module 语法：

*   关键字：`import`, `export`, `function`, `const`, `let`, `async`, `await`...
*   模板字符串：`` `...${...}...` ``
*   正则表达式：`/pattern/flags`

---

## 5. 树构建器 (TreeBuilder)

`TreeBuilder` 将 Token 流转换为树状结构，基于界定符推断层级关系。

### 5.1 构建策略

```java
public static TokenNode build(List<Token> tokens) {
    TokenNode root = TokenNode.createRoot();
    Deque<TokenNode> stack = new ArrayDeque<>();
    stack.push(root);
    
    for (Token token : tokens) {
        if (token.isOpenDelimiter()) {
            // 遇到开放界定符，创建新 BLOCK 并入栈
            TokenNode block = TokenNode.createBlock(token);
            current.addChild(block);
            stack.push(block);
        } else if (token.isCloseDelimiter()) {
            // 遇到闭合界定符，尝试匹配并出栈
            // ...
        } else {
            // 其他 Token 作为 LEAF 添加
            current.addChild(TokenNode.createLeaf(token));
        }
    }
    
    return root;
}
```

### 5.2 容错处理

*   **括号不匹配**：不强制添加闭合符，保持未闭合状态
*   **多余的闭合符**：作为普通 LEAF 节点添加
*   **结构过于混乱**：使用 `buildFlat()` 生成扁平结构

---

## 6. TokenNode 树操作

### 6.1 节点类型

| 类型 | 描述 | 子节点 |
| :--- | :--- | :--- |
| `ROOT` | 根节点 | 有 |
| `BLOCK` | 由界定符包围的块 | 有 |
| `LEAF` | 叶子节点（单个 Token） | 无 |
| `FRAGMENT` | 多个连续 Token 的片段 | 有 |

### 6.2 树操作 API

```java
// 添加子节点
node.addChild(child);

// 在指定位置插入
node.insertChild(index, child);

// 删除子节点
node.removeChild(child);
node.removeChildAt(index);

// 替换子节点
node.replaceChild(index, newChild);

// 深度复制
TokenNode copy = node.deepCopy();

// 收集所有 BLOCK 节点
List<TokenNode> blocks = root.collectBlocks();

// 收集所有 LEAF 节点
List<TokenNode> leaves = root.collectLeaves();

// 序列化回字符串
String output = root.serialize();
```

---

## 7. 通用变异策略 (`MutationStrategy`)

`MutationStrategy` 提供格式无关的变异操作，可被各格式特定的 Mutator 复用。

### 7.1 结构变异

#### 子树复制（制造深层嵌套）

```java
/**
 * 选择一个 BLOCK 节点，将其内容复制并嵌套
 * 用于测试解析器的递归深度限制
 */
public static TokenNode duplicateSubtree(TokenNode root, int depth, ThreadLocalRandom rand);
```

#### 节点删除

```java
/**
 * 随机删除一些子节点
 * 用于测试必需元素缺失的处理
 */
public static TokenNode deleteNodes(TokenNode root, double deleteProb, ThreadLocalRandom rand);
```

#### 节点交换

```java
/**
 * 随机交换两个兄弟节点的位置
 * 用于测试顺序依赖的逻辑
 */
public static TokenNode swapNodes(TokenNode root, ThreadLocalRandom rand);
```

### 7.2 值变异

#### 字符串注入

```java
/**
 * 在字符串类型的 Token 中注入特殊 payload
 */
public static TokenNode injectPayload(TokenNode root, String[] payloads, ThreadLocalRandom rand);
```

#### 类型混淆

```java
/**
 * 将数字改成字符串，将布尔值改成数字等
 * 用于测试类型系统的健壮性
 */
public static TokenNode typeConfusion(TokenNode root, ThreadLocalRandom rand);

// 示例转换：
// NUMBER "42"    -> STRING "\"42\""
// BOOLEAN "true" -> NUMBER "1"
// STRING "hello" -> NULL "null"
```

#### 数字边界值变异

```java
/**
 * 将数字替换为边界值（MAX_INT, MIN_INT, 0, -1 等）
 */
public static TokenNode mutateNumbers(TokenNode root, ThreadLocalRandom rand);

// 边界值列表：
String[] boundaryValues = {
    "0", "-1", "1", 
    "2147483647", "-2147483648",       // INT32 边界
    "9223372036854775807",             // INT64 MAX
    "1.7976931348623157E308",          // Double MAX
    "0/0",                             // NaN (Lua 兼容)
    "math.huge", "-math.huge",         // Infinity (Lua 兼容)
};
```

#### 关键词替换

```java
/**
 * 将关键字替换为类似但可能导致解析错误的关键字
 */
public static TokenNode replaceKeywords(TokenNode root, String[][] replacements, 
                                       ThreadLocalRandom rand);
```

### 7.3 常用攻击载荷

```java
public static final String[] COMMON_PAYLOADS = {
    "\\x00",                           // Null byte
    "%s%s%s%s%s",                      // Format string
    "../../../etc/passwd",             // Path traversal
    "<script>alert(1)</script>",       // XSS
    "{{7*7}}",                         // Template injection
    "${7*7}",                          // Expression injection
    "$(id)",                           // Command injection
    "' OR '1'='1",                     // SQL injection
    "\\uD800",                         // Lone surrogate
    "AAAA" + "A".repeat(1000),         // Buffer overflow
};
```

---

## 8. 语法检查器 (*SyntaxChecker)

### 8.1 设计目的

语法检查器用于检测变异后代码的语法问题，为修复器提供修复依据。

### 8.2 XmlSyntaxChecker

检查 XML 的 well-formedness：

```java
public class CheckResult {
    public final boolean isValid;
    public final int unmatchedOpenTagCount;     // 未闭合的开始标签数
    public final int unmatchedCloseTagCount;    // 多余的结束标签数
    public final List<String> unmatchedOpenTags; // 未闭合的标签名
    public final List<String> mismatchedTags;   // 不匹配的标签对
    public final boolean hasUnclosedAttribute;  // 属性引号未闭合
    public final boolean hasInvalidComment;     // 注释包含 --
    public final boolean hasInvalidEntity;      // 无效的实体引用
    public final boolean hasUnclosedCData;      // CDATA 未闭合
    public final boolean hasUnquotedAttribute;  // 属性值无引号
    public final List<String> undefinedEntities; // 未定义的实体
}
```

### 8.3 其他检查器

| 检查器 | 检查内容 |
| :--- | :--- |
| `LuaSyntaxChecker` | 括号配对、关键字匹配（if-then-end）、字符串闭合 |
| `CxxSyntaxChecker` | 嵌套结构（N...E, I...E）、类型编码合法性 |
| `MjsSyntaxChecker` | 括号配对、模板字符串闭合、import/export 语法 |

---

## 9. 语法修复器 (*SyntaxFixer)

### 9.1 设计原则

*   **最小化修改**：尽量保持原始结构
*   **迭代修复**：循环修复直到语法正确或达到最大尝试次数
*   **优先级排序**：按问题严重程度依次修复

### 9.2 XmlSyntaxFixer

修复能力：

```java
// 修复 XML 代码
String fixed = fixer.fix(xmlString);

// 基于 Token 列表修复
List<Token> fixedTokens = fixer.fixTokens(tokens);

// 工具方法
String escaped = XmlSyntaxFixer.escapeXmlAttribute(value);  // 转义属性值
String escaped = XmlSyntaxFixer.escapeXmlText(value);       // 转义文本
```

修复项目：

| 问题 | 修复方法 |
| :--- | :--- |
| 未闭合的标签 | 添加缺失的结束标签 |
| 不匹配的标签 | 修正标签名 |
| 属性值未引用 | 添加引号 |
| 注释中的 `--` | 替换为 `- -` |
| 未定义的实体 | 转义为 `&amp;xxx;` |
| 未闭合的 CDATA | 添加 `]]>` |

### 9.3 修复流程

```java
public String fix(String xml) {
    String fixed = xml;
    int attempts = 0;
    
    while (attempts < MAX_FIX_ATTEMPTS) {
        CheckResult result = checker.check(fixed);
        
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
        if (!result.unmatchedOpenTags.isEmpty()) {
            fixed = fixUnmatchedOpenTags(fixed, result.unmatchedOpenTags);
        }
        // ...
        
        if (fixed.equals(before)) break;  // 无法继续修复
        attempts++;
    }
    
    return fixed;
}
```

---

## 10. 使用示例

### 10.1 XML 变异流程

```java
import edu.nju.fuzzing.mutate.grammar.*;

public class XmlFuzzer {
    
    private final XmlTokenizer tokenizer = new XmlTokenizer();
    private final XmlSyntaxChecker checker = new XmlSyntaxChecker();
    private final XmlSyntaxFixer fixer = new XmlSyntaxFixer(checker);
    
    public byte[] mutateXml(byte[] original) {
        ThreadLocalRandom rand = ThreadLocalRandom.current();
        
        // 1. 分词
        List<Token> tokens = tokenizer.tokenize(original);
        
        // 2. 构建树
        TokenNode tree = TreeBuilder.build(tokens);
        
        // 3. 应用变异
        int mutationType = rand.nextInt(5);
        switch (mutationType) {
            case 0:
                // 深层嵌套
                tree = MutationStrategy.duplicateSubtree(tree, 10, rand);
                break;
            case 1:
                // 删除节点
                tree = MutationStrategy.deleteNodes(tree, 0.3, rand);
                break;
            case 2:
                // 交换节点
                tree = MutationStrategy.swapNodes(tree, rand);
                break;
            case 3:
                // 注入 payload
                tree = MutationStrategy.injectPayload(tree, 
                    MutationStrategy.COMMON_PAYLOADS, rand);
                break;
            case 4:
                // 类型混淆
                tree = MutationStrategy.typeConfusion(tree, rand);
                break;
        }
        
        // 4. 序列化
        String mutated = tree.serialize();
        
        // 5. 语法修复（90% 概率）
        if (rand.nextInt(10) > 0) {
            mutated = fixer.fix(mutated);
        }
        
        return mutated.getBytes(StandardCharsets.UTF_8);
    }
}
```

### 10.2 Lua 脚本变异

```java
public byte[] mutateLua(byte[] original) {
    ThreadLocalRandom rand = ThreadLocalRandom.current();
    
    LuaTokenizer tokenizer = new LuaTokenizer();
    List<Token> tokens = tokenizer.tokenize(original);
    TokenNode tree = TreeBuilder.build(tokens);
    
    // 关键词替换
    String[][] replacements = {
        {"local", "global"},           // 无效关键字
        {"function", "func"},          // 简写
        {"return", "returns"},         // 拼写错误
        {"nil", "null"},               // 其他语言习惯
    };
    tree = MutationStrategy.replaceKeywords(tree, replacements, rand);
    
    // 数字边界值
    tree = MutationStrategy.mutateNumbers(tree, rand);
    
    // 修复语法
    LuaSyntaxFixer fixer = new LuaSyntaxFixer();
    String output = fixer.fix(tree.serialize());
    
    return output.getBytes(StandardCharsets.UTF_8);
}
```

---

## 11. 最佳实践

### 11.1 变异策略组合

| 策略 | 权重 | 目标 |
| :--- | :--- | :--- |
| 结构变异 | 40% | 测试解析器的结构处理 |
| 值变异 | 30% | 测试业务逻辑 |
| Payload 注入 | 20% | 安全漏洞探测 |
| 保持原样 | 10% | 基准测试 |

### 11.2 修复与不修复

```java
// 90% 概率修复语法 -> 测试深层逻辑
// 10% 概率不修复 -> 测试解析器的容错能力
if (rand.nextInt(10) > 0) {
    output = fixer.fix(output);
}
```

### 11.3 与 Coverage 反馈结合

```java
// 当语法变异发现新覆盖时，记录变异参数
if (hasNewCoverage) {
    saveMutationParams(mutationType, params);
    
    // 对该种子进行更多同类型变异
    energy *= 2;
}
```

---

## 12. 扩展开发

### 12.1 添加新格式支持

1. 实现 `Tokenizer` 接口
2. 定义格式特定的 `Token.Type`（如需要）
3. 实现对应的 `SyntaxChecker` 和 `SyntaxFixer`
4. 创建格式特定的 `Mutator` 类
5. 在 `MutatorFactory` 中注册

### 12.2 自定义变异策略

```java
public class CustomMutationStrategy {
    
    /**
     * 自定义：重复相同的子节点 N 次
     */
    public static TokenNode repeatChildren(TokenNode root, int times, ThreadLocalRandom rand) {
        List<TokenNode> blocks = root.collectBlocks();
        if (blocks.isEmpty()) return root;
        
        TokenNode target = blocks.get(rand.nextInt(blocks.size()));
        List<TokenNode> original = new ArrayList<>(target.getChildren());
        
        for (int i = 0; i < times; i++) {
            for (TokenNode child : original) {
                target.addChild(child.deepCopy());
            }
        }
        
        return root;
    }
}
```

---

## 13. 总结

语法感知变异框架通过：

1. **容错分词**：将任意输入转换为 Token 流，不因格式错误而失败
2. **结构建模**：将 Token 流转换为树状结构，便于结构级变异
3. **智能变异**：提供结构变异和值变异两类策略
4. **自动修复**：变异后自动修复语法问题，确保用例能进入深层逻辑

该框架与 `AflHavocMutator` 配合使用，实现了"结构引导 + 随机扰动"的双轨制变异架构，是高效 Fuzzing 的核心组件。
