# LuaMutator 审查报告

**审查日期**: 2025-12-31  
**目标版本**: Lua 5.4  
**文件位置**: `src/main/java/edu/nju/fuzzing/mutate/LuaMutator.java`

---

## 1. 概述

LuaMutator 是针对 Lua 脚本的语法感知变异器，采用**容错分词 → 树构建 → 语法感知变异 → 序列化**的三阶段架构。

### 当前架构

```
输入字节流 → LuaTokenizer → Token流 → buildTree → TokenNode树 → MutationStrategy → 序列化输出
```

### 相关文件

| 文件 | 说明 |
|------|------|
| `LuaMutator.java` | 主变异器实现 |
| `grammar/LuaTokenizer.java` | Lua 分词器 |
| `grammar/Token.java` | Token 定义 |
| `grammar/TokenNode.java` | 语法树节点 |
| `grammar/MutationStrategy.java` | 通用变异策略 |
| `LuaMutatorTest.java` | 测试文件 |

---

## 2. 问题清单

### 🔴 高严重性问题

#### 问题 1: KEYWORD_REPLACEMENTS 包含非法 Lua 语法

**位置**: `LuaMutator.java` 第 52-63 行

```java
private static final String[][] KEYWORD_REPLACEMENTS = {
    {"local", ""},           // ❌ 删除 local 导致语法错误
    {"local", "global"},     // ❌ Lua 没有 global 关键字
    {"function", "func"},    // ❌ Lua 没有 func 关键字
    {"end", ""},             // ❌ 删除 end 导致块未闭合
    {"then", ""},            // ❌ 删除 then 导致 if 语句不完整
    {"do", ""},              // ❌ 删除 do 导致语法错误
    {"==", "="},             // ⚠️ 比较变赋值，语法可能正确但语义错误
    {"~=", "!="},            // ❌ Lua 不支持 != 运算符
    {"and", "&"},            // ⚠️ Lua 5.3+ 支持位运算 &，但语义不同
    {"or", "|"},             // ⚠️ Lua 5.3+ 支持位运算 |，但语义不同
    {"not", "!"},            // ❌ Lua 不支持 ! 运算符
};
```

**问题描述**:
- `global` 不是 Lua 关键字，会被解析为标识符导致语法错误
- `func` 不是 Lua 关键字
- `!=` 和 `!` 不是 Lua 合法运算符（应使用 `~=` 和 `not`）
- 删除 `end`/`then`/`do` 等结构关键字会导致语法解析直接失败

**影响**: 生成的大量测试用例会在 Lua 解析阶段就被拒绝，无法触及深层代码路径，导致覆盖率难以提升。

**建议修复**:
```java
private static final String[][] KEYWORD_REPLACEMENTS = {
    // 保留安全的替换
    {"and", "or"},
    {"or", "and"},
    {"==", "~="},
    {"~=", "=="},
    {"<", ">"},
    {">", "<"},
    {"<=", ">="},
    {">=", "<="},
    {"true", "false"},
    {"false", "true"},
    // 可选：低概率保留破坏性替换用于测试解析器健壮性
};
```

---

#### 问题 2: 运算符变异不区分一元/二元运算符

**位置**: `LuaMutator.java` 第 125-136 行 `mutateOperators` 方法

```java
private void mutateOperators(TokenNode tree, ThreadLocalRandom rand) {
    String[] operators = {"+", "-", "*", "/", "%", "^", "..", "==", "~=", 
        "<", ">", "<=", ">=", "and", "or", "not", "//", "&", "|", "~", "<<", ">>"};
    // ...
    String newOp = operators[rand.nextInt(operators.length)];
    replaceTokenValue(leaf, newOp);
}
```

**问题描述**:
- `not` 是一元运算符，如果替换二元运算符会导致 `a not b` 这种非法语法
- 位运算符 `&`, `|`, `~`, `<<`, `>>` 仅在 Lua 5.3+ 支持（Lua 5.4 支持）
- 随机替换不考虑运算符的**元数**（一元 vs 二元）

**示例非法输出**:
```lua
a not b      -- 语法错误，not 是一元运算符
```

**建议修复**:
```java
// 区分一元和二元运算符
private static final String[] BINARY_OPS = {
    "+", "-", "*", "/", "%", "^", "..", "==", "~=", 
    "<", ">", "<=", ">=", "and", "or", "//", "&", "|", "~", "<<", ">>"
};
private static final String[] UNARY_OPS = {"not", "-", "#", "~"};

// 根据上下文选择合适的运算符类型替换
```

---

### 🟠 中严重性问题

#### 问题 3: 字符串变异破坏引号配对

**位置**: `LuaMutator.java` 第 154-172 行 `mutateStringValue` 方法

```java
private String mutateStringValue(String original, ThreadLocalRandom rand) {
    // ...
    switch (op) {
        case 0:
            return original.substring(1, original.length() - 1);  // ❌ 去掉引号
        case 1:
            String payload = INJECTION_PAYLOADS[rand.nextInt(INJECTION_PAYLOADS.length)];
            return quote + inner + payload + quote;  // ⚠️ payload 可能包含未转义引号
        // ...
        case 4:
            return "[[" + inner + "]]";  // ⚠️ 如果 inner 包含 ]] 会提前闭合
        default:
            return quote + "\\0\\1\\2\\3" + inner + quote;  // ⚠️ 转义序列可能不正确
    }
}
```

**问题描述**:
- `case 0` 直接移除引号，生成裸字符串会导致解析错误
- `INJECTION_PAYLOADS` 包含 `"'; DROP TABLE users; --"` 等含引号的 payload，插入后会破坏字符串结构
- 长字符串 `[[...]]` 如果内容包含 `]]` 会提前闭合
- `\0\1\2\3` 在 Lua 中应该是 `\000\001\002\003` 或 `\x00\x01\x02\x03`（Lua 5.2+）

**建议修复**:
```java
private String mutateStringValue(String original, ThreadLocalRandom rand) {
    // ...
    case 0:
        // 保留引号，只清空内容
        return quote + "" + quote;
    case 1:
        // 对 payload 进行转义处理
        String escaped = escapeForLua(payload, quote);
        return quote + inner + escaped + quote;
    // ...
}

private String escapeForLua(String s, char quote) {
    return s.replace("\\", "\\\\")
            .replace(String.valueOf(quote), "\\" + quote)
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\0", "\\000");
}
```

---

#### 问题 4: 转义序列格式错误

**位置**: `LuaMutator.java` 第 39-47 行 `INJECTION_PAYLOADS`

```java
private static final String[] INJECTION_PAYLOADS = {
    "\\0",                    // ❌ Lua 需要 \000 或 \x00
    // ...
    "\\x00\\x01\\x02",        // ⚠️ \x 转义仅 Lua 5.2+ 支持
};
```

**问题描述**:
- Lua 中 `\0` 是非法转义（需要3位数字：`\000`）
- `\x` 十六进制转义仅在 Lua 5.2+ 支持（Lua 5.4 支持）

**建议修复**:
```java
private static final String[] INJECTION_PAYLOADS = {
    "\\000",                  // 正确的 NUL 字符
    "\\x00\\x01\\x02",        // Lua 5.4 支持
    // ...
};
```

---

#### 问题 5: insertRandomStatement 插入的语句语法错误

**位置**: `LuaMutator.java` 第 191-197 行 `insertRandomStatement` 方法

```java
private void insertRandomStatement(TokenNode tree, ThreadLocalRandom rand) {
    String[] statements = {
        // ...
        "goto fuzz_label ::fuzz_label::",  // ❌ 语法错误，标签定义要独立
    };
```

**问题描述**:
- `goto fuzz_label ::fuzz_label::` 在一行不合法
- 标签定义 `::label::` 必须作为独立语句，不能紧跟 `goto`

**建议修复**:
```java
"::fuzz_label:: goto fuzz_label",  // 先定义标签，再跳转
// 或分两个语句
"::fuzz_label::\ngoto fuzz_label",
```

---

### 🟡 低严重性问题

#### 问题 6: MutationStrategy.mutateNumbers 使用非法 Lua 数值

**位置**: `grammar/MutationStrategy.java`

```java
String[] boundaryValues = {
    // ...
    "NaN", "Infinity", "-Infinity",  // ❌ Lua 不支持这些字面量
    "1e309", "-1e309",               // ⚠️ 会被解析为 inf
    // ...
};
```

**问题描述**:
- Lua 不支持 `NaN`、`Infinity`、`-Infinity` 字面量
- 需要使用 `0/0`（NaN）或 `math.huge`（Infinity）

**建议修复**:
```java
String[] boundaryValues = {
    "0/0",           // NaN
    "math.huge",     // Infinity
    "-math.huge",    // -Infinity
    "1e308",         // 接近最大值
    // ...
};
```

---

#### 问题 7: pickOp 包含一元运算符混入二元运算符池

**位置**: `LuaMutator.java` 第 294-297 行 `pickOp` 方法

```java
private String pickOp(ThreadLocalRandom rand) {
    String[] ops = {"+", "-", "*", "/", "%", "^", "..", "==", "~=", 
        "<", "<=", ">", ">=", "and", "or", "//", "&", "|", "~", "<<", ">>"};
    return ops[rand.nextInt(ops.length)];
}
```

**问题描述**:
- `~` 作为一元运算符使用时是位取反
- 但这里用于生成二元表达式可能导致语法问题
- 在 Lua 5.3+ 中 `~` 既是一元位取反也是二元异或

---

#### 问题 8: 测试覆盖不足

**位置**: `test/.../LuaMutatorTest.java`

**问题描述**:
- 测试仅验证生成的代码包含某些关键词，**没有验证语法合法性**
- 没有调用实际 Lua 解释器验证生成代码是否可解析
- 应添加类似 `luac -p` 或嵌入 LuaJ 的语法检查

**建议修复**:
```java
@Test
void testSyntaxValidity() {
    // 使用 lua 命令验证语法
    ProcessBuilder pb = new ProcessBuilder("lua", "-e", "load([[" + code + "]])");
    Process p = pb.start();
    assertEquals(0, p.waitFor(), "生成的代码应该是有效的 Lua 语法");
}
```

---

## 3. 改进建议

### 3.1 快速修复（30 分钟内）

1. **修复 KEYWORD_REPLACEMENTS**：移除非法替换，保留安全的同类替换
2. **修复转义序列**：`\0` → `\000`
3. **修复 goto 语句**：调整标签定义顺序
4. **修复数值字面量**：`NaN` → `0/0`, `Infinity` → `math.huge`

### 3.2 添加语法验证层（1 天内）

1. **轻量级语法检查器**：检查块结构平衡（do-end, if-then-end）
2. **语义修复后处理**：自动补全缺失的 `end`、闭合括号
3. **变异-验证-重试循环**：变异后检查语法，失败则重试

### 3.3 改进变异策略（可选）

1. **区分运算符元数**：一元运算符和二元运算符分开处理
2. **模板化变异**：使用预定义的合法代码模板
3. **语法制导变异**：基于 Lua 语法规则进行变异

---

## 4. 预期效果

| 改进阶段 | 预计合法率 |
|---------|-----------|
| 当前状态 | ~70% |
| 快速修复后 | ~85% |
| 添加验证层后 | ~90% |
| 改进变异策略后 | ~95% |

---

## 5. 相关文档

- [Lua 5.4 Reference Manual](https://www.lua.org/manual/5.4/)
- [docs/mutate/Mutator.md](../Mutator.md)
