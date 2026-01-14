# 开发日志（2026-01-08）- Mutate 语法感知变异器

> 主题：文本格式（XML/Lua/MJS/C++）的语法感知变异实现

---

## 1. 变更概览

### A. 语法基础设施

目标：提供 Token 化 → 语法树 → 变异 → 修复的通用流程。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/grammar/Token.java](../../src/main/java/edu/nju/fuzzing/mutate/grammar/Token.java)
  - Token 类型枚举：RAW、分隔符、字面量、XML 特有、C++ 特有等

- [src/main/java/edu/nju/fuzzing/mutate/grammar/TokenNode.java](../../src/main/java/edu/nju/fuzzing/mutate/grammar/TokenNode.java)
  - 树节点类型：ROOT、BLOCK、LEAF、FRAGMENT
  - 树操作：`addChild`、`removeChild`、`replaceChild`、`flatten`

- [src/main/java/edu/nju/fuzzing/mutate/grammar/Tokenizer.java](../../src/main/java/edu/nju/fuzzing/mutate/grammar/Tokenizer.java)
  - 接口：`tokenize()` 返回 Token 列表，`buildTree()` 构建语法树

- [src/main/java/edu/nju/fuzzing/mutate/grammar/TreeBuilder.java](../../src/main/java/edu/nju/fuzzing/mutate/grammar/TreeBuilder.java)
  - 栈式构建：自动匹配括号/标签对

### B. MutationStrategy 通用变异策略

目标：提供跨格式复用的树变异操作。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/grammar/MutationStrategy.java](../../src/main/java/edu/nju/fuzzing/mutate/grammar/MutationStrategy.java)
  - `duplicateSubtree`：复制子树（测试重复处理）
  - `deleteNodes`：删除节点（测试缺失处理）
  - `swapNodes`：交换兄弟节点（测试顺序依赖）
  - `injectPayload`：注入攻击载荷
  - `typeConfusion`：类型混淆（字符串→数字）
  - `mutateNumbers`：数值边界变异

### C. XML 变异器

目标：针对 XML 解析器的结构感知变异。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/XmlMutator.java](../../src/main/java/edu/nju/fuzzing/mutate/XmlMutator.java)
  - 标签嵌套深度攻击、属性注入、CDATA 边界
  - XXE 载荷（外部实体、参数实体、Billion Laughs）
  - 语法修复：标签配对、属性引号、实体转义

- [src/main/java/edu/nju/fuzzing/mutate/grammar/XmlTokenizer.java](../../src/main/java/edu/nju/fuzzing/mutate/grammar/XmlTokenizer.java)
  - Token 类型：TAG_OPEN、TAG_CLOSE、ATTR_NAME、ATTR_VALUE、CDATA、COMMENT

### D. Lua 变异器

目标：针对 Lua 解释器的语法感知变异。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/LuaMutator.java](../../src/main/java/edu/nju/fuzzing/mutate/LuaMutator.java)
  - 攻击载荷：os.execute、loadstring、栈溢出递归、无限循环
  - 关键字替换：`local` ↔ `global`、`and` ↔ `or`
  - 语法修复：end 配对、字符串引号、注释闭合

- [src/main/java/edu/nju/fuzzing/mutate/grammar/LuaTokenizer.java](../../src/main/java/edu/nju/fuzzing/mutate/grammar/LuaTokenizer.java)
  - Token 类型：KEYWORD、IDENT、NUMBER、STRING、OPERATOR、COMMENT

### E. MJS/C++ 变异器

目标：JavaScript 和 C++ 源码变异。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/MjsMutator.java](../../src/main/java/edu/nju/fuzzing/mutate/MjsMutator.java)
  - 原型污染、类型强制转换、数组越界

- [src/main/java/edu/nju/fuzzing/mutate/CxxMutator.java](../../src/main/java/edu/nju/fuzzing/mutate/CxxMutator.java)
  - 指针运算、内存操作、未定义行为触发

---

## 2. 设计决策

| 决策点 | 选择 | 理由 |
|--------|------|------|
| 语法树 vs 正则 | 语法树 | 结构感知更精准 |
| 攻击载荷策略 | 10% 概率注入 | 平衡覆盖与安全测试 |
| 语法修复时机 | 变异后可选 | 可测试解析错误处理 |

---

## 3. 文件结构

```
src/main/java/edu/nju/fuzzing/mutate/
├── XmlMutator.java
├── LuaMutator.java
├── MjsMutator.java
├── CxxMutator.java
└── grammar/
    ├── Token.java
    ├── TokenNode.java
    ├── Tokenizer.java
    ├── TreeBuilder.java
    ├── MutationStrategy.java
    ├── XmlTokenizer.java
    ├── XmlChecker.java
    ├── XmlFixer.java
    ├── LuaTokenizer.java
    ├── LuaChecker.java
    └── LuaFixer.java
```

---

## 4. 后续规划

- [ ] 基于语法规则的生成式变异
- [ ] 更多语言支持（JSON、SQL、HTML）
- [ ] 语法覆盖率反馈
