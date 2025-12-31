# CxxMutator 审查报告

**审查日期**: 2025-12-31  
**文件位置**: `src/main/java/edu/nju/fuzzing/mutate/CxxMutator.java`

---

## 1. 概述

CxxMutator 是针对 C++ Mangled Name (Itanium C++ ABI) 的变异器。用于测试 demangler（如 c++filt、libcxxabi）的健壮性。

### 当前架构

```
输入字节流 → CxxTokenizer → Token流 → 扁平变异 → 序列化输出
```

### 相关文件

| 文件 | 说明 |
|------|------|
| `CxxMutator.java` | 主变异器实现 |
| `grammar/CxxTokenizer.java` | C++ Mangled Name 分词器 |
| `grammar/Token.java` | Token 定义（CXX_PREFIX, CXX_NESTED 等） |
| `CxxMutatorTest.java` | 测试文件 |

### Itanium C++ ABI Name Mangling 结构

```
_Z           # 前缀
N...E        # 嵌套名称
I...E        # 模板参数
<length>name # 长度前缀 + 名称 (如 4main)
S_, S0_, St  # 替换引用
P, R, K      # 类型修饰符（指针、引用、const）
i, l, d      # 基础类型编码
```

---

## 2. 问题清单

### 🔴 高严重性问题

#### 问题 1: 长度前缀与实际名称不匹配

**位置**: `CxxMutator.java` 第 174-191 行 `mutateLengths` 方法

```java
private List<Token> mutateLengths(List<Token> tokens, ThreadLocalRandom rand) {
    for (Token token : tokens) {
        if (token.getType() == Token.Type.CXX_LENGTH && rand.nextInt(3) == 0) {
            int lengthChoice = rand.nextInt(5);
            String newLength;
            switch (lengthChoice) {
                case 0: newLength = "0"; break;
                case 1: newLength = String.valueOf(rand.nextInt(100)); break;
                case 2: newLength = "2147483647"; break;
                case 3: newLength = "99999999999"; break;
                default: newLength = "-1"; break;  // ❌ 负数非法
            }
            result.add(token.withValue(newLength));
        }
    }
}
```

**问题描述**:
- 将长度改为 `"0"`, `"2147483647"`, `"-1"` 等，但**不修改对应名称的实际长度**
- 例如原本 `4main` 变成 `0main`，demangler 会解析为长度 0 的名称后跟未知内容 `main`
- 负数 `-1` 在 mangled name 中完全非法

**影响**: 绝大多数 demangler 会直接拒绝这种输入，无法测试深层解码逻辑。

**建议修复**:
```java
// 方案 1：同步更新长度和名称
private List<Token> mutateLengths(List<Token> tokens, ThreadLocalRandom rand) {
    for (int i = 0; i < tokens.size(); i++) {
        Token token = tokens.get(i);
        if (token.getType() == Token.Type.CXX_LENGTH && rand.nextInt(3) == 0) {
            // 找到对应的名称 token
            if (i + 1 < tokens.size() && tokens.get(i + 1).getType() == Token.Type.CXX_NAME) {
                Token nameToken = tokens.get(i + 1);
                String name = nameToken.getValue();
                
                int op = rand.nextInt(4);
                switch (op) {
                    case 0: // 截断名称
                        int newLen = Math.max(1, name.length() / 2);
                        result.add(token.withValue(String.valueOf(newLen)));
                        result.add(nameToken.withValue(name.substring(0, newLen)));
                        i++; // 跳过名称 token
                        break;
                    case 1: // 扩展名称
                        String extended = name + "AAAA";
                        result.add(token.withValue(String.valueOf(extended.length())));
                        result.add(nameToken.withValue(extended));
                        i++;
                        break;
                    // ...
                }
            }
        }
    }
}
```

---

#### 问题 2: 名称变异后不更新长度前缀

**位置**: `CxxMutator.java` 第 199-216 行 `mutateNames` 方法

```java
private List<Token> mutateNames(List<Token> tokens, ThreadLocalRandom rand) {
    for (Token token : tokens) {
        if (token.getType() == Token.Type.CXX_NAME && rand.nextInt(4) == 0) {
            String original = token.getValue();
            int mutOp = rand.nextInt(4);
            String newName;
            switch (mutOp) {
                case 0: newName = original + "AAAA"; break;
                case 1: newName = original.isEmpty() ? "x" : original.substring(0, Math.min(1, original.length())); break;
                case 2: newName = "A".repeat(100 + rand.nextInt(200)); break;
                default: newName = original + "\0\0"; break;  // ❌ NUL 字符非法
            }
            result.add(token.withValue(newName));
            // ❌ 未更新前面的长度 token
        }
    }
}
```

**问题描述**:
- `newName = original + "AAAA"` 或 `"A".repeat(100+)` 后，前面的长度 token 未同步更新
- 生成 `4mainAAAA` 这种非法结构（声明长度 4，实际名称 8 字符）
- NUL 字符 `\0` 在 mangled name 中非法

**建议修复**:
需要实现长度-名称同步机制，参见问题 1 的修复方案。

---

#### 问题 3: 模板 I...E 配对不完整

**位置**: `CxxMutator.java` 第 218-230 行 `insertTemplates` 方法

```java
private List<Token> insertTemplates(List<Token> tokens, ThreadLocalRandom rand) {
    List<Token> result = new ArrayList<>(tokens);
    int count = 1 + rand.nextInt(5);
    for (int i = 0; i < count; i++) {
        int pos = rand.nextInt(Math.max(1, result.size()));
        result.add(pos, new Token(Token.Type.CXX_TEMPLATE, "I"));
        result.add(pos + 1, new Token(Token.Type.CXX_TYPE, BASE_TYPES[rand.nextInt(BASE_TYPES.length)]));
        if (rand.nextBoolean()) {  // ❌ 50% 概率不添加闭合 E
            result.add(pos + 2, new Token(Token.Type.CXX_NESTED, "E"));
        }
    }
    return result;
}
```

**问题描述**:
- 有 50% 概率生成未闭合的模板 `I` 而无对应的 `E`
- 这会导致 demangler 解析失败

**用户需求**: 需要保留部分故意生成非法结构的功能，但比例应降低。

**建议修复**:
```java
private List<Token> insertTemplates(List<Token> tokens, ThreadLocalRandom rand) {
    // ...
    // 降低未闭合比例到 10%（用于测试解析器健壮性）
    if (rand.nextInt(10) != 0) {  // 90% 概率添加闭合 E
        result.add(pos + 2, new Token(Token.Type.CXX_NESTED, "E"));
    }
    // ...
}
```

---

### 🟠 中严重性问题

#### 问题 4: 替换序号超出实际定义范围

**位置**: `CxxMutator.java` 第 155-172 行 `mutateSubstitutions` 方法

```java
private List<Token> mutateSubstitutions(List<Token> tokens, ThreadLocalRandom rand) {
    // ...
    switch (subChoice) {
        case 0: newSub = "S_"; break;
        case 1: newSub = "S" + rand.nextInt(100) + "_"; break;      // ⚠️ 可能超出范围
        case 2: newSub = "S" + (rand.nextInt(10000) + 1000) + "_"; break;  // ❌ 几乎必定超出
        default: newSub = STD_SUBS[rand.nextInt(STD_SUBS.length)]; break;
    }
}
```

**问题描述**:
- 生成 `S9999_` 但原始 mangled name 可能只有 2-3 个替换定义
- demangler 遇到未定义的替换序号会报错拒绝

**建议修复**:
```java
// 统计当前符号中的替换定义数量
private int countSubstitutions(List<Token> tokens) {
    int count = 0;
    for (Token t : tokens) {
        // 名称、类型等会自动成为替换候选
        if (t.getType() == Token.Type.CXX_NAME || t.getType() == Token.Type.CXX_TYPE) {
            count++;
        }
    }
    return count;
}

// 生成合法范围内的替换序号
int maxSub = Math.max(1, countSubstitutions(tokens));
case 1: newSub = "S" + rand.nextInt(maxSub) + "_"; break;
```

---

#### 问题 5: 嵌套结构 N...E 故意破坏比例过高

**位置**: `CxxMutator.java` 第 267-289 行 `corruptNestedStructure` 方法

```java
private List<Token> corruptNestedStructure(List<Token> tokens, ThreadLocalRandom rand) {
    for (Token token : tokens) {
        if ("N".equals(token.getValue()) || "I".equals(token.getValue())) {
            openCount++;
            result.add(token);
            if (rand.nextInt(3) == 0) {  // 33% 概率重复开始符
                result.add(token);
                openCount++;
            }
        } else if ("E".equals(token.getValue())) {
            if (rand.nextInt(4) == 0) {  // 25% 概率删除结束符
                continue;
            }
            // ...
        }
    }
}
```

**问题描述**:
- 这是 `mutationType == 9`（约 10%）时调用的变异
- 内部又有 33% 概率重复 N/I，25% 概率删除 E
- 综合导致约 3-5% 的变异会严重破坏结构

**用户需求**: 需要保留此功能但降低比例。

**建议修复**:
```java
// 降低破坏比例
if (rand.nextInt(10) == 0) {  // 10% 概率重复开始符
    result.add(token);
    openCount++;
}

if (rand.nextInt(10) == 0) {  // 10% 概率删除结束符
    continue;
}
```

---

#### 问题 6: 名称中嵌入 NUL 字符

**位置**: `CxxMutator.java` 第 212 行

```java
default: newName = original + "\0\0"; break;
```

**问题描述**:
- `\0` 在 mangled name 中非法
- 大多数 demangler 会在 NUL 处截断或直接拒绝

**建议修复**:
```java
// 仅在攻击模式使用 NUL，正常模式使用其他边界值
if (rand.nextInt(20) == 0) {  // 5% 概率用于攻击测试
    newName = original + "\0\0";
} else {
    newName = original + "_" + rand.nextInt(1000);
}
```

---

#### 问题 7: 生成器中闭合 E 数量不匹配

**位置**: `CxxMutator.java` 第 351-354 行

```java
int closeCount = depth + (rand.nextInt(10) - 5);  // 可能多或少 5 个
for (int i = 0; i < Math.max(0, closeCount); i++) sb.append("E");
```

**问题描述**:
- 故意生成不平衡的结构（E 数量与 I/N 不匹配）
- 这导致过多无效输入

**建议修复**:
```java
// 大部分时间保持平衡，少量不平衡用于测试
int closeCount;
if (rand.nextInt(10) == 0) {  // 10% 不平衡
    closeCount = depth + (rand.nextInt(10) - 5);
} else {  // 90% 平衡
    closeCount = depth;
}
```

---

### 🟢 低严重性问题

#### 问题 8: 未使用树结构进行变异

**问题描述**:
- 与 LuaMutator 类似，CxxMutator 操作扁平 Token 列表
- 无法保持 N...E / I...E 的层级配对关系

**建议**: 引入 `CxxTreeBuilder` 构建层级结构。

---

#### 问题 9: 测试未验证 demangler 可解析

**位置**: `test/.../CxxMutatorTest.java`

```java
@Test
void testPrefix() {
    // 只检查 _Z 前缀
    assertTrue(mangle.startsWith("_Z"), ...);
}

@Test
void testCharset() {
    // 只检查字符集
    Pattern validChars = Pattern.compile("^[_a-zA-Z0-9]+$");
    assertTrue(validChars.matcher(mangle).matches(), ...);
}
```

**问题描述**:
- 未调用 `c++filt` 或类似工具验证语法合法性
- 只进行表面检查

**建议修复**:
```java
@Test
void testDemangleability() {
    ProcessBuilder pb = new ProcessBuilder("c++filt", "-n", mangledName);
    Process p = pb.start();
    // 检查是否成功解码（不是返回原字符串）
    String result = readOutput(p);
    assertNotEquals(mangledName, result, "应该能成功 demangle");
}
```

---

## 3. 改进建议

### 3.1 长度-名称同步机制（优先级最高）

创建一个工具方法，在变异长度或名称时保持同步：

```java
public class LengthNameSync {
    
    /**
     * 同步更新长度和名称
     */
    public static void syncLengthName(List<Token> tokens, int lengthIdx, int nameIdx, 
                                      String newName) {
        tokens.set(lengthIdx, tokens.get(lengthIdx).withValue(String.valueOf(newName.length())));
        tokens.set(nameIdx, tokens.get(nameIdx).withValue(newName));
    }
    
    /**
     * 查找长度-名称配对
     */
    public static List<int[]> findLengthNamePairs(List<Token> tokens) {
        List<int[]> pairs = new ArrayList<>();
        for (int i = 0; i < tokens.size() - 1; i++) {
            if (tokens.get(i).getType() == Token.Type.CXX_LENGTH &&
                tokens.get(i + 1).getType() == Token.Type.CXX_NAME) {
                pairs.add(new int[]{i, i + 1});
            }
        }
        return pairs;
    }
}
```

### 3.2 丰富语料库

当前变异依赖种子质量。建议添加预定义的 mangled name 语料：

```java
private static final String[] CORPUS = {
    // 简单函数
    "_Z4funcv",                           // void func()
    "_Z4funci",                           // func(int)
    "_Z4funcid",                          // func(int, double)
    
    // 命名空间
    "_ZN3foo3barEv",                      // foo::bar()
    "_ZN3std6vectorIiE4sizeEv",           // std::vector<int>::size()
    
    // 模板
    "_Z4funcIiEvT_",                      // template<class T> void func(T)
    "_Z4funcIiET_S0_",                    // 带替换的模板
    
    // 复杂类型
    "_Z4funcPFviE",                       // func(void (*)(int))
    "_Z4funcA10_i",                       // func(int[10])
    "_Z4funcRKi",                         // func(const int&)
    
    // 操作符
    "_ZNK3FooplERKS_",                    // Foo::operator+(const Foo&) const
    "_ZN3FooclEi",                        // Foo::operator()(int)
    
    // 构造/析构
    "_ZN3FooC1Ev",                        // Foo::Foo()
    "_ZN3FooD1Ev",                        // Foo::~Foo()
    
    // 特殊
    "_ZSt4cout",                          // std::cout
    "_ZNSt6vectorIiE9push_backERKi",      // std::vector<int>::push_back
};
```

### 3.3 降低非法结构比例

调整各种破坏性变异的概率：

| 变异类型 | 当前比例 | 建议比例 |
|---------|---------|---------|
| 不闭合模板 I | 50% | 10% |
| 重复 N/I | 33% | 10% |
| 删除 E | 25% | 10% |
| 不平衡 E 数量 | 50% | 10% |
| NUL 字符 | 25% | 5% |

---

## 4. 预期效果

| 改进阶段 | 预计合法率 |
|---------|-----------|
| 当前状态 | ~55% |
| 长度-名称同步后 | ~75% |
| 降低非法比例后 | ~85% |
| 添加丰富语料后 | ~90% |

---

## 5. 三个变异器对比

| 问题维度 | LuaMutator | XmlMutator | CxxMutator |
|---------|------------|------------|------------|
| 高严重性问题 | 2 | 3 | 3 |
| 中严重性问题 | 3 | 4 | 4 |
| 低严重性问题 | 3 | 3 | 2 |
| 使用树结构 | ✅ 是 | ❌ 否 | ❌ 否 |
| 结构配对保持 | 部分 | 差 | 差 |
| 预估有效率 | ~70% | ~50% | ~55% |

---

## 6. 相关文档

- [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling)
- [docs/mutate/Mutator.md](../Mutator.md)
