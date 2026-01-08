# 开发日志（2026-01-08）- Mutate 核心框架

> 主题：变异器核心接口、工厂路由、AFL Havoc 风格通用变异

---

## 1. 变更概览

### A. Mutator 接口

目标：统一变异器契约，懒惰生成避免 OOM。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/Mutator.java](../../src/main/java/edu/nju/fuzzing/mutate/Mutator.java)
  - `Iterator<Testcase> mutate(Seed seed, int energy)`：按需生成，energy 为上限
  - 不保证线程安全，调用方负责同步

### B. MutatorFactory 类型路由

目标：根据 `SeedType` 路由到对应变异器，未知类型回退 Havoc。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/MutatorFactory.java](../../src/main/java/edu/nju/fuzzing/mutate/MutatorFactory.java)
  - 类型映射：XML/LUA/MJS/CXX → 语法感知；PNG/ELF/JPEG/PCAP → 结构感知
  - 混合策略：已知类型保留 10% 能量给 Havoc，保持多样性
  - 兜底：`UNKNOWN` 使用 `AflHavocMutator`

### C. MutationOps 基础算子库

目标：13 个无状态静态算子，供各变异器组合使用。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/MutationOps.java](../../src/main/java/edu/nju/fuzzing/mutate/MutationOps.java)
  - 位操作：`flipBit`、`flipByte`
  - 算术：`arithByte/Short/Int`（支持字节序）
  - 边界值：`setInteresting8/16/32`（AFL 经典边界值）
  - 块操作：`swapBytes`、`overwriteBlock`、`deleteBlock`、`insertBlock`、`cloneBlock`
  - 字典：`overwriteToken`、`insertToken`

### D. AflHavocMutator 通用变异

目标：AFL 风格随机堆叠变异，作为通用兜底。

落点：

- [src/main/java/edu/nju/fuzzing/mutate/AflHavocMutator.java](../../src/main/java/edu/nju/fuzzing/mutate/AflHavocMutator.java)
  - 堆叠次数：`1 + log2(energy)`，自适应能量
  - 加权随机选择算子（flipBit 权重 10，arith 5-10，block 5-8）
  - 30% 概率与队列随机种子拼接（splicing）
  - 支持外部字典注入

---

## 2. 设计决策

| 决策点 | 选择 | 理由 |
|--------|------|------|
| 返回 Iterator vs List | Iterator | 懒惰生成，大能量时避免 OOM |
| 能量语义 | 上限而非精确值 | 变异可能提前耗尽 |
| 算子设计 | 无状态静态方法 | 线程安全，易于测试 |
| 混合策略 | 10% Havoc | 防止类型感知变异过于单一 |

---

## 3. 文件结构

```
src/main/java/edu/nju/fuzzing/mutate/
├── Mutator.java           # 核心接口
├── MutatorFactory.java    # 工厂路由
├── MutationOps.java       # 13 个基础算子
├── AflHavocMutator.java   # 通用变异器
├── grammar/               # 语法感知（见 mutate-grammar.md）
└── binary/                # 结构感知（见 mutate-binary.md）
```

---

## 4. 后续规划

- [ ] MOpt 自适应权重调整
- [ ] 基于覆盖反馈的算子选择
- [ ] 字典词频统计与动态优先级
