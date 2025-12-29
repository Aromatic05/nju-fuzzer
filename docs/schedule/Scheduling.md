# Scheduling - 调度（Selection + Power）模块文档

## 概述

调度模块回答两件事：

1) **下一轮 fuzz 选哪个 seed？**（Selection / Prioritization）
2) **给这个 seed 分配多少变异预算？**（Power / Energy scheduling）

当前实现由两个组件组成：

- `SeedPrioritizer`：从 `SeedQueue.getSeeds()` 中选出下一枚种子
- `PowerScheduler`：为选中的 `Seed` 计算 `energy`（变异迭代次数）

位置：
- 选种：`src/main/java/edu/nju/fuzzing/schedule/SeedPrioritizer.java`
- 能量：`src/main/java/edu/nju/fuzzing/schedule/PowerScheduler.java`
- 调度信号承载：`src/main/java/edu/nju/fuzzing/model/Seed.java`
- 主循环调用：`src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java`

---

## 设计目标

- **确定性 + 可测试**：在同一输入队列状态下，优先选择逻辑尽量稳定，避免“拍脑袋随机”。
- **兼容无覆盖模式**：`--coverage none` 时没有 edge-level 信号，调度仍能工作（靠 execTime/bitmapSize/handicap/depth 等）。
- **可渐进增强**：当 `CoverageDB` 可用时，调度能消费 `favored/rarity/redundant/stability` 等信号。

---

## 调度信号来源（Seed 元数据）

调度器强调“只读 Seed”，信号由 Engine 写回：

- 基础动态指标：
  - `exec_time`（纳秒）
  - `bitmap_size`（nonZeroBytes）
  - `handicap`（新种子保护）
  - `depth`（血缘深度）
  - `was_fuzzed`（是否已经作为 parent 被 fuzz 过）

- CoverageDB 扩展指标（有 edge-level 覆盖时）：
  - `favored`：是否在 `CoverageDB.favoredSeeds` 中
  - `redundant`：是否可被其他 topRated seeds 覆盖（`CoverageDB.isRedundant`）
  - `rarity_score`：$\sum 1/freq(edge)$，越大越稀有
  - `min_edge_freq`：该 seed 覆盖边集合中最小频率
  - `stability`：`UNKNOWN/STABLE/UNSTABLE`（可选稳定性确认）

这些字段会被写入 `<seed>.meta`，因此下次启动也可复用。

---

## SeedPrioritizer（选种）

### 行为概述

`pick(List<Seed>)` 的逻辑分两段：

1) **优先选择未 fuzz 过（`was_fuzzed=false`）的种子**
   - 在所有未 fuzz 的 seed 中计算一个 score，并选出 score 最大者。

2) **兜底 Round-Robin**
   - 当所有种子都 fuzz 过后，按 `currentIndex % size` 轮询。
   - `currentIndex` 只自增不取模：当队列增长时可以自然轮转到新加入的元素（测试也依赖这个行为）。

### 评分函数（scoreForSelection）

当前 score 是若干信号的线性组合（越大越优先）：

- 覆盖相关：`bitmapSize`（倾向覆盖更“肥”的种子）
- CoverageDB 信号：
  - `favored` 强加成
  - `redundant` 负加成
  - `rarity_score` / `min_edge_freq` 加成（偏好稀有边）
  - `UNSTABLE` 轻微惩罚
- 性能相关：`execTimeNanos` 越小越好（通过 $1/exec$ 的软加成实现）
- 结构相关：`depth` 越浅越好（避免深层血缘陷阱）
- 新手保护：`handicap` 越大越优先

确定性与同分处理：

- 未 fuzz 阶段的“选最优”采用严格 `>` 比较更新 best（不是 `>=`）。
- 因此当多个 seed 得分相同，会保持队列的先后顺序稳定（更利于复现与测试）。

注意：这是启发式，不保证全局最优，但具备可解释性与可测试性。

---

## PowerScheduler（能量分配）

### 行为概述

`assignEnergy(Seed)` 返回一个整数 energy，作为 `Mutator.mutate(seed, energy)` 的迭代预算。

- 基准值：`BASE_ENERGY = 100`
- 上限：`MAX_ENERGY = 5000`
- 最终结果会 clamp 到 `[1, MAX_ENERGY]`。

### 因子

调度因子以乘法方式叠加：

- 执行时间因子：快的种子更高能量，极慢的种子降权
- 覆盖规模因子：`bitmapSize` 大者加成
- Handicap（新种子保护）：`handicap` 大者加成（注意实现中 handicap 最低为 1）
- 深度因子：较深的 seed 轻微加成（当前实现保持中性偏加）
- 输入大小因子：小输入轻微加成；超大输入降权
- 类型因子：可识别类型（非 UNKNOWN）轻微加成

说明：

- 这两个因子对“缺省/空数据/UNKNOWN 类型”的 seed 设计为中性或轻微影响，避免破坏已有基准断言。

- CoverageDB 信号：
  - `favored` 加成（例如 x1.5）
  - `redundant` 降权（例如 x0.5）
  - `UNSTABLE` 降权（例如 x0.7）
  - `rarity_score` 增益但封顶（避免能量爆炸）
  - `min_edge_freq <= 2` 轻微加成（更关注“真的很稀有”的边）

---

## 与 FuzzingEngine 的集成点

- `Seed parent = prioritizer.pick(seedQueue.getSeeds())`
- `int energy = scheduler.assignEnergy(parent)`
- `Iterator<Testcase> it = mutator.mutate(parent, energy)`

当 `CoverageDB` 可用时，引擎会：

- 启动后执行一次“初始种子校准”，让 `favored/rarity/redundant` 能从第一轮开始影响调度。
- interesting 晋升时写回新 seed 的调度信号，并在 favored 集合变化时刷新整个队列的提示字段。

---

## 已知限制与扩展建议

- 目前没有实现 AFL 的完整 queue cycle、`cull_queue`、fuzz level 等复杂机制。
- `redundant` 只是“降权提示”，队列不会物理删除；后续可以加定期 culling。
- `rarity_score` 的定义当前基于 hit frequency（次数）；若要更贴近 AFL 可引入 additional heuristics（如 exec speed、bitmap density、favored rotation）。

---

## 验收建议（最小可验证点）

- 当存在多个未 fuzz seed 时：`favored=true` 的 seed 应优先被 pick（对应单元测试）。
- `PowerScheduler`：favored 提升、redundant 降低、rarity 提升应能体现在 energy 结果上（对应单元测试）。
