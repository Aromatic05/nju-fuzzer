# SeedQueue - 队列（Queue）模块文档

## 概述

`SeedQueue` 负责管理“可被进一步变异”的持久化语料条目（`Seed`）的**内存队列视图**。

它解决两个问题：

1. **加载初始种子**：从用户提供的 seeds 目录递归读取文件并构造 `Seed`。
2. **接收新晋升种子**：当 `FuzzingEngine` 发现 interesting 输入并写入 `workdir/queue/` 后，将对应 `Seed` 入队。

`SeedQueue` 与 CLI 的关系：CLI 通过 `--seeds` 把初始 seeds 目录传入引擎（不再写死 `workdir/seeds`），因此队列的“初始输入集”可以在运行时被替换。

位置：
- 实现：`src/main/java/edu/nju/fuzzing/queue/SeedQueue.java`
- 主循环调用者：`src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java`

---

## 责任边界

`SeedQueue` 的职责**刻意保持轻量**：

- 只维护 `List<Seed>`（队列本体）与少量 I/O（加载 seeds / 保存 meta）。
- 不负责：
  - 覆盖率判定（属于 `CoverageMonitor`/`CoverageDB`）
  - 入队/写盘策略（由 `CorpusManager` 完成 `queue/` 的写入，Engine 决定“是否晋升”）
  - 调度决策（由 `SeedPrioritizer`、`PowerScheduler`）

---

## 数据结构与 API

### 内部数据结构

- `private final List<Seed> seeds = new ArrayList<>();`
- `getSeeds()` 返回 `Collections.unmodifiableList(seeds)`，避免外部误修改队列。

### 关键方法

#### `int loadInitialSeeds(Path seedDir)`

行为：

- 递归遍历 `seedDir` 下所有普通文件（`Files.walk`）。
- 跳过：
  - 隐藏文件（文件名以 `.` 开头）
  - `.meta` 文件（避免把元数据当成输入）
- 对每个 seed 文件：
  - 读入 `byte[] data` 并调用 `Seed.loadWithMetadata(file, data)` 构造。
  - 加入队列。

注意事项：

- 如果 `seedDir` 不存在或不是目录，会抛 `IOException`。
- 由于递归加载，目录中若包含大量文件，会导致启动时 I/O 成本增加。
- 加载顺序取决于 `Files.walk` 的遍历顺序；当前实现不对其排序。

#### `void addSeed(Seed seed)`

行为：

- 将 `seed` 追加到队列尾部。
- 立即调用 `seed.saveMetadata()` 写入 `<seedFile>.meta`。

设计意图：

- `.meta` 用于保存调度相关的轻量字段（如 `exec_time/bitmap_size/favored/...`），保证下次启动可复用。
- 实际输入 bytes 已由 `CorpusManager.saveToQueue()` 写入 `workdir/queue/`。

补充：当前 `.meta` 会持久化一部分由 CoverageDB 计算出的“调度提示字段”，例如：

- `favored` / `redundant`
- `rarity_score` / `min_edge_freq`
- `stability`（当启用稳定性确认且可判定时）

#### `List<Seed> getSeeds()` / `int size()` / `boolean isEmpty()`

- 为调度器提供只读访问。

---

## 与其他模块的契约

### 与 `FuzzingEngine`

- `FuzzingEngine` 在启动时调用 `loadInitialSeeds(initialSeedDir)`（该目录来自 CLI `--seeds` 或默认 `workdir/seeds`）。
- 发现 interesting 输入后：
  1) `CorpusManager.saveToQueue(bytes, coverage)` 负责写盘，返回保存路径
  2) `new Seed(saved.toFile(), testcase)` 构造新种子
  3) `seedQueue.addSeed(newSeed)` 入队并写 `.meta`

### 与 `SeedPrioritizer` / `PowerScheduler`

- 调度器只通过 `getSeeds()` 读取队列。
- 调度信号来自 `Seed` 的元数据字段（例如 `favored/redundant/rarityScore/stability`），这些字段由 Engine 在“校准”或“晋升”阶段写回。

### 与 `CoverageDB`

- `SeedQueue` 不依赖 `CoverageDB`。
- `Seed` 的“调度提示字段”可能来自 `CoverageDB` 的计算结果，但写回过程发生在 Engine 内。

---

## 已知限制与后续扩展

当前实现属于“课程作业可运行”的最小版本，仍有一些刻意留空的点：

- **队列裁剪（queue culling）未实现**：目前只在 `Seed` 上标注 `redundant`，并交由调度器降权；并没有物理移除队列条目。
- **持久化策略较简单**：`addSeed` 总是写 `.meta`，对高频入队场景可能有额外 I/O。
- **缺少 cycle/bookkeeping**：例如 AFL 的 queue cycle、favored 轮转、sync 等。

另：`SeedQueue` 只负责“条目列表 + 元数据落盘”，不负责数值型 seedId 的分配；当前 `CoverageDB` 使用 long seedId，而引擎内部会维护 `Seed.getId() -> long` 的映射。

---

## 验收建议（最小可验证点）

- 给一个包含若干文件的 seeds 目录，启动后能看到：
  - Engine 打印 `Loaded N initial seeds.` 且 N 与目录中文件数一致（不包含 `.meta`）。
- 触发一次 interesting 晋升后：
  - `workdir/queue/` 增加一个输入文件
  - 同目录存在 `<file>.meta`，并包含 `seed_type` 与调度字段键。

与 CLI 联动的最小验收：

- 使用 `--seeds /path/to/seeds` 启动，stdout 中应打印 `seeds = ...` 且实际加载的种子内容来自该目录（见 CLI 冒烟测试）。
