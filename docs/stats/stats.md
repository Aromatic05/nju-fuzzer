# stats - 运行期统计与日志（Stats/Telemetry）模块文档

## 概述

`edu.nju.fuzzing.stats` 负责把 fuzzing 运行期的关键指标（执行次数、速度、覆盖、队列规模、paths/crash/hang 等）做三件事：

1. **聚合（FuzzStats）**：线程安全地维护计数与派生指标（exec/s、lastNewPathSecAgo）。
2. **展示（StatusPrinter）**：周期性在控制台打印单行状态 + 事件提示。
3. **落盘（StatsWriter）**：以 CSV 形式把 `StatsTick` 快照追加写入 `workdir/stats/stats.csv`，供离线分析。

本模块的设计目标是：主循环只负责调用 `recordXXX()`，其余展示/落盘细节解耦。

---

## 组件与职责

### 1) StatsTick（数据契约，位于 model 包）

- 位置：`edu.nju.fuzzing.model.StatsTick`
- 类型：`record`
- 职责：表示某一时刻的不可变统计快照，供 `StatusPrinter` 展示、`StatsWriter` 落盘。

#### 字段（当前实现）

- `targetName`：目标名称
- `elapsedSec`：已运行秒数（相对时间）
- `execsTotal`：累计执行次数
- `coveredEdges`：累计覆盖边数（通常由 CoverageDB/MonitorEx 提供）
- `execsPerSec`：近期执行速度（次/秒）
- `queueSize`：队列规模（内存队列或 corpus 队列大小）
- `totalPaths`：累计 interesting inputs 数量（paths）
- `crashes`：累计 crash
- `hangs`：累计 hang/timeout
- `lastNewPathSecAgo`：距离上次发现新路径的秒数

#### 重要说明：兼容构造器

`StatsTick` 额外提供一个**旧 9 参构造器**（不含 `totalPaths`），会把 `totalPaths` 默认填为 0，用于兼容旧测试/调用点。

---

### 2) FuzzStats（统计核心）

- 位置：`edu.nju.fuzzing.stats.FuzzStats`
- 职责：统计聚合与速率计算。

#### 线程安全

内部计数器使用 `AtomicLong/AtomicInteger`，允许：

- 主线程（FuzzingEngine）高频更新
- 后台线程（StatusPrinter）按秒读快照

#### 常用 API

- `recordExec()`：执行一次后调用
- `recordNewPath()`：发现 interesting 并入队后调用
- `recordCrash()` / `recordHang()`：分类后调用
- `updateCoveredEdges(int)`：同步覆盖总量（可由 CoverageDB/MonitorEx 提供）
- `toStatsTick(int queueSize)`：生成快照

---

### 3) StatusPrinter（控制台输出）

- 位置：`edu.nju.fuzzing.stats.StatusPrinter`
- 机制：`ScheduledExecutorService` 定时从 supplier 获取 `StatsTick` 并打印。
- 输出：
  - 周期性状态行：来自 `StatsTick.toStatusLine()`
  - 事件：`printEvent/printNewPath/printCrash/printHang`

---

### 4) StatsWriter（CSV 落盘）

- 位置：`edu.nju.fuzzing.stats.StatsWriter`
- 写入文件：通常为 `workdir/stats/stats.csv`

#### CSV Header（当前实现）

```
timestamp,target_name,exec_count,covered_edges,execs_per_sec,queue_size,total_paths,crash_count,hang_count
```

#### CSV 行格式（tick 一行）

```
elapsedSec,targetName,execsTotal,coveredEdges,execsPerSec,queueSize,totalPaths,crashes,hangs
```

> 说明：本实现的 `timestamp` 实际写入的是 `elapsedSec`（相对时间秒数），便于不同运行复现/对齐。

---

## 与 FuzzingEngine 的协作

`FuzzingEngine` 负责在正确的时机调用统计接口：

- 每次 `harness.execute(...)` 后：`fuzzStats.recordExec()`
- crash/hang 分类后：`recordCrash/recordHang` + 可选打印事件
- interesting input 晋升入队后：`recordNewPath()`
- CoverageDB 更新后（可选）：`updateCoveredEdges(coverageDB.getTotalEdgesSeen())`
- 周期性：
  - `StatusPrinter` 后台输出
  - `StatsWriter.tick(fuzzStats.toStatsTick(queueSize))` 追加写入

---

## 使用示例（简化）

```java
FuzzStats fuzzStats = new FuzzStats(targetSpec.tid());

try (StatsWriter writer = new StatsWriter(workdir.resolve("stats/stats.csv"))) {
    try (StatusPrinter printer = StatusPrinter.builder()
            .statsSupplier(() -> fuzzStats.toStatsTick(seedQueue.size()))
            .intervalSeconds(1)
            .build()) {
        printer.start();

        // fuzz loop...
        fuzzStats.recordExec();
        fuzzStats.recordNewPath();
        fuzzStats.recordCrash();
        fuzzStats.recordHang();

        writer.tick(fuzzStats.toStatsTick(seedQueue.size()));
    }
}
```

---

## 测试关注点

- `StatsWriterTest`：header 仅写一次、追加行格式正确、flush 行为可读
- `StatusPrinterTest`：`toStatusLine` 格式与事件输出
- `CorpusIntegrationTest`：paths/crash/hang 与 tick 字段一致

