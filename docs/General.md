# 组件说明（Detailed Components Guide）

本文档面向实现与维护者，按“接口 → 功能 → 数据流”的粒度说明当前代码结构与关键行为。

---

## 1. 数据模型（model）

### 1.1 TargetSpec

**用途**：描述一个 fuzz target 的运行方式（命令模板、环境变量、超时）。

```java
public record TargetSpec(
    String tid,
    Path binary,
    List<String> argvTemplate,
    Map<String, String> env,
    Duration timeout
) {}
```

- `argvTemplate` 可包含 `@@` 占位符，决定 FILE 模式。
- `env` 由 CLI 注入（覆盖模式需要的 SHM 变量）。

### 1.2 Seed

**用途**：持久语料条目，进入队列并参与调度/变异。

- 关键字段：`id/parentId/depth/type/handicap/execTime/bitmapSize`。
- 调度提示字段：`favored/redundant/minEdgeFrequency/rarityScore/stability`。
- 元数据持久化：`saveMetadata()` 写入 `.meta` 文件。
- 加载入口：`loadWithMetadata(File, byte[], SeedType)`。

### 1.3 Testcase

**用途**：单次变异产物（短命 DTO）。

```java
public record Testcase(byte[] data, Seed parent, String description) {}
```

- `data` 为本次输入字节，`parent` 为父 seed 引用。

### 1.4 RunResult / ExecResult

**RunResult**：执行结果（进程级）。

```java
public record RunResult(
    long execId,
    Path inputFile,
    long execTimeMs,
    long execTimeNanos,
    int exitCode,
    boolean timedOut,
    Termination termination,
    Path stdoutFile,
    Path stderrFile
) {}
```

**ExecResult**：执行结果 + 覆盖快照。

```java
public record ExecResult(RunResult run, CoverageEx coverage) {}
```

### 1.5 CoverageEx

**用途**：扩展覆盖快照，用于全局覆盖统计与调度。

- `hitEdges/newEdges/bitmapHash` 提供 edge-level 信息。
- `stability` 指示覆盖稳定性（UNKNOWN/STABLE/UNSTABLE）。
- `interesting` 为本次 diff 的本地判定（最终入队由 CoverageDB 决定）。

---

## 2. CLI 入口与组装（cli）

### 2.1 CliParser

- 解析命令行参数并输出 `CliArgs`。
- 参数影响：`workdir/seeds/tid/cmd/coverage/seedType/timeout` 等。

### 2.2 FuzzerMain

**职责**：创建 TargetSpec、覆盖监控器、CoverageDB，最终启动 `FuzzingEngine`。

覆盖模式规则：

- `none`：`NullCoverageMonitor`，无覆盖反馈。
- `shm`：`ShmCoverageMonitor`，读取 AFL++ SHM bitmap。
- `shmex`：`ShmCoverageMonitorEx`，带 edge-level 覆盖与可选稳定性确认。

---

## 3. 主循环与执行抽象（core）

### 3.1 FuzzingEngine

**主流程**：

1. `SeedQueue.loadInitialSeeds()` 加载初始种子
2. `ExecutorHarness.start()` 启动覆盖环境（attach SHM）
3. 覆盖基线校准（覆盖 DB 可用时）
4. 进入主循环：选种 → 调度 → 变异 → 执行 → 评估 → 入队 → 统计

**关键交互点**：

- `SeedPrioritizer.pick()` 决定 parent seed。
- `PowerScheduler.assignEnergy()` 生成变异能量。
- `Mutator.mutate()` 产出 `Iterator<Testcase>`。
- `ExecutorHarness.execute()` 返回 `ExecResult`。
- `CoverageDB.update()` 给出最终是否 interesting。
- `CorpusManager.saveInteresting()` 返回新 seed 并入队。

### 3.2 ExecutorHarness

**接口**：

```java
void start() throws Exception;
ExecResult execute(ExecInput input) throws Exception;
void close();
```

**行为约束**：

- 顺序固定：`beforeRun → executor.run → afterRun`。
- 可透传扩展覆盖：若 `CoverageMonitorEx` 可用，返回 `CoverageEx`。

---

## 4. 执行器（exec）

### 4.1 Executor

```java
RunResult run(TargetCommand cmd, byte[] stdinData, Duration timeout, Path outDir);
```

### 4.2 ProcessExecutor

**功能**：

- 基于 `ProcessBuilder` 启动目标程序。
- 支持 STDIN/FILE 输入模式。
- 3 段超时策略：`wait → destroy → destroyForcibly`。
- 控制 stdout/stderr 输出策略（`nju.fuzzer.execLogs`）。

### 4.3 CommandResolver / TargetCommand

**CommandResolver**：

- 若 `argvTemplate` 含 `@@`，切换 FILE 模式并替换路径。
- 否则使用 STDIN 模式。

**TargetCommand**：

```java
public record TargetCommand(
    List<String> argv,
    InputMode inputMode,
    Path inputFile,
    Map<String, String> env
) {}
```

### 4.4 CrashOracle

- 默认 crash 判定：`exitCode > 128`。
- 可配置非 crash 退出码集合（避免误报）。

---

## 5. 覆盖监控与全局覆盖数据库（cov）

### 5.1 CoverageMonitor / CoverageMonitorEx

**CoverageMonitor**：

```java
void beforeRun();
Coverage afterRun(RunResult result);
void close();
```

**CoverageMonitorEx**：

```java
CoverageEx afterRunEx(RunResult result);
CoverageDB getCoverageDB();
boolean isStabilityDetectionEnabled();
```

**实现**：

- `ShmCoverageMonitor`：基础覆盖（bitmap diff）。
- `ShmCoverageMonitorEx`：扩展覆盖（edge-level + CoverageDB）。
- `NullCoverageMonitor`：无覆盖占位。

### 5.2 CoverageDB

**职责**：

- `globalSeen`：全局覆盖 bitmap。
- `edgeFrequency`：边命中频率。
- `topRated`：每条边的最优 seed。
- `favoredSet`：favored seeds 集合。

**核心 API**：

```java
UpdateResult update(long seedId, DiffResultEx diff, int inputSize, long execTimeNanos);
UpdateResult evaluate(DiffResultEx diff);  // 不修改状态，仅判断是否包含新边
```

---

## 6. 队列与调度（queue / schedule）

### 6.1 SeedQueue

- `loadInitialSeeds(Path dir, SeedType defaultType)`：递归加载初始种子。
- `addSeed(Seed seed)`：入队并写 `.meta`。
- `getSeeds()`：返回只读视图。

### 6.2 SeedPrioritizer

- 对每个 seed 计算综合分值（favored/rarity/execTime/depth/handicap）。
- 优先未 fuzzed seed；否则 round-robin。

### 6.3 PowerScheduler

- 依据执行时间、输入大小、seed 类型、favored/rarity/unstable、历史停滞等分配能量。
- `recordNewPathDuringRound()` + `recordRoundResult()` 用于反馈加权。

---

## 7. 变异体系（mutate）

### 7.1 Mutator 接口

```java
Iterator<Testcase> mutate(Seed seed, int energy);
```

### 7.2 MutatorFactory

- 根据 `SeedType` 返回具体变异器。
- 支持混合策略（一定概率强制 Havoc）。

### 7.3 变异器实现

- **通用 Havoc**：`AflHavocMutator`。
- **二进制结构变异**：`binary/`（PNG/JPEG/ELF/PCAP）。
- **语法感知变异**：`grammar/`（XML/LUA/MJS/CXX）。

---

## 8. 语料落盘与统计（corpus / stats）

### 8.1 CorpusManager

```java
Path saveToQueue(byte[] input, Coverage coverage);
Path saveCrash(byte[] input, RunResult result);
Path saveHang(byte[] input, RunResult result);
CorpusStats stats();
```

**FileCorpusManager**：默认磁盘实现，输出路径 `queue/`、`crashes/`、`hangs/`。

### 8.2 FuzzStats / StatsWriter / StatsCurveWriter

- `FuzzStats`：
  - `recordExec(long execTimeNanos)` 统计执行次数与平均耗时。
  - `recordNewPath()/recordCrash()/recordHang()` 统计路径与异常。
- `StatsWriter`：输出 `stats.csv`（每 tick 一行）。
- `StatsCurveWriter`：输出 `curve.csv`（按秒或自定义桶汇总增量）。

### 8.3 StatusPrinter

- 周期打印状态行（`StatsTick.toStatusLine()`）。
- 提供 `printEvent/printCrash/printHang` 等事件输出。

---

## 9. 可视化组件（visualization）

> 这些脚本为离线分析工具，不参与 fuzzing 主循环。

### 9.1 visualization/visualize.py

- 输入：当前目录 `stats.csv`（单目标）。
- 输出：
  - `coverage_<target>.png`
  - `execs_per_sec_20min_avg.png`
  - `final_coverage.png`

### 9.2 visualization/visualize_totally.py

- 输入：`./<target>/stats.csv` 多目标并排目录。
- 输出：
  - `coverage_all_targets.png`
  - `final_coverage_comparison.png`

### 9.3 visualization/vertical.py

- 输入：`./<config>/<target>/stats.csv` 多配置纵向对比。
- 输出：
  - `coverage_vertical_<target>.png`
  - `final_coverage_vertical_<target>.png`

---

## 10. 边界约定（保持一致性）

1. **执行顺序固定**：`beforeRun → run → afterRun`。
2. **覆盖模式不分支**：无覆盖使用 `NullCoverageMonitor`。
3. **CoverageDB 是全局裁判**：favored/rarity/redundant 只由 CoverageDB 维护。
4. **CorpusManager 唯一写盘入口**：避免多处写盘导致元信息分裂。
5. **Crash 判定可配置**：`CrashOracle` 可排除非 crash 退出码。
