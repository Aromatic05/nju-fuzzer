# NJU 模糊测试工具 —— 架构说明（Coverage-Guided Fuzzer）

本文档描述 NJU-Fuzzer 的当前架构与各组件职责，面向实现与维护者。

**版本：** v2.1 (2026-01-14)  
**状态：** 主链路可用（选种 → 调度 → 变异 → 执行 → 覆盖反馈 → 入队 → 统计）

---

## 1. 架构总览

### 1.1 分层与职责

```
┌──────────────────────────────────────────────────────────┐
│                         CLI 层                           │
│  CliParser/FuzzerMain  负责参数解析、组件组装与启动       │
└──────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│                    Core 引擎层                           │
│  FuzzingEngine: 选种 → 调度 → 变异 → 执行 → 评估 → 入队   │
└───────────────┬───────────────────────────────┬──────────┘
                │                               │
                ▼                               ▼
      ┌──────────────────┐             ┌──────────────────┐
      │ ExecutorHarness  │             │  CoverageDB      │
      │ before/run/after │             │ global seen/top  │
      └───────┬──────────┘             └─────────┬────────┘
              │                                  │
              ▼                                  ▼
   ┌────────────────────┐              ┌────────────────────┐
   │ Executor (进程执行)│              │ Queue/Schedule     │
   │ ProcessExecutor    │              │ SeedQueue/Prior    │
   └────────────────────┘              │ PowerScheduler     │
                                       └────────────────────┘
                │                               │
                ▼                               ▼
   ┌────────────────────┐              ┌────────────────────┐
   │ CoverageMonitor    │              │ MutatorFactory     │
   │ Shm/Null/ShmEx      │              │ Havoc + 格式变异   │
   └────────────────────┘              └────────────────────┘
                          │
                          ▼
               ┌────────────────────┐
               │ Corpus/Stats       │
               │ queue/crash/hang   │
               │ stats.csv/curve.csv│
               └────────────────────┘
```

### 1.2 核心闭环（主流程）

```
seedQueue.loadInitialSeeds()  // 初始种子 + 兜底 dummy seed
harness.start()               // attach SHM once
calibrateInitialQueueSeeds()  // 覆盖基线（可选）

while (!timeUp) {
  seed = prioritizer.pick(seedQueue)
  energy = scheduler.assignEnergy(seed)
  for tc in mutator.mutate(seed, energy) {
    result = harness.execute(tc)
    classify crash/hang
    coverageUpdate = coverageDB.update(...)
    if (interesting) corpus.saveInteresting + seedQueue.add
    stats.tick()
  }
}

harness.close()
corpusManager.close()
```

---

## 2. 核心组件详解

### 2.1 CLI 与组装（FuzzerMain）

- 解析参数，构造 `TargetSpec`（命令模板、超时、环境变量）。
- 根据 `--coverage none|shm|shmex` 初始化覆盖监控器：
  - `none`：`NullCoverageMonitor`
  - `shm`：`ShmCoverageMonitor`
  - `shmex`：`ShmCoverageMonitorEx`（含 CoverageDB + stability 可选）
- 负责 workdir 目录初始化（queue/crashes/hangs/stats/tmp）。

### 2.2 FuzzingEngine（主循环）

- **加载种子**：`SeedQueue.loadInitialSeeds`，无种子时自动创建 dummy seed。
- **执行环境**：通过 `ExecutorHarness` 统一编排 `beforeRun → run → afterRun`。
- **覆盖基线**：若 CoverageDB 可用，对初始种子做一次校准，便于 favored/rarity 立即生效。
- **调度与变异**：`SeedPrioritizer` 选种，`PowerScheduler` 给能量，`Mutator` 生成测试用例。
- **异常判定**：`CrashOracle` 判定 crash；超时作为 hang。
- **入队与持久化**：由 `CorpusManager` 统一落盘并返回新 `Seed`。
- **统计与可观测性**：`StatusPrinter` 状态行 + `stats.csv` + `curve.csv`。
- **容错**：可选 fault-tolerant 模式，避免主循环因单次异常中断。

### 2.3 ExecutorHarness（执行抽象层）

- 统一插桩/非插桩路径：主循环不分支。
- 生命周期：`start()`/`close()` 包裹覆盖监控器资源。
- 顺序固定：`beforeRun → executor.run → afterRun`。

### 2.4 Executor（进程执行）

- `ProcessExecutor` 基于 `ProcessBuilder` 执行目标程序。
- 支持 STDIN/FILE 输入模式（`@@` 占位）。
- 三段超时处理（等待 → 终止 → 强杀），纳秒级计时。

### 2.5 CoverageMonitor / CoverageMonitorEx

- **基础模式**：`CoverageMonitor` 只提供 “是否 interesting”。
- **扩展模式**：`CoverageMonitorEx` 返回 `CoverageEx`，含 edge-level 信息供调度。
- **实现**：
  - `ShmCoverageMonitor` / `ShmCoverageMonitorEx` 读取 AFL++ SHM bitmap。
  - `NullCoverageMonitor` 用于无覆盖模式。
- **策略**：`CoverageDiffStrategy`/`CoverageDiffStrategyEx` 可插拔，支持 seen/nonzero、hash 过滤、组合策略。

### 2.6 CoverageDB（全局覆盖数据库）

- 维护 `globalSeen`、`edgeFrequency`、`topRated`、`favoredSet`。
- 提供 `UpdateResult`：新边、top-rated 变更、favored 更新。
- 为调度提供 **rarity / redundant / favored** 信号。

### 2.7 SeedQueue / SeedPrioritizer

- `SeedQueue` 管理内存种子列表与初始加载。
- `SeedPrioritizer` 结合 `favored/rarity/execTime/depth` 评分；兜底为轮询。

### 2.8 PowerScheduler（能量调度）

- 结合执行时间、seed 类型、尺寸、favored/rarity/unstable 等因素。
- 具备 “老种子衰减” 与 “新路径奖励” 机制。
- 可由 `FuzzStats` 提供全局平均执行时间阈值。

### 2.9 Mutator 体系

- **AFL 风格 Havoc**：通用位级变异（兜底与混合策略）。
- **格式/语法感知变异**：
  - 二进制：PNG/JPEG/ELF/PCAP
  - 文本/语法：XML/LUA/MJS/CXX
- `MutatorFactory` 根据 `SeedType` 选择合适 Mutator，并带有概率混合策略。

### 2.10 Corpus / Stats

- `CorpusManager` 统一负责 `queue/`、`crashes/`、`hangs/` 的落盘。
- `StatsWriter/StatsCurveWriter` 输出 exec/paths/crash/hang 等统计数据。
- `StatusPrinter` 负责实时状态行与事件日志。

---

## 3. 数据模型（核心 record/POJO）

- **Seed**：持久语料实体，带 `id/parentId/depth/handicap/favored/rarity/execTime` 等元数据。
- **Testcase**：一次变异产生的短命输入，附 mutation meta。
- **RunResult**：单次执行结果（exitCode、execTime、termination、timedOut）。
- **CoverageEx**：扩展覆盖快照（hit/new edges、hash、stability）。
- **ExecResult**：`RunResult + CoverageEx` 的统一返回结构。

---

## 4. 关键设计约定（边界契约）

1. **执行链路固定**：`beforeRun → run → afterRun` 不可重排。
2. **主循环不分支覆盖模式**：无覆盖用 `NullCoverageMonitor`。
3. **CoverageDB 是全局裁判**：favored/rarity/redundant 仅由 CoverageDB 维护。
4. **CorpusManager 唯一写盘入口**：避免多点写盘导致元数据不一致。
5. **Crash 判定可配置**：通过 `CrashOracle` 排除“非崩溃退出码”。

---

## 5. 包结构（当前实现）

```
edu.nju.fuzzing
├─ cli          # 命令行入口（FuzzerMain）
├─ core         # 主循环与执行抽象层
├─ exec         # 进程执行、输入模式、CrashOracle
├─ cov          # 覆盖监控、策略、CoverageDB
├─ queue        # SeedQueue
├─ schedule     # SeedPrioritizer / PowerScheduler
├─ mutate       # Havoc + 格式/语法感知变异
├─ corpus       # 语料库管理
├─ stats        # 统计与状态显示
├─ model        # 核心数据模型
└─ visualization# 可视化脚本
```

---

## 6. 文档索引

- `docs/ARCHITECTURE.md` - 架构总览（本文件）
- `docs/General.md` - 组件整合与主循环说明
- `docs/PROJECT.md` - 运行方法与使用说明

---

**最后更新：** 2026-01-14  
**维护者：** NJU Fuzzing Team
