# FuzzingEngine - 主循环（闭环编排）模块文档

## 概述

`FuzzingEngine` 是 NJU Fuzzer 的“主循环编排器”，负责把已有的基础组件（种子队列、调度、变异、执行/覆盖、语料落盘、统计）串成一个可持续运行的闭环：

- 选种（Seed selection）
- 能量分配（Power scheduling）
- 变异生成（Mutation）
- 执行与覆盖收集（Execution + Coverage）
- 结果分类（normal/crash/hang）
- interesting 晋升（persist + enqueue）
- 统计与监控（StatusPrinter + stats.csv）

它的目标不是实现所有策略细节，而是保证“数据流正确、资源生命周期正确、输出结构可复现”。

---

## 位置与入口

- 代码位置：`src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java`
- 典型启动路径：CLI `FuzzerMain` 解析参数 → 构造 `TargetSpec` → 构造/组装 `FuzzingEngine` → `engine.run()`

CLI 入口与参数含义见：[docs/CLI/CLI.md](../CLI/CLI.md)。

---

## 依赖与协作关系

`FuzzingEngine` 采用依赖注入（DI）方式组装核心组件；同时为了兼容测试/CLI，也提供“旧构造器重载”自动组装默认组件。

### 核心依赖（DI 构造器）

- `ExecutorHarness`：统一执行环境（封装 `beforeRun -> executor.run -> afterRun`）
- `SeedQueue`：内存种子队列容器（初始 seeds + 新种子入队；见 `docs/Queue/SeedQueue.md`）
- `SeedPrioritizer`：种子选择策略（优先未 fuzz 过的种子，否则兜底轮询；见 `docs/schedule/Scheduling.md`）
- `PowerScheduler`：能量调度（根据 Seed 元数据与可选 CoverageDB 信号分配 energy；见 `docs/schedule/Scheduling.md`）
- `Mutator`：根据 seed + energy 生成 `Iterator<Testcase>`
- `CorpusManager`：将 inputs 持久化到 `queue/crashes/hangs`
- `CoverageDB`（可选）：全局覆盖数据库（edgeFreq/topRated/favored/redundant/rarity；需要 edge-level 覆盖数据）
- `FuzzStats`：实时统计（execs、paths、crash/hang、coveredEdges 等）

### 协作数据流（简图）

```
SeedQueue -> SeedPrioritizer -> PowerScheduler -> Mutator -> Testcase
                                                |
                                                v
                                   buildExecInput(TargetSpec, Testcase)
                                                |
                                                v
                                      ExecutorHarness.execute(ExecInput)
                                                |
                                                v
                                         ExecResult(run + coverage)
                                                |
      +-------------------------+---------------+-------------------+
      |                         |                                   |
   crash -> CorpusManager.saveCrash()         hang -> saveHang()   normal
                                                                        |
                                                           interesting? (CoverageEx.interesting)
                                                                        |
                                                           saveToQueue() + new Seed + enqueue
```

---

## 关键数据模型（与主循环关系最紧密）

- `TargetSpec`：描述目标程序运行方式（argvTemplate/env/timeout），支持 `@@` 文件模式和 STDIN 模式
- `Testcase`：一次执行的输入（`byte[] data`）、父种子引用（`Seed parent`）、变异描述（`description`）
- `ExecInput`：一次执行的“执行参数封装”（`TargetCommand + stdinData + timeout + outDir + saveLogs`）
- `ExecResult`：一次执行的统一输出（`RunResult + CoverageEx`）
- `CoverageEx`：覆盖快照（interesting、nonZeroBytes、bitmapHash、可选 hitEdges/newEdges、execTimeNanos）
- `Seed`：队列条目，除基本血缘/统计外，还会承载调度提示字段（favored/rarity/redundant/minEdgeFreq/stability 等），并写入 `<seed>.meta` 以便复用

---

## 主循环行为定义（run 方法）

### 1) 目录与运行态输出

启动时会确保创建（或存在）：

- `workdir/stats/stats.csv`：统计 CSV
- `workdir/tmp/exec-logs/`：执行 stdout/stderr（默认仅在“晋升为 interesting”时保存，且仅保存非空输出）

> 注意：为了避免长跑写爆 inode，FILE 模式下当前实现复用单个 `.cur_input`（每次覆盖写），不会产生海量 inputs 小文件。
>
> `.cur_input` 默认不会写到 workdir：引擎会优先使用 `/dev/shm`（tmpfs）。严格模式（默认开启）下，若无法使用 tmpfs，将 fail-fast，避免磁盘落盘。

### 2) 初始种子加载

- 优先从 `initialSeedDir` 加载种子（通过 `SeedQueue.loadInitialSeeds()`；该目录由 CLI `--seeds` 或默认 `workdir/seeds` 提供）
- 如果加载为 0：自动生成一个 dummy seed（payload 为 `hello-from-engine`）并入队，保证循环可跑

### 3) 生命周期管理

- `harness.start()`：在 fuzzing 开始前调用一次（插桩目标 attach SHM 等）
- 如果 `CoverageDB` 可用：启动后会对初始队列做一次“基线校准执行”，填充全局 seen/topRated/frequency，并同步 favored/rarity/redundant 等提示字段
- `statusPrinter.start()`：后台定时打印状态
- finally 里统一 `statusPrinter.stop()`、`harness.close()`、`corpusManager.close()`

### 4) 循环退出条件

- 以 wall-clock 秒为准：运行超过 `durationSec` 即退出

### 5) 单轮迭代逻辑（简化描述）

1. `Seed parent = prioritizer.pick(seedQueue.getSeeds())`
2. `int energy = scheduler.assignEnergy(parent)`
3. `Iterator<Testcase> it = mutator.mutate(parent, energy)`
4. 对每个 testcase：
   - `ExecInput input = buildExecInput(spec, tc, .cur_input, execLogsDir)`
   - `ExecResult r = harness.execute(input)`
   - `fuzzStats.recordExec()`
   - crash/hang：分别落盘到 `crashes/`、`hangs/` 并更新统计
   - normal：若 `r.coverage().interesting()` 为 true，则进入“晋升判定”
    - 可选全局确认（CoverageDB.evaluate）：当 `CoverageDB` 可用且 `hitEdges` 非空时，只在存在“全局新边”时才晋升，避免局部 diff 误判
    - 可选稳定性确认（stability rerun）：当启用稳定性检测且 `hitEdges` 非空时，对候选输入额外重复执行少量次数并标记 `STABLE/UNSTABLE/UNKNOWN`
     - 晋升落盘：`CorpusManager.saveToQueue(tc.data, r.coverage().toBasic())`
     - 构造 `Seed` 并写回元数据（execTime/bitmapSize/edges/stability 等），再 `seedQueue.addSeed(newSeed)`
     - 更新统计：`fuzzStats.recordNewPath()`
     - 若有 edge-level 数据且 `CoverageDB` 可用：`CoverageDB.update(...)` 更新 freq/topRated/favored，并把 favored/rarity/minFreq/redundant 同步回 Seed（favored 变化时会刷新全队列提示字段）

---

## buildExecInput：STDIN/FILE 模式与性能约束

`buildExecInput` 的职责是把 `TargetSpec + Testcase` 转为 `ExecInput`：

- 如果 argvTemplate 含 `@@`：
  - 走 FILE 模式：把 testcase bytes 覆盖写入固定文件 `.cur_input`（位于 tmpfs 优先的 tmpInputsDir），并把该路径替换给 `@@`
  - `stdinData=null`
- 否则：
  - 走 STDIN 模式：`stdinData = testcase.data`，默认不写 `.cur_input`
  - 如需把 STDIN 也落为 `.cur_input`（调试/复现），可设置 `-Dnju.fuzzer.persistTmpInputs=true`

这样做有两个目的：

1. 支持 `@@` 文件输入模式（很多目标只支持 file 输入）
2. 避免为每次执行创建独立临时文件导致 inode/磁盘耗尽

补充：stdout/stderr 默认不会为每次执行落盘。默认策略是 `-Dnju.fuzzer.execLogs=interesting`，仅在输入被确认“晋升为 interesting”时，由引擎进行一次 best-effort 二次执行抓 stdout/stderr，并写到 `workdir/tmp/exec-logs`（且仅保存非空输出）。

---

## 与 CoverageMonitorEx / CoverageDB 的关系（重要）

- `FuzzingEngine` 本身只依赖 `ExecutorHarness`，不直接依赖具体 monitor 类型。
- `CoverageDB` 的来源有两种：
  - **显式注入**：CLI/测试构造器直接传入 `CoverageDB`。
  - **从 monitor 获取**：当 `ExecutorHarness` 为 `InstrumentedExecutorHarness` 且其 monitor 为 `CoverageMonitorEx` 时，引擎会优先使用 `monitor.getCoverageDB()`（避免出现“接口存在但闲置”的情况）。

- 是否能更新 `CoverageDB` 取决于 `ExecResult.coverage()` 是否携带 edge-level 信息：
  - 当底层 monitor 是 `CoverageMonitorEx` 时，Harness 会返回含 `hitEdges/newEdges/bitmapHash` 的 `CoverageEx`，引擎才能进行全局确认与 DB 更新。
  - 当 monitor 仅提供 basic coverage 时，`CoverageEx.hitEdges/newEdges` 为空；此时引擎会跳过 CoverageDB 相关逻辑，保持可运行。

当前实现的“基础 SHM monitor”也已升级为 `CoverageMonitorEx`：即使是 `--coverage shm`，也会通过 `CoverageDiffStrategyEx.wrap(...)` 从 bitmap 中提取 `hitEdges/newEdges`（把非零 byte 下标视作 edge index），从而让 CoverageDB 在基础路径下也能工作。

相关代码：

- [src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitor.java](../../src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitor.java)
- [src/test/java/edu/nju/fuzzing/cov/ShmCoverageMonitorTest.java](../../src/test/java/edu/nju/fuzzing/cov/ShmCoverageMonitorTest.java)

注意：`--coverage shmex` 的 monitor 自带 CoverageDB；`--coverage shm` 的 monitor 不持有 CoverageDB（由 CLI/引擎创建与持有）。

---

## 统计与输出（与 stats 模块的契约）

- `FuzzStats` 是引擎中统计的唯一来源：
  - `recordExec()`：每次 execute 后调用
  - `recordNewPath()`：每次保存 interesting input 后调用
  - `recordCrash()/recordHang()`：分类后调用
  - `updateCoveredEdges()`：在 CoverageDB 更新后同步（可选）
- `StatsWriter`：把 `StatsTick` 追加写入 `workdir/stats/stats.csv`
- `StatusPrinter`：周期性打印 `StatsTick.toStatusLine()`

CSV 的字段定义以 `docs/stats/stats.md` 为准。

---

## 已知限制与扩展点

### 已知限制（当前实现刻意简化）

- interesting 判定主要依赖 `CoverageEx.interesting()`（本地 diff/策略），全局裁判（CoverageDB）只在 edge-level 数据可用时参与。
- `ExecInput.saveLogs` 当前不作为 stdout/stderr 落盘开关使用；日志落盘由系统属性 `nju.fuzzer.execLogs` 控制。
- 在默认 `execLogs=interesting` 策略下，日志是在“晋升为 interesting 时”的二次执行中抓取的，因此 `tmp/exec-logs` 文件数量与晋升次数近似成正比（每次晋升通常 1~2 个文件）。

---

## 运行期关键系统属性（IO/可观测性）

- `-Dnju.fuzzer.execLogs=interesting|all|none`
- `-Dnju.fuzzer.execLogsMaxBytes=<bytes>`（默认 1MB）
- `-Dnju.fuzzer.tmpInputsDir=<path>`（覆盖 `.cur_input` 目录，仅 FILE 模式需要）
- `-Dnju.fuzzer.requireTmpfsInputs=true|false`（默认 true；true 时强制 tmpfs）
- `-Dnju.fuzzer.persistTmpInputs=true|false`（默认 false；STDIN 是否也写 `.cur_input`）
- `-Dnju.fuzzer.curveBucketSec=<sec>`（默认 1；曲线分桶）
- `-Dnju.fuzzer.statsFlushEvery=<N>`（默认 100；stats/curve 的 flush 批次）
- 缺少 AFL++ 风格的阶段化变异（deterministic/havoc/splice）编排；目前由 `Mutator` 自己决定生成策略。

变异接线说明（当前默认行为）：

- 引擎默认 mutator 会对每个 parent seed **先执行 1 次 identity**（便于 baseline/可观测性），再把剩余 energy 交给基于 `SeedType` 选择出来的 mutator。
- `SeedType.UNKNOWN` 或按概率混合时，会回退到 Havoc 变异。
- 当前默认 mutator 工厂为“构造器友好”版本：为了避免引擎初始化时强绑定 live corpus，Havoc 的 splice corpus 以空列表构造（偏确定性、便于测试）。
- 当 `CoverageDB` 可用时，会额外做“初始 seeds 校准”和“interesting 稳定性确认”，这会增加一定执行开销；当前以可解释/可复现优先。

### 扩展点

- 更换/增强 `SeedPrioritizer`：favored、round-robin、随机加权、cull queue
- 更换 `PowerScheduler`：引入 CoverageDB rarity/topRated/favored
- 更换 `Mutator`：按 `SeedType`（XML/PNG/PCAP…）选择语法变异器，混合 havoc
- 调整 stability rerun：控制重跑次数、只对特定类型/阈值的候选触发，或在资源受限时关闭
- crash 去重/最小化：基于 stack signature / stdout/stderr / asan 等

---

## 测试与验收点

与 `FuzzingEngine` 直接相关的测试通常关注：

- workdir 结构创建：`stats/stats.csv`、`tmp/inputs`、`tmp/exec-logs`
- STDIN 模式能执行并在 stdout 中看到期望内容（例如 `/bin/cat` 回显）
- FILE 模式（含 `@@`）能创建输入文件并完成执行
- crash/hang 能落盘到 corpus 目录并更新计数

与 CLI 联动的验收：

- 见 [docs/CLI/CLI.md](../CLI/CLI.md) 的“快速开始”与对应 smoke tests。

---
