## 整合组件概要

### 1) 核心数据模型

* **Seed（持久语料条目）**

  * `id, parentId, depth`
  * `dataRef/path, len`
  * `execTimeAvgNanos`
  * `bitmapSize/nonZeroBytes/edgeCount`（按你定义）
  * `favored, handicap, fuzzLevel, lastFuzzCycle`
  * （可选）`formatHint / semanticFeaturesRef / deterministicDoneMask`

* **Testcase（一次尝试，短命）**

  * `testcaseId`
  * `parentSeedId`
  * `inputRef`（stdin bytes 或 file path）
  * `mutationMeta`（stage/op/site/patch/splicePartner 等）

* **RunResult（执行结果）**

  * `execId, execTimeNanos, exitCode, timedOut, termination`
  * `stdoutFile/stderrFile`（可选落盘）
  * `inputFile`（仅 FILE 模式需要）

* **CoverageEx（覆盖快照，调度友好）**

  * `hitEdges, newEdges, bitmapHash`
  * `execTimeNanos, stable`
  * `interesting`（本地 diff 是否发现新覆盖，可选由 DB 最终裁决）

* **ExecResult（统一输出）**

  * `ExecResult(run: RunResult, coverage: CoverageEx)`

---

### 2) 组件分层与职责

#### A. 执行与覆盖（你现在的集成重点）

* **Executor（底层执行器，如 ProcessExecutor）**

  * 只负责启动进程、stdin/file 输入、timeout、stdout/stderr 重定向
  * 返回 `RunResult`

* **CoverageMonitor（覆盖采集器，如 ShmCoverageMonitor）**

  * `start()` attach SHM
  * `beforeRun()` 清零 bitmap
  * `afterRun(RunResult)` 读取 bitmap + 调用策略 diff -> `CoverageEx`（或 `DiffResultEx` 再包装）
  * `close()` detach SHM

* **ExecutorHarness（标准执行环境，组合 Executor + CoverageMonitor）**

  * `start()/close()`：转发到 CoverageMonitor（及必要初始化）
  * `execute(testcase)`：编排 `beforeRun -> executor.run -> afterRun`
  * 返回 `ExecResult`

> 无覆盖模式：把 `CoverageMonitor` 换成 `NullCoverageMonitor`，保持主循环不分支。

---

#### B. 调度与变异

* **QueueSelector（种子选择/排序）**

  * 从队列选择一个 `Seed`
  * favored 优先 / 随机加权 / queue cycle

* **PowerScheduler（能量调度）**

  * `Seed + CoverageDB/Stats -> MutationBudget`
  * 输出 `totalIters`、各 stage iter 分配、是否跳过 deterministic

* **Mutator（变异组件）**

  * `Seed + Budget -> Iterator<Testcase>`
  * 可混合：byte-level + 语义变异（format-aware/token/AST）

---

#### C. 全局覆盖与入队（决定“是否值得保存”）

* **CoverageDB（全局覆盖索引）**

  * 维护 `edgeFreq[]`
  * 维护 `topRated[edge] -> seedId`
  * 维护 `favoredSet`
  * `update(parentSeedId, coverageEx) -> CoverageUpdate`

    * `interesting`（最终入队判定）
    * `newEdges`（全局 virgin 意义的新边）
    * `favoredChanged`（可选）

* **CorpusManager（持久化/入队）**

  * `saveCrash/saveHang`
  * `saveInteresting(testcase, execResult, parentSeed) -> childSeed`
  * 负责写盘（queue/crashes/hangs）+ 初始化 childSeed 元数据

* **Stats/Telemetry**

  * exec/s、paths、crashes、hangs、queue size 等

---

## 主循环伪代码（包含 Harness/Monitor 启动时机）

> 这里以你“覆盖率监控集成到执行引擎（Harness）”的方案写。
> `harness.start()` 会 `monitor.start()` attach SHM；`harness.close()` detach。

```java
// ---- init ----
Executor baseExecutor = new ProcessExecutor();
CoverageMonitor monitor = new ShmCoverageMonitor(bitmapSource, diffStrategy);
// 或无覆盖模式：CoverageMonitor monitor = new NullCoverageMonitor(mapSize);

ExecutorHarness harness = new InstrumentedExecutorHarness(baseExecutor, monitor);

QueueManager queue = new QueueManager(initialSeeds);
CoverageDB covDb = new CoverageDB(mapSize);
QueueSelector selector = new QueueSelector(...);
PowerScheduler scheduler = new PowerScheduler(...);
Mutator mutator = new Mutator(...);
CorpusManager corpus = new FileCorpusManager(workdir);
Stats stats = new Stats(...);

// ---- start coverage env (attach SHM once) ----
harness.start();

try {
  while (shouldContinue()) {

    // 1) pick seed
    Seed parent = selector.select(queue, covDb, stats);

    // 2) compute energy / mutation budget
    MutationBudget budget = scheduler.computeBudget(parent, covDb, stats);

    // 3) generate testcases
    for (Testcase tc : mutator.mutate(parent, budget, mutCtx)) {

      // 4) execute + collect coverage (beforeRun/run/afterRun inside harness)
      ExecResult er = harness.execute(tc);
      
      // 5) handle abnormal terminations first
      if (er.run().termination() == Termination.TIMEOUT) {
        corpus.saveHang(tc, er, parent);
        stats.onHang(er);
        continue;
      }
      if (er.run().termination() == Termination.ERROR) {
        // 这里 ERROR 可能是 crash 或非零退出，取决于你 RunResult.Termination 设计
        corpus.saveCrash(tc, er, parent); // 或 saveError
        stats.onCrashOrError(er);
        continue;
      }

      // 6) update global coverage DB (freq/topRated/favored) + final interesting decision
      CoverageUpdate upd = covDb.update(parent.id(), er.coverage());

      // 7) persist interesting input and enqueue as new seed
      if (upd.interesting()) {
        Seed child = corpus.saveInteresting(tc, er, parent);
        queue.add(child);
        stats.onNewPath(child, upd);
      }

      // 8) update parent runtime stats (exec avg / fuzz level / cycle bookkeeping)
      parentStats.update(parent, er, upd);
      stats.onExec(er);
    }
  }
} finally {
  // ---- stop coverage env (detach SHM once) ----
  harness.close();
}
```

---

## 最重要的“边界约定”（确保后面不返工）

1. **ExecId 贯穿一致**：`RunResult.execId == CoverageEx.execId == Testcase.execId(如果你有)`
2. **Harness 负责顺序编排**：`beforeRun -> run -> afterRun` 固定，外层不再手动调 monitor
3. **CoverageDB 是 favored/topRated 的唯一来源**（避免策略里塞太多全局状态）
4. **CorpusManager 是唯一写盘入口**（避免多处写 queue/crash/hang 造成不一致）
5. **无覆盖模式用 NullCoverageMonitor**，主循环不写分支
