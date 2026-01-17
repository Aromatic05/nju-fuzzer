## 全量开发日志

# 开发日志（2025-12-24）

> 主题：把“能真实跑起来”的闭环补齐：共享内存 attach 修复、覆盖路径可选、基础 monitor 产出 edge-level、CoverageDB 全局确认、调度增强、Mutator 接线，并补齐 queue/schedule/CLI/engine 文档与验收点。

## 1. 今日工作总览（按目标分组）

### A. 共享内存路径可用（真实跑 AFL++ 插桩目标的前提）

目标：修复 SHM attach 的关键问题，确保通过 `InstrumentedExecutorHarness.start()` 走启动路径时不会出现“Not attached”。

落点：

- [src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitorEx.java](../../src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitorEx.java)
  - `fromEnvironment()`：修复 SysVShmBitmapSource 参数顺序（`shmId/mapSize`），并在构造后立即 `attach()`。
  - `start()`：当 bitmapSource 是 SysV SHM 且未 attach 时补 `attach()`。

### B. 调度更强且确定性（排序 + 能量）

目标：在不引入随机性、可复现的前提下，让“未 fuzz 种子”阶段真正挑出最优者；并让能量分配更贴近真实跑的效率。

落点：

- [src/main/java/edu/nju/fuzzing/schedule/SeedPrioritizer.java](../../src/main/java/edu/nju/fuzzing/schedule/SeedPrioritizer.java)
  - 保留框架：优先未 fuzz；否则 RR。
  - 未 fuzz 选择：从“遇到第一个就返回”升级为“确定性打分选最高”。
  - 打分包含：bitmapSize、execTime（软惩罚）、depth（偏好浅层）、handicap（新种子加成）
  - CoverageDB 提示（当存在）：favored/rarity/minFreq/redundant/stability。
  - 同分稳定：只在 `s > bestScore` 时更新 best（不使用 `>=`）。

- [src/main/java/edu/nju/fuzzing/schedule/PowerScheduler.java](../../src/main/java/edu/nju/fuzzing/schedule/PowerScheduler.java)
  - 在原公式基础上新增：输入大小因子、类型因子（SeedType 可识别轻微加成）。
  - 继续叠加 CoverageDB 信号：favored 增益、redundant/unstable 衰减、rarity/minFreq 增益且封顶。

### C. Mutator 接线入主循环 + 测试 UTF-8 读取问题

目标：默认运行路径要真实连接 MutatorFactory（identity + 剩余能量变异）；同时修复测试在某些环境下用 UTF-8 读取 stdout 可能失败的问题。

落点：

- [src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java](../../src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java)
  - 默认 mutator：每个 seed 先跑 1 次 identity，再把剩余能量交给按 SeedType 选出的 mutator。
- [src/test/java/edu/nju/fuzzing/core/FuzzingEngineTest.java](../../src/test/java/edu/nju/fuzzing/core/FuzzingEngineTest.java)
- [src/test/java/edu/nju/fuzzing/cli/FuzzerMainCmdSmokeTest.java](../../src/test/java/edu/nju/fuzzing/cli/FuzzerMainCmdSmokeTest.java)
  - 测试读取 stdout：从 `Files.readString(..., UTF_8)` 改为 `readAllBytes()` + 子序列搜索（只影响测试，不改变运行行为）。

### D. “基础 monitor 路径下 CoverageDB 跑不起来”修复

目标：让基础 SHM 覆盖路径也能产出 edge-level 的 hit/new，使引擎侧 `CoverageDB.update()` 能被触发。

落点：

- [src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitor.java](../../src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitor.java)
  - `ShmCoverageMonitor` 升级实现 `CoverageMonitorEx` 并提供 `afterRunEx()`。
  - 用 `CoverageDiffStrategyEx.wrap(diffStrategy, mapSize)` 从 bitmap 提取 `hitEdges/newEdges`（非零 byte 下标视作 edge index）。
- [src/test/java/edu/nju/fuzzing/cov/ShmCoverageMonitorTest.java](../../src/test/java/edu/nju/fuzzing/cov/ShmCoverageMonitorTest.java)
  - 新增用例验证 `afterRunEx()` 返回非空 hitEdges/newEdges。

### E. 晋升逻辑：局部 interesting + 全局确认（避免误判）

目标：避免仅依赖局部 diff 策略的“误判晋升”，引入 CoverageDB 的无副作用全局确认。

落点：

- [src/main/java/edu/nju/fuzzing/cov/CoverageDB.java](../../src/main/java/edu/nju/fuzzing/cov/CoverageDB.java)
  - 增加 `evaluate(DiffResultEx)`：只读取 `globalSeen` 计算 truly-new edges，不修改 DB 状态。
- [src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java](../../src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java)
  - `handleNormalExecution`：先 local interesting，再 `coverageDB.evaluate` 全局确认；只有 truly-new 才晋升。

### F. CLI：运行时可选 coverage（none|shm|shmex）+ 可指定 seeds

目标：把原先“写死在代码里”的 coverage/seeds 变为最小 CLI 开关，默认仍保持兼容（none 可跑）。

落点：

- [src/main/java/edu/nju/fuzzing/cli/CliArgs.java](../../src/main/java/edu/nju/fuzzing/cli/CliArgs.java)
- [src/main/java/edu/nju/fuzzing/cli/CliParser.java](../../src/main/java/edu/nju/fuzzing/cli/CliParser.java)
  - 新增解析：`--seeds`（默认 `workdir/seeds`）、`--coverage`（默认 `none`）。
- [src/main/java/edu/nju/fuzzing/cli/FuzzerMain.java](../../src/main/java/edu/nju/fuzzing/cli/FuzzerMain.java)
  - `--coverage none`：Null monitor。
  - `--coverage shm|shmex`：
    - 若环境已有 `__AFL_SHM_ID`：使用环境并透传 env。
    - 若环境无 `__AFL_SHM_ID`：自动创建 SysV SHM 段并注入到子进程 env。
  - `shmex` 默认开启稳定性确认（`setStabilityDetectionEnabled(true)`）。

对应测试：

- [src/test/java/edu/nju/fuzzing/cli/FuzzerMainCmdSmokeTest.java](../../src/test/java/edu/nju/fuzzing/cli/FuzzerMainCmdSmokeTest.java)
  - 覆盖 `--seeds` 覆盖、非法 `--coverage` fail-fast。

### G. SysV SHM 段管理器：自动创建并退出清理

目标：在没有 AFL++ 外部管理 SHM 的场景下，CLI 自己创建 SHM 并在退出时清理。

落点：

- [src/main/java/edu/nju/fuzzing/cov/SysVShmSegment.java](../../src/main/java/edu/nju/fuzzing/cov/SysVShmSegment.java)
  - `shmget(IPC_PRIVATE, size, IPC_CREAT|0600)` 创建段。
  - 退出时 `shmctl(IPC_RMID)` 标记删除。
- [src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitorEx.java](../../src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitorEx.java)
  - 新增 `create(shmId, mapSize)`，支持不依赖环境变量 attach。

### H. CoverageDB → Seed → 调度消费闭环 + 稳定性字段落地

目标：让 CoverageDB 的 favored/topRated/rarity/isRedundant 等能力变成可被调度消费的“信号”，并让 stability 字段在主循环里被真实计算。

落点：

- [src/main/java/edu/nju/fuzzing/model/Seed.java](../../src/main/java/edu/nju/fuzzing/model/Seed.java)
  - 新增并持久化：favored/redundant/min_edge_freq/rarity_score/stability。
- [src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java](../../src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java)
  - 覆盖 DB 来源：注入为空时优先复用 `CoverageMonitorEx.getCoverageDB()`。
  - 初始 seeds 校准：填充 globalSeen/topRated/frequency，让提示字段从第一轮开始生效。
  - 晋升后同步提示字段；favored 变化时刷新全队列提示。
  - 在开关开启时做重复执行确认，标注 STABLE/UNSTABLE/UNKNOWN。

对应测试：

- [src/test/java/edu/nju/fuzzing/schedule/SeedPrioritizerTest.java](../../src/test/java/edu/nju/fuzzing/schedule/SeedPrioritizerTest.java)
- [src/test/java/edu/nju/fuzzing/schedule/PowerSchedulerTest.java](../../src/test/java/edu/nju/fuzzing/schedule/PowerSchedulerTest.java)
- [src/test/java/edu/nju/fuzzing/cov/CoverageDBTest.java](../../src/test/java/edu/nju/fuzzing/cov/CoverageDBTest.java)

---

## 2. 文档更新（模块文档补齐）

- Queue 模块：[docs/Queue/SeedQueue.md](../Queue/SeedQueue.md)
- Schedule 模块：[docs/schedule/Scheduling.md](../schedule/Scheduling.md)
- Engine 模块：[docs/Engine/FuzzingEngine.md](../Engine/FuzzingEngine.md)
- CLI 模块（新增）：[docs/CLI/CLI.md](../CLI/CLI.md)

---

## 3. 验证与复现（本日可重复执行的命令）

### 3.1 单测

- `mvn -q test`

### 3.2 冒烟运行（无覆盖，任何机器可跑）

- `mvn -q -DskipTests exec:java -Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain -Dexec.args="--workdir /tmp/nju-fuzzer-smoke/workdir --seeds /tmp/nju-fuzzer-smoke/seeds --duration 1 --timeout 500 --tid SMOKE --cmd /bin/cat --coverage none"`

期望观察：

- 打印 workdir/seeds/coverage 参数。
- 生成 workdir 结构：`queue/ crashes/ hangs/ stats/stats.csv tmp/inputs tmp/exec-logs`。

---

## 4. 风险与已知差距（不阻塞运行）

- exec-logs 小文件增长：`ProcessExecutor` 每次执行会写 `stdout_<id>.log/stderr_<id>.log` 到 `tmp/exec-logs/`，长跑可能写爆 inode/磁盘。
- CLI 解析器简化：`CliParser` 按 `key value` 成对解析，不支持复杂 GNU flag 语法。
- 稳定性确认与初始校准开销：在 `shmex` 与 CoverageDB 可用场景下会增加执行次数；若追求吞吐，可提供进一步阈值/开关。

# 开发日志（2025-12-31）

> 主题：补齐“一键跑目标 + 运行时曲线统计 + 更合理的 crash 判定”闭环。

## 1. 今日变更概览（按功能分组）

### A. 新增一键运行脚本（单参数）

目标：用一条命令启动 fuzz，且运行产物不互相覆盖。

落点：

- [one_click.sh](../../one_click.sh)
  - 仅接受一个参数：目标程序名（例如 `mjs`/`lua` 等）
  - 目标程序路径固定：`./env/out/<program>`
  - 种子目录：脚本内部做 program→ID 映射后使用 `./env/seeds/<ID>/`
  - workdir：`./workdir/<program>/<YYYYMMDD-HHMMSS>-<pid>/`（每次运行独立目录）
  - 曲线分桶：通过 JVM 系统属性 `-Dnju.fuzzer.curveBucketSec=$CURVE_BUCKET_SEC` 传入

### B. 运行时记录覆盖率增长曲线（curve.csv）

目标：运行过程中按时间分桶记录覆盖增长与增量指标，便于画曲线与对比不同运行。

落点：

- [src/main/java/edu/nju/fuzzing/stats/StatsCurveWriter.java](../../src/main/java/edu/nju/fuzzing/stats/StatsCurveWriter.java)
  - 新增 writer：输出 `stats/curve.csv`
  - 支持 `bucketSeconds`（秒级分桶，默认 1 秒）
  - 记录累计值 + 桶内增量：`new_edges/new_paths/new_execs/new_crashes/new_hangs`

- [src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java](../../src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java)
  - 引擎中创建并 tick `StatsCurveWriter`
  - 通过系统属性 `nju.fuzzer.curveBucketSec` 控制分桶间隔

说明：`curve.csv` 使用 append 模式；格式/表头升级后建议使用新的 workdir（或删除旧文件）以避免旧表头残留。

### C. crash 判定策略调整：退出码 > 128 视为 crash

目标：避免把“输入被拒绝导致的非 0 退出码”误当成 crash；仅把“信号类异常退出”统计为 crash。

落点：

- [src/main/java/edu/nju/fuzzing/exec/CrashOracle.java](../../src/main/java/edu/nju/fuzzing/exec/CrashOracle.java)
  - 默认规则：`exitCode > 128` 视为 crash（shell 约定 `exitCode = 128 + signal`，如 139=SIGSEGV）
  - 默认忽略 `130/143`（SIGINT/SIGTERM），避免手动中断污染 crash 统计
  - 仍支持 CLI 传入 `--nonCrashExitCodes` 扩展白名单

### D. 长跑 IO 优化：只为晋升输入保存 stdout/stderr + 避免空文件

目标：产生了大量的小文件甚至是空文件，由于文件系统簇大小的问题，300多MB的数据实际占用了6个GB的空间，这仅仅是一个他日get一个小时跑出来的结果。这次优化是为了解决长跑下 `workdir/tmp` 生成大量小文件的问题，同时保留对复现/triage 有价值的输出。

落点：

- [src/main/java/edu/nju/fuzzing/exec/ProcessExecutor.java](../../src/main/java/edu/nju/fuzzing/exec/ProcessExecutor.java)
  - `-Dnju.fuzzer.execLogs=interesting|all|none`（默认 `interesting`）
  - `all` 模式下使用 PIPE 捕获 stdout/stderr，并且 **仅当非空时才落盘**（避免 0 字节文件）
  - 增加 `-Dnju.fuzzer.execLogsMaxBytes=<bytes>`（默认 1MB）防止异常输出导致内存/磁盘压力

- [src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java](../../src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java)
  - 默认 `execLogs=interesting`：普通执行不保存 stdout/stderr
  - 当 testcase 被确认晋升（interesting 入队）时，best-effort 二次执行并临时切 `execLogs=all` 抓取 stdout/stderr，写入 `workdir/tmp/exec-logs/`

### E. 临时输入 `.cur_input` 不写磁盘（tmpfs 优先 + 严格模式）

目标：在 FILE 模式（`@@`）下复用 `.cur_input` 的同时，确保默认不会落到磁盘目录。

落点：

- [src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java](../../src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java)
  - 默认 `.cur_input` 写入 `/dev/shm`（tmpfs）
  - `-Dnju.fuzzer.requireTmpfsInputs=true|false`（默认 true）：开启时若 tmpfs 不可用则 fail-fast，避免回退到 `workdir/tmp/inputs`
  - STDIN 模式默认不写 `.cur_input`；如需落盘调试可设置 `-Dnju.fuzzer.persistTmpInputs=true`

### F. stats/curve 写入减少 flush（降低 IO）

目标：避免每 tick flush 导致频繁 IO。

落点：

- [src/main/java/edu/nju/fuzzing/stats/StatsWriter.java](../../src/main/java/edu/nju/fuzzing/stats/StatsWriter.java)
- [src/main/java/edu/nju/fuzzing/stats/StatsCurveWriter.java](../../src/main/java/edu/nju/fuzzing/stats/StatsCurveWriter.java)
  - `-Dnju.fuzzer.statsFlushEvery=<N>`（默认 100；<=0 表示仅 close 时 flush）
  - `close()` 幂等，避免重复 close 触发异常

## 2. 文档更新（模块文档同步）

- CLI 文档补充：
  - [docs/CLI/CLI.md](../CLI/CLI.md)（新增 `stats/curve.csv` 说明 + `one_click.sh` 使用方式）

- Executor 模块文档补充：
  - [docs/ExecutorHarness/Executor.md](../ExecutorHarness/Executor.md)（强调 crash 判定由 `CrashOracle` 统一处理，非 0 不等价于 crash）

- IO/统计策略同步：
  - [docs/Engine/FuzzingEngine.md](../Engine/FuzzingEngine.md)
  - [docs/stats/stats.md](../stats/stats.md)
  - [docs/ExecutorHarness/ExecutorHarness.md](../ExecutorHarness/ExecutorHarness.md)

## 3. 验证

- 单测：`mvn -q test`
- 一键运行：`bash one_click.sh <program>`（产物在 `./workdir/<program>/<run-id>/` 下）

运行期常用 JVM 参数示例（保持脚本单参数原则时可按需添加）：

- 减少 stats flush：`-Dnju.fuzzer.statsFlushEvery=1000`
- 禁止每次执行保存日志（默认已是）：`-Dnju.fuzzer.execLogs=interesting`
- 限制 stdout/stderr 捕获：`-Dnju.fuzzer.execLogsMaxBytes=1048576`

---

### 10.1 CoverageMonitor DevLog（Iterations 1-5）

来源：`docs/CoverageMonitor/DevLog.md`

- ✅ Iterations 1-3（基础覆盖监控 → 策略增强 → corpus/统计）
  - Iteration 1：AFL++ SHM 覆盖率监控
    - BitmapSource 抽象接口
    - SysVShmBitmapSource（JNA）读取 System V 共享内存
    - SeenNonZeroStrategy：基于“全局 seen”的差分
    - ShmCoverageMonitor：管理 bitmap 读取与策略调用
    - 真实 AFL++ 插装二进制（lua, mjs）测试通过
  - Iteration 2：增强覆盖率策略
    - HashFilteredStrategy：FNV-1a hash 过滤减少重复计算
    - PrevBitmapStrategy：与上一次 bitmap 对比
    - CompositeStrategy：组合策略（ANY/ALL/FIRST）
    - CoverageDiffStrategy：增强接口与工厂方法
    - SeenNonZero vs PrevBitmap 降噪效果验证
  - Iteration 3：Corpus 管理与统计
    - FileCorpusManager：保存 queue/crashes/hangs
    - FuzzStats：线程安全统计（execs/paths/crashes/hangs/时间）
    - StatusPrinter：周期性状态输出 + 事件通知
    - StatsTick：统计快照增强（含 totalPaths、lastNewPathSecAgo）

- 🚀 集成到主流程（当时的更新点）
  - FuzzingEngine 增强
    - 构造函数重载：无覆盖版本（非插装目标）/有覆盖版本（CoverageMonitor + CorpusManager）
    - 生命周期：start → beforeRun → execute → afterRun → close
    - 结果处理：Crash/Hang/Interesting coverage 分别保存并更新统计
    - 状态输出：StatusPrinter 显示 exec/s、paths、crashes、hangs
  - 集成测试：覆盖无覆盖模式、有覆盖模式、Crash 检测
  - MockBitmapSource：单元测试无需真实 SHM

- ✅ Iteration 4（2025-12-22）：扩展覆盖监控支持种子调度
  - 背景需求（调度需要的覆盖信号）
    - 边索引（Edge Indices）：不仅要“是否新”，还要“哪些边”
    - 全局 CoverageDB：维护 edgeFreq、topRated、favored
    - 稀有度评分（rarity score）与冗余检测
  - 实现组件
    - 基础工具：XxHash64、EdgeSet
    - 策略扩展：DiffResultEx、CoverageDiffStrategyEx（含 wrap 兼容层）
    - 全局数据库：CoverageDB（topRated 标准、favored、线程安全）
    - 扩展模型：CoverageEx、CoverageMonitorEx、ShmCoverageMonitorEx
  - 测试覆盖：新增 30 tests（EdgeSet/CoverageDB/XxHash64）
  - 向后兼容：保留基础接口并提供转换方法
  - commit 组织：按工具/集合/扩展结果/DB/模型/监控分拆

- ✅ Iteration 5（2025-12-31）：长跑 IO 与统计落盘优化（与 Engine/Executor/Stats 联动）
  - execLogs：默认 interesting，仅晋升后 best-effort 二次执行抓 stdout/stderr
  - 空输出不落盘；execLogsMaxBytes 限制捕获
  - FILE 模式 `.cur_input` 默认 tmpfs；requireTmpfsInputs fail-fast
  - stats/curve 批量 flush，减少 IO

### 10.2 开发日志（2025-12-24）逐条复述

来源：`docs/DevLog/2025-12-24.md`

- A. 共享内存路径可用（真实跑 AFL++ 插桩目标的前提）
  - 修复 SHM attach 关键问题：fromEnvironment 参数顺序、构造后 attach、start() 补 attach
- B. 调度更强且确定性（排序 + 能量）
  - SeedPrioritizer：未 fuzz 种子确定性打分选最优；同分稳定
  - PowerScheduler：叠加输入大小/类型因子与 CoverageDB 信号
- C. Mutator 接线入主循环 + 测试 UTF-8 读取问题
  - 引擎默认 mutator：identity 1 次 + 剩余能量交给按 SeedType 路由的 mutator
  - 测试输出读取策略改为 readAllBytes + 子序列搜索，避免环境差异
- D. 基础 monitor 路径下 CoverageDB 跑不起来修复
  - ShmCoverageMonitor 提供 afterRunEx()，用 wrap 从 bitmap 抽取 hit/new edges
- E. 晋升逻辑：局部 interesting + 全局确认（避免误判）
  - CoverageDB.evaluate(DiffResultEx) 无副作用全局确认 truly-new edges
  - 引擎：local interesting 后再 evaluate 确认
- F. CLI：coverage（none|shm|shmex）+ seeds 可指定
  - CliParser：新增 --seeds（默认 workdir/seeds）、--coverage（默认 none）
  - FuzzerMain：环境已有 __AFL_SHM_ID 则复用；否则 CLI 自建 SysV SHM 并注入 env；shmex 默认开启稳定性确认
- G. SysV SHM 段管理器：自动创建并退出清理
  - SysVShmSegment：shmget(IPC_PRIVATE) 创建；退出 shmctl(IPC_RMID) 清理
  - ShmCoverageMonitorEx.create(shmId, mapSize)
- H. CoverageDB → Seed → 调度消费闭环 + 稳定性字段落地
  - Seed 持久化 favored/redundant/min_edge_freq/rarity_score/stability
  - 引擎：CoverageDB 来源注入与复用、初始 seeds 校准、晋升同步提示字段、favored 变化刷新全队列、稳定性重复执行确认
- 文档更新：Queue/Schedule/Engine/CLI 模块文档同步
- 验证与复现：mvn test + 冒烟运行命令
- 风险与已知差距：exec-logs 小文件增长、CLI 解析简化、稳定性确认与校准开销

### 10.3 开发日志（2025-12-31）逐条复述

来源：`docs/DevLog/2025-12-31.md`

- A. 新增一键运行脚本（单参数）
  - one_click.sh：单参数 program；workdir 按时间戳+pid 隔离；curveBucketSec 通过 JVM 属性传入
- B. 覆盖率增长曲线（curve.csv）
  - StatsCurveWriter：按时间分桶记录累计与增量（new_edges/new_paths/new_execs/new_crashes/new_hangs）
  - 引擎 tick 并支持 nju.fuzzer.curveBucketSec
  - 说明：append 模式，表头升级建议新 workdir
- C. crash 判定策略：exitCode > 128 视为 crash
  - CrashOracle：默认忽略 130/143；支持 nonCrashExitCodes
- D. 长跑 IO 优化：仅晋升输入保存 stdout/stderr + 避免空文件
  - ProcessExecutor：execLogs=interesting|all|none；all 用 PIPE 捕获、非空才落盘；execLogsMaxBytes 限制
  - 引擎：晋升时二次执行抓日志
- E. `.cur_input` 不写磁盘（tmpfs 优先 + 严格模式）
  - 默认写 /dev/shm；requireTmpfsInputs=true fail-fast；stdin 模式默认不落盘
- F. stats/curve 写入减少 flush
  - StatsWriter/StatsCurveWriter：statsFlushEvery 控制 flush 频率；close() 幂等
- 文档更新：CLI/Executor/Engine/stats 同步
- 验证：mvn test + one_click.sh

### 10.4 开发日志（2026-01-08）- Mutate 核心框架逐条复述

来源：`docs/DevLog/2026-01-08-mutate-core.md`

- A. Mutator 接口：Iterator<Testcase> + energy 上限语义 + 非线程安全由调用方保证
- B. MutatorFactory：按 SeedType 路由；未知回退 Havoc；已知类型保留 10% 能量给 Havoc
- C. MutationOps：13 个无状态静态算子（flip/arith/interesting values/swap/overwrite/delete/insert/clone/token）
- D. AflHavocMutator：堆叠次数 1+log2(energy)；加权随机；splicing；字典注入
- 设计决策：Iterator vs List、能量语义、无状态算子、混合策略
- 文件结构与后续规划（MOpt/覆盖反馈/字典词频）

### 10.5 开发日志（2026-01-08）- Mutate 二进制结构感知逐条复述

来源：`docs/DevLog/2026-01-08-mutate-binary.md`

- A. 扫描基础设施：FormatScanner/ScanResult/BinaryChunk/FieldMapping/FieldType
- B. StructureMutator：EVIL_INTEGERS/EVIL_OFFSETS；length/offset/count/flags 等字段变异；chunk 级操作；ELF 特有策略；ConstraintFixer 可选修复 CRC
- C. PNG：TLV 解析（Length/Type/Data/CRC）；关键块 IHDR/IDAT/IEND；PngMutator 变异策略（长度/删除/复制/交换/CRC/头字段攻击/PLTE 攻击）
- D. ELF：header/section/program header 解析；ElfMutator 多策略（offset/count/删除/复制/位翻转/flags/type/entry/machine/重叠 section 等）
- E. JPEG/PCAP：扫描器与 mutator（marker/segment 长度/表破坏；pcap 包长度/时间戳/链路类型）
- 设计决策与后续规划（格式扩展/覆盖反馈/CRC 决策）

### 10.6 开发日志（2026-01-08）- Mutate 语法感知逐条复述

来源：`docs/DevLog/2026-01-08-mutate-grammar.md`

- A. 语法基础设施：Token/TokenNode/Tokenizer/TreeBuilder
- B. MutationStrategy：duplicate/delete/swap/inject/typeConfusion/mutateNumbers
- C. XML：XmlMutator + XmlTokenizer（标签/属性/CDATA/COMMENT）；修复（标签配对/引号/实体转义）
- D. Lua：LuaMutator + LuaTokenizer；载荷/关键字替换；修复（end 配对/引号/注释闭合）
- E. MJS/C++：MjsMutator（原型污染/类型转换/数组越界）；CxxMutator（指针/内存/UB）
- 设计决策与后续规划（生成式/更多语言/语法覆盖反馈）

---

## 11. 全量覆盖：Problems 条目清单（对齐原文标题，不漏项）

> 本节把每个 Problems 文件里的“问题标题”全部列出，确保整合日志对齐审查清单。
> 详细的逐段解释、代码片段与完整建议，仍以原 Problems 文档为准（它们本身就是“审查报告”全文）。

### 11.1 PNG（PngMutator_Problems）

来源：`docs/mutate/Problems/PngMutator_Problems.md`

- 高严重性
  - 问题 1：长度字段变异不更新实际数据大小
  - 问题 2：Chunk 顺序约束未被强制
  - 问题 3：CRC 修复策略过于激进
- 中严重性
  - 问题 4：关键 Chunk 的数据未被保护
  - 问题 5：生成模式的 ColorType 和 BitDepth 组合可能非法
  - 问题 6：Scanline 数据大小计算可能溢出
  - 问题 7：PLTE 大小不匹配攻击未被充分利用
  - 问题 8：未使用的字段
  - 问题 9：EVIL_INTS 未被充分利用
  - 问题 10：缺少 Critical Chunk Type 变异
- 其他章节：设计优势 / 设计劣势 / 对比 / 改进建议 / 预期效果 / 测试建议 / 总体评估 / 用户需求确认 / 相关文档

### 11.2 ELF（ElfMutator_Problems）

来源：`docs/mutate/Problems/ElfMutator_Problems.md`

- 高严重性
  - 问题 1：ELF Header 必需字段未被充分保护
  - 问题 2：Offset/Count 字段变异不保证一致性
- 中严重性
  - 问题 3：Section/Program Header 删除不更新计数
  - 问题 4：生成模式的 ELF 不符合基本规范
  - 问题 5：缺少关键攻击向量
  - 问题 6：字节序处理不一致
  - 问题 7：未使用的字段
- 其他章节：设计优势 / 设计劣势 / 对比 / 改进建议 / 预期效果 / 语料需求 / 用户需求确认 / 总体评估 / 相关文档

### 11.3 JPEG（JpegMutator_Problems）

来源：`docs/mutate/Problems/JpegMutator_Problems.md`

- 高严重性
  - 问题 1：长度欺骗攻击未真正生效
  - 问题 2：Segment 顺序约束未被强制
  - 问题 3：关键 Segment 可能被删除
- 中严重性
  - 问题 4：0xFF Escape 逻辑在生成器中混乱
  - 问题 5：Exif TIFF Header 攻击不完整
  - 问题 6：Sampling Factor 攻击未覆盖边界情况
  - 问题 7：DQT Zero Table 攻击未被充分利用
  - 问题 8：未使用的字段
  - 问题 9：Progressive JPEG (SOF2) 未充分测试
  - 问题 10：缺少 COM 和其他 APPn Segments
- 其他章节：设计优势 / 设计劣势 / 对比 / 改进建议 / 预期效果 / 测试建议 / 总体评估 / 用户需求确认 / 相关文档

### 11.4 PCAP（PcapMutator_Problems）

来源：`docs/mutate/Problems/PcapMutator_Problems.md`

- 高严重性
  - 问题 1：长度欺骗攻击未真正生效
  - 问题 2：IP 长度字段不一致未被充分利用
  - 问题 3：TCP/IP Checksum 未被系统性破坏
- 中严重性
  - 问题 4：IP 分片攻击未完整实现
  - 问题 5：TCP Data Offset 非法值未充分测试
  - 问题 6：IPv6 支持薄弱
  - 问题 7：时间戳攻击单一
  - 问题 8：未使用的字段
  - 问题 9：UDP 长度字段未变异
  - 问题 10：缺少应用层协议
- 其他章节：设计优势 / 设计劣势 / 对比 / 改进建议 / 预期效果 / 测试建议 / 总体评估 / 用户需求确认 / 相关文档

### 11.5 XML（XmlMutator_Problems）

来源：`docs/mutate/Problems/XmlMutator_Problems.md`

- 高严重性
  - 问题 1：标签名变异导致开/闭标签不匹配
  - 问题 2：属性值中的特殊字符未转义
  - 问题 3：未使用 TreeBuilder 进行结构化变异（设计问题）
- 中严重性
  - 问题 4：注释内容包含 `--` 导致非法注释
  - 问题 5：CDATA 损坏逻辑反向
  - 问题 6：使用未定义的实体引用
  - 问题 7：编码声明与实际编码不匹配
  - 问题 8：属性值可能无引号
  - 问题 9：命名空间前缀未声明
  - 问题 10：随机删除结束标签破坏结构
- 其他章节：改进建议 / 预期效果 / 与 LuaMutator 对比 / 相关文档

### 11.6 Lua（LuaMutator_Problems）

来源：`docs/mutate/Problems/LuaMutator_Problems.md`

- 高严重性
  - 问题 1：KEYWORD_REPLACEMENTS 包含非法 Lua 语法
  - 问题 2：运算符变异不区分一元/二元运算符
- 中严重性
  - 问题 3：字符串变异破坏引号配对
  - 问题 4：转义序列格式错误
  - 问题 5：insertRandomStatement 插入的语句语法错误
  - 问题 6：MutationStrategy.mutateNumbers 使用非法 Lua 数值
  - 问题 7：pickOp 包含一元运算符混入二元运算符池
  - 问题 8：测试覆盖不足
- 其他章节：改进建议 / 预期效果 / 相关文档

### 11.7 C++ Mangled（CxxMutator_Problems）

来源：`docs/mutate/Problems/CxxMutator_Problems.md`

- 高严重性
  - 问题 1：长度前缀与实际名称不匹配
  - 问题 2：名称变异后不更新长度前缀
  - 问题 3：模板 I...E 配对不完整
- 中严重性
  - 问题 4：替换序号超出实际定义范围
  - 问题 5：嵌套结构 N...E 故意破坏比例过高
  - 问题 6：名称中嵌入 NUL 字符
  - 问题 7：生成器中闭合 E 数量不匹配
  - 问题 8：未使用树结构进行变异
  - 问题 9：测试未验证 demangler 可解析
- 其他章节：改进建议 / 预期效果 / 三个变异器对比 / 相关文档


## 12. Mutate 系统开发（2026-01-08）

### 12.1 核心框架：接口、工厂路由、算子库、Havoc 兜底

- **Mutator 接口**：`Iterator<Testcase> mutate(Seed seed, int energy)`，按需生成避免 OOM。
- **MutatorFactory 路由**：按 `SeedType` 映射语法感知/结构感知；未知类型回退 Havoc；已知类型保留 10% 能量给 Havoc 保多样性。
- **MutationOps**：13 个无状态基础算子（flip/arith/interesting values/block/dict）。
- **AflHavocMutator**：加权随机堆叠变异，堆叠次数 `1 + log2(energy)`，并支持 splicing 与外部字典注入。

### 12.2 二进制结构感知：PNG/ELF/JPEG/PCAP

- **Scanner + ScanResult**：统一抽象提取 chunk/field/byteorder 等结构信息。
- **StructureMutator**：按 FieldType（LENGTH/OFFSET/COUNT/FLAGS/…）提供更“格式敏感”的变异。
- **ConstraintFixer（可选）**：例如 PNG CRC 修复（默认不修复，保留两种路径）。

### 12.3 语法感知：XML/Lua/MJS/C++

- **Tokenizer → TokenNode 树 → MutationStrategy**：通用的结构化变异流程。
- **MutationStrategy**：duplicate/delete/swap/inject/type confusion/numbers 等通用策略。

---