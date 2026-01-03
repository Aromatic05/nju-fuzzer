# CLI - 命令行入口模块文档

## 概述

CLI 模块负责把命令行参数解析为可运行的配置，并组装核心执行链路：

`CliParser` → `CliArgs` → `FuzzerMain` → `TargetSpec` → `FuzzingEngine.run()`

它的目标是：

- 保持**默认可运行**（即使没有 AFL++ 插桩与共享内存环境，也能用 `--coverage none` 启动并跑通主循环）。
- 支持在运行时切换 coverage 模式：`none | shm | shmex`。
- 支持指定 seeds 目录（`--seeds`），避免写死 `workdir/seeds`。

位置：

- 参数模型：[src/main/java/edu/nju/fuzzing/cli/CliArgs.java](../../src/main/java/edu/nju/fuzzing/cli/CliArgs.java)
- 参数解析：[src/main/java/edu/nju/fuzzing/cli/CliParser.java](../../src/main/java/edu/nju/fuzzing/cli/CliParser.java)
- 程序入口：[src/main/java/edu/nju/fuzzing/cli/FuzzerMain.java](../../src/main/java/edu/nju/fuzzing/cli/FuzzerMain.java)

---

## 快速开始（可复现）

无覆盖（默认）+ STDIN 模式（适用于任何机器）：

- `mvn -q -DskipTests exec:java -Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain -Dexec.args="--workdir /tmp/nju-fuzzer/workdir --duration 1 --timeout 500 --tid DEMO --cmd /bin/cat --coverage none"`

FILE 模式（argv 中包含 `@@`，将输入写入固定文件并把路径替换给目标进程）：

- `mvn -q -DskipTests exec:java -Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain -Dexec.args="--workdir /tmp/nju-fuzzer/workdir --duration 1 --timeout 500 --tid DEMO --cmd '/bin/cat @@' --coverage none"`

启用共享内存覆盖率（需要目标程序是 AFL++/兼容插桩）：

- `--coverage shm`：基础 SHM monitor（仍产出 edge-level hit/new，用于 CoverageDB 更新）
- `--coverage shmex`：扩展 SHM monitor（自带 CoverageDB，并默认启用稳定性确认）

---

## 参数与默认值

`CliParser` 采用“最小骨架”风格：按 `key value` 成对解析。

- `--workdir`：工作目录（默认 `workdir`）
- `--seeds`：初始 seeds 目录（默认 `workdir/seeds`）
- `--duration`：运行秒数（默认 `3`）
- `--timeout`：单次执行超时毫秒（默认 `1000`）
- `--tid`：任务 ID（默认 `DEMO`）
- `--cmd`：目标命令行（默认 `/bin/cat`）
- `--coverage`：`none|shm|shmex`（默认 `none`；非法值会 fail-fast 抛出异常）
- `--seedType`：本次 run 的 seed 类型（默认 `UNKNOWN`；大小写不敏感，例如 `xml`）
- `--nonCrashExitCodes`：逗号或空格分隔的 exit code 白名单（默认空；示例：`1,2,4`）

Crash 判定口径：

- 默认情况下：使用 `CrashOracle` 的 shell 约定规则：`exitCode > 128` 视为 crash（通常是 `128 + signal`，如 `139=SIGSEGV`）。
- `130`（SIGINT）与 `143`（SIGTERM）默认视为 non-crash（避免手动中断污染 crash 统计）。
- `--cmd` 的引号/空格分隔由 `CmdLineTokenizer` 处理；实践中建议把整条命令用引号包起来传给 Maven `-Dexec.args`。

---

## `--cmd` 的 STDIN 与 FILE 两种输入方式

- STDIN 模式：当 argvTemplate 不含 `@@` 时，`FuzzingEngine` 会把 testcase bytes 直接作为 stdin 传给子进程。
- FILE 模式：当 argvTemplate 含 `@@` 时，`FuzzingEngine` 会把 testcase bytes 写入 `workdir/tmp/inputs/.cur_input`，并把该路径替换 `@@` 传给子进程。

这两种模式的具体实现见引擎文档：[docs/Engine/FuzzingEngine.md](../Engine/FuzzingEngine.md)。

---

## `--coverage` 模式与共享内存注入

### none

- 使用 `NullCoverageMonitor`。
- 不依赖 `__AFL_SHM_ID` / `AFL_MAP_SIZE`。
- 仍可跑通主循环、产出 workdir 结构与日志。

### shm / shmex

两种模式都会确保子进程 env 中包含：

- `__AFL_SHM_ID`
- `AFL_MAP_SIZE`

`FuzzerMain` 的行为分两类：

1) **环境已有 `__AFL_SHM_ID`**

- 直接 `fromEnvironment()` attach。
- 同时显式把 `__AFL_SHM_ID` / `AFL_MAP_SIZE` 透传给子进程（避免宿主环境与子进程 env 不一致）。

2) **环境没有 `__AFL_SHM_ID`**

- 自动创建 SysV SHM 段（`SysVShmSegment.create(mapSize)`）。
- 使用 `ShmCoverageMonitor.create(shmId, mapSize)` 或 `ShmCoverageMonitorEx.create(shmId, mapSize)` attach。
- 把 `__AFL_SHM_ID` / `AFL_MAP_SIZE` 写入 `TargetSpec.env`，从而注入到子进程。
- 注册 shutdown hook：退出时关闭 monitor，并 `IPC_RMID` 标记删除（等所有进程 detach 后内核回收）。

稳定性确认：

- `shmex` 默认 `setStabilityDetectionEnabled(true)`
- `shm` 默认关闭

---

## 可验证产物（workdir layout）

`FuzzerMain` 会创建并维护以下目录：

- `workdir/queue`：晋升的 interesting inputs
- `workdir/crashes`：崩溃输入
- `workdir/hangs`：超时输入
- `workdir/stats/stats.csv`：统计输出
- `workdir/tmp/exec-logs/`：stdout/stderr 日志（默认只在 *晋升为 interesting* 时才会保存，且仅保存非空输出）

关于临时输入（`.cur_input`）：

- FILE 模式（`--cmd` 含 `@@`）必须使用输入文件；引擎会复用单个 `.cur_input`，避免 inode 爆炸。
- 默认情况下 `.cur_input` **不会写到 workdir**：会优先写到 `/dev/shm`（tmpfs）。
- 严格模式（默认开启）下，若无法使用 tmpfs，将直接 fail-fast，避免任何磁盘落盘。

---

## 测试覆盖

- CLI 冒烟：
  - [src/test/java/edu/nju/fuzzing/cli/FuzzerMainCmdSmokeTest.java](../../src/test/java/edu/nju/fuzzing/cli/FuzzerMainCmdSmokeTest.java)
  - 覆盖 STDIN/FILE 两种模式、`--seeds` 覆盖、非法 `--coverage` fail-fast。

- CLI 参数解析：
  - [src/test/java/edu/nju/fuzzing/cli/CliParserTest.java](../../src/test/java/edu/nju/fuzzing/cli/CliParserTest.java)

- Crash 判定口径：
  - [src/test/java/edu/nju/fuzzing/exec/CrashOracleTest.java](../../src/test/java/edu/nju/fuzzing/exec/CrashOracleTest.java)
  - [src/test/java/edu/nju/fuzzing/core/FuzzingEngineCrashOracleIntegrationTest.java](../../src/test/java/edu/nju/fuzzing/core/FuzzingEngineCrashOracleIntegrationTest.java)

---

## 参数使用说明（非常详尽）

本节面向“实际跑目标程序”的使用场景，给出每个参数的语义、边界条件、典型写法与坑点。

### 0) 解析规则（重要）

`CliParser` 采用最小实现：**按 `key value` 成对解析**。

- 所有参数必须写成：`--key value`
- 不支持单独 flag（例如 `--foo` 这种没有 value 的写法）
- 如果你最后一个 token 只有 key 没有 value，它会被忽略（因为循环按 `i < args.length - 1` 解析）

### 1) `--workdir`：工作目录

- 默认：`workdir`
- 作用：
  - 所有输出目录（queue/crashes/hangs/stats/tmp）都在这里
  - 用于复现、归档、对比不同 run

建议：每次 fuzz run 使用独立目录，例如：`workdir/run-YYYYMMDD-HHMMSS-<target>`。

### 2) `--seeds`：初始 seeds 目录

- 默认：`<workdir>/seeds`
- 加载行为（见 `SeedQueue.loadInitialSeeds`）：
  - 递归读取普通文件（支持子目录）
  - 跳过隐藏文件（文件名以 `.` 开头）
  - 跳过 `*.meta`
  - 对每个 seed：读取 `.meta` 中的调度提示字段（favored/redundant/...），类型强制使用本次 run 的 `--seedType`（同一次 run 必须一致）

如果 seeds 目录为空：引擎会创建 dummy seed（内容 `hello-from-engine`），位置：`<workdir>/tmp/seeds/seed_000001`。

### 3) `--duration`：运行时长（秒）

- 默认：`3`
- 语义：到点后主循环退出（会打印 `[EVENT] Time up! Stopping fuzzing.`）。

### 4) `--timeout`：单次执行超时（毫秒）

- 默认：`1000`
- 执行器行为（`ProcessExecutor`）：
  - 超时后先 `destroy()`，短暂等待，再 `destroyForcibly()`
  - 此次执行会被标记为 hang（`RunResult.Termination.TIMEOUT`），并进入 `hangs/` 分支

### 5) `--tid`：任务 ID / 目标名

- 默认：`DEMO`
- 作用：
  - 出现在控制台状态行最左侧：`[tid][HH:MM:SS] ...`
  - 出现在 `stats.csv` 的 `target_name` 列

建议：用“目标 + 关键配置”命名，例如：`XMLLINT_07`、`LUA_5MIN`。

### 6) `--cmd`：目标命令行

#### 6.1 分词规则（`CmdLineTokenizer`）

- 空格分隔 token
- 支持单引号/双引号成对包裹 token（只影响分词，不保留引号）
- 不支持复杂转义（比如 bash 的各种反斜杠转义），因此尽量把 `--cmd` 写得“简单、可分词”
- 引号不闭合会 fail-fast：`Unclosed quote in cmdLine`

#### 6.2 输入模式：STDIN vs FILE（`@@`）

- **STDIN 模式**：`--cmd` 中不包含 `@@`
  - testcase bytes 会作为 stdin 写给子进程
- **FILE 模式**：`--cmd` 中包含 `@@`
  - 每次执行会把 testcase bytes 覆盖写到 `<workdir>/tmp/inputs/.cur_input`
  - 运行前会把 argv 中的 `@@` 替换为 `.cur_input` 的绝对路径

注意：当前实现即使在 STDIN 模式下也会覆盖写 `.cur_input`（用于快速抓取“最近一次输入”调试）。

更新：现在 STDIN 模式默认 **不写** `.cur_input`（避免无谓落盘）；仅当显式开启 `-Dnju.fuzzer.persistTmpInputs=true` 时才会写。

---

## 运行期 IO 行为（重要）

本项目提供若干 JVM 系统属性用于控制长跑 IO：

- `-Dnju.fuzzer.execLogs=interesting|all|none`
  - 默认 `interesting`：仅在“晋升为 interesting”时进行一次 best-effort 的二次执行抓 stdout/stderr，并写入 `workdir/tmp/exec-logs`。
  - `all`：每次执行都抓 stdout/stderr（仅非空才写），长跑可能产生大量文件。
  - `none`：完全丢弃 stdout/stderr。
- `-Dnju.fuzzer.execLogsMaxBytes=<bytes>`：单次执行捕获 stdout/stderr 的最大字节数（默认 1MB）。

- `-Dnju.fuzzer.tmpInputsDir=<path>`：覆盖 `.cur_input` 的目录（FILE 模式使用）。
- `-Dnju.fuzzer.requireTmpfsInputs=true|false`：是否强制 tmpfs（默认 `true`）。
  - 为 `true` 时，若 tmpInputsDir 不在 tmpfs（例如不在 `/dev/shm` 且 fileStore 不是 tmpfs/ramfs），将 fail-fast。

- `-Dnju.fuzzer.persistTmpInputs=true|false`：STDIN 模式是否也写 `.cur_input`（默认 `false`）。

- `-Dnju.fuzzer.curveBucketSec=<sec>`：`stats/curve.csv` 的分桶间隔秒数（默认 1）。
- `-Dnju.fuzzer.statsFlushEvery=<N>`：`stats.csv/curve.csv` 每写 N 行 flush（默认 100；<=0 表示仅 close 时 flush）。

#### 6.3 Maven 传参建议（减少引号问题）

在 bash 下，推荐：**外层用单引号包住整个 `-Dexec.args`**，内部 `--cmd` 用双引号。

示例（FILE 模式，xmllint）：

```bash
mvn -q -DskipTests exec:java \
  -Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain \
  -Dexec.args='--workdir /tmp/nju-fuzzer/xmllint-run \
              --seeds env/seeds/07 \
              --duration 60 \
              --timeout 200 \
              --tid XMLLINT \
              --cmd "env/out/xmllint --noout @@" \
              --coverage none \
              --nonCrashExitCodes 1,2,4'
```

### 7) `--coverage`：覆盖率模式

- `none`：不使用覆盖率监控（Null monitor）。
- `shm`：使用 SysV SHM bitmap；CoverageDB 由引擎侧创建维护。
- `shmex`：使用扩展 SHM monitor；CoverageDB 可由 monitor 持有复用，并默认启用稳定性确认。

环境变量（shm/shmex）：

- `__AFL_SHM_ID`
- `AFL_MAP_SIZE`

`FuzzerMain` 会确保这些变量被注入到子进程 env（环境已有则透传；环境没有则自动创建 SHM 段并注入）。

### 8) `--nonCrashExitCodes`：非 crash 退出码白名单

用途：解决“目标程序用非 0 退出码表示输入非法”导致的 crash 风暴。

- 格式：逗号或空格分隔，例如 `1,2,4` 或 `1 2 4`
- 无效 token 会被忽略（容错）
- 最终生效集合 = `130/143`（默认）+ 你提供的 codes
- 启动时会打印：`effectiveNonCrashExitCodes = [...]`（用于核对口径）

典型：xmllint 常用 `--nonCrashExitCodes 1,2,4`。

---

## 控制台日志说明（StatusPrinter / 事件行）

控制台输出主要来自三处：

- `FuzzerMain`：启动摘要（workdir/cmd/seeds/coverage/口径）
- `FuzzingEngine`：流程事件（加载种子、时间到停止等）
- `StatusPrinter` + `StatsTick`：每秒状态行，以及 crash/hang/newpath 事件

### 1) 启动摘要（FuzzerMain）

典型输出（示例）：

```text
NJUFuzzer skeleton started.
workdir = /tmp/nju-fuzzer/run
duration = 60s
timeout  = 200ms
tid      = XMLLINT
cmd      = env/out/xmllint --noout @@
seeds    = /abs/path/to/seeds
coverage = none
effectiveNonCrashExitCodes = [130, 143, 1, 2, 4]
```

其中 `effectiveNonCrashExitCodes` 只有在集合非空时才打印。

### 2) 流程事件行（FuzzingEngine.printEvent）

格式：`[EVENT] <message>`

常见：

- `[EVENT] Loading initial seeds from ...`
- `[EVENT] Loaded N initial seeds.`
- `[EVENT] WARNING: No initial seeds found. Starting with dummy seed.`
- `[EVENT] Time up! Stopping fuzzing.`

### 3) 周期状态行（每秒 1 次）

状态行格式（来自 `StatsTick.toStatusLine()`）：

```text
[TID][HH:MM:SS] cov: <coveredEdges> | execs: <execsTotal> | spd: <execsPerSec>/s | queue: <queueSize> | paths: <totalPaths> | crash: <crashes> | hang: <hangs> | last: <sec> s ago
```

字段解释：

- `TID`：`--tid`
- `HH:MM:SS`：本次 run 经过的时间（`elapsedSec` 格式化）
- `cov`：`coveredEdges`，由 `CoverageDB.getTotalEdgesSeen()` 提供（`--coverage none` 时通常为 0）
- `execs`：累计执行次数
- `spd`：近期执行速度（`getRecentExecsPerSec()`，基于快照差分，会随时间窗口波动）
- `queue`：当前队列种子数量（内存队列 `SeedQueue.size()`；落盘文件数通常是 `2*queue` 因为还有 `.meta`）
- `paths`：累计晋升次数（每次保存到 `queue/` 都会 `recordNewPath()`）
- `crash`：累计 crash 次数
- `hang`：累计 hang 次数
- `last`：距离上一次晋升过去的秒数

### 4) 事件行（new path / crash / hang）

- new path：`[NEW PATH] id=<n>, coverage=<m>`
  - `id` 是晋升次数（不是文件名里的 id）
  - `coverage` 当前打印的是 `edgeCount()`（hit edges 数），在 `--coverage none` 下通常为 0

- crash：`[CRASH] id=<n>, reason=exit_<code>`
  - 只有当 `CrashOracle` 判定为 crash 才会出现

- hang：`[HANG] id=<n>, timeout=<ms>ms`
  - 对应超时执行

---

## stats/stats.csv 说明（CSV 内容、字段含义、注意事项）

文件位置：`<workdir>/stats/stats.csv`

### 1) Header（列名）

当前 header 固定为：

```csv
timestamp,target_name,exec_count,covered_edges,execs_per_sec,queue_size,total_paths,crash_count,hang_count
```

### 2) 每列含义

- `timestamp`
  - 注意：这是 **elapsed seconds**（从本次 fuzz run 开始算的秒数），不是 epoch 时间戳。
- `target_name`
  - 等于 `--tid`
- `exec_count`
  - 累计执行次数（每次 `harness.execute()` 后 `recordExec()`）
- `covered_edges`
  - CoverageDB 口径的已覆盖 edges 数
  - `--coverage none` 时通常为 0（因为 CoverageDB 不启用/不更新）
- `execs_per_sec`
  - 近期速度（浮点），来自 `FuzzStats.getRecentExecsPerSec()`
- `queue_size`
  - 当前队列大小（内存种子数）
- `total_paths`
  - 累计晋升次数（每次 `saveToQueue()` 后 `recordNewPath()`）
- `crash_count`
  - 累计 crash 次数（以 CrashOracle 判定为准）
- `hang_count`
  - 累计 hang 次数（超时）

### 3) 写入频率与文件大小

`FuzzingEngine` 当前默认 `tickIntervalMs = 0`，意味着：

- `StatsWriter.tick(...)` **可能每次 exec 都写一行**（长跑会很大）
- 同时 `StatusPrinter` 仍按 1 秒一行打印到控制台

如果你只是想看趋势：可以在后处理阶段对 CSV 抽样（例如每 N 行取一行）。

### 4) 一行样例

```csv
12,XMLLINT,534,2872,15.20,265,262,0,18
```

解释：运行 12 秒，累计执行 534 次；覆盖 edges 2872；速度约 15/s；队列 265；晋升 262；crash 0；hang 18。

### 5) stats/curve.csv：按秒分桶的增长曲线（运行时记录）

除了 `stats.csv`，引擎还会生成一份“每秒一行”的曲线文件（相对 workdir 路径为 `stats/curve.csv`），由 `StatsCurveWriter` 从累计指标推导每秒增量。

输出列：

- `timestamp`：elapsed seconds
- `target_name`
- `covered_edges`：截至该秒的累计覆盖（AFL bitmap 非零 byte index 计数）
- `total_paths`：截至该秒的累计新路径数（interesting inputs）
- `new_edges`：该秒内新增覆盖（`covered_edges` 的增量）
- `new_paths`：该秒内新增路径（`total_paths` 的增量）
- `exec_count`：截至该秒的累计执行次数
- `new_execs`：该桶（秒/分桶区间）内新增执行次数（`exec_count` 的增量）
- `crash_count` / `hang_count`：截至该秒的累计数量
- `new_crashes` / `new_hangs`：该桶内新增 crash/hang 数（对应累计值的增量）

代码位置：

- writer 实现：[src/main/java/edu/nju/fuzzing/stats/StatsCurveWriter.java](../../src/main/java/edu/nju/fuzzing/stats/StatsCurveWriter.java)
- 引擎接入（创建并 tick）：[src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java](../../src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java#L333-L410)

### 6) 一键运行脚本：one_click.sh

仓库根目录提供 [one_click.sh](../../one_click.sh)，用于“一条命令跑指定目标”。约束与约定：

- **参数仅一个**：程序名（如 `mjs`、`lua`）
- 目标程序：`./env/out/<program>`
- 种子目录：脚本内置 program→ID 映射后使用 `./env/seeds/<ID>/`
- 输出 workdir：`./workdir/<program>/<YYYYMMDD-HHMMSS>-<pid>/`

注意：不同目标的启动命令会带上必要参数（对齐评测表的 AFL-CMD），例如：

- `readelf`：`readelf -a @@ @@`
- `objdump`：`objdump -d @@`
- `mjs`：`mjs -f @@`
- `tcpdump`：`tcpdump -nr @@`
- `cxxfilt`/`readpng`：不带 `@@`，走 STDIN 模式

运行示例：

- `bash one_click.sh mjs`

可调参数（直接编辑脚本顶部变量）：

- `CURVE_BUCKET_SEC`：曲线分桶间隔（通过 JVM 系统属性 `nju.fuzzer.curveBucketSec` 传入）

---

## workdir 目录输出说明（包含使用指导 / 复现指南）

### 0) 总览

`FuzzerMain` 会创建：

- `queue/`：晋升的输入（后续变异的 seeds）
- `crashes/`：crash 输入
- `hangs/`：超时输入
- `stats/`：统计（`stats.csv`）
- `tmp/`：临时复用输入与执行日志

### 1) queue/：晋升输入 + .meta 元数据

#### 文件命名

`FileCorpusManager.saveToQueue` 的命名：

- `id_%06d_cov_%d_%s`

字段：

- `id_%06d`：队列编号（递增）
- `cov_%d`：`coverage.newBytes()`（不是“总边数/覆盖边数”）
- `%s`：输入短 hash

#### 同名 `.meta` 文件

每个 queue 文件会有同名 `.meta`（由 `SeedQueue.addSeed()` 触发 `Seed.saveMetadata()` 写入）。

`.meta` 为 Java Properties 格式，常见字段：

- 血缘：`parent_id`, `depth`, `birth_type`
- 调度：`handicap`, `was_fuzzed`, `energy`, `exec_time`, `bitmap_size`
- CoverageDB hints：`favored`, `redundant`, `min_edge_freq`, `rarity_score`, `stability`
- 类型：`seed_type`（来自 `--seedType` 或沿用父种子）

注意：edge set 不会写入 `.meta`（避免元数据膨胀）。

### 2) crashes/：crash 输入

命名：`crash_%06d_exit_%d_%s`

- `%d` exit code 来自目标进程
- 是否进入 crashes 由 CrashOracle 决定：
  - 默认将 `130/143` 视为 non-crash
  - 额外由 `--nonCrashExitCodes` 指定

### 3) hangs/：超时输入

命名：`hang_%06d_%s`

### 4) tmp/inputs/.cur_input：最近一次输入（复用文件）

- 每次执行都会覆盖写该文件（避免创建大量临时文件）
- FILE 模式下，目标收到的参数就是这个路径
- STDIN 模式下也会写入（为了方便你随手拿到“最近一次输入”）

### 5) tmp/exec-logs/：stdout/stderr 落盘

`ProcessExecutor` 每次执行都会写：

- `stdout_<execId>.log`
- `stderr_<execId>.log`

注意：

- `execId` 仅在本次 fuzz run 内递增；与 queue/crash/hang 的编号没有一一映射。
- 长跑会产生大量小文件（inode/磁盘风险）。

### 6) tmp/seeds/：dummy seed

当 seeds 目录为空时，会在这里生成：

- `tmp/seeds/seed_000001`（内容为 `hello-from-engine`）
- 以及对应的 `seed_000001.meta`

---

## 如何使用这些产物（复现 / triage 流程）

### 1) 复现 crash/hang

你需要根据目标的输入模式选择复现方式：

- **如果目标是 FILE 模式（你 fuzz 时 `--cmd` 用了 `@@`）**：
  - 直接把 `crashes/<file>` 或 `hangs/<file>` 作为目标的文件参数重放
  - 示例：`env/out/xmllint --noout <workdir>/crashes/crash_...`

- **如果目标是 STDIN 模式（你 fuzz 时 `--cmd` 不含 `@@`）**：
  - 用管道把输入喂给目标
  - 示例：`cat <workdir>/crashes/crash_... | <target argv...>`

### 2) 快速抓“刚刚那次输入”

如果你中途 Ctrl-C 停止 fuzz，或者想立刻复现“最后一次执行”，直接用：

- `<workdir>/tmp/inputs/.cur_input`

它就是最近一次执行时写入的字节序列。

### 3) 处理“非 0 退出码不代表 crash”的目标

对 xmllint / 各类解析器，建议先把常见的“输入非法”退出码加到白名单：

- `--nonCrashExitCodes 1,2,4`

这样可以避免把大量“正常拒绝输入”误记为 crash，从而：

- `crashes/` 不会被无意义输入淹没
- `crash_count` 更接近“真正异常”
