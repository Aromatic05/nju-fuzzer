
# NJU-Fuzzer 项目文档（整合版）

> 本文档整合 `docs/` 下现有模块文档与开发日志，形成一份“可运行、可复现、可扩展”的完整项目说明。
>
> **定位**：Coverage-Guided Fuzzer（覆盖率引导模糊测试器），核心链路为：
> `SeedQueue → Scheduling → Mutator → ExecutorHarness(Executor+Coverage) → Corpus → Stats`。

---

## 1. 总览

### 1.1 项目目标

- **在 Java 生态内实现可运行的 coverage-guided fuzzing 闭环**：选种、变异、执行、覆盖反馈、晋升入队、统计落盘。
- **兼容两类目标程序**：
	- **非插桩目标**：`--coverage none`，仍能跑通主循环与产物结构（用于任何机器的复现/教学/调试）。
	- **AFL++ 插桩目标**：`--coverage shm|shmex`，通过 SysV SHM bitmap 获取覆盖反馈，驱动入队与调度。

### 1.2 关键特性（按闭环分组）

- **运行入口**：CLI 解析参数并组装执行链路（见 `docs/CLI/CLI.md`）。
- **执行抽象层**：`ExecutorHarness` 统一编排 `beforeRun → run → afterRun`，避免主循环写分支（见 `docs/ExecutorHarness/ExecutorHarness.md`）。
- **覆盖率监控**：`ShmCoverageMonitor`/`ShmCoverageMonitorEx` 读取 AFL++ SHM bitmap，可插拔 diff 策略（见 `docs/CoverageMonitor/CoverageMonitor.md`、`docs/CoverageMonitor/ExtendedComponents.md`）。
- **全局覆盖数据库**：`CoverageDB` 维护 `edgeFreq/topRated/favored/redundant/rarity`，支持全局确认 interesting（见扩展覆盖组件文档）。
- **队列与调度**：`SeedQueue` + `SeedPrioritizer` + `PowerScheduler`，可消费 CoverageDB 提示字段（见 `docs/Queue/SeedQueue.md`、`docs/schedule/Scheduling.md`）。
- **变异系统**：Havoc（通用）+ 结构/语法感知变异器（按 `SeedType` 路由）（见 `docs/mutate/Mutator.md` 及 mutate-devlog）。
- **语料落盘**：`queue/crashes/hangs` 三类输出，元信息 `.meta`（见架构/引擎文档）。
- **统计与可观测性**：状态行 + `stats.csv` + `curve.csv`（见 `docs/stats/stats.md`）。

### 1.3 仓库结构（读者导览）

- `src/main/java/edu/nju/fuzzing/`：核心实现
	- `cli/` `core/` `exec/` `cov/` `queue/` `schedule/` `mutate/` `corpus/` `stats/` `model/`
- `docs/`：模块文档、架构、开发日志、mutator 审查报告（Problems）
- `env/`：构建 AFL++ 与目标程序、拉取 seeds 的脚本与产物目录（需要 root）
- `one_click.sh`：一键 fuzz（按目标名映射 seeds 与命令模板）
- `docker-compose.yml`/`Dockerfile`：容器化构建与运行

---

## 2. 工具运行方法与示例（Quick Start）

本节以“先跑起来”为目标，按从易到难给出三条路径：**纯 Java 无覆盖** → **本机构建插桩目标** → **Docker 一键跑**。

### 2.1 方式 A：无覆盖（任何机器可跑）

依赖：JDK 17 + Maven。

1) 运行（STDIN 模式）：

```bash
mvn -q -DskipTests exec:java \
	-Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain \
	-Dexec.args="--workdir /tmp/nju-fuzzer/workdir \
							--duration 1 \
							--timeout 500 \
							--tid DEMO \
							--cmd /bin/cat \
							--coverage none"
```

2) 运行（FILE 模式：命令含 `@@` 占位符）：

```bash
mvn -q -DskipTests exec:java \
	-Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain \
	-Dexec.args="--workdir /tmp/nju-fuzzer/workdir \
							--duration 1 \
							--timeout 500 \
							--tid DEMO \
							--cmd '/bin/cat @@' \
							--coverage none"
```

期望产物（workdir layout）：

- `queue/`：晋升的 interesting inputs（无覆盖模式通常较少）
- `crashes/`：崩溃样本
- `hangs/`：超时样本
- `stats/stats.csv`：运行期统计
- `stats/curve.csv`：覆盖/paths/exec 等增长曲线（秒级分桶）
- `tmp/exec-logs/`：stdout/stderr（默认仅对“晋升输入”保存，且只保存非空输出）

### 2.2 方式 B：本机/实验环境构建 AFL++ 插桩目标并启用覆盖率

这条路径用于“真正的覆盖率引导 fuzzing”。

1) 构建 AFL++ 与目标（脚本需要 root）：

```bash
sudo bash env/env.sh
```

脚本会依次安装依赖、拉取 targets、构建 AFL++、构建目标、拉取 seeds，并在 `env/out` 与 `env/seeds` 产生输出。

2) 一键 fuzz（推荐，最少心智负担）：

```bash
bash one_click.sh lua
```

`one_click.sh` 会：

- 按目标名映射 seeds 目录（`./env/seeds/<ID>`）与 `SeedType`
- 构造目标命令模板（含/不含 `@@`）
- 固定 `--coverage shmex`（扩展 SHM monitor，默认启用稳定性确认）
- 每次运行创建独立 workdir：`./workdir/<program>/<run-id>/`

3) 手动运行（更灵活，适用于调试参数）：

- `--coverage shm`：基础 SHM monitor（可产生 edge-level hit/new，并由引擎侧维护 CoverageDB）
- `--coverage shmex`：扩展 SHM monitor（monitor 自带 CoverageDB，并默认开启稳定性确认）

典型示例（以 `xmllint` 为例，FILE 模式）：

```bash
mvn -q -DskipTests exec:java \
	-Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain \
	-Dexec.args='--workdir /tmp/nju-fuzzer/xmllint-run \
							--seeds env/seeds/07 \
							--seedType XML \
							--duration 60 \
							--timeout 2000 \
							--tid XMLLINT \
							--cmd "env/out/xmllint @@" \
							--coverage shmex \
							--nonCrashExitCodes 1,2,4'
```

### 2.3 方式 C：Docker / docker-compose（最稳的可复现环境）

仓库提供 `Dockerfile` 与 `docker-compose.yml`：

- `build-image`：构建基础镜像 `nju-fuzzer:latest`（会尝试执行 `env/env.sh` 并把 `env/out` 与 `env/seeds` 带进最终镜像）。
- `fuzzer-<target>`：直接在容器中运行 `one_click.sh <target>`，并把输出 workdir 挂载到宿主机 `./workdir/<target>/`。

示例：运行 Lua 目标

```bash
docker compose run --rm fuzzer-lua
```

或后台跑：

```bash
docker compose up fuzzer-lua
```

---

## 3. 使用方法（CLI / 参数 / 目录）

### 3.1 入口链路

整体入口链路保持固定：

`CliParser → CliArgs → FuzzerMain → TargetSpec → FuzzingEngine.run()`

模块说明见 `docs/CLI/CLI.md`。

### 3.2 核心参数（最常用）

- `--workdir <dir>`：工作目录（输出都在这里）
- `--seeds <dir>`：初始 seeds 目录（可覆盖默认 `workdir/seeds`）
- `--seedType <type>`：本次 run 的种子类型（同一次 run 必须一致；与 `SeedType` 枚举对齐）
- `--duration <sec>`：运行秒数
- `--timeout <ms>`：单次执行超时
- `--tid <name>`：目标名称（出现在状态行与 stats 中）
- `--cmd "<argvTemplate>"`：目标命令模板；含 `@@` 则为 FILE 模式，否则 STDIN 模式
- `--coverage none|shm|shmex`：覆盖率模式
- `--nonCrashExitCodes <codes>`：非 crash 退出码白名单（用于区分“非 0 退出但不是崩溃”）

### 3.3 STDIN 与 FILE 两种输入模式

- **STDIN 模式**（命令模板不含 `@@`）
	- testcase bytes 写入子进程 stdin
- **FILE 模式**（命令模板含 `@@`）
	- testcase bytes 覆盖写入固定文件 `.cur_input`
	- 运行前将 argv 中的 `@@` 替换为该文件路径（支持多个 `@@`）

### 3.4 运行期关键系统属性（长跑 IO / tmpfs）

- `-Dnju.fuzzer.execLogs=interesting|all|none`
	- 默认 `interesting`：仅对“晋升为 interesting”的输入 best-effort 二次执行抓 stdout/stderr
- `-Dnju.fuzzer.execLogsMaxBytes=<bytes>`：stdout/stderr 捕获上限（默认 1MB）
- `-Dnju.fuzzer.tmpInputsDir=<path>`：覆盖 `.cur_input` 目录（FILE 模式）
- `-Dnju.fuzzer.requireTmpfsInputs=true|false`：是否强制 tmpfs（默认 true；不可用则 fail-fast）
- `-Dnju.fuzzer.persistTmpInputs=true|false`：STDIN 模式是否也写 `.cur_input`（默认 false）
- `-Dnju.fuzzer.curveBucketSec=<sec>`：`curve.csv` 分桶间隔（默认 1 秒）
- `-Dnju.fuzzer.statsFlushEvery=<N>`：stats/curve 每写 N 行 flush（默认 100；<=0 表示只在 close 时 flush）

---

## 4. 设计方案（架构、流程、类层次）

本节按“总-分”组织：先给总体分层与数据流，再展开到关键类与模块职责。

### 4.1 分层架构（总）

```
┌─────────────────────────────────────────────────┐
│               FuzzingEngine (主循环)            │
│  Seed选择 → 能量调度 → 变异 → 执行 → 入队/落盘   │
└────────────────┬────────────────────────────────┘
								 │
				┌────────▼─────────┐
				│ ExecutorHarness   │   执行抽象层（固定编排）
				│ start/execute/close│
				└────┬────────┬────┘
						 │        │
		┌────────▼──┐ ┌──▼───────────────┐
		│ Executor  │ │ CoverageMonitor  │
		│ (进程执行) │ │ (覆盖监控)        │
		└───────────┘ └──────────────────┘
						 │
		┌────────▼───────────┐
		│ ProcessExecutor     │
		│ stdin/file + timeout│
		└─────────────────────┘
```

### 4.2 主循环闭环（流程）

主循环的“闭环编排”定义在 `FuzzingEngine`，核心步骤为：

1) `SeedQueue` 提供 seeds 视图
2) `SeedPrioritizer` 选 parent seed
3) `PowerScheduler` 计算 `energy`
4) `Mutator` 生成 `Iterator<Testcase>`（懒生成，避免大能量 OOM）
5) `ExecutorHarness.execute(ExecInput)`：执行并收集覆盖（`beforeRun → run → afterRun`）
6) 分类：normal / crash / hang
7) interesting：本地 diff +（可选）CoverageDB 全局确认 +（可选）稳定性确认
8) `CorpusManager` 落盘到 `queue/crashes/hangs`，并构造新 `Seed` 入队
9) `FuzzStats/StatusPrinter/StatsWriter/StatsCurveWriter` 更新与落盘

伪代码（简化）：

```java
harness.start();
try {
	while (!timeUp()) {
		Seed parent = prioritizer.pick(seedQueue.getSeeds());
		int energy = powerScheduler.assignEnergy(parent);
		Iterator<Testcase> it = mutator.mutate(parent, energy);
		while (it.hasNext()) {
			Testcase tc = it.next();
			ExecInput input = buildExecInput(targetSpec, tc);
			ExecResult r = harness.execute(input);
			// crash/hang/normal + (interesting -> persist + enqueue)
		}
	}
} finally {
	harness.close();
}
```

### 4.3 数据模型（核心 record/POJO）

位于 `edu.nju.fuzzing.model`：

- `TargetSpec`：目标运行规格（argvTemplate/env/timeout）
- `TargetCommand`：解析后的实际 argv/env/inputMode
- `Testcase`：一次变异输入（bytes + parent + 描述）
- `ExecInput`：一次执行参数封装（cmd/stdin/timeout/outDir）
- `RunResult`：一次执行结果（exitCode/timeout/termination/execId/execTime…）
- `Coverage` / `CoverageEx`：覆盖快照（basic + edge-level + stability）
- `ExecResult`：`RunResult + CoverageEx`
- `Seed`：队列条目（路径、元数据、调度提示字段、血缘信息）
- `StatsTick`：统计快照（用于展示与 CSV 落盘）

### 4.4 类层次与模块职责（分）

以下为“读代码入口”的最小类图索引（按包组织，展示关键类的层次与职责）。

#### CLI（参数解析与组装）

```
edu.nju.fuzzing.cli
	CliParser
	CliArgs
	CmdLineTokenizer
	FuzzerMain
```

#### Core（引擎与执行抽象层）

```
edu.nju.fuzzing.core
	FuzzingEngine
	ExecutorHarness (interface)
	InstrumentedExecutorHarness
```

#### Exec（进程执行与 crash 口径）

```
edu.nju.fuzzing.exec
	Executor (interface)
	ProcessExecutor
	CrashOracle
	CommandResolver
	TargetCommand
	InputMode
```

#### Coverage（覆盖监控、策略与全局 DB）

```
edu.nju.fuzzing.cov
	CoverageMonitor (interface)
	CoverageMonitorEx (interface)
	ShmCoverageMonitor / ShmCoverageMonitorEx
	NullCoverageMonitor
	BitmapSource (interface)
		SysVShmBitmapSource
	CoverageDiffStrategy (interface)
		SeenNonZeroStrategy
		PrevBitmapStrategy
		HashFilteredStrategy
		CompositeStrategy
	CoverageDiffStrategyEx
	EdgeSet / DiffResultEx / XxHash64
	CoverageDB
	SysVShmSegment
```

#### Queue / Schedule（队列与调度）

```
edu.nju.fuzzing.queue
	SeedQueue

edu.nju.fuzzing.schedule
	SeedPrioritizer
	PowerScheduler
```

#### Mutate（变异器体系）

```
edu.nju.fuzzing.mutate
	Mutator (interface)
	MutatorFactory
	MutationOps
	AflHavocMutator
	XmlMutator / LuaMutator / MjsMutator / CxxMutator
	PngMutator / ElfMutator / JpegMutator / PcapMutator
	mutate.binary.* (FormatScanner/Scanner/StructureMutator/ConstraintFixer/...)
	mutate.grammar.* (Tokenizer/TreeBuilder/MutationStrategy/TokenNode/...)
```

#### Corpus / Stats（落盘与可观测性）

```
edu.nju.fuzzing.corpus
	CorpusManager (interface)
	FileCorpusManager

edu.nju.fuzzing.stats
	FuzzStats
	StatusPrinter
	StatsWriter
	StatsCurveWriter
```

---

## 5. 扩展与定制（使用方法的“下一步”）

### 5.1 接入新目标程序

最推荐的接入方式是：

1) 把目标放到 `env/out/<name>`（或自己选择路径）
2) 准备 seeds：`env/seeds/<ID>/`
3) 选择输入模式：
	 - STDIN：`--cmd "env/out/<name>"`
	 - FILE：`--cmd "env/out/<name> ... @@ ..."`
4) 运行：优先用 `one_click.sh` 或参考其映射逻辑新增一条 case

### 5.2 增加一种 SeedType / Mutator

1) 在 `SeedType` 增加枚举
2) 实现 `Mutator`：`Iterator<Testcase> mutate(Seed seed, int energy)`
3) 在 `MutatorFactory` 增加路由
4) （可选）补一份 Problems/审查清单：记录“合法率/深层触达率/约束修复策略”等经验

### 5.3 覆盖策略与调度策略替换

- 覆盖 diff 策略：实现/替换 `CoverageDiffStrategy` 或 `CoverageDiffStrategyEx`
- 调度：
	- 选种：调整 `SeedPrioritizer.scoreForSelection` 的信号组合
	- 能量：调整 `PowerScheduler` 因子与封顶策略
	- 当 `CoverageDB` 可用时，优先消费 `favored/rarity/redundant/stability` 等提示字段

---

## 6. 常见问题（Troubleshooting）

### 6.1 `--cmd` 引号/空格解析失败

`CliParser` 是“最小骨架”：按 `--key value` 成对解析；`--cmd` 的分词由 `CmdLineTokenizer` 处理。

建议：在 bash 下外层用单引号包住整个 `-Dexec.args`，内部 `--cmd` 用双引号。

### 6.2 `--coverage shm|shmex` 跑不起来

- 确认目标是 AFL++/兼容插桩产物
- 确认容器/宿主机有足够的 SHM（docker 场景常用 `shm_size: "1g"`）
- 若走自动创建 SHM：CLI 会创建 SysV SHM 并把 `__AFL_SHM_ID/AFL_MAP_SIZE` 注入子进程 env

### 6.3 FILE 模式 `.cur_input` 写盘失败或落到磁盘

默认强制 tmpfs：`-Dnju.fuzzer.requireTmpfsInputs=true`。

- 若机器没有 `/dev/shm` 或不可写，会 fail-fast
- 可通过 `-Dnju.fuzzer.tmpInputsDir=<path>` 指定一个 tmpfs 目录

### 6.4 长跑磁盘占用过高

- 默认已采用 `execLogs=interesting` 且只保存非空 stdout/stderr
- 如仍需极限压 IO：可 `-Dnju.fuzzer.execLogs=none`
- `statsFlushEvery` 调大可减少 flush 频率（代价是异常退出时末尾数据可能未落盘）

---

## 7. 进一步阅读（原始模块文档索引）

- 架构总览：`docs/ARCHITECTURE.md`
- CLI：`docs/CLI/CLI.md`
- 引擎：`docs/Engine/FuzzingEngine.md`
- ExecutorHarness：`docs/ExecutorHarness/ExecutorHarness.md`
- Executor：`docs/ExecutorHarness/Executor.md`
- CoverageMonitor：`docs/CoverageMonitor/CoverageMonitor.md`
- 扩展覆盖组件：`docs/CoverageMonitor/ExtendedComponents.md`
- 队列：`docs/Queue/SeedQueue.md`
- 调度：`docs/schedule/Scheduling.md`
- 统计：`docs/stats/stats.md`
- 变异体系：`docs/mutate/Mutator.md`、`docs/mutate/binary.md`、`docs/mutate/grammar.md`
- Mutator 审查与问题记录：`docs/mutate/Problems/`

