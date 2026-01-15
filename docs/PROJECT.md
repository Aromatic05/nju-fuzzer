# NJU-Fuzzer 项目文档

本项目是南京大学自动化测试课程代码大作业：**覆盖率引导的变异式模糊测试工具** 的项目文档。

<a id="toc"></a>
## 目录（可导航，细化）

<details open>
<summary>一. 概览</summary>

- [1. 项目简介](#sec-intro)
    - [1.1 项目目标](#sec-1-1)
    - [1.2 关键特性](#sec-1-2)
    - [1.3 仓库结构](#sec-1-3)
- [2. 工具运行方法与示例（快速启动）](#sec-quickstart)
    - [2.1 方式 A：无覆盖（任何机器可跑）](#sec-2-1)
    - [2.2 方式 B：本机/实验环境构建 AFL++ 插桩目标并启用覆盖率](#sec-2-2)
    - [2.3 方式 C：Docker / docker-compose](#sec-2-3)
- [3. 使用方法（详细指南）](#sec-usage)
    - [3.1 入口链路](#sec-3-1)
    - [3.2 核心参数（最常用）](#sec-3-2)
    - [3.3 STDIN 与 FILE 两种输入模式](#sec-3-3)
    - [3.4 运行期关键系统属性](#sec-3-4)
    - [3.5 拓展与定制](#sec-3-5)
        - [3.5.1 接入新目标程序](#sec-3-5-1)
        - [3.5.2 增加一种 SeedType / Mutator](#sec-3-5-2)
        - [3.5.3 覆盖策略与调度策略替换](#sec-3-5-3)
- [4. 设计方案（总览）](#sec-design-overview)
    - [4.1 整体架构](#sec-4-1)
    - [4.2 主循环闭环（流程）](#sec-4-2)
    - [4.3 数据模型（核心 record/POJO）](#sec-4-3)
    - [4.4 类层次与模块职责](#sec-4-4)
        - [CLI（参数解析与组装）](#sec-4-4-cli)
        - [Core（引擎与执行抽象层）](#sec-4-4-core)
        - [Exec（进程执行与 crash 口径）](#sec-4-4-exec)
        - [Coverage（覆盖监控、策略与全局 DB）](#sec-4-4-cov)
        - [Queue / Schedule（队列与调度）](#sec-4-4-queue)
        - [Mutate（变异器体系）](#sec-4-4-mutate)
        - [Corpus / Stats（落盘与可观测性）](#sec-4-4-corpus)

</details>

<details>
<summary>二. 模块设计与实现（整合）</summary>

- [1. CLI 命令行参数入口解析](#sec-cli-module)
- [2. ExecutorHarness 标准执行环境](#sec-m-executorharness)
- [3. Executor 进程执行器](#sec-m-executor)
- [4. CoverageMonitor 覆盖率监控](#sec-m-covmonitor)
- [5. CoverageMonitor 扩展组件（EdgeSet/CoverageDB/CoverageEx）](#sec-m-cov-extended)
- [6. FuzzingEngine 主循环（闭环编排）](#sec-m-engine)
- [7. SeedQueue 种子队列](#sec-m-seedqueue)
- [8. Scheduling 调度（Selection + Power）](#sec-m-scheduling)
- [9. Stats 运行期统计与日志](#sec-m-stats)
- [10. Mutator 变异体系总览](#sec-m-mutator)
- [11. MutatorFactory 变异器工厂](#sec-m-mutatorfactory)
- [12. MutationOps 底层变异算子](#sec-m-mutationops)
- [13. 二进制结构感知变异框架（binary）](#sec-m-binary)
- [14. 语法感知变异框架（grammar）](#sec-m-grammar)

</details>

<details>
<summary>三. 附录（其他文档）</summary>

- [1. ARCHITECTURE 架构说明](#sec-architecture-appendix)
- [2. 开发日志（整合版）](./Devlog.md)
- [3. Mutator 审查清单（Problems）](mutate/Problems/PngMutator_Problems.md)
- [4. 实验结果与可视化（result/）](./Visual/visualization.md)

</details>

---




<a id="sec-overview"></a>
# 一. 概览

<a id="sec-intro"></a>
## 1. 项目简介
<a id="sec-1-1"></a>
### 1.1 项目目标

- **在 Java 生态内实现可运行的 coverage-guided fuzzing 闭环**：选种、变异、执行、覆盖反馈、晋升入队、统计落盘。
- **兼容两类目标程序**：
	- **非插桩目标**：`--coverage none`，仍能跑通主循环与产物结构（用于任何机器的复现/教学/调试）。
	- **AFL++ 插桩目标**：`--coverage shm|shmex`，通过 SysV SHM bitmap 获取覆盖反馈，驱动入队与调度。

<a id="sec-1-2"></a>
### 1.2 关键特性

- **运行入口**：CLI 解析参数并组装执行链路（见 `docs/CLI/CLI.md`）。
- **执行抽象层**：`ExecutorHarness` 统一编排 `beforeRun → run → afterRun`，避免主循环写分支（详细说明见ExecutorHarness部分）。
- **覆盖率监控**：`ShmCoverageMonitor`/`ShmCoverageMonitorEx` 读取 AFL++ SHM bitmap，可插拔 diff 策略（详细说明见CoverageMonitor部分）。
- **全局覆盖数据库**：`CoverageDB` 维护 `edgeFreq/topRated/favored/redundant/rarity`，支持全局确认 interesting（详细说明见CoverageMoniter.ExtendedConponents部分）。
- **队列与调度**：`SeedQueue` + `SeedPrioritizer` + `PowerScheduler`，可消费 CoverageDB 提示字段（详细说明见Queue与Scheduling部分）。
- **变异系统**：Havoc（通用）+ 结构/语法感知变异器（按 `SeedType` 路由）（详细说明见Mutator部分）。
- **语料落盘**：`queue/crashes/hangs` 三类输出，元信息 `.meta`（详细说明见落盘部分）。
- **统计与可观测性**：状态行 + `stats.csv` + `curve.csv`（详细说明见stats部分）。

<a id="sec-1-3"></a>
### 1.3 仓库结构

- `docs/`：项目文档（包含本文件、各模块设计说明、CLI 说明等）。
- `env/`：包含环境搭建脚本，目标程序源码和第三方库及构建产物（经过 AFL++ 插桩）、seeds 等。
- `src/main/java/edu/nju/fuzzing/`：核心代码。
    - `cli/`：CLI 解析与入口。
    - `core/`：核心引擎代码（ExecutorHarness、FuzzingEngine 等）。
    - `corpus/`：语料库管理（CorpusManager等）。
    - `cov/`：覆盖率监控相关（CoverageMonitor、CoverageDB等）。
    - `exec/`：执行引擎相关（Executor等）。
    - `model/`：数据模型（Seed、Testcase、ExecResult等）。
    - `mutate/`：变异器相关（Mutator等）。
    - `queue/`：种子队列（SeedQueue）。
    - `schedule/`：调度器相关（SeedPrioritizer、PowerScheduler等）。
    - `stats/`：统计与状态显示（Stats、StatusPrinter等）。
- `src/test/java/edu/nju/fuzzing/`：单元测试与集成测试代码。
- `pom.xml`：Maven 构建文件。
- `Dockerfile` 与 `docker-compose.yml`：Docker 环境定义与一键运行脚本。
- `one_click.sh`：一键运行脚本。
- `result/`：实验结果与可视化

---

<a id="sec-quickstart"></a>
## 2. 工具运行方法与示例（快速启动）

本节以“先跑起来”为目标，按从易到难给出三条路径：**纯 Java 无覆盖** → **本机构建插桩目标** → **Docker 一键跑**。

### 2.1 方式 A：无覆盖（任何机器可跑）
<a id="sec-2-1"></a>

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
<a id="sec-2-2"></a>

这条路径用于“真正的覆盖率引导 fuzzing”。

1) 构建 AFL++ 与目标（脚本需要 root）：

```bash
cd env && ./env.sh
```

脚本会依次安装依赖、拉取 targets、构建 AFL++、构建目标、拉取 seeds，并在 `env/out` 与 `env/seeds` 产生输出。

2) 一键 fuzz（推荐，最少心智负担）：

```bash
./one_click.sh lua
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

### 2.3 方式 C：Docker / docker-compose
<a id="sec-2-3"></a>

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

<a id="sec-usage"></a>
## 3. 使用方法（详细指南）

### 3.1 入口链路
<a id="sec-3-1"></a>

整体入口链路保持固定：

`CliParser → CliArgs → FuzzerMain → TargetSpec → FuzzingEngine.run()`

模块说明见CLI部分。

### 3.2 核心参数（最常用）
<a id="sec-3-2"></a>

- `--workdir <dir>`：工作目录（输出都在这里）
- `--seeds <dir>`：初始 seeds 目录（可覆盖默认 `workdir/seeds`）
- `--seedType <type>`：本次 run 的种子类型（同一次 run 必须一致；与 `SeedType` 枚举对齐）
- `--duration <sec>`：运行秒数
- `--timeout <ms>`：单次执行超时
- `--tid <name>`：目标名称（出现在状态行与 stats 中）
- `--cmd "<argvTemplate>"`：目标命令模板；含 `@@` 则为 FILE 模式，否则 STDIN 模式
- `--coverage none|shm|shmex`：覆盖率模式
- `--nonCrashExitCodes <codes>`：非 crash 退出码白名单（可选；用于把部分“非 0 退出但不是崩溃”的目标行为排除出 crash 统计；与默认的 `130/143` 合并）。

### 3.3 STDIN 与 FILE 两种输入模式
<a id="sec-3-3"></a>

- **STDIN 模式**（命令模板不含 `@@`）
	- testcase bytes 写入子进程 stdin
- **FILE 模式**（命令模板含 `@@`）
	- testcase bytes 覆盖写入固定文件 `.cur_input`
	- 运行前将 argv 中的 `@@` 替换为该文件路径（支持多个 `@@`）

### 3.4 运行期关键系统属性
<a id="sec-3-4"></a>

- `-Dnju.fuzzer.execLogs=interesting|all|none`
	- 默认 `interesting`：仅对“晋升为 interesting”的输入 best-effort 二次执行抓 stdout/stderr
- `-Dnju.fuzzer.execLogsMaxBytes=<bytes>`：stdout/stderr 捕获上限（默认 1MB）
- `-Dnju.fuzzer.tmpInputsDir=<path>`：覆盖 `.cur_input` 目录（FILE 模式）
- `-Dnju.fuzzer.requireTmpfsInputs=true|false`：是否强制 tmpfs（默认 true；不可用则 fail-fast）
- `-Dnju.fuzzer.persistTmpInputs=true|false`：STDIN 模式是否也写 `.cur_input`（默认 false）
- `-Dnju.fuzzer.curveBucketSec=<sec>`：`curve.csv` 分桶间隔（默认 1 秒）
- `-Dnju.fuzzer.statsFlushEvery=<N>`：stats/curve 每写 N 行 flush（默认 100；<=0 表示只在 close 时 flush）

### 3.5 拓展与定制
<a id="sec-3-5"></a>

### 3.5.1 接入新目标程序
<a id="sec-3-5-1"></a>

最推荐的接入方式是：

1) 把目标放到 `env/out/<name>`（或自己选择路径）
2) 准备 seeds：`env/seeds/<ID>/`
3) 选择输入模式：
	 - STDIN：`--cmd "env/out/<name>"`
	 - FILE：`--cmd "env/out/<name> ... @@ ..."`
4) 运行：优先用 `one_click.sh` 或参考其映射逻辑新增一条 case

### 3.5.2 增加一种 SeedType / Mutator
<a id="sec-3-5-2"></a>

1) 在 `SeedType` 增加枚举
2) 实现 `Mutator`：`Iterator<Testcase> mutate(Seed seed, int energy)`
3) 在 `MutatorFactory` 增加路由
4) （可选）补一份 Problems/审查清单：记录“合法率/深层触达率/约束修复策略”等经验

### 3.5.3 覆盖策略与调度策略替换
<a id="sec-3-5-3"></a>

- 覆盖 diff 策略：实现/替换 `CoverageDiffStrategy` 或 `CoverageDiffStrategyEx`
- 调度：
	- 选种：调整 `SeedPrioritizer.scoreForSelection` 的信号组合
	- 能量：调整 `PowerScheduler` 因子与封顶策略
	- 当 `CoverageDB` 可用时，优先消费 `favored/rarity/redundant/stability` 等提示字段

---
<a id="sec-design-overview"></a>
## 4. 设计方案（总览）

### 4.1 整体架构
<a id="sec-4-1"></a>
```
┌─────────────────────────────────────────────────┐
│               FuzzingEngine (主循环)            │
│  Seed选择 → 能量调度 → 变异 → 执行 → 入队/落盘  │
└────────────────────────────────┬────────────────┘
								 │
				┌────────────────┴───┐
				│ ExecutorHarness    │   执行抽象层（固定编排）
				│ start/execute/close│
				└┬────────────────┬──┘
				 │		          │
		┌────────┴──┐ ┌───────────┴───────┐
		│ Executor  │ │ CoverageMonitor   │
		│ (进程执行)│ │ (覆盖监控)        │
		└───────────┘ └──┬────────────────┘
						 │
		┌────────────────┴────┐
		│ ProcessExecutor     │
		│ stdin/file + timeout│
		└─────────────────────┘
```
### 4.2 主循环闭环（流程）
<a id="sec-4-2"></a>

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
<a id="sec-4-3"></a>

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

### 4.4 类层次与模块职责
<a id="sec-4-4"></a>

以下为“读代码入口”的最小类图索引（按包组织，展示关键类的层次与职责）。

#### CLI（参数解析与组装）
<a id="sec-4-4-cli"></a>

```
edu.nju.fuzzing.cli
	CliParser
	CliArgs
	CmdLineTokenizer
	FuzzerMain
```

#### Core（引擎与执行抽象层）
<a id="sec-4-4-core"></a>

```
edu.nju.fuzzing.core
	FuzzingEngine
	ExecutorHarness (interface)
	InstrumentedExecutorHarness
```

#### Exec（进程执行与 crash 口径）
<a id="sec-4-4-exec"></a>

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
<a id="sec-4-4-cov"></a>

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
<a id="sec-4-4-queue"></a>

```
edu.nju.fuzzing.queue
	SeedQueue

edu.nju.fuzzing.schedule
	SeedPrioritizer
	PowerScheduler
```

#### Mutate（变异器体系）
<a id="sec-4-4-mutate"></a>

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
<a id="sec-4-4-corpus"></a>

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


<a id="sec-modules"></a>
# 二. 模块设计与实现（整合）

<a id="sec-cli-module"></a>
## 1. CLI 命令行参数入口解析

### 概述

CLI 模块负责把命令行参数解析为可运行的配置，并组装核心执行链路：

`CliParser` → `CliArgs` → `FuzzerMain` → `TargetSpec` → `FuzzingEngine.run()`

它的目标是：

- 保持**默认可运行**（即使没有 AFL++ 插桩与共享内存环境，也能用 `--coverage none` 启动并跑通主循环）。
- 支持在运行时切换 coverage 模式：`none | shm | shmex`。
- 支持指定 seeds 目录（`--seeds`），避免写死 `workdir/seeds`。

位置：

- 参数模型：[src/main/java/edu/nju/fuzzing/cli/CliArgs.java](../src/main/java/edu/nju/fuzzing/cli/CliArgs.java)
- 参数解析：[src/main/java/edu/nju/fuzzing/cli/CliParser.java](../src/main/java/edu/nju/fuzzing/cli/CliParser.java)
- 程序入口：[src/main/java/edu/nju/fuzzing/cli/FuzzerMain.java](../src/main/java/edu/nju/fuzzing/cli/FuzzerMain.java)

---

### 快速开始（可复现）

无覆盖（默认）+ STDIN 模式（适用于任何机器）：

- `mvn -q -DskipTests exec:java -Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain -Dexec.args="--workdir /tmp/nju-fuzzer/workdir --duration 1 --timeout 500 --tid DEMO --cmd /bin/cat --coverage none"`

FILE 模式（argv 中包含 `@@`，将输入写入固定文件并把路径替换给目标进程）：

- `mvn -q -DskipTests exec:java -Dexec.mainClass=edu.nju.fuzzing.cli.FuzzerMain -Dexec.args="--workdir /tmp/nju-fuzzer/workdir --duration 1 --timeout 500 --tid DEMO --cmd '/bin/cat @@' --coverage none"`

启用共享内存覆盖率（需要目标程序是 AFL++/兼容插桩）：

- `--coverage shm`：基础 SHM monitor（仍产出 edge-level hit/new，用于 CoverageDB 更新）
- `--coverage shmex`：扩展 SHM monitor（自带 CoverageDB，并默认启用稳定性确认）

---

### 参数与默认值

`CliParser` 采用“最小骨架”风格：按 `key value` 成对解析。

- `--workdir`：工作目录（默认 `workdir`）
- `--seeds`：初始 seeds 目录（默认 `workdir/seeds`）
- `--duration`：运行秒数（默认 `3`）
- `--timeout`：单次执行超时毫秒（默认 `1000`）
- `--tid`：任务 ID（默认 `DEMO`）
- `--cmd`：目标命令行（默认 `/bin/cat`）
- `--coverage`：`none|shm|shmex`（默认 `none`；非法值会 fail-fast 抛出异常）
- `--seedType`：本次 run 的 seed 类型（默认 `UNKNOWN`；大小写不敏感，例如 `xml`）
- `--nonCrashExitCodes`：逗号或空格分隔的 exit code 白名单（默认空；示例：`1,2,4`）。

>Crash 判定口径：
>- 默认情况下：使用 `CrashOracle` 的 shell 约定规则：`exitCode > 128` 视为 crash（通常是 `128 + signal`，如 >`139=SIGSEGV`）。
>- `130`（SIGINT）与 `143`（SIGTERM）默认视为 non-crash（避免手动中断污染 crash 统计）。
>- 如提供 `--nonCrashExitCodes`，会与默认集合合并，用于目标特定的“非 0 退出但不是崩溃”的口径修正。
>- `--cmd` 的引号/空格分隔由 `CmdLineTokenizer` 处理；实践中建议把整条命令用引号包起来传给 Maven `-Dexec.>args`。
---

### `--cmd` 的 STDIN 与 FILE 两种输入方式

- STDIN 模式：当 argvTemplate 不含 `@@` 时，`FuzzingEngine` 会把 testcase bytes 直接作为 stdin 传给子进程。
- FILE 模式：当 argvTemplate 含 `@@` 时，`FuzzingEngine` 会把 testcase bytes 写入 `workdir/tmp/inputs/.cur_input`，并把该路径替换 `@@` 传给子进程。

这两种模式的具体实现见引擎文档：[docs/Engine/FuzzingEngine.md](Engine/FuzzingEngine.md)。

---

### `--coverage` 模式与共享内存注入

#### none

- 使用 `NullCoverageMonitor`。
- 不依赖 `__AFL_SHM_ID` / `AFL_MAP_SIZE`。
- 仍可跑通主循环、产出 workdir 结构与日志。

#### shm / shmex

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

### 可验证产物（workdir layout）

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

### 测试覆盖

- CLI 冒烟：
    - [src/test/java/edu/nju/fuzzing/cli/FuzzerMainCmdSmokeTest.java](../src/test/java/edu/nju/fuzzing/cli/FuzzerMainCmdSmokeTest.java)
  - 覆盖 STDIN/FILE 两种模式、`--seeds` 覆盖、非法 `--coverage` fail-fast。

- CLI 参数解析：
    - [src/test/java/edu/nju/fuzzing/cli/CliParserTest.java](../src/test/java/edu/nju/fuzzing/cli/CliParserTest.java)

- Crash 判定口径：
    - [src/test/java/edu/nju/fuzzing/exec/CrashOracleTest.java](../src/test/java/edu/nju/fuzzing/exec/CrashOracleTest.java)
    - [src/test/java/edu/nju/fuzzing/core/FuzzingEngineCrashOracleIntegrationTest.java](../src/test/java/edu/nju/fuzzing/core/FuzzingEngineCrashOracleIntegrationTest.java)

---

### 参数使用说明（非常详尽）

本节面向“实际跑目标程序”的使用场景，给出每个参数的语义、边界条件、典型写法与坑点。

#### 0) 解析规则（重要）

`CliParser` 采用最小实现：**按 `key value` 成对解析**。

- 所有参数必须写成：`--key value`
- 不支持单独 flag（例如 `--foo` 这种没有 value 的写法）
- 如果你最后一个 token 只有 key 没有 value，它会被忽略（因为循环按 `i < args.length - 1` 解析）

#### 1) `--workdir`：工作目录

- 默认：`workdir`
- 作用：
  - 所有输出目录（queue/crashes/hangs/stats/tmp）都在这里
  - 用于复现、归档、对比不同 run

建议：每次 fuzz run 使用独立目录，例如：`workdir/run-YYYYMMDD-HHMMSS-<target>`。

#### 2) `--seeds`：初始 seeds 目录

- 默认：`<workdir>/seeds`
- 加载行为（见 `SeedQueue.loadInitialSeeds`）：
  - 递归读取普通文件（支持子目录）
  - 跳过隐藏文件（文件名以 `.` 开头）
  - 跳过 `*.meta`
  - 对每个 seed：读取 `.meta` 中的调度提示字段（favored/redundant/...），类型强制使用本次 run 的 `--seedType`（同一次 run 必须一致）

如果 seeds 目录为空：引擎会创建 dummy seed（内容 `hello-from-engine`），位置：`<workdir>/tmp/seeds/seed_000001`。

#### 3) `--duration`：运行时长（秒）

- 默认：`3`
- 语义：到点后主循环退出（会打印 `[EVENT] Time up! Stopping fuzzing.`）。

#### 4) `--timeout`：单次执行超时（毫秒）

- 默认：`1000`
- 执行器行为（`ProcessExecutor`）：
  - 超时后先 `destroy()`，短暂等待，再 `destroyForcibly()`
  - 此次执行会被标记为 hang（`RunResult.Termination.TIMEOUT`），并进入 `hangs/` 分支

#### 5) `--tid`：任务 ID / 目标名

- 默认：`DEMO`
- 作用：
  - 出现在控制台状态行最左侧：`[tid][HH:MM:SS] ...`
  - 出现在 `stats.csv` 的 `target_name` 列

建议：用“目标 + 关键配置”命名，例如：`XMLLINT_07`、`LUA_5MIN`。

#### 6) `--cmd`：目标命令行

##### 6.1 分词规则（`CmdLineTokenizer`）

- 空格分隔 token
- 支持单引号/双引号成对包裹 token（只影响分词，不保留引号）
- 不支持复杂转义（比如 bash 的各种反斜杠转义），因此尽量把 `--cmd` 写得“简单、可分词”
- 引号不闭合会 fail-fast：`Unclosed quote in cmdLine`

##### 6.2 输入模式：STDIN vs FILE（`@@`）

- **STDIN 模式**：`--cmd` 中不包含 `@@`
  - testcase bytes 会作为 stdin 写给子进程
- **FILE 模式**：`--cmd` 中包含 `@@`
  - 每次执行会把 testcase bytes 覆盖写到 `<workdir>/tmp/inputs/.cur_input`
  - 运行前会把 argv 中的 `@@` 替换为 `.cur_input` 的绝对路径

注意：当前实现即使在 STDIN 模式下也会覆盖写 `.cur_input`（用于快速抓取“最近一次输入”调试）。

更新：现在 STDIN 模式默认 **不写** `.cur_input`（避免无谓落盘）；仅当显式开启 `-Dnju.fuzzer.persistTmpInputs=true` 时才会写。

---

### 运行期 IO 行为（重要）

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

##### 6.3 Maven 传参建议（减少引号问题）

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

#### 7) `--coverage`：覆盖率模式

- `none`：不使用覆盖率监控（Null monitor）。
- `shm`：使用 SysV SHM bitmap；CoverageDB 由引擎侧创建维护。
- `shmex`：使用扩展 SHM monitor；CoverageDB 可由 monitor 持有复用，并默认启用稳定性确认。

环境变量（shm/shmex）：

- `__AFL_SHM_ID`
- `AFL_MAP_SIZE`

`FuzzerMain` 会确保这些变量被注入到子进程 env（环境已有则透传；环境没有则自动创建 SHM 段并注入）。

#### 8) `--nonCrashExitCodes`：非 crash 退出码白名单

用途：解决“目标程序用非 0 退出码表示输入非法”导致的 crash 风暴。

- 格式：逗号或空格分隔，例如 `1,2,4` 或 `1 2 4`
- 无效 token 会被忽略（容错）
- 最终生效集合 = `130/143`（默认）+ 你提供的 codes
- 启动时会打印：`effectiveNonCrashExitCodes = [...]`（用于核对口径）

典型：xmllint 常用 `--nonCrashExitCodes 1,2,4`。

---

### 控制台日志说明（StatusPrinter / 事件行）

控制台输出主要来自三处：

- `FuzzerMain`：启动摘要（workdir/cmd/seeds/coverage/口径）
- `FuzzingEngine`：流程事件（加载种子、时间到停止等）
- `StatusPrinter` + `StatsTick`：每秒状态行，以及 crash/hang/newpath 事件

#### 1) 启动摘要（FuzzerMain）

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

#### 2) 流程事件行（FuzzingEngine.printEvent）

格式：`[EVENT] <message>`

常见：

- `[EVENT] Loading initial seeds from ...`
- `[EVENT] Loaded N initial seeds.`
- `[EVENT] WARNING: No initial seeds found. Starting with dummy seed.`
- `[EVENT] Time up! Stopping fuzzing.`

#### 3) 周期状态行（每秒 1 次）

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

#### 4) 事件行（new path / crash / hang）

- new path：`[NEW PATH] id=<n>, coverage=<m>`
  - `id` 是晋升次数（不是文件名里的 id）
  - `coverage` 当前打印的是 `edgeCount()`（hit edges 数），在 `--coverage none` 下通常为 0

- crash：`[CRASH] id=<n>, reason=exit_<code>`
  - 只有当 `CrashOracle` 判定为 crash 才会出现

- hang：`[HANG] id=<n>, timeout=<ms>ms`
  - 对应超时执行

---

### stats/stats.csv 说明（CSV 内容、字段含义、注意事项）

文件位置：`<workdir>/stats/stats.csv`

#### 1) Header（列名）

当前 header 固定为：

```csv
timestamp,target_name,exec_count,covered_edges,execs_per_sec,queue_size,total_paths,crash_count,hang_count
```

#### 2) 每列含义

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

#### 3) 写入频率与文件大小

`FuzzingEngine` 当前默认 `tickIntervalMs = 0`，意味着：

- `StatsWriter.tick(...)` **可能每次 exec 都写一行**（长跑会很大）
- 同时 `StatusPrinter` 仍按 1 秒一行打印到控制台

如果你只是想看趋势：可以在后处理阶段对 CSV 抽样（例如每 N 行取一行）。

#### 4) 一行样例

```csv
12,XMLLINT,534,2872,15.20,265,262,0,18
```

解释：运行 12 秒，累计执行 534 次；覆盖 edges 2872；速度约 15/s；队列 265；晋升 262；crash 0；hang 18。

#### 5) stats/curve.csv：按秒分桶的增长曲线（运行时记录）

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

- writer 实现：[src/main/java/edu/nju/fuzzing/stats/StatsCurveWriter.java](../src/main/java/edu/nju/fuzzing/stats/StatsCurveWriter.java)
- 引擎接入（创建并 tick）：[src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java](../src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java#L333-L410)

#### 6) 一键运行脚本：one_click.sh

仓库根目录提供 [one_click.sh](../one_click.sh)，用于“一条命令跑指定目标”。约束与约定：

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

### workdir 目录输出说明（包含使用指导 / 复现指南）

#### 0) 总览

`FuzzerMain` 会创建：

- `queue/`：晋升的输入（后续变异的 seeds）
- `crashes/`：crash 输入
- `hangs/`：超时输入
- `stats/`：统计（`stats.csv`）
- `tmp/`：临时复用输入与执行日志

#### 1) queue/：晋升输入 + .meta 元数据

##### 文件命名

`FileCorpusManager.saveToQueue` 的命名：

- `id_%06d_cov_%d_%s`

字段：

- `id_%06d`：队列编号（递增）
- `cov_%d`：`coverage.newBytes()`（不是“总边数/覆盖边数”）
- `%s`：输入短 hash

##### 同名 `.meta` 文件

每个 queue 文件会有同名 `.meta`（由 `SeedQueue.addSeed()` 触发 `Seed.saveMetadata()` 写入）。

`.meta` 为 Java Properties 格式，常见字段：

- 血缘：`parent_id`, `depth`, `birth_type`
- 调度：`handicap`, `was_fuzzed`, `energy`, `exec_time`, `bitmap_size`
- CoverageDB hints：`favored`, `redundant`, `min_edge_freq`, `rarity_score`, `stability`
- 类型：`seed_type`（来自 `--seedType` 或沿用父种子）

注意：edge set 不会写入 `.meta`（避免元数据膨胀）。

#### 2) crashes/：crash 输入

命名：`crash_%06d_exit_%d_%s`

- `%d` exit code 来自目标进程
- 是否进入 crashes 由 CrashOracle 决定：
  - 默认将 `130/143` 视为 non-crash
  - 额外由 `--nonCrashExitCodes` 指定

#### 3) hangs/：超时输入

命名：`hang_%06d_%s`

#### 4) tmp/inputs/.cur_input：最近一次输入（复用文件）

- 每次执行都会覆盖写该文件（避免创建大量临时文件）
- FILE 模式下，目标收到的参数就是这个路径
- STDIN 模式下也会写入（为了方便你随手拿到“最近一次输入”）

#### 5) tmp/exec-logs/：stdout/stderr 落盘

`ProcessExecutor` 每次执行都会写：

- `stdout_<execId>.log`
- `stderr_<execId>.log`

注意：

- `execId` 仅在本次 fuzz run 内递增；与 queue/crash/hang 的编号没有一一映射。
- 长跑会产生大量小文件（inode/磁盘风险）。

#### 6) tmp/seeds/：dummy seed

当 seeds 目录为空时，会在这里生成：

- `tmp/seeds/seed_000001`（内容为 `hello-from-engine`）
- 以及对应的 `seed_000001.meta`

---

### 如何使用这些产物（复现 / triage 流程）

#### 1) 复现 crash/hang

你需要根据目标的输入模式选择复现方式：

- **如果目标是 FILE 模式（你 fuzz 时 `--cmd` 用了 `@@`）**：
  - 直接把 `crashes/<file>` 或 `hangs/<file>` 作为目标的文件参数重放
  - 示例：`env/out/xmllint --noout <workdir>/crashes/crash_...`

- **如果目标是 STDIN 模式（你 fuzz 时 `--cmd` 不含 `@@`）**：
  - 用管道把输入喂给目标
  - 示例：`cat <workdir>/crashes/crash_... | <target argv...>`

#### 2) 快速抓“刚刚那次输入”

如果你中途 Ctrl-C 停止 fuzz，或者想立刻复现“最后一次执行”，直接用：

- `<workdir>/tmp/inputs/.cur_input`

它就是最近一次执行时写入的字节序列。

#### 3) 处理“非 0 退出码不代表 crash”的目标

对 xmllint / 各类解析器，建议先把常见的“输入非法”退出码加到白名单：

- `--nonCrashExitCodes 1,2,4`

这样可以避免把大量“正常拒绝输入”误记为 crash，从而：

- `crashes/` 不会被无意义输入淹没
- `crash_count` 更接近“真正异常”

---

## 2. ExecutorHarness 标准执行环境
<a id="sec-m-executorharness"></a>

### 概述

`ExecutorHarness` 是一个高层抽象，将底层的 `Executor`（进程执行）与 `CoverageMonitor`（覆盖监控）整合为统一的执行环境。它负责正确编排覆盖监控的生命周期（清零 bitmap → 执行 → 收集覆盖），并提供一致的 API，无论是否启用覆盖监控。

---

### 核心设计

#### 为什么需要 ExecutorHarness？

**问题：** 原始设计中，主循环需要手动管理覆盖监控：

```java
// ❌ 错误示范：主循环混入覆盖监控细节
monitor.beforeRun();
RunResult run = executor.run(...);
Coverage coverage = monitor.afterRun(run);
```

**缺点：**
1. 主循环代码冗长，容易遗漏 `beforeRun()` 或 `afterRun()`
2. 无覆盖模式需要写分支逻辑（`if (monitor != null)`）
3. 覆盖监控的 `start()/close()` 时机难以统一管理

**解决方案：** `ExecutorHarness` 封装执行 + 覆盖的完整流程

```java
// ✅ 正确示范：主循环只关心输入和结果
ExecResult result = harness.execute(input);
```

---

### 接口定义

#### `ExecutorHarness`

位置：`edu.nju.fuzzing.core.ExecutorHarness`

```java
public interface ExecutorHarness extends AutoCloseable {
    
    /**
     * 初始化执行环境
     * - 插桩目标：attach AFL++ SHM
     * - 非插桩目标：no-op
     * 
     * 必须在 execute() 前调用一次
     */
    void start() throws Exception;
    
    /**
     * 执行目标程序一次并收集覆盖
     * 
     * 内部顺序（固定）：
     * 1. monitor.beforeRun()  - 清零 bitmap
     * 2. executor.run()       - 执行目标
     * 3. monitor.afterRun()   - 收集覆盖
     * 
     * @param input 执行参数（命令、stdin、超时、日志）
     * @return 统一结果（RunResult + CoverageEx）
     */
    ExecResult execute(ExecInput input) throws Exception;
    
    /**
     * 释放资源
     * - 插桩目标：detach AFL++ SHM
     * - 非插桩目标：no-op
     */
    @Override
    void close();
}
```

---

### 实现类

#### `InstrumentedExecutorHarness`

位置：`edu.nju.fuzzing.core.InstrumentedExecutorHarness`

**描述：** 标准实现，组合 `Executor` + `CoverageMonitor`

##### 构造函数

```java
public InstrumentedExecutorHarness(
    Executor executor,             // 底层执行器（如 ProcessExecutor）
    CoverageMonitor coverageMonitor, // 覆盖监控器（ShmCoverageMonitor 或 NullCoverageMonitor）
    int mapSize                    // 覆盖图大小（默认 65536）
)
```

**两种使用模式：**

1. **有覆盖监控**
   ```java
   ShmCoverageMonitor monitor = ShmCoverageMonitor.fromEnvironment();
   ExecutorHarness harness = new InstrumentedExecutorHarness(executor, monitor);
   ```

2. **无覆盖监控**（统一代码路径）
   ```java
   NullCoverageMonitor nullMonitor = new NullCoverageMonitor(65536);
   ExecutorHarness harness = new InstrumentedExecutorHarness(executor, nullMonitor);
   ```

##### 生命周期管理

###### 1. `start()` - 初始化

```java
@Override
public void start() throws Exception {
    // 如果是 ShmCoverageMonitor，调用其 start() 方法（attach SHM）
    if (coverageMonitor.getClass().getName().contains("ShmCoverageMonitor")) {
        try {
            var startMethod = coverageMonitor.getClass().getMethod("start");
            startMethod.invoke(coverageMonitor);
        } catch (NoSuchMethodException e) {
            // NullCoverageMonitor 没有 start()，忽略
        }
    }
}
```

**设计说明：**
- `CoverageMonitor` 接口只定义 `beforeRun()/afterRun()`
- `ShmCoverageMonitor` 额外有 `start()/close()`（attach/detach SHM）
- 使用反射调用 `start()`，保持接口简洁

###### 2. `execute()` - 执行

```java
@Override
public ExecResult execute(ExecInput input) throws Exception {
    // 1. 清零 bitmap（插桩目标）或 no-op（非插桩）
    coverageMonitor.beforeRun();
    
    // 2. 执行目标程序
    RunResult run = executor.run(
        input.cmd(),
        input.stdinData(),
        input.timeout(),
        input.outDir()
    );
    
    // 3. 收集覆盖（插桩目标）或返回空覆盖（非插桩）
    Coverage coverage = coverageMonitor.afterRun(run);
    
    // 4. 转换为 CoverageEx（扩展覆盖信息）
    CoverageEx coverageEx = CoverageEx.fromBasic(coverage);
    
    return new ExecResult(run, coverageEx);
}
```

**关键点：**
- `beforeRun/run/afterRun` 的顺序固定，外层不能改
- `CoverageEx.fromBasic()` 将基础覆盖信息升级为调度友好的扩展格式
- 返回统一的 `ExecResult`，简化上层处理

###### 3. `close()` - 清理

```java
@Override
public void close() {
    try {
        coverageMonitor.close();
    } catch (Exception e) {
        // 记录但不抛异常，避免掩盖主逻辑错误
        System.err.println("Warning: Failed to close coverage monitor: " + e.getMessage());
    }
}
```

---

### 辅助类型

#### `ExecInput` - 执行输入

位置：`edu.nju.fuzzing.model.ExecInput`

```java
public record ExecInput(
    TargetCommand cmd,    // 目标命令（已解析 @@）
    byte[] stdinData,     // stdin 数据（FILE 模式为 null）
    Duration timeout,     // 超时时间
    Path outDir,          // 输出目录
    boolean saveLogs      // 是否保存日志（崩溃/超时时需要）
) {
    // 工厂方法：默认不保存日志
    public static ExecInput of(TargetCommand cmd, byte[] stdinData, 
                                Duration timeout, Path outDir) {
        return new ExecInput(cmd, stdinData, timeout, outDir, false);
    }
    
    // 工厂方法：保存日志（用于崩溃/超时分析）
    public static ExecInput withLogs(TargetCommand cmd, byte[] stdinData,
                                      Duration timeout, Path outDir) {
        return new ExecInput(cmd, stdinData, timeout, outDir, true);
    }
}
```

**使用场景：**
- 正常执行：`ExecInput.of(...)`（不保存日志）
- 崩溃/超时：`ExecInput.withLogs(...)`（保存日志供调试）

> 重要说明（当前实现）：stdout/stderr 的实际落盘由 `ProcessExecutor` 读取 JVM 系统属性 `nju.fuzzer.execLogs` 控制。
> 也就是说，`ExecInput.saveLogs` 目前不作为落盘开关使用。
>
> 当前默认策略是：全局 `-Dnju.fuzzer.execLogs=interesting`，仅在 `FuzzingEngine` 确认某个输入需要晋升为 interesting 时，进行一次 best-effort 的二次执行并临时切换到 `execLogs=all` 来抓取 stdout/stderr（且仅保存非空输出）。

#### `ExecResult` - 执行结果

位置：`edu.nju.fuzzing.model.ExecResult`

```java
public record ExecResult(
    RunResult run,        // 执行结果（退出码、时间、终止状态）
    CoverageEx coverage   // 覆盖信息（边、稳定性、是否有趣）
) {
    // 便捷方法：是否发现新覆盖
    public boolean isInteresting() {
        return coverage.interesting();
    }
    
    // 便捷方法：是否崩溃
    public boolean isCrash() {
        return run.termination() == RunResult.Termination.ERROR;
    }
    
    // 便捷方法：是否超时
    public boolean isTimeout() {
        return run.timedOut();
    }
    
    // 便捷方法：是否正常执行
    public boolean isNormal() {
        return run.termination() == RunResult.Termination.NORMAL;
    }
}
```

**设计优势：**
- 将 `RunResult` 和 `CoverageEx` 打包为单一返回值
- 提供便捷方法（`isCrash()`、`isInteresting()`），简化主循环判断
- 类型安全，避免传错参数

#### `NullCoverageMonitor` - 空覆盖监控器

位置：`edu.nju.fuzzing.cov.NullCoverageMonitor`

```java
public final class NullCoverageMonitor implements CoverageMonitor {
    
    private final int mapSize;
    
    public NullCoverageMonitor(int mapSize) {
        this.mapSize = mapSize;
    }
    
    @Override
    public void beforeRun() {
        // No-op：无 bitmap 需要清零
    }
    
    @Override
    public Coverage afterRun(RunResult result) {
        // 返回空覆盖（newBytes=0, interesting=false）
        return Coverage.empty(result);
    }
    
    @Override
    public void close() {
        // No-op：无资源需要释放
    }
}
```

**作用：**
- 提供统一的 `CoverageMonitor` 接口，避免主循环写 `if (monitor != null)`
- 非插桩目标使用此监控器，保持执行流程一致
- 返回空覆盖信息，不影响主循环逻辑

---

### 使用示例

#### 完整示例：插桩目标

```java
// 1. 创建执行器和覆盖监控器
Executor executor = new ProcessExecutor();
ShmCoverageMonitor monitor = ShmCoverageMonitor.fromEnvironment();
ExecutorHarness harness = new InstrumentedExecutorHarness(executor, monitor);

// 2. 启动覆盖环境（attach SHM）
harness.start();

try {
    // 3. 准备输入
    Path inputFile = tempDir.resolve("input.bin");
    Files.write(inputFile, testData);
    
    TargetSpec spec = new TargetSpec(
        "FILE",
        Path.of("/path/to/instrumented/target"),
        List.of("target", "@@"),
        Map.of("AFL_MAP_SIZE", "65536"),
        Duration.ofSeconds(1)
    );
    TargetCommand cmd = CommandResolver.resolve(spec, inputFile);
    ExecInput input = ExecInput.of(cmd, null, Duration.ofSeconds(1), workDir);
    
    // 4. 执行并获取结果
    ExecResult result = harness.execute(input);
    
    // 5. 处理结果
    if (result.isCrash()) {
        System.out.println("CRASH: " + result.run().exitCode());
        corpus.saveCrash(input, result);
    } else if (result.isTimeout()) {
        System.out.println("TIMEOUT");
        corpus.saveHang(input, result);
    } else if (result.isInteresting()) {
        System.out.println("NEW COVERAGE: " + result.coverage().newEdgeCount() + " edges");
        corpus.saveInteresting(input, result);
    } else {
        System.out.println("Normal execution, no new coverage");
    }
    
} finally {
    // 6. 清理资源（detach SHM）
    harness.close();
}
```

#### 简化示例：非插桩目标

```java
// 使用 NullCoverageMonitor，代码流程完全一致
Executor executor = new ProcessExecutor();
NullCoverageMonitor nullMonitor = new NullCoverageMonitor(65536);
ExecutorHarness harness = new InstrumentedExecutorHarness(executor, nullMonitor);

harness.start();  // no-op

try {
    ExecResult result = harness.execute(input);
    
    // result.coverage() 总是空覆盖
    // result.isInteresting() 总是 false
    
    if (result.isCrash()) {
        corpus.saveCrash(input, result);
    }
} finally {
    harness.close();  // no-op
}
```

#### 主循环集成

```java
// 从 General.md 的伪代码改写
ExecutorHarness harness = new InstrumentedExecutorHarness(executor, monitor);
harness.start();

try {
    while (shouldContinue()) {
        Seed parent = selector.select(queue, covDb, stats);
        MutationBudget budget = scheduler.computeBudget(parent, covDb, stats);
        
        for (Testcase tc : mutator.mutate(parent, budget)) {
            // 构造输入
            ExecInput input = ExecInput.of(tc.cmd(), tc.stdinData(), timeout, workDir);
            
            // 执行（自动处理覆盖监控）
            ExecResult er = harness.execute(input);
            
            // 异常处理
            if (er.isTimeout()) {
                corpus.saveHang(tc, er, parent);
                continue;
            }
            if (er.isCrash()) {
                corpus.saveCrash(tc, er, parent);
                continue;
            }
            
            // 更新全局覆盖
            CoverageUpdate upd = covDb.update(parent.id(), er.coverage());
            
            // 入队有趣的输入
            if (upd.interesting()) {
                Seed child = corpus.saveInteresting(tc, er, parent);
                queue.add(child);
            }
        }
    }
} finally {
    harness.close();
}
```

---

### 设计要点

#### 1. 统一代码路径

**原则：** 主循环不应区分插桩/非插桩模式

```java
// ❌ 错误：分支逻辑
if (monitor != null) {
    monitor.beforeRun();
    run = executor.run(...);
    coverage = monitor.afterRun(run);
} else {
    run = executor.run(...);
    coverage = Coverage.empty(run);
}

// ✅ 正确：统一接口
ExecResult result = harness.execute(input);
```

#### 2. 覆盖监控生命周期

- **start()**：在主循环开始前调用一次（attach SHM）
- **beforeRun() → run() → afterRun()**：每次执行时调用
- **close()**：在主循环结束后调用一次（detach SHM）

**错误示范：**
```java
// ❌ 每次执行都 attach/detach SHM（性能灾难）
for (testcase : testcases) {
    monitor.start();
    monitor.beforeRun();
    run = executor.run(...);
    coverage = monitor.afterRun(run);
    monitor.close();
}
```

**正确示范：**
```java
// ✅ start/close 只调用一次
harness.start();
try {
    for (testcase : testcases) {
        ExecResult result = harness.execute(input);
    }
} finally {
    harness.close();
}
```

#### 3. ExecId 一致性

- `ProcessExecutor` 生成 `execId`
- `RunResult.execId` 传递到 `CoverageEx.execId`
- 整个执行链路使用同一个 `execId`

#### 4. 异常处理策略

- `execute()` 抛出 `Exception`，由主循环决定如何处理
- `close()` 吞掉异常并打印警告，避免掩盖主逻辑错误
- 超时/崩溃通过 `ExecResult` 的便捷方法判断，不抛异常

#### 5. 日志保存策略

```java
// 正常执行：不保存日志（节省 I/O）
ExecInput input = ExecInput.of(cmd, stdinData, timeout, outDir);

// 崩溃/超时：保存日志供分析
if (result.isCrash() || result.isTimeout()) {
    ExecInput inputWithLogs = ExecInput.withLogs(cmd, stdinData, timeout, outDir);
    // 重新执行以保存日志，或修改 ProcessExecutor 根据 saveLogs 决定是否保留
}
```

---

### 测试策略

#### 单元测试

1. **NullCoverageMonitor**
   - `beforeRun()` 不抛异常
   - `afterRun()` 返回空覆盖
   - `close()` 不抛异常

2. **InstrumentedExecutorHarness**
   - `start()` 正确调用 `ShmCoverageMonitor.start()`
   - `execute()` 按顺序调用 `beforeRun/run/afterRun`
   - `close()` 正确清理资源

3. **ExecInput/ExecResult**
   - 工厂方法正确设置参数
   - 便捷方法返回正确结果

#### 集成测试

1. **有覆盖监控**
   - 执行插桩目标，验证覆盖数据非空
   - 多次执行，验证 bitmap 正确清零

2. **无覆盖监控**
   - 执行非插桩目标，验证返回空覆盖
   - 验证主循环逻辑不受影响

3. **异常场景**
   - 目标崩溃时，验证 `isCrash()` 返回 true
   - 目标超时时，验证 `isTimeout()` 返回 true

---

### 与其他组件的关系

```
FuzzingEngine (主循环)
    └── ExecutorHarness (执行环境)
            ├── Executor (进程执行)
            │       └── ProcessExecutor (具体实现)
            └── CoverageMonitor (覆盖监控)
                    ├── ShmCoverageMonitor (插桩模式)
                    └── NullCoverageMonitor (非插桩模式)
```

**数据流：**
```
ExecInput → ExecutorHarness.execute() → ExecResult
    ↓                                        ↓
TargetCommand                        RunResult + CoverageEx
    ↓                                        ↓
ProcessExecutor.run()               CoverageMonitor.afterRun()
```

---

## 3. Executor 进程执行器
<a id="sec-m-executor"></a>


### 概述

执行器组件负责底层的进程启动、输入输出重定向、超时控制和执行结果收集。它提供了一个干净的抽象层，将进程管理的复杂性与上层的覆盖监控和模糊测试逻辑分离。

---

### 核心接口

#### `Executor`

位置：`edu.nju.fuzzing.exec.Executor`

**职责：** 执行目标程序并返回运行结果

```java
public interface Executor {
    /**
     * 执行目标程序一次
     * 
     * @param cmd 目标命令（包含 argv、env、inputMode）
     * @param stdinData stdin 输入数据（FILE 模式下为 null）
     * @param timeout 执行超时时间
     * @param outDir 输出目录（用于保存 stdout/stderr 日志）
     * @return 执行结果（包含 execId、退出码、终止状态、时间等）
     * @throws Exception 执行失败时抛出异常
     */
    RunResult run(TargetCommand cmd, byte[] stdinData, Duration timeout, Path outDir) 
        throws Exception;
}
```

**设计原则：**
- **单一职责**：只负责进程启动和结果收集，不涉及覆盖监控
- **无状态**：每次调用 `run()` 都是独立的执行
- **同步阻塞**：等待进程执行完成或超时后返回
- **异常透明**：不吞掉异常，让上层决定如何处理

---

### 实现类

#### `ProcessExecutor`

位置：`edu.nju.fuzzing.exec.ProcessExecutor`

**描述：** 基于 Java `ProcessBuilder` 的默认实现，支持 STDIN 和 FILE 两种输入模式。

##### 核心功能

1. **ExecId 生成**
   - 使用 `AtomicLong` 生成全局唯一的 `execId`
   - 确保每次执行都有唯一标识
   - 用于日志文件命名和结果追踪

```java
private final AtomicLong execIdCounter = new AtomicLong(0);
long execId = execIdCounter.incrementAndGet();
```

2. **输入模式处理**

   - **STDIN 模式**：将 `stdinData` 写入进程的 stdin
     - 捕获 `IOException`（broken pipe），避免因目标提前退出而导致写入失败
     - 写完后立即 flush 并关闭 stdin
   
   - **FILE 模式**：通过 `@@` 占位符传递文件路径
     - 关闭 stdin，避免目标程序阻塞等待输入
     - `CommandResolver` 负责将 `@@` 替换为实际文件路径

3. **超时控制**

   - 使用三阶段终止策略：
     1. **正常等待**：`waitFor(timeoutMs)`
     2. **优雅终止**：`destroy()` + `waitFor(KILL_GRACE_MS)`
     3. **强制终止**：`destroyForcibly()` + `waitFor(FORCE_KILL_GRACE_MS)`

```java
boolean finished = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
if (!finished) {
    // Timeout: destroy
    p.destroy();
    if (!p.waitFor(KILL_GRACE_MS, TimeUnit.MILLISECONDS)) {
        p.destroyForcibly();
        p.waitFor(FORCE_KILL_GRACE_MS, TimeUnit.MILLISECONDS);
    }
    timedOut = true;
}
```

4. **精确计时**

   - 使用 `System.nanoTime()` 而非 `System.currentTimeMillis()`
   - 计算实际执行时间：`execTimeNanos = endNs - startNs`
   - 避免时钟跳变的影响

5. **终止状态判定**

```java
if (timedOut) {
    termination = RunResult.Termination.TIMEOUT;
} else if (exitCode != 0) {
    termination = RunResult.Termination.ERROR;
} else {
    termination = RunResult.Termination.NORMAL;
}
```

6. **日志管理**

        `ProcessExecutor` 的 stdout/stderr 落盘由 JVM 系统属性控制：

        - `-Dnju.fuzzer.execLogs=interesting|all|none`
            - 默认 `interesting`：执行器本身不会落盘 stdout/stderr；由上层（`FuzzingEngine`）在“晋升为 interesting”时临时切到 `all` 并二次执行抓日志。
            - `all`：每次执行都抓 stdout/stderr，并写入 `outDir/stdout_<execId>.log` / `outDir/stderr_<execId>.log`。
            - `none`：完全丢弃 stdout/stderr。

        - 重要优化：仅当 stdout/stderr **非空**时才写文件（避免 0 字节小文件爆炸）。
        - `-Dnju.fuzzer.execLogsMaxBytes=<bytes>`：单次执行最多捕获的 stdout/stderr 字节数（默认 1MB；用于避免异常输出导致内存/磁盘压力）。

##### 返回值：`RunResult`

```java
return RunResult.of(
    execId,           // 全局唯一执行 ID
    inputFile,        // 输入文件路径（FILE 模式）
    execTimeMs,       // 执行时间（毫秒，兼容旧 API）
    exitCode,         // 进程退出码
    timedOut,         // 是否超时
    termination,      // 终止状态：NORMAL/ERROR/TIMEOUT
    stdoutFile,       // stdout 日志文件
    stderrFile        // stderr 日志文件
);
```

---

### 辅助类型

#### `TargetCommand`

位置：`edu.nju.fuzzing.exec.TargetCommand`

**描述：** 封装目标程序的执行参数

```java
public record TargetCommand(
    List<String> argv,      // 命令行参数（已解析 @@）
    Map<String, String> env, // 环境变量
    InputMode inputMode,    // 输入模式：STDIN 或 FILE
    Path inputFile          // 输入文件路径（FILE 模式下非空）
) {}
```

#### `InputMode`

```java
public enum InputMode {
    STDIN,  // stdin 输入模式
    FILE    // 文件输入模式（通过 @@ 占位符）
}
```

#### `CommandResolver`

位置：`edu.nju.fuzzing.exec.CommandResolver`

**职责：** 将 `TargetSpec` 和输入文件解析为 `TargetCommand`

```java
public static TargetCommand resolve(TargetSpec spec, Path inputFile) {
    // 检测是否包含 @@ 占位符
    if (argvTemplate.contains("@@")) {
        // FILE 模式：替换 @@ 为实际文件路径
        return new TargetCommand(
            resolvedArgv, 
            spec.env(), 
            InputMode.FILE, 
            inputFile
        );
    } else {
        // STDIN 模式
        return new TargetCommand(
            argvTemplate, 
            spec.env(), 
            InputMode.STDIN, 
            null
        );
    }
}
```

---

### 使用示例

#### 基础使用

```java
// 1. 创建执行器
Executor executor = new ProcessExecutor();

// 2. 准备输入数据
Path inputFile = tempDir.resolve("input.bin");
Files.write(inputFile, testData);

// 3. 解析目标命令
TargetSpec spec = new TargetSpec(
    "FILE",
    Path.of("/bin/cat"),
    List.of("/bin/cat", "@@"),
    Map.of(),
    Duration.ofSeconds(1)
);
TargetCommand cmd = CommandResolver.resolve(spec, inputFile);

// 4. 执行
RunResult result = executor.run(
    cmd,
    null,  // FILE 模式下 stdinData 为 null
    Duration.ofSeconds(1),
    workDir
);

// 5. 检查结果
if (result.timedOut()) {
    System.out.println("Execution timed out");
} else {
    // 注意：Executor 只负责返回退出码与终止状态；是否算 crash 由 CrashOracle 决定。
    CrashOracle crashOracle = CrashOracle.defaultOracle();
    if (crashOracle.isCrash(result)) {
        System.out.println("Crashed with exit code: " + result.exitCode());
    } else if (result.exitCode() != 0) {
        System.out.println("Non-crash abnormal exit: " + result.exitCode());
    } else {
        System.out.println("Normal execution: " + result.execTimeMs() + "ms");
    }
}
```

#### STDIN 模式

```java
TargetSpec spec = new TargetSpec(
    "STDIN",
    Path.of("/bin/grep"),
    List.of("/bin/grep", "pattern"),  // 无 @@
    Map.of(),
    Duration.ofSeconds(1)
);
TargetCommand cmd = CommandResolver.resolve(spec, null);

byte[] stdinData = "line1\npattern\nline3\n".getBytes();

RunResult result = executor.run(
    cmd,
    stdinData,  // 写入 stdin
    Duration.ofSeconds(1),
    workDir
);
```

---

### 设计要点

### Crash 判定：退出码与 crash 的关系

`RunResult` 的 `termination` 只有三类：

- `NORMAL`：退出码为 0
- `ERROR`：退出码非 0（但不等价于 crash）
- `TIMEOUT`：超时（上层统计为 hang）

项目中 crash 的判定由 `CrashOracle` 统一处理（位置：`edu.nju.fuzzing.exec.CrashOracle`），核心规则是：

- **默认仅将“signal-like”异常退出视作 crash**：`exitCode > 128`（shell 习惯编码 `exitCode = 128 + signal`，例如 139=SIGSEGV）
- 默认忽略 `130/143`（SIGINT/SIGTERM），避免手动中断污染 crash 统计
- 可通过 CLI 参数 `--nonCrashExitCodes` 扩展“非 crash 退出码白名单”（适配目标程序把非 0 当作“输入拒绝”的情况）


#### 1. ExecId 一致性

- `ProcessExecutor` 是 `execId` 的**唯一生成点**
- `RunResult.execId` 会传递到 `CoverageEx.execId`
- 避免在多个地方生成 ID 导致不一致

#### 2. 输入模式透明

- 上层通过 `CommandResolver` 自动识别输入模式
- `Executor` 根据 `cmd.inputMode()` 处理 stdin/file
- 主循环不需要区分 STDIN/FILE

#### 3. 异常处理策略

- **Broken pipe**：目标提前退出时忽略 stdin 写入失败
- **Timeout**：三阶段终止，避免僵尸进程
- **其他异常**：向上抛出，由 `ExecutorHarness` 或主循环处理

#### 4. 性能优化

- 使用 `AtomicLong` 避免同步开销
- 进程启动/终止的 grace period 设置合理
- 日志文件按需保留（通过 `saveLogs` 控制）

---

### 与 ExecutorHarness 的关系

```
ExecutorHarness
    ├── CoverageMonitor (beforeRun/afterRun)
    └── Executor (run)
```

- **Executor**：只负责进程执行
- **CoverageMonitor**：负责覆盖监控
- **ExecutorHarness**：编排两者的调用顺序

这种分层设计确保了：
- 每个组件职责单一
- 可以独立测试和替换实现
- 支持插桩/非插桩目标的统一接口

---

### 测试要点

1. **正常执行**：验证 exitCode、execTime、termination
2. **超时处理**：验证 `timedOut` 标志和强制终止
3. **崩溃处理**：验证非零退出码的 ERROR 状态
4. **STDIN 模式**：验证数据正确写入
5. **FILE 模式**：验证 `@@` 正确替换
6. **并发执行**：验证 execId 唯一性
7. **Broken pipe**：验证目标提前退出时不抛异常



---

## 4. CoverageMonitor 覆盖率监控
<a id="sec-m-covmonitor"></a>

### 概述

Coverage Monitor 是 NJU Fuzzer 的核心组件，负责监控 AFL++ 插装目标程序的代码覆盖率。通过读取 AFL++ 共享内存（SHM）中的 bitmap 数据，判定每次执行是否触发了新的代码路径，从而指导模糊测试器保存有价值的输入到语料库。

本模块采用分层设计，支持多种覆盖率对比策略，易于扩展和测试。

---

### 架构设计

#### 核心接口

```
CoverageMonitor (interface)
    ↓
ShmCoverageMonitor (implementation)
    ↓
┌─────────────────────────┬──────────────────────────┐
│                         │                          │
BitmapSource           CoverageDiffStrategy       FuzzStats
(interface)             (interface)              (statistics)
    ↓                       ↓
SysVShmBitmapSource    SeenNonZeroStrategy
                       PrevBitmapStrategy
                       HashFilteredStrategy
                       CompositeStrategy
```

#### 模块职责

* **CoverageMonitor**：定义覆盖率监控的生命周期接口（start, beforeRun, afterRun, close）
* **ShmCoverageMonitor**：完整实现，协调 BitmapSource 和 CoverageDiffStrategy
* **BitmapSource**：抽象 AFL++ SHM bitmap 读取，当前使用 JNA 实现
* **CoverageDiffStrategy**：可插拔的覆盖率对比策略，判定"是否 interesting"
* **FuzzStats**：统计执行次数、速度、新路径等指标

---

### 核心组件

#### 1. CoverageMonitor 接口

```java
public interface CoverageMonitor extends AutoCloseable {
    /** 初始化覆盖率监控（attach SHM） */
    void start() throws Exception;

    /** 每次执行前调用（清零 bitmap） */
    void beforeRun();

    /** 每次执行后调用（读取 bitmap，判定 interesting） */
    Coverage afterRun(RunResult result);

    /** 获取当前统计快照 */
    CoverageStats snapshotStats();

    /** 释放资源（detach SHM） */
    @Override
    void close();
}
```

**生命周期：**

1. `start()` - 从环境变量读取 `__AFL_SHM_ID`，attach 共享内存
2. `beforeRun()` - 清零 bitmap，准备接收新的覆盖率数据
3. `afterRun(RunResult)` - 读取 bitmap，使用策略判定是否 interesting
4. `close()` - detach 共享内存，释放资源

---

#### 2. ShmCoverageMonitor 实现

完整的 AFL++ 覆盖率监控实现，协调 bitmap 读取和对比策略。

**关键特性：**

* 从环境变量自动读取 `__AFL_SHM_ID` 和 `AFL_MAP_SIZE`
* 支持可插拔的对比策略（`CoverageDiffStrategy`）
* 自动计算执行速度（exec/s）
* 线程安全的统计更新

**构造示例：**

```java
// 使用默认策略（SeenNonZeroStrategy）
BitmapSource bitmapSource = new SysVShmBitmapSource(mapSize, shmId);
CoverageDiffStrategy strategy = new SeenNonZeroStrategy(mapSize);
CoverageMonitor monitor = new ShmCoverageMonitor(bitmapSource, strategy);

monitor.start();  // Attach SHM
```

---

#### 3. BitmapSource 接口

抽象 AFL++ bitmap 读取，支持不同的实现方式（JNA、JNI、文件 mmap）。

```java
public interface BitmapSource extends AutoCloseable {
    int mapSize();
    void attach() throws RuntimeException;
    boolean isAttached();
    void readInto(byte[] dst);
    void clear();
    void close();
}
```

**当前实现：SysVShmBitmapSource（JNA）**

* 使用 JNA 调用 `shmat()` / `shmdt()` 访问 System V 共享内存
* 高性能的 native memory copy（`Pointer.read()`）
* 支持清零操作（`Pointer.setMemory()`）

**使用示例：**

```java
BitmapSource source = new SysVShmBitmapSource(65536, shmId);
source.attach();

byte[] bitmap = new byte[65536];
source.readInto(bitmap);  // 读取当前 bitmap
source.clear();           // 清零 bitmap
source.close();           // Detach SHM
```

---

#### 4. CoverageDiffStrategy 策略

判定"本次执行是否触发新覆盖"的核心逻辑，支持多种策略。

```java
public interface CoverageDiffStrategy {
    DiffResult diff(byte[] current);

    record DiffResult(int newBytes, boolean interesting) {}
}
```

##### 4.1 SeenNonZeroStrategy（推荐）

**原理**：维护全局 `seen` bitset，判定"从未覆盖过的边"

**适用场景**：

* 生产环境首选
* 精确追踪全局覆盖率增长
* 减少重复输入入队

**示例**：

```java
CoverageDiffStrategy strategy = new SeenNonZeroStrategy(65536);
DiffResult result = strategy.diff(bitmap);
if (result.interesting()) {
    System.out.println("发现新覆盖: " + result.newBytes() + " bytes");
}
```

##### 4.2 PrevBitmapStrategy

**原理**：相对上一次执行的差异判定

**适用场景**：

* 快速原型验证
* 对比连续执行的覆盖率变化

**注意**：可能产生较多误判（重复触发已知路径）

##### 4.3 HashFilteredStrategy

**原理**：基于 XXHash64 快速去重，bitmap 相同则跳过判定

**适用场景**：

* 减少重复判定开销
* 与其他策略组合使用

**示例**：

```java
CoverageDiffStrategy baseStrategy = new SeenNonZeroStrategy(mapSize);
CoverageDiffStrategy strategy = new HashFilteredStrategy(mapSize, baseStrategy);
```

##### 4.4 CompositeStrategy

**原理**：组合多种策略，同时满足多个条件才判定为 interesting

**适用场景**：

* 严格的覆盖率判定（减少噪声）
* 自定义复合判定逻辑

**示例**：

```java
List<CoverageDiffStrategy> strategies = List.of(
    new SeenNonZeroStrategy(mapSize),
    new HashFilteredStrategy(mapSize)
);
CoverageDiffStrategy strategy = new CompositeStrategy(strategies);
```

---

### 数据模型

#### Coverage

表示一次执行的覆盖率快照。

```java
public record Coverage(
    long execId,              // 执行 ID
    long timestampMillis,     // 时间戳
    int mapSize,              // Bitmap 大小
    int nonZeroBytes,         // 非零字节数（总覆盖）
    int newBytes,             // 新增覆盖字节数
    long bitmapHash,          // Bitmap hash（可选）
    boolean interesting       // 是否有价值（应入队）
) {
    /** 创建空覆盖（无覆盖率监控时） */
    public static Coverage empty(RunResult result) {
        return new Coverage(
            result.execId(), 
            System.currentTimeMillis(),
            0, 0, 0, 0L, false
        );
    }
}
```

#### CoverageStats

覆盖率监控的统计快照。

```java
public record CoverageStats(
    long execs,                    // 总执行次数
    double execsPerSec,            // 执行速度
    long lastInterestingExecId,    // 最后一次有价值的执行 ID
    long lastInterestingAtMillis   // 最后一次有价值的执行时间
) {}
```

---

### 集成到 FuzzingEngine

#### 初始化

`FuzzingEngine` 提供三种构造器：

1. **无覆盖率监控**（非插装目标）

```java
FuzzingEngine engine = new FuzzingEngine(
    workdir, durationSec, targetSpec, executor, timeout
);
```

2. **有覆盖率监控**（AFL++ 插装目标）

```java
BitmapSource bitmapSource = new SysVShmBitmapSource(mapSize, shmId);
CoverageDiffStrategy strategy = new SeenNonZeroStrategy(mapSize);
CoverageMonitor monitor = new ShmCoverageMonitor(bitmapSource, strategy);

CorpusManager corpusManager = new FileCorpusManager(workdir);

FuzzingEngine engine = new FuzzingEngine(
    workdir, durationSec, targetSpec, executor, timeout,
    monitor, corpusManager
);
```

#### 主循环集成

```java
public void run() throws Exception {
    // Start coverage monitor
    if (coverageMonitor instanceof ShmCoverageMonitor shmMonitor) {
        shmMonitor.start();  // Attach SHM
    }

    try {
        while (shouldContinue()) {
            byte[] payload = generatePayload();

            // 执行前清零
            if (coverageMonitor != null) {
                coverageMonitor.beforeRun();
            }

            // 执行目标
            RunResult result = executor.run(command, stdinData, timeout, logDir);

            // 执行后收集覆盖率
            Coverage coverage = coverageMonitor != null
                ? coverageMonitor.afterRun(result)
                : Coverage.empty(result);

            // 处理结果
            handleResult(payload, result, coverage);
        }
    } finally {
        // Close coverage monitor
        if (coverageMonitor instanceof AutoCloseable closeable) {
            closeable.close();  // Detach SHM
        }
    }
}

private void handleResult(byte[] input, RunResult result, Coverage coverage) {
    if (corpusManager == null) return;

    // 保存 crash
    if (result.termination() == RunResult.Termination.ERROR) {
        corpusManager.saveCrash(input, result);
        return;
    }

    // 保存 hang
    if (result.timedOut()) {
        corpusManager.saveHang(input, result);
        return;
    }

    // 保存 interesting 输入
    if (coverage != null && coverage.interesting()) {
        corpusManager.saveToQueue(input, coverage);
    }
}
```

---

### 环境变量配置

#### AFL++ 插装目标

确保目标程序使用 `afl-cc` 编译：

```bash
export AFL_USE_ASAN=1  # 可选：启用 AddressSanitizer
export AFL_MAP_SIZE=65536  # 可选：指定 bitmap 大小（默认 65536）

cd env/third_party/AFLplusplus
./afl-cc -o target target.c
```

#### 运行时环境变量

AFL++ 会自动设置 `__AFL_SHM_ID`，无需手动配置：

```bash
# AFLplusplus 自动注入
export __AFL_SHM_ID=<shm_id>
export AFL_MAP_SIZE=65536  # 可选
```

`ShmCoverageMonitor` 会从环境变量自动读取这些配置。

---

### 测试

#### 单元测试覆盖

* **ShmCoverageMonitor**: 14 tests
  * 生命周期测试（start, beforeRun, afterRun, close）
  * 策略集成测试
  * 统计更新测试

* **SeenNonZeroStrategy**: 9 tests
  * 全局 seen 判定
  * 重复输入过滤

* **PrevBitmapStrategy**: 13 tests
  * 相对差异判定
  * 边界情况

* **HashFilteredStrategy**: 11 tests
  * Hash 去重
  * 策略包装

* **CompositeStrategy**: 14 tests
  * 多策略组合
  * 短路逻辑

* **MockBitmapSource**: 9 tests
  * 测试辅助工具

#### 集成测试

**FuzzingEngineIntegrationTest**（3 tests）：

1. `shouldRunWithoutCoverage` - 无覆盖率监控模式
2. `shouldRunWithCoverageMonitoring` - 覆盖率监控集成
3. `shouldHandleCrashingTarget` - 崩溃检测

**总计**：174 tests passing（144 基础 + 30 扩展）

---

### 性能优化

#### 内存复用

`ShmCoverageMonitor` 复用 bitmap buffer，避免频繁分配：

```java
private final byte[] buffer = new byte[mapSize];

@Override
public Coverage afterRun(RunResult result) {
    bitmapSource.readInto(buffer);  // 复用 buffer
    DiffResult diff = strategy.diff(buffer);
    // ...
}
```

#### Hash 缓存

`HashFilteredStrategy` 缓存上一次 hash，避免重复计算：

```java
long currentHash = XxHash64.hash(current);
if (currentHash == prevHash) {
    return new DiffResult(0, false);  // 快速返回
}
prevHash = currentHash;
```

#### 统计更新

使用 `AtomicLong` 无锁更新统计，减少同步开销：

```java
private final AtomicLong execs = new AtomicLong(0);
private final AtomicLong lastInterestingExecId = new AtomicLong(0);
```

---

### 扩展指南

#### 自定义对比策略

实现 `CoverageDiffStrategy` 接口：

```java
public class MyCustomStrategy implements CoverageDiffStrategy {
    @Override
    public DiffResult diff(byte[] current) {
        int newBytes = computeNewBytes(current);
        boolean interesting = isInteresting(current);
        return new DiffResult(newBytes, interesting);
    }

    private int computeNewBytes(byte[] current) {
        // 自定义逻辑
    }

    private boolean isInteresting(byte[] current) {
        // 自定义判定
    }
}
```

#### 自定义 BitmapSource

实现 `BitmapSource` 接口，支持不同的 SHM 访问方式：

```java
public class FileMmapBitmapSource implements BitmapSource {
    private MappedByteBuffer mmap;

    @Override
    public void attach() {
        // mmap file
    }

    @Override
    public void readInto(byte[] dst) {
        mmap.position(0);
        mmap.get(dst);
    }

    @Override
    public void close() {
        // unmap
    }
}
```

---

### 故障排查

#### 常见问题

**Q: `ShmCoverageMonitor.start()` 抛出 "Environment variable __AFL_SHM_ID not set"**

A: 确保目标程序使用 `afl-cc` 编译，且 AFL++ 运行时注入了环境变量。测试时可手动设置：

```bash
export __AFL_SHM_ID=12345
export AFL_MAP_SIZE=65536
```

**Q: 覆盖率监控不生效，queue 目录为空**

A: 检查以下几点：

1. 目标程序是否使用 `afl-cc` 插装编译
2. `CoverageMonitor` 是否正确传入 `FuzzingEngine` 构造器
3. `CorpusManager` 是否初始化
4. 检查 `StatusPrinter` 输出，确认 `[NEW]` 事件

**Q: 执行速度低（< 100 exec/s）**

A: 优化建议：

1. 减少 `tickSleepMs`（默认 1000ms）
2. 使用 `HashFilteredStrategy` 减少重复判定
3. 检查目标程序是否有文件 I/O 阻塞

**Q: 测试时提示 "AFL++ instrumented binary not found"**

A: 集成测试需要真实的 AFL++ 插装二进制。测试会自动跳过（`assumeTrue`），不影响其他测试。

---


## 5. CoverageMonitor 扩展组件（EdgeSet/CoverageDB/CoverageEx）
<a id="sec-m-cov-extended"></a>


本文档详细介绍为支持种子调度而新增的扩展覆盖监控组件。

---

### 概述

扩展组件在保持向后兼容的同时，为种子调度器提供边级别的覆盖详情：

```
基础组件栈（已有）:
BitmapSource → CoverageDiffStrategy → CoverageMonitor → Coverage

扩展组件栈（新增）:
BitmapSource → CoverageDiffStrategyEx → CoverageMonitorEx → CoverageEx
                         ↓
                    CoverageDB (全局状态)
                         ↓
                    EdgeSet (边索引集合)
```

---

### 1. EdgeSet - 稀疏边索引集合

#### 设计理念

AFL++ bitmap 是 65536 字节数组，但实际触发的边通常只有数百到数千个。`EdgeSet` 使用排序的 `int[]` 存储边索引，实现高效的内存占用和快速的集合操作。

#### API 参考

```java
public final class EdgeSet implements Iterable<Integer> {
    // 构造方法
    public static EdgeSet fromBitmap(byte[] bitmap);
    public static EdgeSet of(int... indices);
    public static EdgeSet empty();
    
    // 查询
    public int size();
    public boolean isEmpty();
    public boolean contains(int index);
    public int[] toArray();
    public BitSet toBitSet(int mapSize);
    
    // 集合操作（返回新对象，不修改原对象）
    public EdgeSet union(EdgeSet other);
    public EdgeSet intersect(EdgeSet other);
    public EdgeSet subtract(EdgeSet other);
    
    // 迭代
    public Iterator<Integer> iterator();
    public Stream<Integer> stream();
    
    // Object 方法
    public boolean equals(Object obj);
    public int hashCode();
    public String toString();
}
```

#### 使用示例

```java
// 从 bitmap 提取边
byte[] bitmap = new byte[65536];
// ... 执行目标程序，bitmap 被填充 ...
EdgeSet hitEdges = EdgeSet.fromBitmap(bitmap);
System.out.println("Hit " + hitEdges.size() + " edges");

// 计算新边（集合差）
EdgeSet seenEdges = EdgeSet.of(10, 20, 30);
EdgeSet newEdges = hitEdges.subtract(seenEdges);
System.out.println("Discovered " + newEdges.size() + " new edges");

// 检查特定边
if (hitEdges.contains(42)) {
    System.out.println("Edge 42 was hit");
}

// 迭代所有边
for (int edge : hitEdges) {
    System.out.println("Edge: " + edge);
}

// 使用 Stream API
double avgFreq = hitEdges.stream()
    .mapToInt(db::getEdgeFrequency)
    .average()
    .orElse(0.0);
```

#### 性能特征

- **空间复杂度**: O(n)，n 为非零边数量（通常 << 65536）
- **查找复杂度**: O(log n)，二分查找
- **union/intersect/subtract**: O(n + m)，归并算法
- **fromBitmap**: O(mapSize)，单次遍历

---

### 2. XxHash64 - 快速哈希函数

#### 设计理念

用于 bitmap 快速去重，避免重复的覆盖率计算。相比 FNV-1a，xxHash64 速度更快（2-3倍）且碰撞率更低。

#### API 参考

```java
public final class XxHash64 {
    // 默认 seed = 0
    public static long hash(byte[] data);
    public static long hash(byte[] data, int offset, int length);
    
    // 自定义 seed
    public static long hash(byte[] data, long seed);
    public static long hash(byte[] data, int offset, int length, long seed);
}
```

#### 使用示例

```java
byte[] bitmap = new byte[65536];

// 计算完整 hash
long hash = XxHash64.hash(bitmap);

// 比较两次执行
long hash1 = XxHash64.hash(bitmap);
executor.run(...);  // 第二次执行
long hash2 = XxHash64.hash(bitmap);

if (hash1 == hash2) {
    System.out.println("Bitmap 未变化，可能重复路径");
}

// 使用不同 seed（用于多个 hash 表）
long hashA = XxHash64.hash(bitmap, 0x12345678L);
long hashB = XxHash64.hash(bitmap, 0x87654321L);
```

---

### 3. DiffResultEx - 扩展 Diff 结果

#### 设计理念

在基础 `DiffResult(newBytes, interesting)` 之上，增加边索引详情，供调度器使用。

#### API 参考

```java
public record DiffResultEx(
    int newCount,           // 新边数量
    EdgeSet newEdges,       // 新边索引
    EdgeSet hitEdges,       // 所有触发的边
    long bitmapHash         // XXHash64
) {
    /** 转为基础 DiffResult（向后兼容） */
    public DiffResult toBasic();
}
```

#### 使用示例

```java
CoverageDiffStrategyEx strategy = CoverageDiffStrategyEx.createDefault(mapSize);
DiffResultEx result = strategy.diffEx(bitmap);

if (result.newCount() > 0) {
    System.out.println("New edges: " + result.newEdges());
    System.out.println("All hit edges: " + result.hitEdges());
    System.out.println("Bitmap hash: 0x" + Long.toHexString(result.bitmapHash()));
    
    // 计算稀有度
    double rarity = db.calculateRarityScore(result.hitEdges());
    System.out.println("Rarity score: " + rarity);
}
```

---

### 4. CoverageDiffStrategyEx - 扩展策略接口

#### 设计理念

扩展现有 `CoverageDiffStrategy`，提供边级别详情，同时保持向后兼容。

#### API 参考

```java
public interface CoverageDiffStrategyEx extends CoverageDiffStrategy {
    /** 扩展 diff，返回边索引详情 */
    DiffResultEx diffEx(byte[] current);
    
    /** 获取全局 seen BitSet（用于 CoverageDB 初始化） */
    BitSet getSeenBitSet();
    
    /** 查询单条边是否已见过 */
    boolean hasSeenEdge(int index);
    
    /** 工厂方法：创建默认策略（SeenNonZeroStrategyEx） */
    static CoverageDiffStrategyEx createDefault(int mapSize);
    
    /** 包装现有策略为扩展策略 */
    static CoverageDiffStrategyEx wrap(CoverageDiffStrategy base, int mapSize);
    
    // 继承自 CoverageDiffStrategy
    @Override
    default DiffResult diff(byte[] current) {
        return diffEx(current).toBasic();
    }
}
```

#### 内置实现

##### SeenNonZeroStrategyEx（推荐）

原生扩展实现，维护全局 `seen` BitSet：

```java
public class SeenNonZeroStrategyEx implements CoverageDiffStrategyEx {
    private final BitSet seen;
    
    @Override
    public DiffResultEx diffEx(byte[] current) {
        EdgeSet hitEdges = EdgeSet.fromBitmap(current);
        EdgeSet newEdges = EdgeSet.empty();
        
        // 识别新边
        for (int edge : hitEdges) {
            if (!seen.get(edge)) {
                seen.set(edge);
                newEdges = newEdges.union(EdgeSet.of(edge));
            }
        }
        
        long hash = XxHash64.hash(current);
        return new DiffResultEx(newEdges.size(), newEdges, hitEdges, hash);
    }
}
```

##### WrappedStrategyEx（兼容层）

包装现有策略，提供扩展接口：

```java
CoverageDiffStrategy legacy = new SeenNonZeroStrategy(mapSize);
CoverageDiffStrategyEx extended = CoverageDiffStrategyEx.wrap(legacy, mapSize);
```

---

### 5. CoverageDB - 全局覆盖数据库

#### 设计理念

CoverageDB 是连接覆盖监控和种子调度的核心组件，维护全局覆盖状态：

- **edgeFreq[i]**: 边 i 被触发的总次数（用于稀有度计算）
- **topRated[i]**: 触发边 i 的"最优" seed ID
- **favored**: 至少 top-rated 一条边的 seeds 集合

#### 核心概念

##### Top-Rated Seeds

对每条边，根据配置的标准选择"最优" seed：

```java
public enum TopRatedCriteria {
    SMALLEST_INPUT,   // 偏好最小输入（默认，减少内存）
    MOST_RECENT,      // 偏好最新发现（探索优先）
    FEWEST_EDGES,     // 偏好覆盖最少边（精准定位）
    FASTEST_EXEC      // 偏好执行最快（吞吐优先）
}
```

##### Favored Seeds

Favored seeds 是至少 top-rated 一条边的 seeds，应优先调度。这些 seeds 代表了当前全局覆盖的"最小子集"。

##### Rarity Score（稀有度分数）

稀有度分数 = Σ(1/freq) over hitEdges

- 稀有边（freq 低）贡献更高分数
- 用于能量分配：高稀有度 → 更多 fuzz 轮数

#### API 参考

```java
public class CoverageDB {
    // 构造
    public CoverageDB(int mapSize);
    public CoverageDB(int mapSize, TopRatedCriteria criteria);
    
    // 更新（线程安全）
    public UpdateResult update(int seedId, DiffResultEx diffResult, 
                               int inputSize, long execTimeNanos);
    
    // 查询
    public int getEdgeFrequency(int edge);
    public double calculateRarityScore(EdgeSet edges);
    public int getMinFrequency(EdgeSet edges);
    public boolean isFavored(int seedId);
    public boolean isRedundant(int seedId, EdgeSet edges);
    public int getFavoredCount();
    public int getTotalEdgesSeen();
    
    // 内部状态（调试用）
    public Map<Integer, Integer> getTopRatedMap();
    public Set<Integer> getFavoredSeeds();
}

public record UpdateResult(
    EdgeSet newEdges,           // 全局新边
    EdgeSet becameTopRated,     // 成为 top-rated 的边
    boolean favoredChanged,     // favored 集合是否变化
    boolean isFavored           // 该 seed 是否 favored
) {}
```

#### 使用示例

```java
// 创建数据库
CoverageDB db = new CoverageDB(65536, TopRatedCriteria.SMALLEST_INPUT);

// 执行后更新
CoverageEx coverage = monitor.afterRunEx(result);
UpdateResult update = db.update(
    seedId,
    new DiffResultEx(coverage.newBytes(), coverage.newEdges(),
                     coverage.hitEdges(), coverage.bitmapHash()),
    input.length,
    coverage.execTimeNanos()
);

// 处理更新结果
if (update.newEdges().size() > 0) {
    System.out.println("Discovered " + update.newEdges().size() + " global new edges!");
    corpusManager.saveToQueue(input, coverage.toBasic());
}

if (update.isFavored()) {
    System.out.println("Seed " + seedId + " is now favored!");
    System.out.println("Top-rated for " + update.becameTopRated().size() + " edges");
}

if (update.favoredChanged()) {
    System.out.println("Favored set changed, total: " + db.getFavoredCount());
    // 可选：触发 queue culling
}

// 稀有度评分（用于能量分配）
double rarityScore = db.calculateRarityScore(coverage.hitEdges());
int baseEnergy = 100;
int energy = (int) (baseEnergy * Math.min(rarityScore, 10.0));
System.out.println("Assigned energy: " + energy);

// 队列精简（检测冗余）
if (db.isRedundant(seedId, coverage.hitEdges())) {
    System.out.println("Seed " + seedId + " is redundant, can be removed");
}
```

#### 线程安全

CoverageDB 使用 `ReentrantLock` 保护更新操作：

```java
private final ReentrantLock lock = new ReentrantLock();

public UpdateResult update(...) {
    lock.lock();
    try {
        // 原子更新 edgeFreq, topRated, favored
    } finally {
        lock.unlock();
    }
}
```

---

### 6. CoverageEx - 扩展覆盖模型

#### 设计理念

在基础 `Coverage` 之上增加边索引和执行时间，供调度器使用。

#### API 参考

```java
public record CoverageEx(
    // 基础字段
    long execId,
    long timestampMillis,
    int mapSize,
    int nonZeroBytes,
    int newBytes,
    long bitmapHash,
    boolean interesting,
    
    // 扩展字段
    EdgeSet hitEdges,        // 本次触发的边
    EdgeSet newEdges,        // 新发现的边
    long execTimeNanos,      // 执行时间（纳秒）
    boolean stable           // 轨迹是否稳定
) {
    // 工厂方法
    public static CoverageEx empty(RunResult result);
    public static CoverageEx from(DiffResultEx diffResult, RunResult result, int mapSize);
    public static CoverageEx of(...);  // 完整构造
    public static CoverageEx fromBasic(Coverage coverage);
    
    // 转换方法
    public Coverage toBasic();
    public CoverageEx markUnstable();
    
    // 便捷方法
    public DiffResultEx diffResultEx();
}
```

#### 使用示例

```java
// 从 DiffResultEx 创建
DiffResultEx diffResult = strategy.diffEx(bitmap);
CoverageEx coverage = CoverageEx.from(diffResult, result, mapSize);

// 访问扩展字段
System.out.println("Hit edges: " + coverage.hitEdges().size());
System.out.println("New edges: " + coverage.newEdges().size());
System.out.println("Exec time: " + coverage.execTimeNanos() / 1_000_000.0 + " ms");
System.out.println("Stable: " + coverage.stable());

// 转为基础 Coverage（向后兼容）
Coverage basic = coverage.toBasic();
corpusManager.saveToQueue(input, basic);

// 从基础 Coverage 升级
Coverage legacy = Coverage.of(...);
CoverageEx extended = CoverageEx.fromBasic(legacy);
```

---

### 7. CoverageMonitorEx - 扩展监控接口

#### 设计理念

扩展 `CoverageMonitor` 接口，提供边级别详情和 CoverageDB 访问。

#### API 参考

```java
public interface CoverageMonitorEx extends CoverageMonitor {
    /** 返回扩展覆盖信息 */
    CoverageEx afterRunEx(RunResult result);
    
    /** 获取全局覆盖数据库 */
    CoverageDB getCoverageDB();
    
    /** 获取扩展策略 */
    CoverageDiffStrategyEx getStrategyEx();
    
    /** 是否启用稳定性检测 */
    boolean isStabilityDetectionEnabled();
    
    /** 获取全局已见边总数 */
    int getTotalEdgesSeen();
    
    // 继承自 CoverageMonitor
    @Override
    default Coverage afterRun(RunResult result) {
        return afterRunEx(result).toBasic();
    }
}
```

#### ShmCoverageMonitorEx 实现

```java
public class ShmCoverageMonitorEx implements CoverageMonitorEx {
    private final BitmapSource bitmapSource;
    private final CoverageDiffStrategyEx strategy;
    private final CoverageDB coverageDB;
    private final boolean enableStabilityDetection;
    
    // 工厂方法
    public static ShmCoverageMonitorEx fromEnvironment();
    public static ShmCoverageMonitorEx forTesting(MockBitmapSource source);
    
    @Override
    public CoverageEx afterRunEx(RunResult result) {
        bitmapSource.readInto(buffer);
        DiffResultEx diffResult = strategy.diffEx(buffer);
        
        // 可选：稳定性检测
        if (enableStabilityDetection && diffResult.newCount() > 0) {
            // 重新执行验证轨迹稳定性
        }
        
        return CoverageEx.from(diffResult, result, mapSize);
    }
}
```

#### 使用示例

```java
// 创建扩展监控器
CoverageDiffStrategyEx strategy = CoverageDiffStrategyEx.createDefault(mapSize);
CoverageDB db = new CoverageDB(mapSize);
BitmapSource source = new SysVShmBitmapSource(mapSize, shmId);

CoverageMonitorEx monitor = new ShmCoverageMonitorEx(
    source, 
    strategy, 
    db,
    /* enableStabilityDetection */ true
);

monitor.start();

// 使用扩展接口
monitor.beforeRun();
RunResult result = executor.run(...);
CoverageEx coverage = monitor.afterRunEx(result);

if (coverage.interesting()) {
    // 更新数据库
    UpdateResult update = db.update(
        seedId,
        coverage.diffResultEx(),
        input.length,
        coverage.execTimeNanos()
    );
    
    if (update.isFavored()) {
        System.out.println("Favored seed!");
    }
}

// 查询全局状态
int totalEdges = monitor.getTotalEdgesSeen();
System.out.println("Total edges discovered: " + totalEdges);
```

---

### 集成到 Fuzzing 循环

完整的集成示例：

```java
public class AdvancedFuzzingEngine {
    private final CoverageMonitorEx monitor;
    private final CoverageDB db;
    private final SeedQueue queue;
    private final Mutator mutator;
    private final PowerScheduler powerScheduler;
    
    public void run() throws Exception {
        monitor.start();
        
        while (shouldContinue()) {
            // 1. 选择 seed（优先 favored）
            Seed seed = queue.select(db);
            
            // 2. 计算能量
            int energy = powerScheduler.calculateEnergy(seed, db);
            
            // 3. Fuzz 循环
            for (int i = 0; i < energy; i++) {
                byte[] payload = mutator.mutate(seed.data());
                
                monitor.beforeRun();
                RunResult result = executor.run(targetCmd, payload, timeout, logDir);
                CoverageEx coverage = monitor.afterRunEx(result);
                
                // 4. 处理结果
                if (result.termination() == RunResult.Termination.ERROR) {
                    corpusManager.saveCrash(payload, result);
                } else if (coverage.interesting()) {
                    // 更新数据库
                    int newSeedId = nextSeedId++;
                    UpdateResult update = db.update(
                        newSeedId,
                        coverage.diffResultEx(),
                        payload.length,
                        coverage.execTimeNanos()
                    );
                    
                    // 保存到队列
                    corpusManager.saveToQueue(payload, coverage.toBasic());
                    queue.add(new Seed(newSeedId, payload, coverage));
                    
                    // 队列精简
                    if (update.favoredChanged()) {
                        queue.cull(db);
                    }
                }
            }
            
            seed.markFuzzed();
        }
        
        monitor.close();
    }
}
```

---

### 性能优化建议

1. **复用 EdgeSet**: EdgeSet 是不可变的，可安全共享
2. **批量更新**: 使用 `CoverageDB.update()` 而非多次单边更新
3. **延迟 queue culling**: 不必每次 favoredChanged 都 cull，可定期执行
4. **缓存稀有度分数**: 对同一 EdgeSet 的稀有度可缓存
5. **使用 XxHash64**: 比 FNV-1a 快 2-3 倍

---

### 故障排查

**Q: CoverageDB 内存占用过高**

A: 检查 topRated 标准：
- `SMALLEST_INPUT`: 内存友好
- `MOST_RECENT`: 可能保留更多 seeds
- 定期执行 queue culling 移除冗余 seeds

**Q: 稀有度评分全为 0**

A: 确保 `CoverageDB.update()` 在 `calculateRarityScore()` 之前调用。频率信息需要先更新。

**Q: Favored 集合为空**

A: 检查：
1. 是否有 interesting coverage（newBytes > 0）
2. `DiffResultEx.hitEdges()` 是否非空
3. `TopRatedCriteria` 配置是否合理

**Q: EdgeSet.fromBitmap() 很慢**

A: `fromBitmap()` 需遍历整个 bitmap（65536 字节），这是正常的。如果频繁调用，考虑缓存 EdgeSet。


---

## 6. FuzzingEngine 主循环（闭环编排）
<a id="sec-m-engine"></a>


### 概述

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

### 位置与入口

- 代码位置：`src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java`
- 典型启动路径：CLI `FuzzerMain` 解析参数 → 构造 `TargetSpec` → 构造/组装 `FuzzingEngine` → `engine.run()`

CLI 入口与参数含义见：[docs/CLI/CLI.md](CLI/CLI.md)。

---

### 依赖与协作关系

`FuzzingEngine` 采用依赖注入（DI）方式组装核心组件；同时为了兼容测试/CLI，也提供“旧构造器重载”自动组装默认组件。

#### 核心依赖（DI 构造器）

- `ExecutorHarness`：统一执行环境（封装 `beforeRun -> executor.run -> afterRun`）
- `SeedQueue`：内存种子队列容器（初始 seeds + 新种子入队；见 `docs/Queue/SeedQueue.md`）
- `SeedPrioritizer`：种子选择策略（优先未 fuzz 过的种子，否则兜底轮询；见 `docs/schedule/Scheduling.md`）
- `PowerScheduler`：能量调度（根据 Seed 元数据与可选 CoverageDB 信号分配 energy；见 `docs/schedule/Scheduling.md`）
- `Mutator`：根据 seed + energy 生成 `Iterator<Testcase>`
- `CorpusManager`：将 inputs 持久化到 `queue/crashes/hangs`
- `CoverageDB`（可选）：全局覆盖数据库（edgeFreq/topRated/favored/redundant/rarity；需要 edge-level 覆盖数据）
- `FuzzStats`：实时统计（execs、paths、crash/hang、coveredEdges 等）

#### 协作数据流（简图）

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

### 关键数据模型（与主循环关系最紧密）

- `TargetSpec`：描述目标程序运行方式（argvTemplate/env/timeout），支持 `@@` 文件模式和 STDIN 模式
- `Testcase`：一次执行的输入（`byte[] data`）、父种子引用（`Seed parent`）、变异描述（`description`）
- `ExecInput`：一次执行的“执行参数封装”（`TargetCommand + stdinData + timeout + outDir + saveLogs`）
- `ExecResult`：一次执行的统一输出（`RunResult + CoverageEx`）
- `CoverageEx`：覆盖快照（interesting、nonZeroBytes、bitmapHash、可选 hitEdges/newEdges、execTimeNanos）
- `Seed`：队列条目，除基本血缘/统计外，还会承载调度提示字段（favored/rarity/redundant/minEdgeFreq/stability 等），并写入 `<seed>.meta` 以便复用

---

### 主循环行为定义（run 方法）

#### 1) 目录与运行态输出

启动时会确保创建（或存在）：

- `workdir/stats/stats.csv`：统计 CSV
- `workdir/tmp/exec-logs/`：执行 stdout/stderr（默认仅在“晋升为 interesting”时保存，且仅保存非空输出）

> 注意：为了避免长跑写爆 inode，FILE 模式下当前实现复用单个 `.cur_input`（每次覆盖写），不会产生海量 inputs 小文件。
>
> `.cur_input` 默认不会写到 workdir：引擎会优先使用 `/dev/shm`（tmpfs）。严格模式（默认开启）下，若无法使用 tmpfs，将 fail-fast，避免磁盘落盘。

#### 2) 初始种子加载

- 优先从 `initialSeedDir` 加载种子（通过 `SeedQueue.loadInitialSeeds()`；该目录由 CLI `--seeds` 或默认 `workdir/seeds` 提供）
- 如果加载为 0：自动生成一个 dummy seed（payload 为 `hello-from-engine`）并入队，保证循环可跑

#### 3) 生命周期管理

- `harness.start()`：在 fuzzing 开始前调用一次（插桩目标 attach SHM 等）
- 如果 `CoverageDB` 可用：启动后会对初始队列做一次“基线校准执行”，填充全局 seen/topRated/frequency，并同步 favored/rarity/redundant 等提示字段
- `statusPrinter.start()`：后台定时打印状态
- finally 里统一 `statusPrinter.stop()`、`harness.close()`、`corpusManager.close()`

#### 4) 循环退出条件

- 以 wall-clock 秒为准：运行超过 `durationSec` 即退出

#### 5) 单轮迭代逻辑（简化描述）

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

### buildExecInput：STDIN/FILE 模式与性能约束

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

### 与 CoverageMonitorEx / CoverageDB 的关系（重要）

- `FuzzingEngine` 本身只依赖 `ExecutorHarness`，不直接依赖具体 monitor 类型。
- `CoverageDB` 的来源有两种：
  - **显式注入**：CLI/测试构造器直接传入 `CoverageDB`。
  - **从 monitor 获取**：当 `ExecutorHarness` 为 `InstrumentedExecutorHarness` 且其 monitor 为 `CoverageMonitorEx` 时，引擎会优先使用 `monitor.getCoverageDB()`（避免出现“接口存在但闲置”的情况）。

- 是否能更新 `CoverageDB` 取决于 `ExecResult.coverage()` 是否携带 edge-level 信息：
  - 当底层 monitor 是 `CoverageMonitorEx` 时，Harness 会返回含 `hitEdges/newEdges/bitmapHash` 的 `CoverageEx`，引擎才能进行全局确认与 DB 更新。
  - 当 monitor 仅提供 basic coverage 时，`CoverageEx.hitEdges/newEdges` 为空；此时引擎会跳过 CoverageDB 相关逻辑，保持可运行。

当前实现的“基础 SHM monitor”也已升级为 `CoverageMonitorEx`：即使是 `--coverage shm`，也会通过 `CoverageDiffStrategyEx.wrap(...)` 从 bitmap 中提取 `hitEdges/newEdges`（把非零 byte 下标视作 edge index），从而让 CoverageDB 在基础路径下也能工作。

相关代码：

- [src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitor.java](../src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitor.java)
- [src/test/java/edu/nju/fuzzing/cov/ShmCoverageMonitorTest.java](../src/test/java/edu/nju/fuzzing/cov/ShmCoverageMonitorTest.java)

注意：`--coverage shmex` 的 monitor 自带 CoverageDB；`--coverage shm` 的 monitor 不持有 CoverageDB（由 CLI/引擎创建与持有）。

---

### 统计与输出（与 stats 模块的契约）

- `FuzzStats` 是引擎中统计的唯一来源：
  - `recordExec()`：每次 execute 后调用
  - `recordNewPath()`：每次保存 interesting input 后调用
  - `recordCrash()/recordHang()`：分类后调用
  - `updateCoveredEdges()`：在 CoverageDB 更新后同步（可选）
- `StatsWriter`：把 `StatsTick` 追加写入 `workdir/stats/stats.csv`
- `StatusPrinter`：周期性打印 `StatsTick.toStatusLine()`

CSV 的字段定义以 `docs/stats/stats.md` 为准。

---

### 已知限制与扩展点

#### 已知限制（当前实现刻意简化）

- interesting 判定主要依赖 `CoverageEx.interesting()`（本地 diff/策略），全局裁判（CoverageDB）只在 edge-level 数据可用时参与。
- `ExecInput.saveLogs` 当前不作为 stdout/stderr 落盘开关使用；日志落盘由系统属性 `nju.fuzzer.execLogs` 控制。
- 在默认 `execLogs=interesting` 策略下，日志是在“晋升为 interesting 时”的二次执行中抓取的，因此 `tmp/exec-logs` 文件数量与晋升次数近似成正比（每次晋升通常 1~2 个文件）。

---

### 运行期关键系统属性（IO/可观测性）

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

#### 扩展点

- 更换/增强 `SeedPrioritizer`：favored、round-robin、随机加权、cull queue
- 更换 `PowerScheduler`：引入 CoverageDB rarity/topRated/favored
- 更换 `Mutator`：按 `SeedType`（XML/PNG/PCAP…）选择语法变异器，混合 havoc
- 调整 stability rerun：控制重跑次数、只对特定类型/阈值的候选触发，或在资源受限时关闭
- crash 去重/最小化：基于 stack signature / stdout/stderr / asan 等

---

### 测试与验收点

与 `FuzzingEngine` 直接相关的测试通常关注：

- workdir 结构创建：`stats/stats.csv`、`tmp/inputs`、`tmp/exec-logs`
- STDIN 模式能执行并在 stdout 中看到期望内容（例如 `/bin/cat` 回显）
- FILE 模式（含 `@@`）能创建输入文件并完成执行
- crash/hang 能落盘到 corpus 目录并更新计数

与 CLI 联动的验收：

- 见 [docs/CLI/CLI.md](CLI/CLI.md) 的“快速开始”与对应 smoke tests。

---

---

## 7. SeedQueue 种子队列
<a id="sec-m-seedqueue"></a>


### 概述

`SeedQueue` 负责管理“可被进一步变异”的持久化语料条目（`Seed`）的**内存队列视图**。

它解决两个问题：

1. **加载初始种子**：从用户提供的 seeds 目录递归读取文件并构造 `Seed`。
2. **接收新晋升种子**：当 `FuzzingEngine` 发现 interesting 输入并写入 `workdir/queue/` 后，将对应 `Seed` 入队。

`SeedQueue` 与 CLI 的关系：CLI 通过 `--seeds` 把初始 seeds 目录传入引擎（不再写死 `workdir/seeds`），因此队列的“初始输入集”可以在运行时被替换。

位置：
- 实现：`src/main/java/edu/nju/fuzzing/queue/SeedQueue.java`
- 主循环调用者：`src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java`

---

### 责任边界

`SeedQueue` 的职责**刻意保持轻量**：

- 只维护 `List<Seed>`（队列本体）与少量 I/O（加载 seeds / 保存 meta）。
- 不负责：
  - 覆盖率判定（属于 `CoverageMonitor`/`CoverageDB`）
  - 入队/写盘策略（由 `CorpusManager` 完成 `queue/` 的写入，Engine 决定“是否晋升”）
  - 调度决策（由 `SeedPrioritizer`、`PowerScheduler`）

---

### 数据结构与 API

#### 内部数据结构

- `private final List<Seed> seeds = new ArrayList<>();`
- `getSeeds()` 返回 `Collections.unmodifiableList(seeds)`，避免外部误修改队列。

#### 关键方法

##### `int loadInitialSeeds(Path seedDir)`

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

##### `void addSeed(Seed seed)`

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

##### `List<Seed> getSeeds()` / `int size()` / `boolean isEmpty()`

- 为调度器提供只读访问。

---

### 与其他模块的契约

#### 与 `FuzzingEngine`

- `FuzzingEngine` 在启动时调用 `loadInitialSeeds(initialSeedDir)`（该目录来自 CLI `--seeds` 或默认 `workdir/seeds`）。
- 发现 interesting 输入后：
  1) `CorpusManager.saveToQueue(bytes, coverage)` 负责写盘，返回保存路径
  2) `new Seed(saved.toFile(), testcase)` 构造新种子
  3) `seedQueue.addSeed(newSeed)` 入队并写 `.meta`

#### 与 `SeedPrioritizer` / `PowerScheduler`

- 调度器只通过 `getSeeds()` 读取队列。
- 调度信号来自 `Seed` 的元数据字段（例如 `favored/redundant/rarityScore/stability`），这些字段由 Engine 在“校准”或“晋升”阶段写回。

#### 与 `CoverageDB`

- `SeedQueue` 不依赖 `CoverageDB`。
- `Seed` 的“调度提示字段”可能来自 `CoverageDB` 的计算结果，但写回过程发生在 Engine 内。

---

### 已知限制与后续扩展

当前实现属于“课程作业可运行”的最小版本，仍有一些刻意留空的点：

- **队列裁剪（queue culling）未实现**：目前只在 `Seed` 上标注 `redundant`，并交由调度器降权；并没有物理移除队列条目。
- **持久化策略较简单**：`addSeed` 总是写 `.meta`，对高频入队场景可能有额外 I/O。
- **缺少 cycle/bookkeeping**：例如 AFL 的 queue cycle、favored 轮转、sync 等。

另：`SeedQueue` 只负责“条目列表 + 元数据落盘”，不负责数值型 seedId 的分配；当前 `CoverageDB` 使用 long seedId，而引擎内部会维护 `Seed.getId() -> long` 的映射。

---

### 验收建议（最小可验证点）

- 给一个包含若干文件的 seeds 目录，启动后能看到：
  - Engine 打印 `Loaded N initial seeds.` 且 N 与目录中文件数一致（不包含 `.meta`）。
- 触发一次 interesting 晋升后：
  - `workdir/queue/` 增加一个输入文件
  - 同目录存在 `<file>.meta`，并包含 `seed_type` 与调度字段键。

与 CLI 联动的最小验收：

- 使用 `--seeds /path/to/seeds` 启动，stdout 中应打印 `seeds = ...` 且实际加载的种子内容来自该目录（见 CLI 冒烟测试）。

---

## 8. Scheduling 调度（Selection + Power）
<a id="sec-m-scheduling"></a>


### 概述

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

### 设计目标

- **确定性 + 可测试**：在同一输入队列状态下，优先选择逻辑尽量稳定，避免“拍脑袋随机”。
- **兼容无覆盖模式**：`--coverage none` 时没有 edge-level 信号，调度仍能工作（靠 execTime/bitmapSize/handicap/depth 等）。
- **可渐进增强**：当 `CoverageDB` 可用时，调度能消费 `favored/rarity/redundant/stability` 等信号。

---

### 调度信号来源（Seed 元数据）

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

### SeedPrioritizer（选种）

#### 行为概述

`pick(List<Seed>)` 的逻辑分两段：

1) **优先选择未 fuzz 过（`was_fuzzed=false`）的种子**
   - 在所有未 fuzz 的 seed 中计算一个 score，并选出 score 最大者。

2) **兜底 Round-Robin**
   - 当所有种子都 fuzz 过后，按 `currentIndex % size` 轮询。
   - `currentIndex` 只自增不取模：当队列增长时可以自然轮转到新加入的元素（测试也依赖这个行为）。

#### 评分函数（scoreForSelection）

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

### PowerScheduler（能量分配）

#### 行为概述

`assignEnergy(Seed)` 返回一个整数 energy，作为 `Mutator.mutate(seed, energy)` 的迭代预算。

- 基准值：`BASE_ENERGY = 100`
- 上限：`MAX_ENERGY = 5000`
- 最终结果会 clamp 到 `[1, MAX_ENERGY]`。

#### 因子

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

### 与 FuzzingEngine 的集成点

- `Seed parent = prioritizer.pick(seedQueue.getSeeds())`
- `int energy = scheduler.assignEnergy(parent)`
- `Iterator<Testcase> it = mutator.mutate(parent, energy)`

当 `CoverageDB` 可用时，引擎会：

- 启动后执行一次“初始种子校准”，让 `favored/rarity/redundant` 能从第一轮开始影响调度。
- interesting 晋升时写回新 seed 的调度信号，并在 favored 集合变化时刷新整个队列的提示字段。

---

### 已知限制与扩展建议

- 目前没有实现 AFL 的完整 queue cycle、`cull_queue`、fuzz level 等复杂机制。
- `redundant` 只是“降权提示”，队列不会物理删除；后续可以加定期 culling。
- `rarity_score` 的定义当前基于 hit frequency（次数）；若要更贴近 AFL 可引入 additional heuristics（如 exec speed、bitmap density、favored rotation）。

---

### 验收建议（最小可验证点）

- 当存在多个未 fuzz seed 时：`favored=true` 的 seed 应优先被 pick（对应单元测试）。
- `PowerScheduler`：favored 提升、redundant 降低、rarity 提升应能体现在 energy 结果上（对应单元测试）。

---

## 9. Stats 运行期统计与日志
<a id="sec-m-stats"></a>


### 概述

`edu.nju.fuzzing.stats` 负责把 fuzzing 运行期的关键指标（执行次数、速度、覆盖、队列规模、paths/crash/hang 等）做三件事：

1. **聚合（FuzzStats）**：线程安全地维护计数与派生指标（exec/s、lastNewPathSecAgo）。
2. **展示（StatusPrinter）**：周期性在控制台打印单行状态 + 事件提示。
3. **落盘（StatsWriter）**：以 CSV 形式把 `StatsTick` 快照追加写入 `workdir/stats/stats.csv`，供离线分析。

同时，为了画“增长曲线”，引入了第四个落盘组件：

4. **曲线（StatsCurveWriter）**：按时间分桶把覆盖/paths/exec/crash/hang 的累计值与桶内增量写入 `workdir/stats/curve.csv`。

本模块的设计目标是：主循环只负责调用 `recordXXX()`，其余展示/落盘细节解耦。

---

### 组件与职责

#### 1) StatsTick（数据契约，位于 model 包）

- 位置：`edu.nju.fuzzing.model.StatsTick`
- 类型：`record`
- 职责：表示某一时刻的不可变统计快照，供 `StatusPrinter` 展示、`StatsWriter` 落盘。

##### 字段（当前实现）

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

##### `coveredEdges` 的口径（重要）

本项目的 `coveredEdges/covered_edges` 是 **AFL++ 风格的内部覆盖率信号**，用于画“覆盖率曲线”和辅助调度，而不是传统的“行覆盖率百分比”。

- 数据来源：AFL++ 插桩目标把 edge trace 写入 SHM bitmap（默认 64KB）。
- 本项目的 edge-level 抽象：把 **bitmap 中非零 byte 的下标** 视作“edge index”。
- `coveredEdges` 的定义：全局累计（all-time）“见过的 edge index 数量”，等价于 `globalSeen.cardinality()`。

为什么需要“累计”：

- 单次执行的 bitmap 只反映“这一次跑到了哪些边”，曲线更关心“到目前为止总共覆盖了多少边”。
- 因此覆盖率曲线通常用累计值（单调不减），便于对比不同 run/不同策略。

是否需要“分桶（bucketize）”：

- 画覆盖率曲线（`coveredEdges`）**不需要分桶**：只看 0/非 0 即可。
- 分桶常用于 **hitcount 的稳定化**（AFL 的 `classify_counts` 思路），把“命中次数”的噪声压到少量档位，用于把“循环次数显著变化”等也视为 interesting。它影响的是 `interesting` 判定/评分策略，不影响 `coveredEdges` 这个“唯一边计数”的分母。

与 GCOV/LCOV 的区别：

- `coveredEdges` 适合机器决策与趋势曲线（快、轻量、可在线更新）。
- 若要给人看的“行覆盖率/分支覆盖率报告”，通常是 fuzzing 后拿 `workdir/queue` 语料 **重放**到开启 `-fprofile-arcs -ftest-coverage` 的目标程序，再用 `lcov/genhtml` 生成报表（离线、慢、但可读）。

##### 重要说明：兼容构造器

`StatsTick` 额外提供一个**旧 9 参构造器**（不含 `totalPaths`），会把 `totalPaths` 默认填为 0，用于兼容旧测试/调用点。

---

#### 2) FuzzStats（统计核心）

- 位置：`edu.nju.fuzzing.stats.FuzzStats`
- 职责：统计聚合与速率计算。

##### 线程安全

内部计数器使用 `AtomicLong/AtomicInteger`，允许：

- 主线程（FuzzingEngine）高频更新
- 后台线程（StatusPrinter）按秒读快照

##### 常用 API

- `recordExec()`：执行一次后调用
- `recordNewPath()`：发现 interesting 并入队后调用
- `recordCrash()` / `recordHang()`：分类后调用
- `updateCoveredEdges(int)`：同步覆盖总量（可由 CoverageDB/MonitorEx 提供）
- `toStatsTick(int queueSize)`：生成快照

---

#### 3) StatusPrinter（控制台输出）

- 位置：`edu.nju.fuzzing.stats.StatusPrinter`
- 机制：`ScheduledExecutorService` 定时从 supplier 获取 `StatsTick` 并打印。
- 输出：
  - 周期性状态行：来自 `StatsTick.toStatusLine()`
  - 事件：`printEvent/printNewPath/printCrash/printHang`

---

#### 4) StatsWriter（CSV 落盘）

- 位置：`edu.nju.fuzzing.stats.StatsWriter`
- 写入文件：通常为 `workdir/stats/stats.csv`

##### CSV Header（当前实现）

```
timestamp,target_name,exec_count,covered_edges,execs_per_sec,queue_size,total_paths,crash_count,hang_count
```

##### CSV 行格式（tick 一行）

```
elapsedSec,targetName,execsTotal,coveredEdges,execsPerSec,queueSize,totalPaths,crashes,hangs
```

> 说明：本实现的 `timestamp` 实际写入的是 `elapsedSec`（相对时间秒数），便于不同运行复现/对齐。

##### Flush 策略（减少长跑 IO）

默认不会每行都 `flush()`，而是按批次 flush：

- `-Dnju.fuzzer.statsFlushEvery=<N>`：每写 N 行 flush 一次（默认 100；<=0 表示只在 close 时 flush）。

这能显著减少频繁 flush 带来的 IO 与 CPU 开销；代价是进程异常退出时，最后一小段数据可能尚未落盘。

---

#### 5) StatsCurveWriter（覆盖增长曲线）

- 位置：`edu.nju.fuzzing.stats.StatsCurveWriter`
- 输出：`workdir/stats/curve.csv`
- 分桶：`-Dnju.fuzzer.curveBucketSec=<sec>`（默认 1 秒）

表头（当前实现）：

```
timestamp,target_name,covered_edges,total_paths,new_edges,new_paths,exec_count,new_execs,crash_count,new_crashes,hang_count,new_hangs
```

说明：

- `timestamp` 为 bucket 的起始秒（相对运行开始的 elapsedSec）
- `new_*` 为“桶内增量”（相邻 bucket 的差值，负值会按 0 处理）

---

### 与 FuzzingEngine 的协作

`FuzzingEngine` 负责在正确的时机调用统计接口：

- 每次 `harness.execute(...)` 后：`fuzzStats.recordExec()`
- crash/hang 分类后：`recordCrash/recordHang` + 可选打印事件
- interesting input 晋升入队后：`recordNewPath()`
- CoverageDB 更新后（可选）：`updateCoveredEdges(coverageDB.getTotalEdgesSeen())`
- 周期性：
  - `StatusPrinter` 后台输出
  - `StatsWriter.tick(fuzzStats.toStatsTick(queueSize))` 追加写入

---

### 使用示例（简化）

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

### 测试关注点

- `StatsWriterTest`：header 仅写一次、追加行格式正确、flush 行为可读
- `StatusPrinterTest`：`toStatusLine` 格式与事件输出
- `CorpusIntegrationTest`：paths/crash/hang 与 tick 字段一致

---

## 10. Mutator 变异体系总览
<a id="sec-m-mutator"></a>


### 1. 引擎变异哲学：混合变异架构

本引擎采用 **“结构引导 + 随机扰动”** 的双轨制变异架构：

*   **语法变异算子 (Structure-Aware Mutators)**：利用对目标格式（如 XML、ELF、JPEG）的先验知识，生成符合或接近协议规范的输入。这种方式能够绕过绝大多数初级校验（如 Magic Number 检查、CRC 校验、基础解析路径），使 Fuzzer 能够触达深层的业务逻辑。
*   **通用变异算法 (Havoc Mutator)**：在不破坏大框架的前提下，对局部数据进行“狂暴”修改。它擅长发现那些连开发者都未曾预料到的位级逻辑错误。

#### 核心接口

```java
public interface Mutator {
    /**
     * 返回一个变异迭代器，支持惰性生成测试用例
     * 
     * @param seed 待变异的种子
     * @param energy 分配的能量（生成的测试用例数量）
     * @return 测试用例迭代器
     */
    Iterator<Testcase> mutate(Seed seed, int energy);
}
```

---

### 2. 通用变异算法：AflHavocMutator

`AflHavocMutator` 是本引擎的"乱拳"组件，是对经典 AFL (American Fuzzy Lop) 核心变异阶段的 Java 高性能实现。

#### 算子权重分配

```java
// 权重表：让轻量级、保持结构的变异出现概率更高
private void initWeights() {
    // In-Place Ops (High Freq): ~50%
    fillWeight(10, OP_FLIP_BIT);
    fillWeight(10, OP_FLIP_BYTE);
    fillWeight(10, OP_ARITH_BYTE);
    fillWeight(10, OP_ARITH_SHORT);
    fillWeight(5,  OP_ARITH_INT);
    fillWeight(5,  OP_SWAP_BYTES);
    
    // Token & Interesting (High Value): ~20%
    fillWeight(10, OP_INTERESTING);
    fillWeight(10, OP_OVERWRITE_TOKEN);
    
    // Structural Ops (Expensive): ~30%
    fillWeight(5, OP_INSERT_TOKEN);
    fillWeight(5, OP_DELETE_BLOCK);
    fillWeight(5, OP_INSERT_BLOCK);
    fillWeight(5, OP_OVERWRITE_BLOCK);
    fillWeight(5, OP_CLONE_BLOCK);
}
```

#### 变异策略
1.  **自适应堆叠 (Adaptive Stacking)**：每次变异不会只执行一个操作，而是随机堆叠 2 到 32 个算子。这种指数级的组合能力使得输入数据可以迅速从原始状态演化为面目全非的畸形状态。
2.  **原地变异优先 (In-Place First)**：优先使用位翻转（Bit-flip）、算术加减（Arithmetic）、魔法数字替换（Interesting Values），这些操作不需要重新分配内存，执行效率极高。
3.  **种子拼接 (Splicing)**：通过“跨物种杂交”，将当前种子与语料库中的另一个随机种子在随机位置断开并拼接。这种方式能有效地合并两个不同路径发现的特征。
4.  **字典感知 (Dictionary-Aware)**：如果用户提供了 `.dict` 文件，Havoc 会在变异过程中高频插入这些 Token，帮助 Fuzzer 突破 Strcmp 等强字符串检查。

#### 优缺点分析
*   **优点**：完全不依赖格式知识，适用于任何二进制或文本目标。速度极快，是发现底层内存损坏漏洞（如缓冲区溢出）的利器。
*   **缺点**：盲目性强。在处理具有严格头部结构、长度校验或校验和（Checksum）的文件时，效率极低，大部分生成的用例会被目标程序在入口处直接丢弃。

---

### 3. 语法变异算子：文本类 (Text-based)

#### 3.1 XmlMutator (XML 变异器)
*   **核心逻辑**：采用基于递归下降的生成策略，确保生成的标签、属性和 DTD 结构在语法层面是准合法的。
*   **变异策略**：
    *   **Billion Laughs 攻击**：通过在 DTD 中定义递归展开的实体，测试解析器的内存膨胀防御。
    *   **XXE (外部实体注入)**：尝试插入 `SYSTEM "file:///etc/passwd"` 等载荷，探测敏感信息泄露风险。
    *   **编码炸弹**：随机切换 UTF-8, UTF-16LE, UTF-16BE 编码并注入相应的 BOM 头，测试解析器底层的编码转换引擎。
*   **优点**：能产生极深层级的嵌套结构，是测试 XML 解析状态机的关键。
*   **缺点**：生成的属性名和标签名是随机选取的，可能无法触发特定业务逻辑（如具体的 Config 检查）。

#### 3.2 MjsMutator (JavaScript 变异器)
*   **核心逻辑**：针对现代 JavaScript (ES Module) 语法，支持表达式、语句和声明的结构化变异。
*   **变异策略**：
    *   **变量作用域攻击**：制造复杂的闭包和 `let`/`const`/`var` 混用场景，测试作用域解析。
    *   **Unicode 标识符**：生成包含特殊 Unicode 字符的变量名，测试解析器的字符处理。
    *   **Arrow Function 嵌套**：构造深层嵌套的箭头函数表达式。
*   **优点**：能够生成语法正确的 JavaScript 代码，可穿透解析器校验。
*   **缺点**：生成的代码逻辑通常是随机的，难以触发特定业务逻辑。

#### 3.3 LuaMutator (Lua 脚本变异器)
*   **核心逻辑**：模拟 Lua 脚本的语法树（Block -> Statement -> Expression）。
*   **变异策略**：
    *   **协程与作用域攻击**：制造复杂的 `coroutine.resume` 逻辑，测试 VM 在协程切换时的变量生存期管理。
    *   **元表 (Metatable) 劫持**：通过设置 `__index` 或 `__gc` 触发无限递归或垃圾回收异常。
    *   **正则模式匹配**：针对 Lua 特有的 `%b` (Balanced) 匹配符生成畸形 Pattern。
*   **优点**：深度触达脚本虚拟机的指令解析和 GC (垃圾回收) 逻辑。
*   **缺点**：很难生成具有复杂控制流逻辑的脚本（例如能计算出特定结果的循环）。

#### 3.4 CxxMutator (C++ 符号变异器)
*   **核心逻辑**：针对 Itanium C++ ABI 符号修饰（Mangling）规范。
*   **变异策略**：
    *   **递归修饰符**：构造 `PPPPPP...i`（指向指针的指针...的整型），诱发 Demangler 的栈溢出。
    *   **模板递归**：构造深层嵌套模板 `I...I...E...E`。
    *   **操作符与构造函数**：随机注入 `C1`, `D2`, `nw` (operator new) 等特殊标记。
*   **优点**：专门针对二进制分析工具（如 `nm`, `readelf`, `gdb`）的解析核心。
*   **缺点**：生成的字符串通常非常短，攻击面相对集中。

---

### 4. 语法变异算子：二进制类 (Binary-based)

#### 4.1 ElfMutator (ELF 变异器)
*   **核心逻辑**：构建合法的 ELF64 文件骨架，包含回填偏移量的 Header Table。
*   **变异策略**：
    *   **计数器炸弹**：设置 `e_phnum` 或 `e_shnum` 为 `0xFFFF`，测试解析器是否盲目分配大量内存。
    *   **段链接环**：使 Section 之间的 `sh_link` 指向自身，制造解析死循环。
    *   **PT_NOTE 溢出**：构造畸形的 Note 段长度，测试 Core Dump 分析器的边界。
*   **优点**：能穿透 Linux 二进制加载器的第一层检查。
*   **缺点**：ELF 格式非常严苛，稍有偏移不齐（Alignment）就会导致解析器直接报错退出。

#### 4.2 JpegMutator (JPEG 变异器)
*   **核心逻辑**：基于 Marker（标记位）的流生成算法。
*   **变异策略**：
    *   **Exif/TIFF 伪造**：注入复杂的元数据块，元数据解析是图像处理库漏洞的“高发地”。
    *   **长度欺骗 (Length Spoofing)**：声明一个极大的段长度，但实际数据很短，诱发 OOB (越界读)。
    *   **渐进式扫描攻击**：使用 SOF2 标记，测试复杂的渐进式重组逻辑。
*   **优点**：相比随机位变异，该算法能产生更有意义的图片格式流。
*   **缺点**：生成的图像通常没有真实的视觉意义（像素是随机的），无法测试特定的滤镜算法（如模糊滤波）。

#### 4.3 PngMutator (PNG 变异器)
*   **核心逻辑**：按 Chunk 结构构建，自动管理 CRC 校验和和 Zlib 压缩流。
*   **变异策略**：
    *   **iCCP 压缩炸弹**：在 ICC Profile 块中存入高压缩比的垃圾数据，诱发解压时的 OOM。
    *   **调色板 OOB**：定义一个小的调色板，但在像素数据中使用大的索引值。
    *   **CRC Fuzzing**：5% 概率生成错误的 CRC 值，探测解析器是否在校验前就处理了恶意数据。
*   **优点**：通过自动重算 CRC，使得变异后的用例 100% 能够进入图像处理内核。
*   **缺点**：Zlib 压缩过程相对耗时，会略微降低 Fuzzing 的吞吐量。

#### 4.4 PcapMutator (网络报文变异器)
*   **核心逻辑**：构建包含 Ethernet -> IP -> TCP/UDP 完整协议栈的流量包。
*   **变异策略**：
    *   **长度不一致攻击**：构造 IP 头中的 Total Length 与 PCAP 头中的 `incl_len` 冲突的报文。
    *   **IHL/Offset 畸形**：设置非法的报文首部长度字段，诱发 DPI (深度包检测) 引擎的解析错位。
    *   **时间戳攻击**：生成时间回溯或跳跃极大的报文序列，测试流量重组器的状态管理。
*   **优点**：针对 IDS (入侵检测系统) 和防火墙提供高质量的测试输入。
*   **缺点**：目前主要支持 IPv4，对 IPv6 或更复杂的协议（如 HTTP 解析）支持有限。

---

### 5. 总结

变异算法的质量直接决定了 Fuzzing 的效率。**语法变异器**解决了“如何进得去”的问题，而 **AflHavocMutator** 解决了“如何挖得深”的问题。

在生产环境中，推荐将这些变异器与 **Coverage Feedback (覆盖率反馈)** 机制相结合。当语法变异器生成了一个有趣的结构并触发了新的代码路径时，Havoc 紧随其后对该路径上的种子进行微调，这是目前模糊测试领域的黄金策略。
---

### 6. 相关文档

- **[binary.md](mutate/binary.md)**：二进制结构感知变异框架详解，包含 FormatScanner、StructureMutator、ConstraintFixer 等组件
- **[grammar.md](mutate/grammar.md)**：语法感知变异框架详解，包含 Tokenizer、TreeBuilder、MutationStrategy 等组件
- **[MutatorFactory.md](mutate/MutatorFactory.md)**：变异器工厂模式的设计与实现
- **[MuatationOps.md](mutate/MuatationOps.md)**：底层变异操作的实现细节

---

## 11. MutatorFactory 变异器工厂
<a id="sec-m-mutatorfactory"></a>

来源：`docs/mutate/MutatorFactory.md`

### 1. 组件概述

`MutatorFactory` 是变异模块的**中央分发器**，位于 `edu.nju.fuzzing.mutate` 包中。它的核心职责是基于 `Seed` 的类型（`SeedType`）动态生产最合适的变异器实例。

在一个典型的 Fuzzing 流程中，我们往往拥有多种格式的种子（如 XML、JPEG、ELF 等）。如果对所有数据都使用盲目的位翻转，效率会非常低下；反之，如果只使用结构化变异，则可能无法触发底层的解析漏洞。`MutatorFactory` 通过**多态创建**和**混合变异策略**完美解决了这一矛盾。

---

### 2. 核心架构与实现

#### 2.1 类结构分析

```java
public class MutatorFactory {
    private final List<Seed> corpus;
    private final Mutator defaultMutator;
    private static final int HAVOC_PROBABILITY = 10;  // 10% 概率使用 Havoc
    
    public MutatorFactory(List<Seed> corpus) {
        this.corpus = corpus;
        this.defaultMutator = new AflHavocMutator(corpus);
    }
    
    public Mutator createMutator(Seed seed) { ... }
}
```

*   **Corpus 引用**：工厂类持有 `corpus`（语料库）的引用，这主要是为了支持 `AflHavocMutator`。Havoc 变异中的"拼接（Splicing）"操作需要从语料库中随机抽取其他种子进行"杂交"。
*   **单例与多态混合**：
    *   **单例模式**：`defaultMutator` (Havoc) 被设计为单例，因为它不持有特定种子的状态，且调用频率最高，使用 `ThreadLocalRandom` 保证线程安全。
    *   **工厂模式**：针对特定格式的变异器（如 `XmlMutator`）采用"按需创建"模式，保证了变异过程的独立性。

#### 2.2 变异分发策略
工厂类在执行 `createMutator(Seed seed)` 时遵循以下优先级逻辑：

1.  **兜底逻辑 (Fallback)**：如果种子类型为 `null` 或 `UNKNOWN`，直接分配 `AflHavocMutator`。
2.  **混合概率策略 (Hybrid Strategy)**：
    *   这是本工厂类最核心的**启发式设计**。
    *   即使种子类型已知（例如是一个 XML），工厂类仍有 **10% (HAVOC_PROBABILITY)** 的概率强制返回 `AflHavocMutator`。
    *   **设计目的**：语法变异器生成的结构通常过于“守规矩”，难以触发解析器最底层的缓冲区溢出等漏洞。通过混入 10% 的“乱拳”位变异，可以极大增强 Fuzzer 的鲁棒性攻击能力。
3.  **多态创建**：在通过概率筛选后，利用 `switch-case` 匹配 `SeedType`，返回对应的专业算子。

#### 2.3 支持的类型映射

```java
switch (type) {
    // --- 文本类 ---
    case XML:   return new XmlMutator();
    case MJS:   return new MjsMutator();
    case LUA:   return new LuaMutator();
    case CXX:   return new CxxMutator();

    // --- 二进制类 ---
    case PNG:   return new PngMutator();
    case ELF:   return new ElfMutator();
    case JPEG:  return new JpegMutator();
    case PCAP:  return new PcapMutator();

    // --- 未实现的类型 ---
    default:    return defaultMutator;
}
```

---

### 3. 在主函数中的实际用法

`MutatorFactory` 处于 Fuzzing 执行循环的核心环路中。以下是它在项目主流程（Main Loop）中的典型应用场景：

#### 3.1 代码集成示例

```java
public class FuzzerMain {
    public static void main(String[] args) {
        // 1. 初始化语料库
        List<Seed> corpus = loadInitialSeeds("seeds/");
        
        // 2. 初始化变异器工厂
        MutatorFactory factory = new MutatorFactory(corpus);

        while (true) {
            // 3. 调度器选出一个种子
            Seed currentSeed = scheduler.pickNextSeed(corpus);
            
            // 4. 根据当前种子，从工厂获取变异器
            // 这里体现了工厂模式的威力：主循环不需要知道具体的变异细节
            Mutator mutator = factory.createMutator(currentSeed);
            
            // 5. 分配能量并生成测试用例
            int energy = calculateEnergy(currentSeed);
            Iterator<Testcase> testcases = mutator.mutate(currentSeed, energy);
            
            // 6. 执行测试
            while (testcases.hasNext()) {
                executor.run(testcases.next());
            }
        }
    }
}
```

#### 3.2 运行流程图解

```
┌─────────────────────────────────────────────────────────────────────┐
│                        createMutator(Seed)                          │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │  seed.getType() → SeedType    │
                    └───────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │   random.nextDouble() < 0.1?  │
                    └───────────────────────────────┘
                           │               │
                      YES  │               │  NO
                           ▼               ▼
              ┌─────────────────┐   ┌─────────────────────────┐
              │ defaultMutator  │   │ switch (type)           │
              │ (AflHavocMutator)│   │   XML  → XmlMutator     │
              └─────────────────┘   │   MJS  → MjsMutator     │
                                    │   LUA  → LuaMutator     │
                                    │   CXX  → CxxMutator     │
                                    │   PNG  → PngMutator     │
                                    │   ELF  → ElfMutator     │
                                    │   JPEG → JpegMutator    │
                                    │   PCAP → PcapMutator    │
                                    │   default → defaultMutator │
                                    └─────────────────────────┘
                           │               │
                           └───────┬───────┘
                                   ▼
                    ┌───────────────────────────────┐
                    │       返回 Mutator 实例       │
                    └───────────────────────────────┘
```

**流程说明**：
1.  **输入**：调度器选中的 `Seed` 对象。
2.  **检测**：工厂检查 `Seed.getType()` 获取种子类型。
3.  **掷骰子**：生成随机数，判定是否命中 10% 的 Havoc 回退逻辑。
4.  **构建**：如果未回退，根据类型 `new` 出对应的专业变异器。
5.  **输出**：返回一个实现了 `Mutator` 接口的对象，供后续迭代生成使用。

---

### 4. 关键作用与价值

#### 4.1 提高变异的“命中深度”
通过将 PNG、XML、ELF 等格式的种子分发给专业的 **Structure-aware Mutator** 或 **Grammar-based Mutator**，生成的用例能够通过解析器的第一层校验（如格式检查、CRC 校验、标签闭合检查、Magic Number 验证），从而引导程序进入深层的业务逻辑处理代码。

- **文本类**（XML/MJS/LUA/CXX）：使用语法感知变异，保持语法正确性
- **二进制类**（PNG/ELF/JPEG/PCAP）：使用结构感知变异，保持格式有效性

#### 4.2 策略的灵活性
`MutatorFactory` 统一了变异接口。如果你需要增加一种新的格式（如 `Protobuf` 或 `WASM`），你只需要：
1.  在 `SeedType` 枚举中添加新类型。
2.  实现一个新的 `Mutator` 类（可继承 `StructureMutator` 或使用 `grammar` 包）。
3.  在 `MutatorFactory` 的 `switch` 中增加一个 `case`。
4.  **完全不需要修改主循环逻辑**。

#### 4.3 解决“语法陷阱”
纯语法变异器往往会陷入死胡同，无法生成破坏文件头或修改关键二进制位的用例。`MutatorFactory` 引入的 **10% Havoc 概率** 确保了种子库即便在高度结构化的变异下，依然保留了“暴力破坏”的基因，从而能够发现更底层的 C/C++ 内存安全漏洞。

---

### 5. 总结

`MutatorFactory` 不仅仅是一个简单的对象生成类，它实际上承载了本 Fuzzing 引擎的**变异调度哲学**。它通过对 `SeedType` 的智能感知和混合概率模型的应用，实现了“结构化探索”与“暴力变异”的完美平衡，是提升 Fuzzing 效率和覆盖率的核心引擎组件。

---

## 12. MutationOps 底层变异算子
<a id="sec-m-mutationops"></a>

来源：`docs/mutate/MuatationOps.md`

### 1. 概述

`MutationOps` 是一个**高性能、无状态的底层变异算子集合**，位于 `edu.nju.fuzzing.mutate` 包中。它参考了 AFL (American Fuzzy Lop) 的经典变异策略，并在此基础上进行了 Java 语言层面的深度优化。

该工具类主要用于对字节数组（`byte[]`）进行随机变异，以产生能够触发目标程序异常行为的测试用例。它是 `AflHavocMutator` 的核心依赖，也可被其他变异器直接调用。

#### 核心设计与优化

*   **高性能 (High Performance)**：摒弃了 Java 中较为沉重的 `ByteBuffer` 包装，全部采用位运算（Bitwise Operations）手动处理多字节读写，最大化执行效率。
*   **无锁随机 (Lock-free Randomness)**：使用 `ThreadLocalRandom` 替代 `java.util.Random`，在多线程并发 Fuzzing 场景下避免锁竞争，大幅提升吞吐量。
*   **零 GC 压力 (Zero GC for In-Place)**：对于原地变异操作，直接修改原数组，不产生任何新的对象分配，减轻垃圾回收（Garbage Collection）压力。
*   **自动降级 (Auto Fallback)**：当数据长度不足时，多字节操作（如 `arithInt`）会自动降级为单字节操作，确保算法的健壮性。

---

### 2. 变异策略分类

`MutationOps` 将变异操作分为两大类：

1.  **原地变异 (In-Place Mutation)**：不改变数据长度，直接修改内容。返回 `void`。
2.  **结构变异 (Structural Mutation)**：改变数据长度（插入或删除），返回新的数组 `byte[]`。

#### 2.1 魔法数字 (Interesting Values)

类中预定义了 AFL 经典的"魔法数字"集合，这些数值通常是整数溢出、缓冲区边界检查等漏洞的触发点：

```java
// 8-bit 边界值
private static final byte[] INTERESTING_8 = {-128, -1, 0, 1, 16, 32, 64, 100, 127};

// 16-bit 边界值
private static final short[] INTERESTING_16 = {-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767};

// 32-bit 边界值
private static final int[] INTERESTING_32 = {-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647};
```

---

### 3. 方法详解

#### 第一类：原地变异 (In-Place Mutation)

**特点**：
*   返回类型：`void`
*   副作用：直接修改传入的 `byte[] data`。
*   性能：极高（无内存分配）。
*   边界安全：空数组或长度不足时自动跳过或降级。

| 方法名 | 描述 | 逻辑细节 |
| :--- | :--- | :--- |
| **`flipBit`** | 随机位翻转 | 随机选择一个字节中的某一位（Bit），将其取反（0变1，1变0）。使用 `data[idx] ^= (1 << bitIdx)` 实现。 |
| **`flipByte`** | 随机字节翻转 | 随机选择一个字节，与 `0xFF` 进行异或操作（即按位取反）。 |
| **`arithByte`** | 字节加减运算 | 随机选择一个字节，对其进行加或减操作，幅度为 `1` 到 `35` 之间的随机数。 |
| **`arithShort`** | Short (2字节) 加减 | 随机选择连续的2个字节，将其视为 Short 进行加减运算。**自动处理大端/小端序**。如果数组长度 < 2，自动降级为 `arithByte`。 |
| **`arithInt`** | Int (4字节) 加减 | 随机选择连续的4个字节，将其视为 Integer 进行加减运算。**自动处理大端/小端序**。如果数组长度 < 4，自动降级为 `arithShort`。 |
| **`setInteresting`** | 特殊值替换 | 随机选择 8bit, 16bit 或 32bit 宽度，用预定义的"魔法数字"覆盖原数据。会根据数组长度自动降级宽度。 |
| **`swapBytes`** | 字节交换 | 随机选取两个不同的索引位置，交换这两个字节的值。用于破坏魔数或校验和结构。 |
| **`overwriteBlock`** | 块覆写 | 随机选取一段连续区域（长度 1-32，不超过数组长度），用随机字节填充。 |
| **`overwriteToken`** | 字典覆写 | 将用户提供的关键字（Token/Dictionary）覆盖写入到数据的随机位置。如果 token 长度超过数据长度则跳过。使用 `System.arraycopy` 实现。 |

---

#### 第二类：结构变异 (Structural Mutation)

**特点**：
*   返回类型：`byte[]` (新数组)
*   副作用：不修改原数组，返回变异后的新副本。
*   性能：涉及内存分配和数组拷贝（`System.arraycopy`）。
*   长度保护：对于极短数据会返回克隆副本以保持语义一致性。

| 方法名 | 描述 | 逻辑细节 |
| :--- | :--- | :--- |
| **`deleteBlock`** | 块删除 | 随机删除一段连续的数据（长度为原数据的 1-50%）。如果数组长度 < 2，返回克隆副本。 |
| **`insertBlock`** | 块插入 | 在随机位置插入一段新数据（长度 1-32）。50% 概率填充随机字节，50% 概率填充固定字节（如 `0x41`）。 |
| **`cloneBlock`** | 块克隆 (拼接) | **非常有效的变异策略**。从原数据中复制一段内容（长度为原数据的 1-50%），插入到原数据的另一个位置。这能保留数据的语义结构（如 XML 标签重复）。 |
| **`insertToken`** | 字典插入 | 将用户提供的关键字（Token）插入到数据的随机位置。返回长度为 `data.length + token.length` 的新数组。 |

---

#### 辅助方法 (Helpers)

这些私有方法用于处理多字节数据的读写，且**不需要创建 ByteBuffer 对象**，这是本类高性能的关键所在：

```java
// 读取 Short (2字节)
private static short getShort(byte[] b, int off, boolean bigEndian) {
    int b1 = b[off] & 0xFF;
    int b2 = b[off + 1] & 0xFF;
    return bigEndian ? (short) ((b1 << 8) | b2) : (short) (b1 | (b2 << 8));
}

// 写入 Short (2字节)
private static void putShort(byte[] b, int off, short val, boolean bigEndian) {
    if (bigEndian) {
        b[off] = (byte) (val >> 8);
        b[off + 1] = (byte) val;
    } else {
        b[off] = (byte) val;
        b[off + 1] = (byte) (val >> 8);
    }
}
```

*   **Endianness**: 所有多字节操作都接受 `boolean bigEndian` 参数，变异时会随机选择大端或小端模式，以覆盖不同架构的目标程序。

---

### 4. 使用示例

以下代码展示了如何在 Fuzzing 循环中使用 `MutationOps`。

```java
import edu.nju.fuzzing.mutate.MutationOps;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

public class MutationExample {

    public static void main(String[] args) {
        // 1. 原始种子数据 (例如 "Hello World")
        byte[] originalData = "Hello World".getBytes();
        
        // 2. 模拟 Fuzzing 流程
        byte[] mutatedData = originalData.clone(); // 保护原始数据
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        // 随机选择一种变异策略
        int strategy = rand.nextInt(4);

        switch (strategy) {
            case 0:
                // --- 场景 A: 原地变异 (In-Place) ---
                System.out.println("Executing Bit Flip...");
                MutationOps.flipBit(mutatedData);
                break;

            case 1:
                // --- 场景 B: 算术变异 (Arithmetic) ---
                System.out.println("Executing Int Addition...");
                // 尝试修改前4个字节
                MutationOps.arithInt(mutatedData); 
                break;

            case 2:
                // --- 场景 C: 结构变异 (Structural - Insert) ---
                System.out.println("Executing Block Insertion...");
                // 注意：结构变异会返回新对象，需要接收返回值
                mutatedData = MutationOps.insertBlock(mutatedData);
                break;

            case 3:
                // --- 场景 D: 字典/Token 变异 ---
                System.out.println("Injecting Dictionary Token...");
                byte[] token = "admin".getBytes();
                // 50% 概率覆盖，50% 概率插入
                if (rand.nextBoolean()) {
                    MutationOps.overwriteToken(mutatedData, token);
                } else {
                    mutatedData = MutationOps.insertToken(mutatedData, token);
                }
                break;
        }

        // 3. 输出结果
        System.out.println("Original: " + Arrays.toString(originalData));
        System.out.println("Mutated : " + Arrays.toString(mutatedData));
        System.out.println("New Len : " + mutatedData.length);
    }
}
```

### 5. 最佳实践与注意事项

1.  **数据隔离**：
    *   对于 **In-Place** 方法，如果你的原始种子（Seed）对象是全局共享的，调用前**务必先 clone 一份副本**，否则会污染原始种子库。
    *   对于 **Structural** 方法，虽然它返回新数组，但输入数组通常不会被修改（除 `insertToken` 等内部逻辑外），但也建议操作副本以保持一致性。

2.  **调度策略 (Scheduling)**：
    *   在实现 Mutator 时，建议**高频使用 In-Place 操作**（如 80% 概率），**低频使用 Structural 操作**（如 20% 概率）。
    *   原因：Structural 操作涉及内存分配 (`new byte[]`) 和内存拷贝，过高频率会导致 Java GC 压力增大，降低 Fuzzing 的每秒执行次数 (Execs/sec)。

3.  **字典的使用**：
    *   `overwriteToken` 和 `insertToken` 极其依赖字典的质量。建议在 Fuzzer 启动时解析目标程序（如提取字符串常量）或加载用户提供的字典文件。

4.  **边界安全**：
    *   所有方法内部都已包含边界检查（例如 `data.length < 4` 时 `arithInt` 会自动降级或直接返回），调用者无需在外部额外判断数组长度。

---

## 13. 二进制结构感知变异框架（binary）
<a id="sec-m-binary"></a>

来源：`docs/mutate/binary.md`

### 1. 概述

本框架提供了一套完整的**二进制格式感知变异引擎**，位于 `edu.nju.fuzzing.mutate.binary` 包中。与传统的盲目位翻转不同，该框架能够理解文件的内部结构，针对控制字段进行精确变异，从而显著提高漏洞发现的效率。

#### 核心设计理念

*   **格式扫描 (Format Scanning)**：首先解析文件，识别出所有逻辑块和关键字段
*   **结构感知变异 (Structure-Aware Mutation)**：针对不同类型的字段采用不同的变异策略
*   **约束修复 (Constraint Fixing)**：变异后自动修复校验和、长度字段等，确保畸形数据能通过初步检查

---

### 2. 架构组件

#### 2.1 核心类图

```
FormatScanner (接口)
    ├── ElfScanner     (ELF 格式扫描器)
    ├── PngScanner     (PNG 格式扫描器)
    ├── JpegScanner    (JPEG 格式扫描器)
    └── PcapScanner    (PCAP 格式扫描器)

ScanResult
    ├── BinaryChunk[]     (识别出的块列表)
    └── FieldMapping[]    (全局字段映射)

BinaryChunk
    ├── startOffset       (块起始位置)
    ├── totalLength       (块总长度)
    ├── chunkType         (块类型标识)
    ├── rawData           (原始数据)
    ├── fields            (块内字段映射)
    └── critical          (是否为关键块)

FieldMapping
    ├── offset            (字段偏移)
    ├── length            (字段长度)
    ├── type              (字段类型)
    ├── byteOrder         (字节序)
    └── originalValue     (原始值)

StructureMutator        (静态变异方法集合)
ConstraintFixer         (约束修复工具)
```

#### 2.2 扫描模式

框架支持两种文件结构扫描模式：

| 模式 | 适用格式 | 结构特点 |
| :--- | :--- | :--- |
| **TLV 模式** (Type-Length-Value) | PNG, JPEG, PCAP | 数据由连续的"块"组成，每个块包含类型标识、长度字段和数据 |
| **Offset 模式** (Header-Section) | ELF, PE | 文件头包含指向各个 Section 的偏移量 |

---

### 3. 字段类型枚举 (`FieldType`)

`FieldType` 定义了二进制文件中可识别的字段类型，变异器会根据字段类型选择不同的攻击策略：

| 字段类型 | 描述 | 变异策略 |
| :--- | :--- | :--- |
| `MAGIC` | 文件头或块头的标识符 | 通常保持不变或谨慎破坏 |
| `TYPE` | 块类型、段类型 | 随机替换为未知类型 |
| `LENGTH` | 数据大小字段 | **高价值目标**：溢出值、0、MAX_INT |
| `OFFSET` | 指向文件其他位置的地址 | 越界指针、负值、环形引用 |
| `COUNT` | 元素个数 | 极大值、0 |
| `CHECKSUM` | 完整性校验值 | 变异后需重算 |
| `FLAGS` | 布尔标志位 | 全0、全1、随机翻转 |
| `VERSION` | 版本号 | 非法版本、极端值 |
| `DATA` | 数据区 | 可随意变异 |
| `PADDING` | 填充/对齐 | 可删除或填充垃圾 |

---

### 4. 格式扫描器

#### 4.1 FormatScanner 接口

```java
public interface FormatScanner {
    /**
     * 扫描文件，识别结构
     */
    ScanResult scan(byte[] data);
    
    /**
     * 检查文件是否符合此格式
     */
    boolean matches(byte[] data);
    
    /**
     * 获取格式名称
     */
    String getFormatName();
}
```

#### 4.2 已实现的扫描器

##### ElfScanner

解析 ELF 可执行文件结构：

*   **识别内容**：ELF Header、Program Headers、Section Headers
*   **字段映射**：`e_type`, `e_machine`, `e_entry`, `e_phoff`, `e_shoff`, `e_phnum`, `e_shnum` 等
*   **字节序检测**：根据 `e_ident[EI_DATA]` 自动切换大小端

##### PngScanner

解析 PNG 图像格式：

*   **识别内容**：8字节签名 + 连续的 Chunk 结构
*   **Chunk 结构**：Length(4) + Type(4) + Data(n) + CRC32(4)
*   **关键块识别**：IHDR、IDAT、IEND 标记为 critical

##### JpegScanner

解析 JPEG 图像格式：

*   **识别内容**：SOI 标记 + 连续的 Segment 结构
*   **Segment 结构**：Marker(2) + Length(2) + Data(n-2)
*   **特殊处理**：SOF、DQT、DHT、SOS 等关键段

##### PcapScanner

解析 PCAP 网络抓包格式：

*   **识别内容**：Global Header + Packet Records
*   **字段映射**：`ts_sec`, `ts_usec`, `incl_len`, `orig_len`
*   **协议层解析**：Ethernet → IP → TCP/UDP

---

### 5. 结构变异器 (`StructureMutator`)

`StructureMutator` 提供静态方法用于结构感知变异。

#### 5.1 整数溢出攻击

```java
// 预定义的危险整数值
public static final long[] EVIL_INTEGERS = {
    0L, 1L, -1L,
    0x7FL, 0x80L, 0xFFL,                    // 8-bit boundaries
    0x7FFFL, 0x8000L, 0xFFFFL,              // 16-bit boundaries
    0x7FFFFFFFL, 0x80000000L, 0xFFFFFFFFL,  // 32-bit boundaries
    0x7FFFFFFFFFFFFFFFL, 0x8000000000000000L, // 64-bit boundaries
    Integer.MAX_VALUE, Integer.MIN_VALUE,
    Long.MAX_VALUE, Long.MIN_VALUE
};
```

| 方法 | 描述 | 攻击目标 |
| :--- | :--- | :--- |
| `mutateLength` | 变异 LENGTH 字段 | Buffer Overflow/Over-read |
| `mutateOffset` | 变异 OFFSET 字段 | 越界读写、信息泄露 |
| `mutateCount` | 变异 COUNT 字段 | 内存耗尽、整数溢出 |
| `mutateFlags` | 变异 FLAGS 字段 | 逻辑错误、权限绕过 |

#### 5.2 块操作

| 方法 | 描述 | 攻击效果 |
| :--- | :--- | :--- |
| `duplicateChunk` | 复制块 | 资源耗尽、状态混乱 |
| `deleteChunk` | 删除块 | 必需字段缺失错误 |
| `swapChunks` | 交换块位置 | 顺序依赖错误 |
| `clearChunkData` | 清空数据区 | 空数据处理错误 |

#### 5.3 位级操作

```java
// 对块的数据区进行位翻转
public static byte[] bitFlipChunkData(byte[] data, BinaryChunk chunk, ThreadLocalRandom rand);

// 对指定范围进行随机字节替换
public static byte[] randomizeRegion(byte[] data, int start, int length, ThreadLocalRandom rand);

// 破坏 Magic 标识
public static byte[] corruptMagic(byte[] data, FieldMapping magicField, ThreadLocalRandom rand);
```

---

### 6. 约束修复器 (`ConstraintFixer`)

变异可能破坏文件的完整性约束，导致目标程序在早期检查阶段就拒绝处理。`ConstraintFixer` 用于修复这些约束，使畸形数据能够进入更深层的解析逻辑。

#### 6.1 校验和修复

```java
// 修复单个 PNG 块的 CRC32
public static byte[] fixPngChunkCrc(byte[] data, int chunkStart);

// 修复所有 PNG 块的 CRC
public static byte[] fixAllPngCrcs(byte[] data);

// 修复 IP 头部校验和
public static byte[] fixIpChecksum(byte[] data, int ipHeaderOffset, int ihl);
```

#### 6.2 长度字段修复

```java
// 更新 PNG 块的长度字段
public static byte[] fixPngChunkLength(byte[] data, int chunkStart, int newDataLength);

// 更新 PCAP 包记录的长度字段
public static byte[] fixPcapPacketLength(byte[] data, int packetHeaderOffset,
        int inclLen, int origLen, boolean bigEndian);

// 更新 ELF Section 的大小字段
public static byte[] fixElfSectionSize(byte[] data, int sectionHeaderOffset,
        long newSize, boolean is64Bit);
```

#### 6.3 Magic 恢复

当变异意外破坏了文件签名时，使用以下方法恢复：

```java
public static byte[] restorePngMagic(byte[] data);  // 恢复 PNG 签名
public static byte[] restoreJpegMagic(byte[] data); // 恢复 JPEG SOI
public static byte[] restoreElfMagic(byte[] data);  // 恢复 ELF Magic
```

---

### 7. 使用示例

#### 7.1 完整的 PNG 变异流程

```java
import edu.nju.fuzzing.mutate.binary.*;
import java.util.concurrent.ThreadLocalRandom;

public class PngFuzzer {
    
    public byte[] mutatePng(byte[] original) {
        ThreadLocalRandom rand = ThreadLocalRandom.current();
        
        // 1. 扫描文件结构
        PngScanner scanner = new PngScanner();
        if (!scanner.matches(original)) {
            return original;
        }
        ScanResult scanResult = scanner.scan(original);
        
        // 2. 选择变异策略
        byte[] mutated = original.clone();
        int strategy = rand.nextInt(5);
        
        switch (strategy) {
            case 0:
                // 变异 LENGTH 字段
                for (BinaryChunk chunk : scanResult.getChunks()) {
                    for (FieldMapping field : chunk.getFieldsByType(FieldType.LENGTH)) {
                        mutated = StructureMutator.mutateLength(mutated, field, rand);
                    }
                }
                break;
                
            case 1:
                // 复制非关键块
                var nonCritical = scanResult.getNonCriticalChunks();
                if (!nonCritical.isEmpty()) {
                    BinaryChunk target = nonCritical.get(rand.nextInt(nonCritical.size()));
                    mutated = StructureMutator.duplicateChunk(mutated, target, 3);
                }
                break;
                
            case 2:
                // 对数据区进行位翻转
                for (BinaryChunk chunk : scanResult.getChunks()) {
                    if (!chunk.isCritical()) {
                        mutated = StructureMutator.bitFlipChunkData(mutated, chunk, rand);
                    }
                }
                break;
                
            case 3:
                // 删除非关键块
                var deletable = scanResult.getNonCriticalChunks();
                if (!deletable.isEmpty()) {
                    BinaryChunk target = deletable.get(rand.nextInt(deletable.size()));
                    mutated = StructureMutator.deleteChunk(mutated, target);
                }
                break;
                
            default:
                // 随机化某个块的数据区
                if (!scanResult.getChunks().isEmpty()) {
                    BinaryChunk chunk = scanResult.getChunks().get(
                        rand.nextInt(scanResult.getChunks().size()));
                    int dataStart = chunk.getStartOffset() + chunk.getDataOffset();
                    mutated = StructureMutator.randomizeRegion(mutated, dataStart, 
                        chunk.getDataLength(), rand);
                }
        }
        
        // 3. 修复校验和
        mutated = ConstraintFixer.fixAllPngCrcs(mutated);
        
        return mutated;
    }
}
```

#### 7.2 ELF 整数溢出攻击

```java
public byte[] attackElfHeaders(byte[] elfData) {
    ThreadLocalRandom rand = ThreadLocalRandom.current();
    
    ElfScanner scanner = new ElfScanner();
    ScanResult result = scanner.scan(elfData);
    
    byte[] mutated = elfData.clone();
    
    // 攻击所有 COUNT 字段
    for (FieldMapping field : result.getGlobalFields()) {
        if (field.getType() == FieldType.COUNT) {
            mutated = StructureMutator.mutateCount(mutated, field, rand);
        }
    }
    
    // 恢复 Magic 以通过初步检查
    mutated = ConstraintFixer.restoreElfMagic(mutated);
    
    return mutated;
}
```

---

### 8. 最佳实践

#### 8.1 变异策略组合

推荐的变异策略权重分配：

| 策略类型 | 权重 | 理由 |
| :--- | :--- | :--- |
| LENGTH 变异 | 30% | 缓冲区溢出的主要触发点 |
| OFFSET 变异 | 25% | 越界读写的关键 |
| 块操作 | 20% | 状态机混乱 |
| 位翻转 | 15% | 底层解析错误 |
| COUNT 变异 | 10% | 内存分配问题 |

#### 8.2 约束修复时机

```
变异操作 --> 90% 概率修复约束 --> 输出
                |
                +--> 10% 概率保持破坏 --> 输出 (测试严格校验)
```

#### 8.3 与 Coverage 反馈结合

```java
// 当发现新覆盖时，优先使用结构感知变异
if (hasNewCoverage(seed)) {
    // 使用精细变异深入探索
    mutator = new StructureAwareMutator(scanner);
} else {
    // 使用暴力变异尝试突破
    mutator = new AflHavocMutator(corpus);
}
```

---

### 9. 扩展开发

#### 9.1 添加新格式支持

1. 实现 `FormatScanner` 接口
2. 在 `scan()` 方法中解析文件结构，填充 `BinaryChunk` 和 `FieldMapping`
3. 在 `ConstraintFixer` 中添加对应的修复方法
4. 在 `MutatorFactory` 中注册新的变异器

#### 9.2 自定义危险值集合

```java
// 针对特定目标的自定义危险值
public static final long[] CUSTOM_EVIL_VALUES = {
    0xCAFEBABE,     // Java Class Magic
    0xFEEDFACE,     // Mach-O Magic
    0x504B0304,     // ZIP Local File Header
    // ... 根据目标添加
};
```

---

### 10. 总结

二进制结构感知变异框架通过"理解"文件格式，实现了：

1. **精准攻击**：针对控制字段（长度、偏移、计数）进行变异
2. **深度渗透**：通过修复校验和等约束，使畸形数据能进入深层解析
3. **高效探索**：相比盲目变异，能更快地发现解析器漏洞

该框架与 `AflHavocMutator` 配合使用效果最佳：结构感知变异负责突破格式检查，Havoc 变异负责挖掘深层内存错误。

---

## 14. 语法感知变异框架（grammar）
<a id="sec-m-grammar"></a>

来源：`docs/mutate/grammar.md`

### 1. 概述

语法感知变异框架位于 `edu.nju.fuzzing.mutate.grammar` 包中，提供了一套完整的**文本格式解析与变异引擎**。与盲目的字节级变异不同，该框架能够理解输入的语法结构，生成在语法层面"看起来合理"但在语义层面"存在问题"的测试用例。

#### 核心价值

*   **绕过初级检查**：生成的用例能通过格式验证、语法解析等早期检查
*   **触达深层逻辑**：使 Fuzzer 能够测试业务逻辑、状态机、类型系统等深层代码
*   **保持可读性**：变异后的数据仍可作为调试用例使用

---

### 2. 架构组件

#### 2.1 核心类图

```
Tokenizer (接口)
    ├── XmlTokenizer    (XML 分词器)
    ├── LuaTokenizer    (Lua 分词器)
    ├── CxxTokenizer    (C++ Mangled Name 分词器)
    └── MjsTokenizer    (JavaScript/MJS 分词器)

Token
    ├── type            (Token 类型)
    ├── value           (文本值)
    ├── startPos        (起始位置)
    └── endPos          (结束位置)

TokenNode
    ├── nodeType        (节点类型: ROOT/BLOCK/LEAF/FRAGMENT)
    ├── token           (关联的 Token)
    ├── children        (子节点列表)
    └── openDelimiter   (开放界定符)

TreeBuilder             (Token 流转树结构)
MutationStrategy        (通用变异策略)

*SyntaxChecker         (语法检查器: Xml/Lua/Cxx/Mjs)
*SyntaxFixer           (语法修复器: Xml/Lua/Cxx/Mjs)
```

#### 2.2 处理流程

```
原始数据 --> Tokenizer.tokenize() --> Token 流
                                        |
                                        v
                              TreeBuilder.build()
                                        |
                                        v
                                   TokenNode 树
                                        |
                                        v
                            MutationStrategy.* 变异操作
                                        |
                                        v
                              TokenNode.serialize()
                                        |
                                        v
                              SyntaxFixer.fix()
                                        |
                                        v
                                   变异后数据
```

---

### 3. Token 系统

#### 3.1 Token 类型枚举

`Token.Type` 定义了所有可识别的 Token 类型：

##### 通用类型

| 类型 | 描述 | 示例 |
| :--- | :--- | :--- |
| `RAW` | 原始字节（无法识别） | 二进制数据 |
| `UNKNOWN` | 未知字符 | 乱码 |
| `WHITESPACE` | 空白符 | 空格、Tab |
| `NEWLINE` | 换行 | `\n`, `\r\n` |
| `COMMENT` | 注释 | `// ...`, `/* ... */` |

##### 界定符

| 类型 | 描述 | 匹配 |
| :--- | :--- | :--- |
| `LBRACE` / `RBRACE` | 花括号 | `{` / `}` |
| `LBRACKET` / `RBRACKET` | 方括号 | `[` / `]` |
| `LPAREN` / `RPAREN` | 圆括号 | `(` / `)` |
| `LANGLE` / `RANGLE` | 尖括号 | `<` / `>` |

##### 字面量

| 类型 | 描述 | 示例 |
| :--- | :--- | :--- |
| `STRING` | 字符串 | `"hello"`, `'world'` |
| `NUMBER` | 数字 | `123`, `3.14`, `1e10` |
| `BOOLEAN` | 布尔值 | `true`, `false` |
| `NULL` | 空值 | `null`, `nil` |

##### XML 特定类型

| 类型 | 描述 | 示例 |
| :--- | :--- | :--- |
| `XML_DECL` | XML 声明 | `<?xml version="1.0"?>` |
| `XML_DOCTYPE` | DOCTYPE | `<!DOCTYPE html>` |
| `XML_CDATA` | CDATA 区块 | `<![CDATA[...]]>` |
| `XML_ENTITY` | 实体引用 | `&amp;`, `&#123;` |
| `XML_TAG_OPEN` | 开始标签 | `<div` |
| `XML_TAG_CLOSE` | 结束标签 | `</div>` |
| `XML_TEXT` | 文本内容 | `Hello World` |

##### C++ Mangled Name 特定类型

| 类型 | 描述 | 示例 |
| :--- | :--- | :--- |
| `CXX_PREFIX` | 前缀 | `_Z` |
| `CXX_NESTED` | 嵌套名称 | `N...E` |
| `CXX_TYPE` | 类型编码 | `i`, `d`, `v` |
| `CXX_MODIFIER` | 修饰符 | `P` (指针), `R` (引用) |
| `CXX_TEMPLATE` | 模板参数 | `I...E` |

#### 3.2 Token 不变性

Token 一旦创建不可修改。变异时使用工厂方法创建新 Token：

```java
// 修改值
Token newToken = token.withValue("new_value");

// 修改类型
Token newToken = token.withType(Token.Type.STRING);

// 同时修改
Token newToken = token.withTypeAndValue(Token.Type.NUMBER, "42");
```

---

### 4. 分词器 (Tokenizer)

#### 4.1 接口定义

```java
public interface Tokenizer {
    /**
     * 将原始字节流切分为 Token 流
     */
    List<Token> tokenize(byte[] input);
    
    /**
     * 便捷方法：直接从字节流构建树
     */
    default TokenNode parse(byte[] input) {
        return buildTree(tokenize(input));
    }
}
```

#### 4.2 容错设计原则

所有分词器遵循以下原则：

1. **绝不抛出异常**：遇到无法识别的字符标记为 `RAW` 或 `UNKNOWN`
2. **尽可能识别有意义的 Token**：即使在错误上下文中也尝试识别
3. **保留位置信息**：每个 Token 记录在原始输入中的起始和结束位置

#### 4.3 已实现的分词器

##### XmlTokenizer

识别 XML 的所有基本结构：

```java
XmlTokenizer tokenizer = new XmlTokenizer();
List<Token> tokens = tokenizer.tokenize(xmlBytes);
// 识别: XML声明, DOCTYPE, CDATA, 注释, 标签, 属性, 实体引用, 文本
```

##### LuaTokenizer

识别 Lua 脚本的语法元素：

*   关键字：`function`, `local`, `if`, `then`, `end`, `for`, `while`, `return`...
*   字符串：`"..."`, `'...'`, `[[...]]` (长字符串)
*   注释：`--...`, `--[[...]]`
*   操作符和标点

##### CxxTokenizer

识别 Itanium C++ ABI 符号修饰：

*   前缀：`_Z`
*   类型编码：`i` (int), `d` (double), `v` (void)...
*   修饰符：`P` (指针), `R` (引用), `K` (const)...
*   嵌套名称：`N...E`
*   模板参数：`I...E`

##### MjsTokenizer

识别 JavaScript/ES Module 语法：

*   关键字：`import`, `export`, `function`, `const`, `let`, `async`, `await`...
*   模板字符串：`` `...${...}...` ``
*   正则表达式：`/pattern/flags`

---

### 5. 树构建器 (TreeBuilder)

`TreeBuilder` 将 Token 流转换为树状结构，基于界定符推断层级关系。

#### 5.1 构建策略

```java
public static TokenNode build(List<Token> tokens) {
    TokenNode root = TokenNode.createRoot();
    Deque<TokenNode> stack = new ArrayDeque<>();
    stack.push(root);
    
    for (Token token : tokens) {
        if (token.isOpenDelimiter()) {
            // 遇到开放界定符，创建新 BLOCK 并入栈
            TokenNode block = TokenNode.createBlock(token);
            current.addChild(block);
            stack.push(block);
        } else if (token.isCloseDelimiter()) {
            // 遇到闭合界定符，尝试匹配并出栈
            // ...
        } else {
            // 其他 Token 作为 LEAF 添加
            current.addChild(TokenNode.createLeaf(token));
        }
    }
    
    return root;
}
```

#### 5.2 容错处理

*   **括号不匹配**：不强制添加闭合符，保持未闭合状态
*   **多余的闭合符**：作为普通 LEAF 节点添加
*   **结构过于混乱**：使用 `buildFlat()` 生成扁平结构

---

### 6. TokenNode 树操作

#### 6.1 节点类型

| 类型 | 描述 | 子节点 |
| :--- | :--- | :--- |
| `ROOT` | 根节点 | 有 |
| `BLOCK` | 由界定符包围的块 | 有 |
| `LEAF` | 叶子节点（单个 Token） | 无 |
| `FRAGMENT` | 多个连续 Token 的片段 | 有 |

#### 6.2 树操作 API

```java
// 添加子节点
node.addChild(child);

// 在指定位置插入
node.insertChild(index, child);

// 删除子节点
node.removeChild(child);
node.removeChildAt(index);

// 替换子节点
node.replaceChild(index, newChild);

// 深度复制
TokenNode copy = node.deepCopy();

// 收集所有 BLOCK 节点
List<TokenNode> blocks = root.collectBlocks();

// 收集所有 LEAF 节点
List<TokenNode> leaves = root.collectLeaves();

// 序列化回字符串
String output = root.serialize();
```

---

### 7. 通用变异策略 (`MutationStrategy`)

`MutationStrategy` 提供格式无关的变异操作，可被各格式特定的 Mutator 复用。

#### 7.1 结构变异

##### 子树复制（制造深层嵌套）

```java
/**
 * 选择一个 BLOCK 节点，将其内容复制并嵌套
 * 用于测试解析器的递归深度限制
 */
public static TokenNode duplicateSubtree(TokenNode root, int depth, ThreadLocalRandom rand);
```

##### 节点删除

```java
/**
 * 随机删除一些子节点
 * 用于测试必需元素缺失的处理
 */
public static TokenNode deleteNodes(TokenNode root, double deleteProb, ThreadLocalRandom rand);
```

##### 节点交换

```java
/**
 * 随机交换两个兄弟节点的位置
 * 用于测试顺序依赖的逻辑
 */
public static TokenNode swapNodes(TokenNode root, ThreadLocalRandom rand);
```

#### 7.2 值变异

##### 字符串注入

```java
/**
 * 在字符串类型的 Token 中注入特殊 payload
 */
public static TokenNode injectPayload(TokenNode root, String[] payloads, ThreadLocalRandom rand);
```

##### 类型混淆

```java
/**
 * 将数字改成字符串，将布尔值改成数字等
 * 用于测试类型系统的健壮性
 */
public static TokenNode typeConfusion(TokenNode root, ThreadLocalRandom rand);

// 示例转换：
// NUMBER "42"    -> STRING "\"42\""
// BOOLEAN "true" -> NUMBER "1"
// STRING "hello" -> NULL "null"
```

##### 数字边界值变异

```java
/**
 * 将数字替换为边界值（MAX_INT, MIN_INT, 0, -1 等）
 */
public static TokenNode mutateNumbers(TokenNode root, ThreadLocalRandom rand);

// 边界值列表：
String[] boundaryValues = {
    "0", "-1", "1", 
    "2147483647", "-2147483648",       // INT32 边界
    "9223372036854775807",             // INT64 MAX
    "1.7976931348623157E308",          // Double MAX
    "0/0",                             // NaN (Lua 兼容)
    "math.huge", "-math.huge",         // Infinity (Lua 兼容)
};
```

##### 关键词替换

```java
/**
 * 将关键字替换为类似但可能导致解析错误的关键字
 */
public static TokenNode replaceKeywords(TokenNode root, String[][] replacements, 
                                       ThreadLocalRandom rand);
```

#### 7.3 常用攻击载荷

```java
public static final String[] COMMON_PAYLOADS = {
    "\\x00",                           // Null byte
    "%s%s%s%s%s",                      // Format string
    "../../../etc/passwd",             // Path traversal
    "<script>alert(1)</script>",       // XSS
    "{{7*7}}",                         // Template injection
    "${7*7}",                          // Expression injection
    "$(id)",                           // Command injection
    "' OR '1'='1",                     // SQL injection
    "\\uD800",                         // Lone surrogate
    "AAAA" + "A".repeat(1000),         // Buffer overflow
};
```

---

### 8. 语法检查器 (*SyntaxChecker)

#### 8.1 设计目的

语法检查器用于检测变异后代码的语法问题，为修复器提供修复依据。

#### 8.2 XmlSyntaxChecker

检查 XML 的 well-formedness：

```java
public class CheckResult {
    public final boolean isValid;
    public final int unmatchedOpenTagCount;     // 未闭合的开始标签数
    public final int unmatchedCloseTagCount;    // 多余的结束标签数
    public final List<String> unmatchedOpenTags; // 未闭合的标签名
    public final List<String> mismatchedTags;   // 不匹配的标签对
    public final boolean hasUnclosedAttribute;  // 属性引号未闭合
    public final boolean hasInvalidComment;     // 注释包含 --
    public final boolean hasInvalidEntity;      // 无效的实体引用
    public final boolean hasUnclosedCData;      // CDATA 未闭合
    public final boolean hasUnquotedAttribute;  // 属性值无引号
    public final List<String> undefinedEntities; // 未定义的实体
}
```

#### 8.3 其他检查器

| 检查器 | 检查内容 |
| :--- | :--- |
| `LuaSyntaxChecker` | 括号配对、关键字匹配（if-then-end）、字符串闭合 |
| `CxxSyntaxChecker` | 嵌套结构（N...E, I...E）、类型编码合法性 |
| `MjsSyntaxChecker` | 括号配对、模板字符串闭合、import/export 语法 |

---

### 9. 语法修复器 (*SyntaxFixer)

#### 9.1 设计原则

*   **最小化修改**：尽量保持原始结构
*   **迭代修复**：循环修复直到语法正确或达到最大尝试次数
*   **优先级排序**：按问题严重程度依次修复

#### 9.2 XmlSyntaxFixer

修复能力：

```java
// 修复 XML 代码
String fixed = fixer.fix(xmlString);

// 基于 Token 列表修复
List<Token> fixedTokens = fixer.fixTokens(tokens);

// 工具方法
String escaped = XmlSyntaxFixer.escapeXmlAttribute(value);  // 转义属性值
String escaped = XmlSyntaxFixer.escapeXmlText(value);       // 转义文本
```

修复项目：

| 问题 | 修复方法 |
| :--- | :--- |
| 未闭合的标签 | 添加缺失的结束标签 |
| 不匹配的标签 | 修正标签名 |
| 属性值未引用 | 添加引号 |
| 注释中的 `--` | 替换为 `- -` |
| 未定义的实体 | 转义为 `&amp;xxx;` |
| 未闭合的 CDATA | 添加 `]]>` |

#### 9.3 修复流程

```java
public String fix(String xml) {
    String fixed = xml;
    int attempts = 0;
    
    while (attempts < MAX_FIX_ATTEMPTS) {
        CheckResult result = checker.check(fixed);
        
        if (result.isValid) {
            return fixed;
        }
        
        String before = fixed;
        
        // 按优先级修复
        if (result.hasInvalidComment) {
            fixed = fixInvalidComments(fixed);
        }
        if (result.hasUnquotedAttribute) {
            fixed = fixUnquotedAttributes(fixed);
        }
        if (!result.unmatchedOpenTags.isEmpty()) {
            fixed = fixUnmatchedOpenTags(fixed, result.unmatchedOpenTags);
        }
        // ...
        
        if (fixed.equals(before)) break;  // 无法继续修复
        attempts++;
    }
    
    return fixed;
}
```

---

### 10. 使用示例

#### 10.1 XML 变异流程

```java
import edu.nju.fuzzing.mutate.grammar.*;

public class XmlFuzzer {
    
    private final XmlTokenizer tokenizer = new XmlTokenizer();
    private final XmlSyntaxChecker checker = new XmlSyntaxChecker();
    private final XmlSyntaxFixer fixer = new XmlSyntaxFixer(checker);
    
    public byte[] mutateXml(byte[] original) {
        ThreadLocalRandom rand = ThreadLocalRandom.current();
        
        // 1. 分词
        List<Token> tokens = tokenizer.tokenize(original);
        
        // 2. 构建树
        TokenNode tree = TreeBuilder.build(tokens);
        
        // 3. 应用变异
        int mutationType = rand.nextInt(5);
        switch (mutationType) {
            case 0:
                // 深层嵌套
                tree = MutationStrategy.duplicateSubtree(tree, 10, rand);
                break;
            case 1:
                // 删除节点
                tree = MutationStrategy.deleteNodes(tree, 0.3, rand);
                break;
            case 2:
                // 交换节点
                tree = MutationStrategy.swapNodes(tree, rand);
                break;
            case 3:
                // 注入 payload
                tree = MutationStrategy.injectPayload(tree, 
                    MutationStrategy.COMMON_PAYLOADS, rand);
                break;
            case 4:
                // 类型混淆
                tree = MutationStrategy.typeConfusion(tree, rand);
                break;
        }
        
        // 4. 序列化
        String mutated = tree.serialize();
        
        // 5. 语法修复（90% 概率）
        if (rand.nextInt(10) > 0) {
            mutated = fixer.fix(mutated);
        }
        
        return mutated.getBytes(StandardCharsets.UTF_8);
    }
}
```

#### 10.2 Lua 脚本变异

```java
public byte[] mutateLua(byte[] original) {
    ThreadLocalRandom rand = ThreadLocalRandom.current();
    
    LuaTokenizer tokenizer = new LuaTokenizer();
    List<Token> tokens = tokenizer.tokenize(original);
    TokenNode tree = TreeBuilder.build(tokens);
    
    // 关键词替换
    String[][] replacements = {
        {"local", "global"},           // 无效关键字
        {"function", "func"},          // 简写
        {"return", "returns"},         // 拼写错误
        {"nil", "null"},               // 其他语言习惯
    };
    tree = MutationStrategy.replaceKeywords(tree, replacements, rand);
    
    // 数字边界值
    tree = MutationStrategy.mutateNumbers(tree, rand);
    
    // 修复语法
    LuaSyntaxFixer fixer = new LuaSyntaxFixer();
    String output = fixer.fix(tree.serialize());
    
    return output.getBytes(StandardCharsets.UTF_8);
}
```

---

### 11. 最佳实践

#### 11.1 变异策略组合

| 策略 | 权重 | 目标 |
| :--- | :--- | :--- |
| 结构变异 | 40% | 测试解析器的结构处理 |
| 值变异 | 30% | 测试业务逻辑 |
| Payload 注入 | 20% | 安全漏洞探测 |
| 保持原样 | 10% | 基准测试 |

#### 11.2 修复与不修复

```java
// 90% 概率修复语法 -> 测试深层逻辑
// 10% 概率不修复 -> 测试解析器的容错能力
if (rand.nextInt(10) > 0) {
    output = fixer.fix(output);
}
```

#### 11.3 与 Coverage 反馈结合

```java
// 当语法变异发现新覆盖时，记录变异参数
if (hasNewCoverage) {
    saveMutationParams(mutationType, params);
    
    // 对该种子进行更多同类型变异
    energy *= 2;
}
```

---

### 12. 扩展开发

#### 12.1 添加新格式支持

1. 实现 `Tokenizer` 接口
2. 定义格式特定的 `Token.Type`（如需要）
3. 实现对应的 `SyntaxChecker` 和 `SyntaxFixer`
4. 创建格式特定的 `Mutator` 类
5. 在 `MutatorFactory` 中注册

#### 12.2 自定义变异策略

```java
public class CustomMutationStrategy {
    
    /**
     * 自定义：重复相同的子节点 N 次
     */
    public static TokenNode repeatChildren(TokenNode root, int times, ThreadLocalRandom rand) {
        List<TokenNode> blocks = root.collectBlocks();
        if (blocks.isEmpty()) return root;
        
        TokenNode target = blocks.get(rand.nextInt(blocks.size()));
        List<TokenNode> original = new ArrayList<>(target.getChildren());
        
        for (int i = 0; i < times; i++) {
            for (TokenNode child : original) {
                target.addChild(child.deepCopy());
            }
        }
        
        return root;
    }
}
```

---

### 13. 总结

语法感知变异框架通过：

1. **容错分词**：将任意输入转换为 Token 流，不因格式错误而失败
2. **结构建模**：将 Token 流转换为树状结构，便于结构级变异
3. **智能变异**：提供结构变异和值变异两类策略
4. **自动修复**：变异后自动修复语法问题，确保用例能进入深层逻辑

该框架与 `AflHavocMutator` 配合使用，实现了"结构引导 + 随机扰动"的双轨制变异架构，是高效 Fuzzing 的核心组件。


<a id="sec-appendix"></a>
# 三. 附录（其他文档）

本章收录与整体设计相关、但不直接对应某个单一模块的文档。

---

<a id="sec-architecture-appendix"></a>
## 1. ARCHITECTURE 架构说明
[架构文档](ARCHITECTURE.md)

## 2. Detailed Components Guide 组件详解
[模块文档](General.md)