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
- `--nonCrashExitCodes`：逗号或空格分隔的 exit code 白名单（默认空；示例：`1,2,4`）

Crash 判定口径：

- 默认情况下：`exitCode != 0` 会被认为是 crash（历史行为）。
- 如果提供了 `--nonCrashExitCodes`，则这些退出码不会触发 crash 分支（不会落盘到 `crashes/`、不会计入 crash_count），而是按“非 crash 的正常执行结果”继续走覆盖率评估/晋升逻辑。
- 为避免手动中断污染统计，`130`（SIGINT）与 `143`（SIGTERM）会被默认视为 non-crash（可与 `--nonCrashExitCodes` 合并）。

已知限制：

- 由于按 `key value` 成对解析，**所有参数必须成对出现**；不支持单独 flag（例如 `--foo`），也不支持复杂的 GNU 风格组合。
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
- `workdir/tmp/inputs/.cur_input`：复用输入文件（避免小文件爆炸）
- `workdir/tmp/exec-logs/`：stdout/stderr 日志（当前实现每次 exec 都会写文件；长跑注意 inode 风险）

---

## 测试覆盖

- CLI 冒烟：
  - [src/test/java/edu/nju/fuzzing/cli/FuzzerMainCmdSmokeTest.java](../../src/test/java/edu/nju/fuzzing/cli/FuzzerMainCmdSmokeTest.java)
  - 覆盖 STDIN/FILE 两种模式、`--seeds` 覆盖、非法 `--coverage` fail-fast。
