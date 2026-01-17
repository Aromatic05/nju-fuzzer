# nju-fuzzer 开发日志

> 截止日期：2026-01-13, 
> 全量开发日志索引见[第 8 节](#8-原始开发日志索引按来源)。

## 阅读入口

- 项目总文档（运行方法/模块实现/接口细节）：[docs/PROJECT.md](PROJECT.md)
- 本文（开发过程/变更线索/Problems 清单）：[docs/Devlog.md](Devlog.md)

---

## 1. 项目目标与闭环定义

本阶段开发以“可真实跑起来、可复现、可扩展”为核心目标，围绕以下闭环推进：

1. **目标可执行**：支持插装目标（AFL++ SHM）与非插装目标（none/Null monitor）。
2. **执行可观测**：覆盖率（bitmap/edge-level）、崩溃/超时判定、stdout/stderr 日志策略。
3. **反馈可驱动**：CoverageDB 全局确认 new edges，调度与能量分配消费这些信号。
4. **变异可演进**：Havoc 兜底 + 按 `SeedType` 的结构/语法感知 Mutator 路由。
5. **产物可沉淀**：workdir 结构、queue/crashes/hangs、stats/curve、可一键复现。

---

## 2. 时间线与里程碑

| 日期 | 里程碑 | 核心产出 |
|---|---|---|
| 2025-12-21 | env环境搭建和target构建脚本 | env/env.sh、AFL++ 插装 lua/mjs 目标 |
| 2025-12-22 | 扩展 CoverageMonitor 支持调度（Iteration 4） | EdgeSet、CoverageDB、CoverageMonitorEx/ShmCoverageMonitorEx、扩展 diff 结果 |
| 2025-12-24 | “真实跑起来”闭环补齐 | SHM attach 修复、基础 monitor edge-level、CoverageDB 全局确认、调度增强、Mutator 接线、CLI coverage/seeds |
| 2025-12-25 | CI/CD 持续集成测试 | GitHub Actions 工作流、单元测试覆盖、冒烟测试脚本 |
| 2025-12-31 | 一键跑目标 + 长跑 IO/统计优化（Iteration 5） | one_click.sh、stats/curve.csv、CrashOracle 策略、execLogs 策略、tmpfs 输入策略 |
| 2026-01-03 | Mutate 核心框架 + 二进制/语法感知变异器(初版) | Mutator/Factory/Ops/Havoc、*Mutator |
| 2026-01-06 | 二进制/语法感知变异器(token解析版) | binary scanner/structure mutator、grammar tokenizer/tree/strategy |
| 2026-01-07 | 最终运行流程与一键发布 | one_click.sh, docker-compose.yml和dockerfile |
| 2026-01-09 | 结构统计和可视化分析 | corpus structure stats脚本，coverage/coverage_visualizer.py |
| 2026-01-13 | 文档完善与项目收尾 | 各模块文档、开发日志、Problems 清单 |

> CoverageMonitor 的 Iterations 1-3 与主流程集成细节记录在 `docs/CoverageMonitor/DevLog.md`。

---

## 3. 进度安排

- **Iteration 1–3（基础覆盖监控 → 引擎集成 → 统计与 corpus）**：已完成  
  - 描述：完成基础覆盖采集与差分链路，与执行引擎和语料管理（文件级 corpus）完成集成，统计与状态输出可稳定落盘并通过集成测试。  
  - 输出：`SHM bitmap` 读取、差分策略组合、`FileCorpusManager`、`FuzzStats` / `StatusPrinter`、集成测试验证。
- **Iteration 4（边级别覆盖 → `CoverageDB` → 调度信号）**：已完成（2025-12-22）  
  - 描述：实现边级别（edge）覆盖模型并引入全局覆盖库存（支持无副作用的全局评估），将真正的“new edge”信号暴露给调度与能量分配模块。  
  - 输出：`EdgeSet`、`CoverageDB`（包含无副作用的 `evaluate` 接口）、`CoverageEx`、`CoverageMonitorEx`。
- **Iteration 5（长跑稳定性与 IO/统计落盘）**：已完成（2025-12-31）  
  - 描述：针对长时间运行做 IO 与日志降噪、统计落盘和性能稳定性优化；引入按需落盘策略以避免 inode/磁盘爆炸并使用 tmpfs 缓存当前输入。  
  - 输出：`execLogs` 策略（`interesting|all|none` 与输出大小限制）、`curve.csv`（统计曲线）、shm tmpfs 输入策略、统计 `flush` 降频。
- **Iteration 6（Mutate 系统化：接口、工厂路由、通用 `Havoc`）**：已完成（2026-01-08）  
  - 描述：对变异子系统进行系统化重构，定义统一 `Mutator` 接口、`MutatorFactory` 路由与通用的 `Havoc` 兜底算子，便于扩展语法/结构感知变异器。  
  - 输出：统一的变异接口与工厂实现，以及基础 `Havoc` 策略。
- **Iteration 7（结构/语法感知 Mutator 质量提升）**：进行中（由 Problems 驱动）  
  - 描述：以问题清单驱动改进，目标提高样本的“可解析率 / 可深入率”，减少被解析器在早期拒绝的比例，从而提升变异有效性与覆盖发现率。  
  - 目标：提升解析成功率、降低无效变异、增强语法/结构修复能力。
- **Iteration 8（CI/CD 与一键发布）**：待定  
  - 描述：规划将现有运行脚本与容器化产物接入自动化流水线，实现可重复的一键构建、测试与发布。  
  - 目标：支持自动化构建/测试/发布（集成 one_click.sh、docker-compose.yml、Dockerfile 等），并将关键验证纳入 CI。
---

## 4. 任务分配

- 负责人：孙一鸣
- 任务分配：
  - 项目整体架构与核心模块设计，框架代码编写与测试，CI/CD和最终发布：孙一鸣
  - Engine/Queue/Scheduler/Stats 模块具体实现与测试：杜宸宇
  - Mutate 模块具体实现与测试：赵怡贤
  - 数据处理：何若扬
  - 文档编写与维护：孙一鸣、杜宸宇、赵怡贤，何若扬


---

## 5. 关键难题与解决过程（按“问题 → 影响 → 解决”组织）

### 5.1 AFL++ SHM 覆盖监控：attach/启动链路不稳定

- **问题**：通过 `InstrumentedExecutorHarness.start()` 启动时出现 “Not attached”，影响插装目标真实跑通。
- **影响**：覆盖监控链路不可用，无法进入 coverage-feedback 模式。
- **解决**（2025-12-24）：
  - 修复 `ShmCoverageMonitorEx.fromEnvironment()` 中 `SysVShmBitmapSource` 参数顺序，并在构造后立即 `attach()`。
  - 在 `start()` 中对 SysV SHM 未 attach 的情况补 `attach()`。

### 5.2 interesting 晋升误判：局部差分导致“假新边”

- **问题**：仅依赖局部 diff 策略可能出现误判晋升。
- **影响**：queue 污染、调度信号偏移、浪费执行预算。
- **解决**（2025-12-24）：
  - 引入 CoverageDB 的**无副作用全局确认**：新增 `CoverageDB.evaluate(DiffResultEx)` 只读取 `globalSeen` 计算 truly-new edges，不修改 DB 状态。
  - 引擎流程：先 local interesting，再 evaluate 全局确认，仅 truly-new 才晋升。

### 5.3 长跑 IO 爆炸：exec-logs 小文件/空文件占满 inode 与磁盘

- **问题**：每次执行落盘 stdout/stderr，会产生海量小文件；即便是空文件也会消耗大量空间。
- **影响**：磁盘被打满(运行1h产生6GiB以上的日志和样例临时文件)，fuzzer 崩溃。
- **解决**（2025-12-31）：
  - 引入 `-Dnju.fuzzer.execLogs=interesting|all|none`（默认 `interesting`）：普通执行不落盘。
  - 仅当 testcase 被确认晋升为 interesting 时 best-effort 二次执行抓 stdout/stderr。
  - `all` 模式下仅当输出非空才落盘，并用 `-Dnju.fuzzer.execLogsMaxBytes` 限制捕获上限。
  - `.cur_input`默认写入 `/dev/shm`（tmpfs）。

### 5.4 crash 判定：非 0 退出码不等价于 crash

- **问题**：很多目标程序会用非 0 表示“输入非法/拒绝”，不应算 crash。
- **影响**：crash 统计与 triage 失真。
- **解决**（2025-12-31）：
  - CrashOracle 默认规则：`exitCode > 128` 视为 crash（与 `128 + signal` 约定一致），忽略 `130/143`（SIGINT/SIGTERM）。
  - 支持 CLI 扩展 `--nonCrashExitCodes` 白名单。

### 5.5 样例输入模式错误, 导致部分目标无法正确读取输入

- **问题**：弄错了 STDIN/FILE 输入模式的实现，导致部分目标无法正确读取输入。
- **影响**：目标程序覆盖率一直维持单一数值不变，fuzzer 无法有效变异。
- **解决**（2025-01-05）：
  - 修正 `ProcessExecutor` 中 STDIN/FILE 输入模式的实现逻辑，确保目标程序能够正确读取输入数据。

### 5.6 docker builder交叉编译, 运行时环境缺少动态库(djpeg)

- **问题**：在builder容器编译时动态库链接, 但是在运行时容器内运行时找不到对应动态库, 导致目标程序无法正常执行。
- **影响**：目标程序无法启动, fuzzer 无法进行有效的模糊测试。
- **解决**（2025-01-05）：
  - 初步解决方案：在容器内绝对路径补齐对应的动态库。
  - 后续解决方案：修改编译脚本, 完全静态链接目标程序, 避免在容器内运行时出现动态库缺失的问题。

### 5.7 变异算子中偶发异常导致主循环崩溃

- **问题**：某些变异算子在处理特定输入时抛出异常，导致主循环中断。
- **影响**：fuzzer 运行不稳定，频繁中断。
- **解决**（2025-01-06）：
  - 在 `FuzzingEngine` 主循环中增加异常捕获机制，对于变异阶段的异常进行日志记录并跳过该变异，确保主循环持续运行。

### 5.8 调度与能量：在“确定性、可复现”前提下增强效果

- **问题**：未 fuzz 阶段如果“遇到第一个就返回”，会错过更优 seed；能量分配缺少更多信号。
- **影响**：覆盖增长慢、资源利用不充分。
- **解决**（2025-01-07）：
  - SeedPrioritizer：对未 fuzz 种子确定性打分选最高，打分包含 bitmapSize、execTime（软惩罚）、depth、handicap，并消费 CoverageDB 信号（favored/rarity/minFreq/redundant/stability）。
  - PowerScheduler：新增输入大小因子、类型因子，并叠加 favored 增益、redundant/unstable 衰减、rarity/minFreq 增益（封顶）。

---

## 6. 实验的一些思考

- **测试样例的多样性**：
  - 对于PNG/JPEG图片, 随机变异和结构感知变异都难以产生有效样例, 需要结合更多语法和格式知识, 我觉得可以在未来的迭代中引入更多基于格式的变异策略, 以提高样例的有效性, 以及增加初始种子的多样性。
  - 对于ELF文件, 可以引入coredump, so, obj等相关文件进行联合变异, 以提高变异样例的有效性, 以及使用systemv, bsd等不同格式的ELF文件进行测试, 还可以放一些PE文件进行异常测试。
- **变异策略的改进**：
  - 目前的变异策略主要集中在结构感知和语法感知, 未来可以考虑引入更多基于语义的变异策略, 例如针对特定协议或文件格式的变异, 以提高变异样例的有效性
- **性能优化**：
  - 在长时间运行中, IO和统计的性能瓶颈比较明显, 未来可以考虑引入更多的缓存和异步处理机制, 以提高整体的运行效率。
- **覆盖率较低的反思**
  - 目标程序存在众多分支和参数, 仅测试一个参数不可能覆盖所有逻辑, 所有我感觉覆盖率的统计意义不大, 仅可以作为引导变异测试的一项参考指标, 最终统计结果并不能说明太多问题。

## 7. 全量覆盖：开发日志逐条复述（对齐原文，不漏项）

[全量开发日志](DevLog/FullLog.md)

---

## 8. 原始开发日志索引（按来源）

- `docs/CoverageMonitor/DevLog.md`
  - Iteration 1-3：AFL++ SHM 覆盖监控、差分策略、corpus/统计与引擎集成。
  - Iteration 4（2025-12-22）：EdgeSet/CoverageDB/扩展覆盖模型。
  - Iteration 5（2025-12-31）：长跑 IO 与统计落盘优化。

- `docs/DevLog/2025-12-24.md`
  - SHM attach 修复、基础 monitor edge-level、CoverageDB evaluate 全局确认、调度/能量增强、Mutator 接线、CLI coverage/seeds。

- `docs/DevLog/2025-12-31.md`
  - one_click.sh、一键跑目标；curve.csv；CrashOracle 规则；execLogs 策略；tmpfs 输入策略；stats flush 降频。

- `docs/Mutate/DevLog/2026-01-08-mutate-core.md`
  - Mutator/Factory/Ops/Havoc 兜底与设计决策。

- `docs/Mutate/DevLog/2026-01-08-mutate-binary.md`
  - PNG/ELF/JPEG/PCAP 的结构扫描、字段/块变异与约束修复。

- `docs/Mutate/DevLog/2026-01-08-mutate-grammar.md`
  - Token/Tree/Strategy 基础设施；XML/Lua/MJS/C++ 的语法感知变异方向。

- `docs/mutate/Problems/*.md`
  - 各 Mutator 的审查问题清单与建议修复方向（用于后续质量提升迭代）。
