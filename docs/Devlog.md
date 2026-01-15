# nju-fuzzer 开发日志

> 截止日期：2026-01-13
>

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

### 5.6 变异算子中偶发异常导致主循环崩溃

- **问题**：某些变异算子在处理特定输入时抛出异常，导致主循环中断。
- **影响**：fuzzer 运行不稳定，频繁中断。
- **解决**（2025-01-06）：
  - 在 `FuzzingEngine` 主循环中增加异常捕获机制，对于变异阶段的异常进行日志记录并跳过该变异，确保主循环持续运行。

### 5.7 调度与能量：在“确定性、可复现”前提下增强效果

- **问题**：未 fuzz 阶段如果“遇到第一个就返回”，会错过更优 seed；能量分配缺少更多信号。
- **影响**：覆盖增长慢、资源利用不充分。
- **解决**（2025-01-07）：
  - SeedPrioritizer：对未 fuzz 种子确定性打分选最高，打分包含 bitmapSize、execTime（软惩罚）、depth、handicap，并消费 CoverageDB 信号（favored/rarity/minFreq/redundant/stability）。
  - PowerScheduler：新增输入大小因子、类型因子，并叠加 favored 增益、redundant/unstable 衰减、rarity/minFreq 增益（封顶）。

---

## 7. 全量覆盖：开发日志逐条复述（对齐原文，不漏项）
> 本节把已有开发日志的“段落结构与要点”逐条铺开，便于你在一个文件里阅读全量信息。

[全量开发日志](DevLog/FullLog.md)

<details>
<summary>点击展开：FullLog.md</summary>

## 全量开发日志

> 本节把已有开发日志的“段落结构与要点”逐条铺开，便于你在一个文件里阅读全量信息。
> 若你希望我把每份原文全文（含代码块）直接粘贴进本文件，也可以继续扩写，但文件会非常长。

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

</details>

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
