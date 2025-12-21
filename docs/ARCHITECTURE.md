## NJU 模糊测试工具 —— 架构说明（Coverage-Guided 阶段）

本文档描述南京大学软件测试课程「模糊测试方向」代码大作业中，**模糊测试工具的架构设计**。
当前阶段为 **Coverage-Guided Fuzzer（覆盖率引导模糊测试）**：系统已实现 AFL++ 风格的覆盖率监控与语料库管理，能够根据覆盖率反馈自动保存 interesting 输入、crash、hang，并提供实时统计与状态显示。

---

### 1. 当前阶段目标

本阶段的目标是：

* 建立一个**可运行的 Java 项目**
* 明确并固定整体架构与模块边界，便于 4 人小组并行开发
* 定义模糊测试主流程所需的**核心数据模型**
* 为作业要求的**六个核心组件**提供清晰的接口
* **✅ 完成覆盖率监控与语料库管理**（AFL++ SHM bitmap 读取、多种对比策略、crash/hang/queue 自动保存）
* 为后续实现 AFL++ 风格模糊测试打好工程基础

**当前阶段已完成：**

* ✅ 覆盖率监控（SHM bitmap 读取、多种策略）
* ✅ 语料库管理（queue/crashes/hangs 自动保存）
* ✅ 统计与状态显示（实时 exec/s、路径数、crash/hang 计数）
* ✅ 集成测试（144 tests passing）

**待完成（后续迭代）：**

* 种子队列管理（从 seedDir 读取、轮转选择）
* 变异算子（havoc mutations）
* 种子排序与能量调度

---

### 2. 系统整体工作流程

模糊测试工具围绕一个持续运行的 **Fuzzing Loop（模糊测试主循环）** 工作：

1. **（待实现）** 从种子队列中选择一个 Seed
2. **（待实现）** 根据调度策略计算该 Seed 的能量（执行预算）
3. **（待实现）** 对 Seed 进行变异，生成多个 Testcase
4. **✅ 执行目标程序（fuzz target）**
5. **✅ 监控执行结果（退出状态、超时、覆盖率反馈）**
6. **✅ 判断 Testcase 是否有价值（新覆盖 / crash / hang）**
7. **✅ 保存测试用例并更新队列**
8. **✅ 写入统计信息**
9. **重复上述过程直到达到时间或轮次上限**

当前已实现步骤 4-9，下一步将实现种子队列管理（步骤 1）、能量调度（步骤 2）、变异算子（步骤 3）。

---

### 3. 核心组件设计（对应作业要求）

系统被拆分为多个模块，其中以下 **六个组件**是作业明确要求实现的核心部分。

#### 3.1 插装组件（Instrumentation，afl-cc）

**作用：**

* 使用 `afl-cc` 对 C/C++ 目标程序进行插装编译
* 使目标程序在运行时能向共享内存写入覆盖率信息

**Skeleton 阶段说明：**

* 插装过程通过脚本或外部流程完成
* Java 主程序假定已经存在可执行的插装目标程序

---

#### 3.2 测试执行组件（Executor）

**作用：**

* 启动子进程执行目标程序
* 控制超时
* 记录执行时间与退出状态

**接口位置：**

```
edu.nju.fuzzing.exec.Executor
```

**输出：**

* `RunResult`（执行时间、退出码、是否超时等）

---

#### 3.3 执行结果监控组件（Coverage Monitor）**【✅ 已完成】**

**作用：**

* 读取 AFL++ 覆盖率共享内存（bitmap）
* 判断是否出现新的覆盖路径
* 识别 crash / hang 等特殊情况

**当前实现：**

* **ShmCoverageMonitor**：完整的 AFL++ SHM bitmap 监控实现
* **BitmapSource**：抽象 SHM 读取接口，当前使用 `SysVShmBitmapSource`（JNA 实现）
* **CoverageDiffStrategy**：可插拔的覆盖率对比策略
  * `SeenNonZeroStrategy`：全局 seen 判定（推荐）
  * `PrevBitmapStrategy`：相对上一次的差异
  * `HashFilteredStrategy`：基于 hash 快速去重
  * `CompositeStrategy`：组合多种策略
* **集成到 FuzzingEngine**：
  * `beforeRun()` 清零 bitmap
  * `afterRun()` 读取覆盖率并判定 interesting
  * 自动保存 interesting 输入到 queue/

**接口位置：**

```
edu.nju.fuzzing.cov.CoverageMonitor
edu.nju.fuzzing.cov.ShmCoverageMonitor
edu.nju.fuzzing.cov.BitmapSource
edu.nju.fuzzing.cov.CoverageDiffStrategy
```

**测试覆盖：**

* 14 tests for ShmCoverageMonitor
* 9 tests for SeenNonZeroStrategy
* 13 tests for PrevBitmapStrategy
* 11 tests for HashFilteredStrategy
* 14 tests for CompositeStrategy
* 3 integration tests in FuzzingEngineIntegrationTest

---

#### 3.4 变异组件（Mutator）

**作用：**

* 根据 Seed 和能量预算生成 Testcase
* 后续将实现 AFL 风格的 bitflip / arith / interest / havoc / splice 等算子

**Skeleton 阶段说明：**

* 可简单复制 Seed 作为占位实现

**接口位置：**

```
edu.nju.fuzzing.mutate.Mutator
```

---

#### 3.5 种子排序组件（Seed Prioritizer）

**作用：**

* 从种子队列中选择下一个要 fuzz 的 Seed
* 支持非随机排序策略（作业后续要求）

**Skeleton 阶段说明：**

* 先采用 FIFO（先进先出）

**接口位置：**

```
edu.nju.fuzzing.schedule.SeedPrioritizer
```

---

#### 3.6 能量调度组件（Power Scheduler）

**作用：**

* 根据 Seed 的历史表现决定 fuzz 次数（energy）

**Skeleton 阶段说明：**

* 使用固定能量值（如常数）

**接口位置：**

```
edu.nju.fuzzing.schedule.PowerScheduler
```

---

### 4. 数据模型设计（组件间契约）

所有组件通过统一的数据模型进行交互，定义于：

```
edu.nju.fuzzing.model
```

主要包括：

* `Seed`：队列中的输入及其元信息（待实现）
* `Testcase`：由 Seed 变异得到的候选输入（待实现）
* `RunResult`：一次目标程序执行的结果（已实现）
* **`Coverage`**：**✅ 覆盖率反馈与"是否有价值"的标志（已实现）**
  * 包含 `execId`, `nonZeroBytes`, `newBytes`, `interesting` 等字段
  * 支持空覆盖（无覆盖率监控时）
* `Decision`：是否保存到 queue / crashes / hangs（集成在 FuzzingEngine）
* `StatsTick`：一次统计快照（用于评估与画图）（已实现）

这些模型构成了**数据通路的稳定契约**，后续实现不应破坏其语义。

---

### 5. 包结构说明

```
edu.nju.fuzzing
├─ cli          # 启动入口、命令行参数解析
├─ core         # 模糊测试主循环（FuzzingEngine）
├─ exec         # 目标程序执行
├─ cov          # ✅ 覆盖率监控（已完成：ShmCoverageMonitor, BitmapSource, Strategies）
├─ corpus       # ✅ 语料库管理（已完成：FileCorpusManager, queue/crashes/hangs）
├─ stats        # ✅ 统计与状态显示（已完成：FuzzStats, StatusPrinter）
├─ mutate       # 变异组件（待实现）
├─ schedule     # 种子排序与能量调度（待实现）
├─ model        # 核心数据结构
└─ util         # 通用工具类
```

该结构支持明确分工，减少多人协作冲突。

---

### 6. 覆盖率监控详细设计

覆盖率监控是本项目的核心组件，采用分层设计：

#### 6.1 架构层次

```
FuzzingEngine
    ↓
CoverageMonitor (interface)
    ↓
ShmCoverageMonitor (implementation)
    ↓
BitmapSource (interface)    CoverageDiffStrategy (interface)
    ↓                              ↓
SysVShmBitmapSource          SeenNonZeroStrategy
                             PrevBitmapStrategy
                             HashFilteredStrategy
                             CompositeStrategy
```

#### 6.2 工作流程

1. **初始化阶段**（`ShmCoverageMonitor.start()`）
   * 从环境变量读取 `__AFL_SHM_ID`
   * 通过 JNA 调用 `shmat()` attach 共享内存
   * 初始化 bitmap buffer 和对比策略

2. **执行前**（`beforeRun()`）
   * 清零 bitmap（通过 `BitmapSource.clear()`）
   * 准备接收新的覆盖率数据

3. **执行后**（`afterRun(RunResult)`）
   * 从 SHM 读取 bitmap（`BitmapSource.readInto(byte[])`）
   * 使用对比策略判定是否 interesting（`CoverageDiffStrategy.diff(byte[])`）
   * 返回 `Coverage` 对象，包含 `newBytes` 和 `interesting` 标志

4. **清理阶段**（`close()`）
   * 通过 JNA 调用 `shmdt()` detach 共享内存
   * 释放资源

#### 6.3 覆盖率对比策略

* **SeenNonZeroStrategy**（推荐）：维护全局 `seen` bitset，判定"从未覆盖过的边"
* **PrevBitmapStrategy**：相对上一次执行的差异，适合快速原型验证
* **HashFilteredStrategy**：基于 XXHash64 快速去重，减少重复判定
* **CompositeStrategy**：组合多种策略，同时满足多个条件才判定为 interesting

#### 6.4 集成到 FuzzingEngine

`FuzzingEngine` 提供三种构造器：

1. **无覆盖率监控**：`new FuzzingEngine(workdir, duration, spec, executor, timeout)`
2. **有覆盖率监控**：`new FuzzingEngine(workdir, duration, spec, executor, timeout, coverageMonitor, corpusManager)`
3. **完整配置**（测试用）：`new FuzzingEngine(..., coverageMonitor, corpusManager, tickSleepMs)`

主循环集成：

```java
// 执行前清零
if (coverageMonitor != null) {
    coverageMonitor.beforeRun();
}

// 执行目标
RunResult rr = executor.run(cmd, stdinData, timeout, tcLogDir);

// 执行后收集覆盖率
Coverage coverage = coverageMonitor != null 
    ? coverageMonitor.afterRun(rr) 
    : Coverage.empty(rr);

// 处理结果
handleResult(payload, rr, coverage, tcId);
```

#### 6.5 语料库管理集成

`FileCorpusManager` 自动保存：

* **Interesting 输入**：`queue/id_{id},newbytes_{n}`
* **Crash**：`crashes/id_{id},exit_{code}`
* **Hang**：`hangs/id_{id},timeout_{ms}ms`

所有文件包含元数据后缀，便于后续分析。

---

```
edu.nju.fuzzing
├─ cli          # 启动入口、命令行参数解析
├─ core         # 模糊测试主循环（FuzzingEngine）
├─ exec         # 目标程序执行
├─ cov          # 覆盖率监控
├─ mutate       # 变异组件
├─ schedule     # 种子排序与能量调度
├─ queue        # 种子队列管理
├─ model        # 核心数据结构
├─ stats        # 统计与评估输出
└─ util         # 通用工具类
```

该结构支持明确分工，减少多人协作冲突。

---

### 6. 工作目录（Workdir）规划

后续运行时将使用统一的输出目录结构：

* `workdir/queue/`：产生新覆盖的输入
* `workdir/crashes/`：触发崩溃的输入
* `workdir/hangs/`：超时输入
* `workdir/stats/`：统计数据（CSV/JSON）
* `workdir/tmp/`：临时文件

Skeleton 阶段可只创建目录，不要求内容完整。
