## NJU 模糊测试工具 —— 初始架构说明（Skeleton 阶段）

本文档描述南京大学软件测试课程「模糊测试方向」代码大作业中，**模糊测试工具的初始架构设计**。
当前阶段为 **可运行的框架模板（Skeleton）**：系统的模块划分、接口设计和数据通路已经确定，但具体算法和平台相关实现（如覆盖率 SHM 读取）暂以占位实现为主，后续将逐步补全。

---

### 1. 当前阶段目标（Skeleton 阶段）

本阶段的目标是：

* 建立一个**可运行的 Java 项目**
* 明确并固定整体架构与模块边界，便于 4 人小组并行开发
* 定义模糊测试主流程所需的**核心数据模型**
* 为作业要求的**六个核心组件**提供清晰的接口
* 保证数据通路完整：即使部分组件为 stub，实现上也能跑完整个流程
* 为后续实现 AFL++ 风格模糊测试打好工程基础

**非目标（当前阶段不要求）：**

* 不要求真实覆盖率反馈（SHM bitmap 先占位）
* 不要求完整 AFL++ 变异算子与调度策略
* 不要求 24h 实验或覆盖率曲线输出

---

### 2. 系统整体工作流程

模糊测试工具围绕一个持续运行的 **Fuzzing Loop（模糊测试主循环）** 工作：

1. 从种子队列中选择一个 Seed
2. 根据调度策略计算该 Seed 的能量（执行预算）
3. 对 Seed 进行变异，生成多个 Testcase
4. 执行目标程序（fuzz target）
5. 监控执行结果（退出状态、超时、覆盖率反馈）
6. 判断 Testcase 是否有价值（新覆盖 / crash / hang）
7. 保存测试用例并更新队列
8. 写入统计信息
9. 重复上述过程直到达到时间或轮次上限

在 Skeleton 阶段，上述流程已经打通，但部分步骤（如覆盖率判断）采用占位实现。

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

#### 3.3 执行结果监控组件（Coverage Monitor）

**作用：**

* 在真实实现中读取 AFL++ 覆盖率共享内存（bitmap）
* 判断是否出现新的覆盖路径
* 识别 crash / hang 等特殊情况

**Skeleton 阶段说明：**

* 覆盖率信息为占位数据
* 接口已固定，后续可直接替换实现

**接口位置：**

```
edu.nju.fuzzing.cov.CoverageMonitor
```

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

* `Seed`：队列中的输入及其元信息
* `Testcase`：由 Seed 变异得到的候选输入
* `RunResult`：一次目标程序执行的结果
* `Coverage`：覆盖率反馈与“是否有价值”的标志
* `Decision`：是否保存到 queue / crashes / hangs
* `StatsTick`：一次统计快照（用于评估与画图）

这些模型构成了**数据通路的稳定契约**，后续实现不应破坏其语义。

---

### 5. 包结构说明

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
