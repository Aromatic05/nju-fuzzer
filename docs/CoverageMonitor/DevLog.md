## CoverageMonitor Integration Status

### ✅ 已完成（Iterations 1-3）

#### Iteration 1: AFL++ SHM 覆盖率监控
- **BitmapSource**: 抽象接口，支持不同的 SHM 实现
- **SysVShmBitmapSource**: JNA 实现，读取 System V 共享内存
- **SeenNonZeroStrategy**: 基于"全局 seen"的覆盖率差分策略
- **ShmCoverageMonitor**: 主监控器，管理 bitmap 读取和策略调用
- **测试验证**: 使用真实 AFL++ 插装二进制（lua, mjs）测试通过

#### Iteration 2: 增强覆盖率策略
- **HashFilteredStrategy**: FNV-1a hash 过滤，减少重复计算
- **PrevBitmapStrategy**: 与上一次 bitmap 对比
- **CompositeStrategy**: 组合多个策略（ANY/ALL/FIRST 模式）
- **CoverageDiffStrategy**: 增强接口，支持工厂方法和组合
- **测试对比**: SeenNonZero vs PrevBitmap 降噪效果验证

#### Iteration 3: Corpus 管理与统计
- **FileCorpusManager**: 文件系统实现，保存 queue/crashes/hangs
- **FuzzStats**: 线程安全的统计追踪（execs, paths, crashes, hangs, 时间）
- **StatusPrinter**: 周期性状态输出，支持事件通知
- **StatsTick**: 增强统计快照，包含 totalPaths 和 lastNewPathSecAgo

### 🚀 集成到主流程（本次更新）

#### FuzzingEngine 增强
- **构造函数重载**: 
  - 无覆盖版本：用于非插装目标
  - 有覆盖版本：集成 CoverageMonitor + CorpusManager
- **生命周期管理**:
  - 启动：ShmCoverageMonitor.start() 初始化监控
  - 循环：beforeRun() → execute → afterRun()
  - 清理：AutoCloseable.close() 释放资源
- **结果处理**:
  - Crash: 保存到 crashes/，记录统计
  - Hang: 保存到 hangs/，记录统计
  - Interesting coverage: 保存到 queue/，记录新路径
- **状态输出**: StatusPrinter 实时显示进度（exec/s, paths, crashes, hangs）

#### 集成测试
- `FuzzingEngineIntegrationTest`: 3 个场景测试
  - 无覆盖监控模式（/bin/cat）
  - 有覆盖监控模式（AFL++ instrumented target）
  - Crash 检测验证
- 使用 MockBitmapSource 进行单元测试，无需真实 SHM

### 📊 当前状态

**测试统计**: 144 tests passing (新增 3 个集成测试)

**满足项目要求**:
✅ **插装组件**: 使用 afl-cc（脚本构建）  
✅ **测试执行组件**: ProcessExecutor 完整实现  
✅ **执行结果监控组件**: ShmCoverageMonitor + 多策略支持  
✅ **覆盖率反馈**: AFL++ SHM bitmap 读取与判定  
✅ **Corpus 管理**: FileCorpusManager 保存 interesting/crash/hang  
✅ **统计与日志**: FuzzStats + StatusPrinter + StatsWriter

**已集成功能**:
- 从环境变量读取 `__AFL_SHM_ID` 和 `AFL_MAP_SIZE`
- 执行前清零 bitmap，执行后读取覆盖率
- 判定 new coverage 并入队
- 识别并保存 crash/hang
- 实时统计输出（exec/s, paths, crashes, hangs）
- CSV 格式统计写入

### 📝 使用示例

```java
// 创建 corpus 管理器
CorpusManager corpusManager = new FileCorpusManager(Paths.get("workdir"));

// 创建覆盖率监控（从环境变量自动配置）
ShmCoverageMonitor coverageMonitor = ShmCoverageMonitor.fromEnvironment();

// 创建 Engine 并运行
FuzzingEngine engine = new FuzzingEngine(
    workdir,
    duration,
    targetSpec,
    executor,
    timeout,
    coverageMonitor,
    corpusManager
);

engine.run(); // 自动处理覆盖率监控、corpus 保存、统计输出
```

### 🔗 相关文件

**核心组件**:
- [FuzzingEngine.java](../../src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java) - 主循环，集成所有组件
- [ShmCoverageMonitor.java](../../src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitor.java) - 覆盖率监控
- [FileCorpusManager.java](../../src/main/java/edu/nju/fuzzing/corpus/FileCorpusManager.java) - Corpus 管理
- [FuzzStats.java](../../src/main/java/edu/nju/fuzzing/stats/FuzzStats.java) - 统计追踪
- [StatusPrinter.java](../../src/main/java/edu/nju/fuzzing/stats/StatusPrinter.java) - 状态输出

**测试**:
- [FuzzingEngineIntegrationTest.java](../../src/test/java/edu/nju/fuzzing/core/FuzzingEngineIntegrationTest.java) - 集成测试
- [CorpusIntegrationTest.java](../../src/test/java/edu/nju/fuzzing/corpus/CorpusIntegrationTest.java) - Corpus 集成测试

---

## ✅ Iteration 4: 扩展覆盖监控支持种子调度（2025-12-22）

### 背景与动机

在完成基础覆盖监控（Iterations 1-3）和主流程集成后，评估了完整的模糊测试数据通路，识别了需要支持种子调度的缺口。

**种子调度的覆盖率需求**：
1. **边索引（Edge Indices）**: 需要知道"哪些边"被触发，而非仅计数
2. **全局覆盖数据库（Coverage DB）**: 维护 `edgeFreq[i]`, `topRated[i]`, `favored` 集合
3. **稀有度评分（Rarity Score）**: 计算 `Σ(1/freq)` over hitEdges
4. **Top-Rated Seeds**: 对每条边，保存触发它的"最优" seed
5. **Favored Seeds**: 至少 top-rated 一条边的 seeds，优先调度

### 实现的组件

#### 基础工具层
- **XxHash64.java** (164 lines): 快速哈希函数，用于 bitmap 去重
- **EdgeSet.java** (276 lines): 稀疏边索引集合，支持集合操作（union/intersect/subtract）

#### 策略扩展层
- **DiffResultEx.java**: 扩展 diff 结果，包含 EdgeSet (newEdges, hitEdges)
- **CoverageDiffStrategyEx.java** (226 lines): 扩展策略接口，返回边级别详情
  - `SeenNonZeroStrategyEx`: 原生扩展实现
  - `WrappedStrategyEx`: 包装现有策略（向后兼容）

#### 全局数据库层
- **CoverageDB.java** (385 lines): 全局覆盖数据库
  - 维护 edgeFreq, topRated, favored 集合
  - 支持 4 种 TopRated 标准（SMALLEST_INPUT, MOST_RECENT, FEWEST_EDGES, FASTEST_EXEC）
  - 提供稀有度评分、冗余检测接口
  - 线程安全设计

#### 监控扩展层
- **CoverageEx.java** (122 lines): 扩展覆盖模型，包含 hitEdges, newEdges, execTimeNanos, stable
- **CoverageMonitorEx.java** (35 lines): 扩展监控接口
- **ShmCoverageMonitorEx.java** (279 lines): 扩展监控实现，集成 CoverageDB

### 测试覆盖

新增 30 个测试，总计 **174 tests passing**：
- **EdgeSetTest**: 12 tests（bitmap 提取、集合操作、成员测试）
- **CoverageDBTest**: 11 tests（新边检测、频率追踪、top-rated 选择、favored 管理）
- **XxHash64Test**: 7 tests（一致性、碰撞、大数据处理）

### 向后兼容性

✅ 保留现有接口：`CoverageMonitor`, `CoverageDiffStrategy`, `Coverage`  
✅ 扩展接口继承基础接口：`CoverageMonitorEx extends CoverageMonitor`  
✅ 提供转换方法：`CoverageEx.toBasic()`, `CoverageEx.fromBasic()`

### Git Commit 组织

拆分为 6 个逻辑 commit：
1. **feat(cov): add XxHash64** - 基础哈希工具
2. **feat(cov): add EdgeSet** - 稀疏边集合
3. **feat(cov): add extended diff result** - 扩展策略接口
4. **feat(cov): add CoverageDB** - 全局数据库
5. **feat(model): add CoverageEx** - 扩展模型
6. **feat(cov): add CoverageMonitorEx** - 扩展监控器

### 新增文件

**源文件**（8 个）：
- XxHash64.java, EdgeSet.java
- DiffResultEx.java, CoverageDiffStrategyEx.java
- CoverageDB.java, CoverageEx.java
- CoverageMonitorEx.java, ShmCoverageMonitorEx.java

**测试文件**（3 个）：
- EdgeSetTest.java, CoverageDBTest.java, XxHash64Test.java

---

## 📊 当前状态总结

**测试统计**: 174 tests passing (144 基础 + 30 扩展)

**已完成的核心组件**:
✅ AFL++ 插装、执行器、覆盖率监控（基础+扩展）  
✅ 全局覆盖数据库、边级别详情、Corpus 管理  
✅ 统计与日志、FuzzingEngine 集成

**待实现的组件**:
🔜 SeedQueue、Mutator、PowerScheduler、Scheduler

**最后更新**: 2025年12月22日  
**版本**: v1.1 - Extended Coverage Monitoring for Seed Scheduling

---

## ✅ Iteration 5: 长跑 IO 与统计落盘优化（2025-12-31）

虽然本次改动主要位于 Engine/Executor/Stats，但它直接改善了 CoverageMonitor（SHM fuzzing）长跑体验：

- stdout/stderr 默认不再全量落盘，避免 `workdir/tmp` 小文件爆炸
  - 默认策略：`-Dnju.fuzzer.execLogs=interesting`
  - 仅当输入被确认“晋升为 interesting 并入队”时，进行一次 best-effort 二次执行抓 stdout/stderr
  - 且仅在输出非空时写 `tmp/exec-logs/stdout_*.log` / `stderr_*.log`
  - `-Dnju.fuzzer.execLogsMaxBytes=<bytes>` 限制捕获上限（默认 1MB）

- FILE 模式复用 `.cur_input` 的同时，默认强制 tmpfs（/dev/shm）避免磁盘落盘
  - `-Dnju.fuzzer.requireTmpfsInputs=true`（默认 true）
  - tmpfs 不可用时 fail-fast（不再回退到 workdir/tmp）

- stats/curve CSV 写入改为批量 flush，降低 IO
  - `-Dnju.fuzzer.statsFlushEvery=<N>`（默认 100；<=0 表示仅 close 时 flush）

相关模块文档：

- `docs/Engine/FuzzingEngine.md`
- `docs/stats/stats.md`
- `docs/ExecutorHarness/Executor.md`
