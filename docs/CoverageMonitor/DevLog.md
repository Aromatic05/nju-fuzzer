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
- [FuzzingEngine.java](../src/main/java/edu/nju/fuzzing/core/FuzzingEngine.java) - 主循环，集成所有组件
- [ShmCoverageMonitor.java](../src/main/java/edu/nju/fuzzing/cov/ShmCoverageMonitor.java) - 覆盖率监控
- [FileCorpusManager.java](../src/main/java/edu/nju/fuzzing/corpus/FileCorpusManager.java) - Corpus 管理
- [FuzzStats.java](../src/main/java/edu/nju/fuzzing/stats/FuzzStats.java) - 统计追踪
- [StatusPrinter.java](../src/main/java/edu/nju/fuzzing/stats/StatusPrinter.java) - 状态输出

**测试**:
- [FuzzingEngineIntegrationTest.java](../src/test/java/edu/nju/fuzzing/core/FuzzingEngineIntegrationTest.java) - 集成测试
- [CorpusIntegrationTest.java](../src/test/java/edu/nju/fuzzing/corpus/CorpusIntegrationTest.java) - Corpus 集成测试
