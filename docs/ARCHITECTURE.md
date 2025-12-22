# NJU 模糊测试工具 —— 架构说明（Coverage-Guided Fuzzer v2）

本文档描述南京大学软件测试课程「模糊测试方向」代码大作业中，**模糊测试工具的最新架构设计**。

**版本：** v2.0 (2025-12-22)  
**状态：** ExecutorHarness 执行抽象层已完成

---

## 1. 项目当前状态

### 1.1 已完成的核心功能

✅ **执行抽象层 (ExecutorHarness)**
- 统一的执行环境接口（插桩/非插桩目标使用同一代码路径）
- `ExecInput` 参数封装（命令、stdin、超时、日志控制）
- `ExecResult` 统一结果类型（RunResult + CoverageEx）
- `InstrumentedExecutorHarness` 实现（自动管理覆盖监控生命周期）
- `NullCoverageMonitor` 无覆盖监控器（避免主循环分支）

✅ **执行器组件 (Executor)**
- `ProcessExecutor` 基于 Java ProcessBuilder 的实现
- ExecId 全局唯一生成（AtomicLong）
- STDIN/FILE 两种输入模式自动识别
- 三阶段超时控制（优雅终止 → 强制终止）
- 精确纳秒级计时（避免 currentTimeMillis 跳变）

✅ **覆盖率监控 (Coverage Monitor)**
- `ShmCoverageMonitor` 完整的 AFL++ SHM bitmap 监控
- `BitmapSource` 抽象（JNA SysV SHM 实现）
- 可插拔的覆盖率对比策略：
  - `SeenNonZeroStrategy` - 全局 virgin 判定（推荐）
  - `PrevBitmapStrategy` - 相对上次差异
  - `HashFilteredStrategy` - XXHash64 快速去重
  - `CompositeStrategy` - 组合多种策略
- `CoverageEx` 扩展覆盖模型：
  - Stability 枚举（UNKNOWN/STABLE/UNSTABLE）
  - execId 外部生成一致性
  - newEdgeCount（语义明确）
  - nonZeroBytes（bitmap 字节数 vs 边数）

✅ **语料库管理 (Corpus Manager)**
- `FileCorpusManager` 自动文件保存
- 三类输出：queue/crashes/hangs
- 元数据后缀（id、newbytes、exit code、timeout）
- 原始输入和元信息分离存储

✅ **统计与监控 (Stats & Monitoring)**
- `FuzzStats` 实时统计（exec/s、路径数、crash/hang 计数）
- `StatusPrinter` 终端状态显示
- CSV 格式统计导出
- `StatsTick` 快照数据模型

✅ **测试覆盖**
- **178 个测试全部通过**
- 单元测试：Executor, CoverageMonitor, Strategies, CorpusManager
- 集成测试：FuzzingEngine, ExecutorHarness
- 端到端测试：FuzzerMain smoke tests

### 1.2 待实现功能

🔜 **种子队列管理 (Queue Manager)**
- 从 seedDir 读取初始种子
- 种子轮转选择（queue cycle）
- favored 标记与优先级

🔜 **变异算子 (Mutator)**
- Deterministic stages（bitflip, arith, interest）
- Havoc mutations（随机变异组合）
- Splice（种子拼接）
- Dictionary-based mutations

🔜 **能量调度 (Power Scheduler)**
- AFL-style energy 计算
- 基于覆盖/执行时间的动态调整
- MutationBudget 生成

🔜 **全局覆盖数据库 (CoverageDB)**
- edgeFreq[] 全局频率统计
- topRated[] 每条边的最优种子
- favoredSet 维护

---

## 2. 架构核心设计

### 2.1 分层架构图

```
┌─────────────────────────────────────────────────┐
│           FuzzingEngine (主循环)                │
│  - 种子选择 → 能量调度 → 变异 → 执行 → 入队     │
└────────────────┬────────────────────────────────┘
                 │
        ┌────────▼─────────┐
        │ ExecutorHarness  │  ◄── 执行抽象层（本次重点）
        │  - start/close   │
        │  - execute()     │
        └────┬────────┬────┘
             │        │
    ┌────────▼──┐ ┌──▼───────────────┐
    │ Executor  │ │ CoverageMonitor  │
    │ (进程执行) │ │ (覆盖监控)        │
    └───────────┘ └──────────────────┘
         │                 │
         │         ┌───────┴──────────┐
         │         │                  │
         │  ┌──────▼──────┐  ┌────────▼─────────┐
         │  │ ShmMonitor  │  │ NullMonitor      │
         │  │ (插桩目标)   │  │ (非插桩目标)      │
         │  └─────────────┘  └──────────────────┘
         │
    ┌────▼───────────┐
    │ ProcessExecutor│
    │ - stdin/file   │
    │ - timeout      │
    │ - execId 生成  │
    └────────────────┘
```

### 2.2 数据流转

```
ExecInput (参数封装)
    │
    ├─ cmd: TargetCommand (argv, env, inputMode)
    ├─ stdinData: byte[]
    ├─ timeout: Duration
    └─ saveLogs: boolean
    │
    ▼
ExecutorHarness.execute()
    │
    ├─ beforeRun() ────────► 清零 bitmap
    ├─ executor.run() ─────► 执行目标
    └─ afterRun() ─────────► 收集覆盖
    │
    ▼
ExecResult (统一结果)
    │
    ├─ run: RunResult
    │   ├─ execId (全局唯一)
    │   ├─ execTimeNanos (精确计时)
    │   ├─ exitCode
    │   └─ termination (NORMAL/ERROR/TIMEOUT)
    │
    └─ coverage: CoverageEx
        ├─ hitEdges: Set<Integer>
        ├─ newEdgeCount: int
        ├─ stability: Stability (UNKNOWN/STABLE/UNSTABLE)
        └─ interesting: boolean
```

---

## 3. 核心组件详解

### 3.1 ExecutorHarness - 标准执行环境

**设计目标：** 统一插桩和非插桩目标的执行路径，避免主循环写 `if (monitor != null)` 分支。

**接口：**
```java
public interface ExecutorHarness extends AutoCloseable {
    void start() throws Exception;           // 初始化（attach SHM）
    ExecResult execute(ExecInput input) throws Exception;  // 执行一次
    void close();                            // 清理（detach SHM）
}
```

**实现：**
```java
public class InstrumentedExecutorHarness implements ExecutorHarness {
    private final Executor executor;
    private final CoverageMonitor coverageMonitor;
    private final int mapSize;
    
    @Override
    public ExecResult execute(ExecInput input) throws Exception {
        coverageMonitor.beforeRun();         // 1. 清零 bitmap
        RunResult run = executor.run(...);   // 2. 执行目标
        Coverage cov = coverageMonitor.afterRun(run);  // 3. 收集覆盖
        return new ExecResult(run, CoverageEx.fromBasic(cov));
    }
}
```

**使用模式：**

1. **插桩目标**（有覆盖监控）
   ```java
   CoverageMonitor monitor = ShmCoverageMonitor.fromEnvironment();
   ExecutorHarness harness = new InstrumentedExecutorHarness(executor, monitor);
   ```

2. **非插桩目标**（无覆盖监控）
   ```java
   NullCoverageMonitor nullMonitor = new NullCoverageMonitor(65536);
   ExecutorHarness harness = new InstrumentedExecutorHarness(executor, nullMonitor);
   ```

**关键设计决策：**
- 生命周期管理：`start()` attach SHM 一次，`close()` detach 一次
- 执行顺序固定：`beforeRun → run → afterRun` 不可变
- 使用反射调用 `ShmCoverageMonitor.start()`（保持接口简洁）
- `NullCoverageMonitor` 提供统一代码路径（避免空指针判断）

### 3.2 Executor - 底层进程执行器

**职责：** 只负责进程启动、输入输出、超时控制，不涉及覆盖监控。

**ProcessExecutor 关键特性：**

1. **ExecId 唯一生成**
   ```java
   private final AtomicLong execIdCounter = new AtomicLong(0);
   long execId = execIdCounter.incrementAndGet();
   ```

2. **输入模式自动识别**
   - **STDIN 模式**：写入 `stdinData` 到进程 stdin
   - **FILE 模式**：通过 `@@` 占位符传递文件路径
   - `CommandResolver` 自动检测并解析

3. **三阶段超时控制**
   ```java
   waitFor(timeoutMs)           // 正常等待
   → destroy() + waitFor(100ms) // 优雅终止
   → destroyForcibly() + waitFor(200ms) // 强制终止
   ```

4. **精确计时**
   ```java
   long startNs = System.nanoTime();
   // ... 执行 ...
   long execTimeNanos = System.nanoTime() - startNs;
   ```

5. **终止状态判定**
   - `TIMEOUT` - 超时
   - `ERROR` - 非零退出码（包括 crash）
   - `NORMAL` - 正常退出

### 3.3 CoverageMonitor - 覆盖率监控

**接口：**
```java
public interface CoverageMonitor extends AutoCloseable {
    void beforeRun();                        // 清零 bitmap
    Coverage afterRun(RunResult result);     // 收集覆盖
    void close();                            // 释放资源
}
```

**实现层次：**

1. **ShmCoverageMonitor** - 插桩目标监控
   - 通过 JNA 访问 AFL++ SHM
   - `start()` attach 共享内存
   - 使用可插拔的 `CoverageDiffStrategy`
   - 返回 `Coverage` 包含 interesting 判定

2. **NullCoverageMonitor** - 非插桩目标监控
   - `beforeRun()` 无操作
   - `afterRun()` 返回空覆盖
   - 保持接口一致性

**覆盖率对比策略：**

| 策略 | 用途 | 特点 |
|------|------|------|
| SeenNonZeroStrategy | 全局 virgin 判定 | 维护全局 seen bitset，推荐用于生产 |
| PrevBitmapStrategy | 相对差异 | 快速原型验证，无持久状态 |
| HashFilteredStrategy | 快速去重 | XXHash64 去重，减少重复判定 |
| CompositeStrategy | 组合策略 | 同时满足多个条件才判定 interesting |

### 3.4 CoverageEx - 扩展覆盖模型

**改进点：**

1. **Stability 枚举** 替代布尔值
   ```java
   public enum Stability {
       UNKNOWN,   // 未知（默认）
       STABLE,    // 多次执行覆盖一致
       UNSTABLE   // 多次执行覆盖不一致
   }
   ```

2. **ExecId 外部生成**
   - 移除内部全局计数器
   - 使用 `result.execId()`，确保与 RunResult 一致

3. **语义明确的字段名**
   - `newEdgeCount` 替代 `newBytes`（明确是"边数"）
   - `nonZeroBytes` 新增（bitmap 非零字节数）

4. **DiffResultEx 扩展**
   ```java
   public record DiffResultEx(
       int newEdges,      // 新边数
       int hitEdges,      // 命中边数
       int nonZeroBytes,  // bitmap 非零字节数（新增）
       long hash          // bitmap hash
   ) {}
   ```

### 3.5 CorpusManager - 语料库管理

**接口：**
```java
public interface CorpusManager {
    void saveCrash(Testcase tc, ExecResult er, Seed parent);
    void saveHang(Testcase tc, ExecResult er, Seed parent);
    void saveInteresting(Testcase tc, ExecResult er, Seed parent);
}
```

**FileCorpusManager 实现：**

- **queue/** - `id_{id},newbytes_{n}`
- **crashes/** - `id_{id},exit_{code}`
- **hangs/** - `id_{id},timeout_{ms}ms`

**元数据管理：**
- 文件名包含关键信息（便于分析）
- 原始输入和元信息分离
- 支持后续重放和调试

---

## 4. 主循环伪代码（最新版本）

```java
// ===== 初始化 =====
Executor executor = new ProcessExecutor();
CoverageMonitor monitor = ShmCoverageMonitor.fromEnvironment();
// 或非插桩：new NullCoverageMonitor(65536)

ExecutorHarness harness = new InstrumentedExecutorHarness(executor, monitor);

QueueManager queue = new QueueManager(initialSeeds);     // 待实现
CoverageDB covDb = new CoverageDB(mapSize);              // 待实现
PowerScheduler scheduler = new PowerScheduler(...);      // 待实现
Mutator mutator = new Mutator(...);                      // 待实现
CorpusManager corpus = new FileCorpusManager(workdir);
FuzzStats stats = new FuzzStats();

// ===== 启动覆盖环境（attach SHM 一次）=====
harness.start();

try {
    while (shouldContinue()) {
        
        // 1) 选择种子（待实现）
        Seed parent = queue.selectNext();
        
        // 2) 计算能量（待实现）
        MutationBudget budget = scheduler.computeBudget(parent, covDb, stats);
        
        // 3) 生成变异（待实现）
        for (Testcase tc : mutator.mutate(parent, budget)) {
            
            // 4) 构造输入
            ExecInput input = ExecInput.of(
                tc.cmd(), 
                tc.stdinData(), 
                timeout, 
                workDir
            );
            
            // 5) 执行（自动处理覆盖监控）
            ExecResult er = harness.execute(input);
            
            // 6) 处理异常情况
            if (er.isTimeout()) {
                corpus.saveHang(tc, er, parent);
                stats.onHang(er);
                continue;
            }
            if (er.isCrash()) {
                corpus.saveCrash(tc, er, parent);
                stats.onCrash(er);
                continue;
            }
            
            // 7) 更新全局覆盖（待实现）
            CoverageUpdate upd = covDb.update(parent.id(), er.coverage());
            
            // 8) 保存有趣的输入
            if (upd.interesting()) {
                Seed child = corpus.saveInteresting(tc, er, parent);
                queue.add(child);
                stats.onNewPath(child, upd);
            }
            
            // 9) 更新统计
            stats.onExec(er);
        }
    }
} finally {
    // ===== 清理资源（detach SHM 一次）=====
    harness.close();
}
```

---

## 5. 关键设计约定（边界契约）

### 5.1 ExecId 一致性

**原则：** ExecId 贯穿整个执行链路，保持唯一性和一致性。

```
ProcessExecutor.execIdCounter.incrementAndGet()
    ↓
RunResult.execId
    ↓
CoverageEx.execId (from result.execId())
    ↓
Testcase.execId (如果需要)
```

**禁止：**
- ❌ 在 CoverageEx 内部生成 execId
- ❌ 在多个地方使用不同的计数器

### 5.2 ExecutorHarness 职责边界

**ExecutorHarness 负责：**
- ✅ 覆盖监控生命周期（start/close）
- ✅ 执行顺序编排（beforeRun → run → afterRun）
- ✅ 返回统一结果（ExecResult）

**ExecutorHarness 不负责：**
- ❌ 决定是否入队（由 CoverageDB 决定）
- ❌ 保存文件（由 CorpusManager 决定）
- ❌ 变异输入（由 Mutator 决定）

### 5.3 无覆盖模式统一代码路径

**原则：** 主循环不应区分插桩/非插桩模式。

```java
// ✅ 正确：统一代码路径
ExecutorHarness harness = createHarness();  // SHM 或 Null
ExecResult result = harness.execute(input);

// ❌ 错误：分支逻辑
if (monitor != null) {
    monitor.beforeRun();
    run = executor.run(...);
    coverage = monitor.afterRun(run);
} else {
    run = executor.run(...);
    coverage = Coverage.empty(run);
}
```

### 5.4 CoverageDB 唯一性

**原则：** CoverageDB 是 favored/topRated 的唯一来源。

- ✅ CoverageDB 维护全局覆盖状态
- ✅ CoverageDB 决定最终的 interesting 判定
- ❌ 不在策略层或监控器里维护全局状态

### 5.5 CorpusManager 唯一写盘入口

**原则：** 所有文件写入通过 CorpusManager 统一管理。

- ✅ queue/crashes/hangs 由 CorpusManager 写入
- ✅ 元数据命名规则统一
- ❌ 不在多处直接写文件（避免不一致）

---

## 6. 包结构

```
edu.nju.fuzzing
├─ cli          # 命令行入口（FuzzerMain）
├─ core         # 核心引擎
│   ├─ FuzzingEngine.java          # 主循环
│   ├─ ExecutorHarness.java        # 执行环境接口 ✅
│   └─ InstrumentedExecutorHarness.java  # 实现 ✅
├─ exec         # 执行器
│   ├─ Executor.java               # 执行器接口 ✅
│   ├─ ProcessExecutor.java        # 实现 ✅
│   ├─ TargetCommand.java          # 命令封装 ✅
│   └─ CommandResolver.java        # 命令解析 ✅
├─ cov          # 覆盖率监控
│   ├─ CoverageMonitor.java        # 监控接口 ✅
│   ├─ ShmCoverageMonitor.java     # SHM 实现 ✅
│   ├─ NullCoverageMonitor.java    # 空实现 ✅
│   ├─ BitmapSource.java           # SHM 抽象 ✅
│   ├─ SysVShmBitmapSource.java    # JNA 实现 ✅
│   └─ strategy/                   # 覆盖率对比策略 ✅
│       ├─ SeenNonZeroStrategy
│       ├─ PrevBitmapStrategy
│       ├─ HashFilteredStrategy
│       └─ CompositeStrategy
├─ corpus       # 语料库管理
│   ├─ CorpusManager.java          # 接口 ✅
│   └─ FileCorpusManager.java      # 实现 ✅
├─ stats        # 统计监控
│   ├─ FuzzStats.java              # 统计 ✅
│   ├─ StatusPrinter.java          # 状态显示 ✅
│   └─ StatsTick.java              # 快照 ✅
├─ model        # 数据模型
│   ├─ TargetSpec.java             # 目标规格 ✅
│   ├─ RunResult.java              # 执行结果 ✅
│   ├─ Coverage.java               # 基础覆盖 ✅
│   ├─ CoverageEx.java             # 扩展覆盖 ✅
│   ├─ ExecInput.java              # 执行输入 ✅
│   └─ ExecResult.java             # 执行结果 ✅
├─ mutate       # 变异组件（待实现）
├─ schedule     # 调度组件（待实现）
├─ queue        # 队列管理（待实现）
└─ util         # 工具类
```

---

## 7. 测试策略

### 7.1 当前测试覆盖

**总计：178 tests passing**

- **Executor 层** (3 tests)
  - ProcessExecutor: 正常执行、超时、崩溃

- **CoverageMonitor 层** (14 tests)
  - ShmCoverageMonitor: attach/detach、beforeRun/afterRun、策略集成

- **覆盖率策略** (47 tests)
  - SeenNonZeroStrategy (9)
  - PrevBitmapStrategy (13)
  - HashFilteredStrategy (11)
  - CompositeStrategy (14)

- **ExecutorHarness 层** (4 tests)
  - InstrumentedExecutorHarness: 生命周期、执行流程
  - NullCoverageMonitor: 空覆盖返回
  - ExecInput/ExecResult: 工厂方法、便捷方法

- **CorpusManager** (15 tests)
  - 文件保存、元数据命名、目录创建

- **Stats** (25 tests)
  - FuzzStats: exec/s 计算、路径/crash/hang 计数
  - StatusPrinter: 终端显示

- **集成测试** (10 tests)
  - FuzzingEngine: 有/无覆盖监控、主循环流程
  - FuzzerMain: 端到端 smoke tests

### 7.2 测试原则

1. **单元测试优先**
   - 每个组件独立测试
   - Mock 外部依赖

2. **集成测试验证边界**
   - ExecutorHarness + Executor + CoverageMonitor
   - FuzzingEngine + 所有子组件

3. **端到端测试验证完整流程**
   - FuzzerMain 命令行测试
   - 真实插桩目标执行

---

## 8. 下一步开发计划

### 8.1 Phase 1: 种子队列管理（优先级：高）

**目标：** 实现 AFL-style 种子队列

- [ ] `QueueManager` 接口和实现
- [ ] 从 seedDir 加载初始种子
- [ ] Queue cycle 机制
- [ ] Seed 数据模型（id, parentId, depth, execTime 等）

### 8.2 Phase 2: 变异算子（优先级：高）

**目标：** 实现基础变异能力

- [ ] `Mutator` 接口
- [ ] Deterministic stages（bitflip, arith, interest）
- [ ] Havoc mutations（随机变异）
- [ ] Testcase 数据模型

### 8.3 Phase 3: 能量调度（优先级：中）

**目标：** 动态调整 fuzz 预算

- [ ] `PowerScheduler` 实现
- [ ] AFL-style energy 计算
- [ ] MutationBudget 模型

### 8.4 Phase 4: 全局覆盖数据库（优先级：中）

**目标：** 维护全局覆盖状态

- [ ] `CoverageDB` 实现
- [ ] edgeFreq[] 频率统计
- [ ] topRated[] 最优种子
- [ ] favoredSet 维护

---

## 9. 文档索引

- **ARCHITECTURE.md** - 本文档（架构总览）
- **General.md** - 组件整合指南与主循环伪代码
- **ExecutorHarness/Executor.md** - 执行器组件详细设计
- **ExecutorHarness/ExecutorHarness.md** - ExecutorHarness 详细设计
- **CoverageMonitor.md** - 覆盖率监控详细设计
- **CoverageEx.md** - 扩展覆盖模型（重构日志）

---

## 10. 贡献指南

### 10.1 开发流程

1. **功能开发**
   - 先写接口和数据模型
   - 实现核心逻辑
   - 编写单元测试（覆盖率 > 80%）

2. **集成**
   - 更新主循环（FuzzingEngine）
   - 编写集成测试
   - 更新文档

3. **提交**
   - 遵循 Conventional Commits 规范
   - 确保所有测试通过
   - 更新 ARCHITECTURE.md（如有架构变更）

### 10.2 代码规范

- **命名约定**：驼峰命名，见名知意
- **注释规范**：公开接口必须有 Javadoc
- **测试规范**：每个 public 方法至少一个测试
- **提交规范**：`feat/fix/refactor/docs/test/chore`

---

**最后更新：** 2025-12-22  
**维护者：** NJU Fuzzing Team  
**版本：** v2.0 (ExecutorHarness Complete)