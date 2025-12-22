# ExecutorHarness - 标准执行环境

## 概述

`ExecutorHarness` 是一个高层抽象，将底层的 `Executor`（进程执行）与 `CoverageMonitor`（覆盖监控）整合为统一的执行环境。它负责正确编排覆盖监控的生命周期（清零 bitmap → 执行 → 收集覆盖），并提供一致的 API，无论是否启用覆盖监控。

---

## 核心设计

### 为什么需要 ExecutorHarness？

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

## 接口定义

### `ExecutorHarness`

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

## 实现类

### `InstrumentedExecutorHarness`

位置：`edu.nju.fuzzing.core.InstrumentedExecutorHarness`

**描述：** 标准实现，组合 `Executor` + `CoverageMonitor`

#### 构造函数

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

#### 生命周期管理

##### 1. `start()` - 初始化

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

##### 2. `execute()` - 执行

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

##### 3. `close()` - 清理

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

## 辅助类型

### `ExecInput` - 执行输入

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

### `ExecResult` - 执行结果

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

### `NullCoverageMonitor` - 空覆盖监控器

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

## 使用示例

### 完整示例：插桩目标

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

### 简化示例：非插桩目标

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

### 主循环集成

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

## 设计要点

### 1. 统一代码路径

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

### 2. 覆盖监控生命周期

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

### 3. ExecId 一致性

- `ProcessExecutor` 生成 `execId`
- `RunResult.execId` 传递到 `CoverageEx.execId`
- 整个执行链路使用同一个 `execId`

### 4. 异常处理策略

- `execute()` 抛出 `Exception`，由主循环决定如何处理
- `close()` 吞掉异常并打印警告，避免掩盖主逻辑错误
- 超时/崩溃通过 `ExecResult` 的便捷方法判断，不抛异常

### 5. 日志保存策略

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

## 测试策略

### 单元测试

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

### 集成测试

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

## 与其他组件的关系

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

## 未来扩展

### 1. 并行执行

```java
public interface ParallelExecutorHarness extends ExecutorHarness {
    List<ExecResult> executeBatch(List<ExecInput> inputs) throws Exception;
}
```

### 2. 远程执行

```java
public class RemoteExecutorHarness implements ExecutorHarness {
    // 通过 RPC 调用远程机器的执行器
}
```

### 3. 容器化执行

```java
public class DockerExecutorHarness implements ExecutorHarness {
    // 在 Docker 容器中执行目标
}
```

---

## 参考

- [Executor.md](Executor.md) - 执行器组件文档
- [General.md](../General.md) - 主循环设计
- [CoverageMonitor.md](../CoverageMonitor.md) - 覆盖监控文档
- [CoverageEx.md](../CoverageEx.md) - 扩展覆盖信息文档
