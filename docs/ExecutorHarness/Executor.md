# 执行器组件（Executor）

## 概述

执行器组件负责底层的进程启动、输入输出重定向、超时控制和执行结果收集。它提供了一个干净的抽象层，将进程管理的复杂性与上层的覆盖监控和模糊测试逻辑分离。

---

## 核心接口

### `Executor`

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

## 实现类

### `ProcessExecutor`

位置：`edu.nju.fuzzing.exec.ProcessExecutor`

**描述：** 基于 Java `ProcessBuilder` 的默认实现，支持 STDIN 和 FILE 两种输入模式。

#### 核心功能

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

    - 默认 stdout/stderr 会重定向到文件：`stdout_{execId}.log`, `stderr_{execId}.log`
    - 文件名包含 execId，避免并发冲突
    - 若长跑产生大量小文件，可通过 JVM 系统属性关闭落盘：`-Dnju.fuzzer.execLogs=none`（stdout/stderr 将丢弃）

#### 返回值：`RunResult`

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

## 辅助类型

### `TargetCommand`

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

### `InputMode`

```java
public enum InputMode {
    STDIN,  // stdin 输入模式
    FILE    // 文件输入模式（通过 @@ 占位符）
}
```

### `CommandResolver`

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

## 使用示例

### 基础使用

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

### STDIN 模式

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

## 设计要点

## Crash 判定：退出码与 crash 的关系

`RunResult` 的 `termination` 只有三类：

- `NORMAL`：退出码为 0
- `ERROR`：退出码非 0（但不等价于 crash）
- `TIMEOUT`：超时（上层统计为 hang）

项目中 crash 的判定由 `CrashOracle` 统一处理（位置：`edu.nju.fuzzing.exec.CrashOracle`），核心规则是：

- **默认仅将“signal-like”异常退出视作 crash**：`exitCode > 128`（shell 习惯编码 `exitCode = 128 + signal`，例如 139=SIGSEGV）
- 默认忽略 `130/143`（SIGINT/SIGTERM），避免手动中断污染 crash 统计
- 可通过 CLI 参数 `--nonCrashExitCodes` 扩展“非 crash 退出码白名单”（适配目标程序把非 0 当作“输入拒绝”的情况）


### 1. ExecId 一致性

- `ProcessExecutor` 是 `execId` 的**唯一生成点**
- `RunResult.execId` 会传递到 `CoverageEx.execId`
- 避免在多个地方生成 ID 导致不一致

### 2. 输入模式透明

- 上层通过 `CommandResolver` 自动识别输入模式
- `Executor` 根据 `cmd.inputMode()` 处理 stdin/file
- 主循环不需要区分 STDIN/FILE

### 3. 异常处理策略

- **Broken pipe**：目标提前退出时忽略 stdin 写入失败
- **Timeout**：三阶段终止，避免僵尸进程
- **其他异常**：向上抛出，由 `ExecutorHarness` 或主循环处理

### 4. 性能优化

- 使用 `AtomicLong` 避免同步开销
- 进程启动/终止的 grace period 设置合理
- 日志文件按需保留（通过 `saveLogs` 控制）

---

## 与 ExecutorHarness 的关系

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

## 测试要点

1. **正常执行**：验证 exitCode、execTime、termination
2. **超时处理**：验证 `timedOut` 标志和强制终止
3. **崩溃处理**：验证非零退出码的 ERROR 状态
4. **STDIN 模式**：验证数据正确写入
5. **FILE 模式**：验证 `@@` 正确替换
6. **并发执行**：验证 execId 唯一性
7. **Broken pipe**：验证目标提前退出时不抛异常

---

## 参考

- [General.md](../General.md) - 主循环设计
- [ExecutorHarness.md](ExecutorHarness.md) - 执行器集成文档
- [RunResult.java](../../src/main/java/edu/nju/fuzzing/model/RunResult.java) - 执行结果定义
