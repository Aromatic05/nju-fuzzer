好的，这是一份针对你的 `stats` 模块的详细模块文档。这份文档遵循软件工程中常见的模块文档规范，涵盖了目的、组件、数据契约、核心功能、使用方法、测试策略等，方便团队协作和未来维护。

---

## 模块文档：`edu.nju.fuzzing.stats`

### 1. 模块概览

`edu.nju.fuzzing.stats` 模块负责模糊测试会话的实时统计、控制台输出和日志持久化。它是**评估组件（Evaluation Component）**的基础，旨在提供关键运行指标的可见性，并生成可用于离线分析和可视化的数据。

### 2. 目的与职责

*   **数据收集**：实时聚合模糊测试过程中的执行次数、覆盖率、崩溃、超时等关键指标。
*   **状态展示**：周期性地在控制台打印 Fuzzer 的当前运行状态，提供操作者对模糊测试进度的直观了解。
*   **日志持久化**：将Fuzzer的运行统计数据按指定格式（CSV）写入磁盘，便于后续进行复杂的数据分析和图表绘制。
*   **解耦设计**：将数据模型、统计逻辑、控制台打印和文件写入职责分离，提高模块的灵活性和可维护性。

### 3. 组件构成

本模块包含以下三个核心组件：

#### 3.1 `StatsTick` (数据契约)

*   **类型**：`record` (Java 16+)
*   **职责**：定义了在特定时间点捕获的模糊测试统计数据的**不可变快照**。它作为 `FuzzStats` 和 `StatusPrinter` / `StatsWriter` 之间的数据传输对象。
*   **关键字段**：
    *   `targetName` (String)：当前模糊目标名称。
    *   `elapsedSec` (long)：模糊测试开始以来的秒数（相对时间）。
    *   `execsTotal` (long)：累计执行的测试用例总数。
    *   `coveredEdges` (int)：当前已发现的唯一覆盖边数。
    *   `execsPerSec` (double)：平均执行速度（次/秒）。
    *   `queueSize` (int)：当前种子队列中的种子数量。
    *   `crashes` (int)：累计发现的崩溃数量。
    *   `hangs` (int)：累计发现的超时（挂起）数量。
    *   `lastNewPathSecAgo` (long)：距离上次发现新路径的秒数。
*   **核心方法**：
    *   `toStatusLine()`：生成一个格式化的单行字符串，用于控制台输出。

#### 3.2 `FuzzStats` (统计核心逻辑)

*   **类型**：`class`
*   **职责**：线程安全地聚合和计算模糊测试的各项实时指标。它是**所有统计数据的单一来源**。
*   **内部状态**：使用 `AtomicLong` 和 `AtomicInteger` 保证并发更新的安全性。
    *   `execsTotal`：总执行次数。
    *   `coveredEdges`：已覆盖边数。
    *   `crashes`：崩溃计数。
    *   `hangs`：超时计数。
    *   `startTime`, `lastExecAt`, `lastNewPathAt`：时间戳用于计算持续时间和速率。
*   **核心方法**：
    *   `recordExec()`：记录一次执行。
    *   `recordCrash()`, `recordHang()`, `recordNewPath()`：分别记录崩溃、超时和新路径事件。
    *   `updateCoveredEdges(int count)`：更新当前总覆盖边数（通常由 `CoverageDB` 提供）。
    *   `getExecsPerSec()`：计算并返回全局平均执行速度。
    *   `getRecentExecsPerSec()`：计算并返回最近一段时间内的执行速度（用于更实时的反馈）。
    *   `toStatsTick(int queueSize)`：生成当前统计状态的 `StatsTick` 快照。

#### 3.3 `StatusPrinter` (控制台输出)

*   **类型**：`class` (实现 `AutoCloseable`)
*   **职责**：以固定时间间隔向控制台（或其他 `PrintStream`）打印格式化的 Fuzzer 状态信息。它在后台线程中运行，不阻塞主模糊测试循环。
*   **内部机制**：使用 `ScheduledExecutorService` 创建一个后台守护线程，定时从 `FuzzStats` 获取 `StatsTick` 快照并打印。
*   **核心方法**：
    *   `start()`：启动后台打印线程。
    *   `stop()` / `close()`：停止后台打印线程并释放资源。
    *   `printNow()`：立即打印当前状态。
    *   `printEvent(String event)`：打印通用事件消息。
    *   `printNewPath(...)`, `printCrash(...)`, `printHang(...)`：打印特定事件的快捷方法。

#### 3.4 `StatsWriter` (日志文件写入)

*   **类型**：`class` (实现 `AutoCloseable`)
*   **职责**：将 `StatsTick` 快照持久化到 CSV 文件中，作为历史记录。确保文件格式符合约定，并支持追加写入。
*   **内部机制**：使用 `BufferedWriter` 以追加模式写入 CSV 文件。在文件不存在时，自动写入 CSV 头。
*   **核心方法**：
    *   `tick(StatsTick t)`：将一个 `StatsTick` 写入 CSV 文件，并立即刷新缓冲区。
    *   `close()`：关闭文件写入流。

### 4. 模块间的协作与数据流

`stats` 模块与其他核心模块的协作方式如下：

1.  **`FuzzingEngine` -> `FuzzStats`**：
    *   `FuzzingEngine` 在每次执行、发现新路径、崩溃、超时时调用 `FuzzStats` 相应的方法 (`recordExec()`, `recordNewPath()`, `recordCrash()`, `recordHang()`) 来更新统计数据。
    *   当 `CoverageDB` 更新了全局覆盖边数后，`FuzzingEngine` 调用 `FuzzStats.updateCoveredEdges()` 同步最新覆盖率。
2.  **`FuzzingEngine` -> `StatusPrinter` / `StatsWriter`**：
    *   `FuzzingEngine` 在启动时初始化并启动 `StatusPrinter` 和 `StatsWriter`。
    *   `StatusPrinter` 在后台定时从 `FuzzStats` 获取 `StatsTick` 并打印。
    *   `StatsWriter` 在 `FuzzingEngine` 的主循环中，以周期性的方式（例如每秒）被调用 `tick(fuzzStats.toStatsTick(queueSize))`，将快照写入 CSV。
3.  **`CorpusManager` -> `FuzzStats` (间接)**：
    *   `CorpusManager` 负责管理磁盘上的种子队列。`FuzzingEngine` 调用 `CorpusManager.stats().queueSize()` 获取队列大小，然后传递给 `FuzzStats.toStatsTick()` 以包含在 `StatsTick` 中。

### 5. 错误处理与线程安全

*   `FuzzStats` 使用 `java.util.concurrent.atomic` 包下的原子类（`AtomicLong`, `AtomicInteger`）来确保在多线程环境下（例如主循环和 `StatusPrinter` 的后台线程）对统计数据进行并发更新时的**线程安全性**。
*   `StatusPrinter` 的后台线程会捕获内部异常并打印错误消息，避免因统计逻辑或 UI 刷新问题导致整个 Fuzzer 崩溃。
*   `StatsWriter` 和 `StatusPrinter` 都实现了 `AutoCloseable`，确保资源（文件句柄、线程池）在使用结束后能被正确关闭。

### 6. 使用示例 (在 `FuzzingEngine` 中的集成)

```java
// --- 初始化阶段 ---
// targetSpec.getId() 提供模糊目标的名称，例如 "target_01"
FuzzStats fuzzStats = new FuzzStats(targetSpec.getId()); 

// 假设 corpusManager 已经初始化，能够提供 queueSize
StatusPrinter statusPrinter = StatusPrinter.builder()
        .statsSupplier(() -> fuzzStats.toStatsTick(corpusManager.stats().queueSize()))
        .intervalSeconds(1) // 每秒打印一次
        .build();

// statsFile 是用于写入 CSV 的文件路径
StatsWriter statsWriter = new StatsWriter(workdir.resolve("logs").resolve(targetSpec.getId() + ".csv"));

// --- 启动阶段 ---
statusPrinter.start(); // 启动控制台实时打印

// --- 主循环中 ---
while (shouldContinue()) {
    // ... 选种、能量调度、变异、执行 (ExecResult result = harness.execute(tc)) ...

    // 更新 FuzzStats
    fuzzStats.recordExec(); // 每次执行都记录
    if (result.isCrash()) {
        fuzzStats.recordCrash();
    } else if (result.isTimeout()) {
        fuzzStats.recordHang();
    }

    // 假设 coverageDB.getTotalEdgesSeen() 返回当前的全局总覆盖边数
    fuzzStats.updateCoveredEdges(coverageDB.getTotalEdgesSeen());

    // 如果发现新路径
    if (isInteresting) {
        // ... 保存新种子到 CorpusManager, 加入 SeedQueue ...
        fuzzStats.recordNewPath();
    }

    // 周期性地将快照写入文件（例如每 100 次执行或每秒写一次）
    // 为了简化，这里假设每次循环都写，实际应有节流机制
    statsWriter.tick(fuzzStats.toStatsTick(corpusManager.stats().queueSize()));
}

// --- 清理阶段 (在 finally 块中) ---
statusPrinter.stop();
statsWriter.close();
```

### 7. 测试策略

本模块采用单元测试和少量集成测试来确保其正确性、线程安全性和合规性。

*   **`FuzzStatsTest`**：
    *   测试 `FuzzStats` 类的所有原子计数器（`execsTotal`, `coveredEdges`, `crashes`, `hangs`）是否正确更新。
    *   测试时间计算（`getElapsedSeconds`, `getExecsPerSec`）的准确性。
    *   测试 `toStatsTick` 是否能正确生成 `StatsTick` 快照。
    *   包含多线程测试，验证 `FuzzStats` 的线程安全性。
*   **`StatusPrinterTest`**：
    *   测试 `StatusPrinter` 是否能正确格式化并打印 `StatsTick` 内容到 `PrintStream`。
    *   测试各种事件消息（`printNewPath`, `printCrash`, `printHang`）的打印。
    *   验证 `start()` / `stop()` 生命周期管理和资源释放（通过 `try-with-resources`）。
    *   测试错误处理（`statsSupplier` 抛异常）。
*   **`StatsWriterTest`**：
    *   测试 `StatsWriter` 是否能在文件不存在时正确写入 CSV 头，并确保不重复写入。
    *   测试 `tick()` 方法是否能正确将 `StatsTick` 数据格式化为 CSV 行并追加到文件。
    *   验证文件路径自动创建和 `close()` 资源释放。
    *   验证 CSV 输出格式严格符合《模糊测试运行结果日志规范》。

---
