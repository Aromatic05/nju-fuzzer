# Coverage Monitor 模块文档

## 概述

Coverage Monitor 是 NJU Fuzzer 的核心组件，负责监控 AFL++ 插装目标程序的代码覆盖率。通过读取 AFL++ 共享内存（SHM）中的 bitmap 数据，判定每次执行是否触发了新的代码路径，从而指导模糊测试器保存有价值的输入到语料库。

本模块采用分层设计，支持多种覆盖率对比策略，易于扩展和测试。

---

## 架构设计

### 核心接口

```
CoverageMonitor (interface)
    ↓
ShmCoverageMonitor (implementation)
    ↓
┌─────────────────────────┬──────────────────────────┐
│                         │                          │
BitmapSource           CoverageDiffStrategy       FuzzStats
(interface)             (interface)              (statistics)
    ↓                       ↓
SysVShmBitmapSource    SeenNonZeroStrategy
                       PrevBitmapStrategy
                       HashFilteredStrategy
                       CompositeStrategy
```

### 模块职责

* **CoverageMonitor**：定义覆盖率监控的生命周期接口（start, beforeRun, afterRun, close）
* **ShmCoverageMonitor**：完整实现，协调 BitmapSource 和 CoverageDiffStrategy
* **BitmapSource**：抽象 AFL++ SHM bitmap 读取，当前使用 JNA 实现
* **CoverageDiffStrategy**：可插拔的覆盖率对比策略，判定"是否 interesting"
* **FuzzStats**：统计执行次数、速度、新路径等指标

---

## 核心组件

### 1. CoverageMonitor 接口

```java
public interface CoverageMonitor extends AutoCloseable {
    /** 初始化覆盖率监控（attach SHM） */
    void start() throws Exception;

    /** 每次执行前调用（清零 bitmap） */
    void beforeRun();

    /** 每次执行后调用（读取 bitmap，判定 interesting） */
    Coverage afterRun(RunResult result);

    /** 获取当前统计快照 */
    CoverageStats snapshotStats();

    /** 释放资源（detach SHM） */
    @Override
    void close();
}
```

**生命周期：**

1. `start()` - 从环境变量读取 `__AFL_SHM_ID`，attach 共享内存
2. `beforeRun()` - 清零 bitmap，准备接收新的覆盖率数据
3. `afterRun(RunResult)` - 读取 bitmap，使用策略判定是否 interesting
4. `close()` - detach 共享内存，释放资源

---

### 2. ShmCoverageMonitor 实现

完整的 AFL++ 覆盖率监控实现，协调 bitmap 读取和对比策略。

**关键特性：**

* 从环境变量自动读取 `__AFL_SHM_ID` 和 `AFL_MAP_SIZE`
* 支持可插拔的对比策略（`CoverageDiffStrategy`）
* 自动计算执行速度（exec/s）
* 线程安全的统计更新

**构造示例：**

```java
// 使用默认策略（SeenNonZeroStrategy）
BitmapSource bitmapSource = new SysVShmBitmapSource(mapSize, shmId);
CoverageDiffStrategy strategy = new SeenNonZeroStrategy(mapSize);
CoverageMonitor monitor = new ShmCoverageMonitor(bitmapSource, strategy);

monitor.start();  // Attach SHM
```

---

### 3. BitmapSource 接口

抽象 AFL++ bitmap 读取，支持不同的实现方式（JNA、JNI、文件 mmap）。

```java
public interface BitmapSource extends AutoCloseable {
    int mapSize();
    void attach() throws RuntimeException;
    boolean isAttached();
    void readInto(byte[] dst);
    void clear();
    void close();
}
```

**当前实现：SysVShmBitmapSource（JNA）**

* 使用 JNA 调用 `shmat()` / `shmdt()` 访问 System V 共享内存
* 高性能的 native memory copy（`Pointer.read()`）
* 支持清零操作（`Pointer.setMemory()`）

**使用示例：**

```java
BitmapSource source = new SysVShmBitmapSource(65536, shmId);
source.attach();

byte[] bitmap = new byte[65536];
source.readInto(bitmap);  // 读取当前 bitmap
source.clear();           // 清零 bitmap
source.close();           // Detach SHM
```

---

### 4. CoverageDiffStrategy 策略

判定"本次执行是否触发新覆盖"的核心逻辑，支持多种策略。

```java
public interface CoverageDiffStrategy {
    DiffResult diff(byte[] current);

    record DiffResult(int newBytes, boolean interesting) {}
}
```

#### 4.1 SeenNonZeroStrategy（推荐）

**原理**：维护全局 `seen` bitset，判定"从未覆盖过的边"

**适用场景**：

* 生产环境首选
* 精确追踪全局覆盖率增长
* 减少重复输入入队

**示例**：

```java
CoverageDiffStrategy strategy = new SeenNonZeroStrategy(65536);
DiffResult result = strategy.diff(bitmap);
if (result.interesting()) {
    System.out.println("发现新覆盖: " + result.newBytes() + " bytes");
}
```

#### 4.2 PrevBitmapStrategy

**原理**：相对上一次执行的差异判定

**适用场景**：

* 快速原型验证
* 对比连续执行的覆盖率变化

**注意**：可能产生较多误判（重复触发已知路径）

#### 4.3 HashFilteredStrategy

**原理**：基于 XXHash64 快速去重，bitmap 相同则跳过判定

**适用场景**：

* 减少重复判定开销
* 与其他策略组合使用

**示例**：

```java
CoverageDiffStrategy baseStrategy = new SeenNonZeroStrategy(mapSize);
CoverageDiffStrategy strategy = new HashFilteredStrategy(mapSize, baseStrategy);
```

#### 4.4 CompositeStrategy

**原理**：组合多种策略，同时满足多个条件才判定为 interesting

**适用场景**：

* 严格的覆盖率判定（减少噪声）
* 自定义复合判定逻辑

**示例**：

```java
List<CoverageDiffStrategy> strategies = List.of(
    new SeenNonZeroStrategy(mapSize),
    new HashFilteredStrategy(mapSize)
);
CoverageDiffStrategy strategy = new CompositeStrategy(strategies);
```

---

## 数据模型

### Coverage

表示一次执行的覆盖率快照。

```java
public record Coverage(
    long execId,              // 执行 ID
    long timestampMillis,     // 时间戳
    int mapSize,              // Bitmap 大小
    int nonZeroBytes,         // 非零字节数（总覆盖）
    int newBytes,             // 新增覆盖字节数
    long bitmapHash,          // Bitmap hash（可选）
    boolean interesting       // 是否有价值（应入队）
) {
    /** 创建空覆盖（无覆盖率监控时） */
    public static Coverage empty(RunResult result) {
        return new Coverage(
            result.execId(), 
            System.currentTimeMillis(),
            0, 0, 0, 0L, false
        );
    }
}
```

### CoverageStats

覆盖率监控的统计快照。

```java
public record CoverageStats(
    long execs,                    // 总执行次数
    double execsPerSec,            // 执行速度
    long lastInterestingExecId,    // 最后一次有价值的执行 ID
    long lastInterestingAtMillis   // 最后一次有价值的执行时间
) {}
```

---

## 集成到 FuzzingEngine

### 初始化

`FuzzingEngine` 提供三种构造器：

1. **无覆盖率监控**（非插装目标）

```java
FuzzingEngine engine = new FuzzingEngine(
    workdir, durationSec, targetSpec, executor, timeout
);
```

2. **有覆盖率监控**（AFL++ 插装目标）

```java
BitmapSource bitmapSource = new SysVShmBitmapSource(mapSize, shmId);
CoverageDiffStrategy strategy = new SeenNonZeroStrategy(mapSize);
CoverageMonitor monitor = new ShmCoverageMonitor(bitmapSource, strategy);

CorpusManager corpusManager = new FileCorpusManager(workdir);

FuzzingEngine engine = new FuzzingEngine(
    workdir, durationSec, targetSpec, executor, timeout,
    monitor, corpusManager
);
```

### 主循环集成

```java
public void run() throws Exception {
    // Start coverage monitor
    if (coverageMonitor instanceof ShmCoverageMonitor shmMonitor) {
        shmMonitor.start();  // Attach SHM
    }

    try {
        while (shouldContinue()) {
            byte[] payload = generatePayload();

            // 执行前清零
            if (coverageMonitor != null) {
                coverageMonitor.beforeRun();
            }

            // 执行目标
            RunResult result = executor.run(command, stdinData, timeout, logDir);

            // 执行后收集覆盖率
            Coverage coverage = coverageMonitor != null
                ? coverageMonitor.afterRun(result)
                : Coverage.empty(result);

            // 处理结果
            handleResult(payload, result, coverage);
        }
    } finally {
        // Close coverage monitor
        if (coverageMonitor instanceof AutoCloseable closeable) {
            closeable.close();  // Detach SHM
        }
    }
}

private void handleResult(byte[] input, RunResult result, Coverage coverage) {
    if (corpusManager == null) return;

    // 保存 crash
    if (result.termination() == RunResult.Termination.ERROR) {
        corpusManager.saveCrash(input, result);
        return;
    }

    // 保存 hang
    if (result.timedOut()) {
        corpusManager.saveHang(input, result);
        return;
    }

    // 保存 interesting 输入
    if (coverage != null && coverage.interesting()) {
        corpusManager.saveToQueue(input, coverage);
    }
}
```

---

## 环境变量配置

### AFL++ 插装目标

确保目标程序使用 `afl-cc` 编译：

```bash
export AFL_USE_ASAN=1  # 可选：启用 AddressSanitizer
export AFL_MAP_SIZE=65536  # 可选：指定 bitmap 大小（默认 65536）

cd env/third_party/AFLplusplus
./afl-cc -o target target.c
```

### 运行时环境变量

AFL++ 会自动设置 `__AFL_SHM_ID`，无需手动配置：

```bash
# AFLplusplus 自动注入
export __AFL_SHM_ID=<shm_id>
export AFL_MAP_SIZE=65536  # 可选
```

`ShmCoverageMonitor` 会从环境变量自动读取这些配置。

---

## 测试

### 单元测试覆盖

* **ShmCoverageMonitor**: 14 tests
  * 生命周期测试（start, beforeRun, afterRun, close）
  * 策略集成测试
  * 统计更新测试

* **SeenNonZeroStrategy**: 9 tests
  * 全局 seen 判定
  * 重复输入过滤

* **PrevBitmapStrategy**: 13 tests
  * 相对差异判定
  * 边界情况

* **HashFilteredStrategy**: 11 tests
  * Hash 去重
  * 策略包装

* **CompositeStrategy**: 14 tests
  * 多策略组合
  * 短路逻辑

* **MockBitmapSource**: 9 tests
  * 测试辅助工具

### 集成测试

**FuzzingEngineIntegrationTest**（3 tests）：

1. `shouldRunWithoutCoverage` - 无覆盖率监控模式
2. `shouldRunWithCoverageMonitoring` - 覆盖率监控集成
3. `shouldHandleCrashingTarget` - 崩溃检测

**总计**：174 tests passing（144 基础 + 30 扩展）

---

## 性能优化

### 内存复用

`ShmCoverageMonitor` 复用 bitmap buffer，避免频繁分配：

```java
private final byte[] buffer = new byte[mapSize];

@Override
public Coverage afterRun(RunResult result) {
    bitmapSource.readInto(buffer);  // 复用 buffer
    DiffResult diff = strategy.diff(buffer);
    // ...
}
```

### Hash 缓存

`HashFilteredStrategy` 缓存上一次 hash，避免重复计算：

```java
long currentHash = XxHash64.hash(current);
if (currentHash == prevHash) {
    return new DiffResult(0, false);  // 快速返回
}
prevHash = currentHash;
```

### 统计更新

使用 `AtomicLong` 无锁更新统计，减少同步开销：

```java
private final AtomicLong execs = new AtomicLong(0);
private final AtomicLong lastInterestingExecId = new AtomicLong(0);
```

---

## 扩展指南

### 自定义对比策略

实现 `CoverageDiffStrategy` 接口：

```java
public class MyCustomStrategy implements CoverageDiffStrategy {
    @Override
    public DiffResult diff(byte[] current) {
        int newBytes = computeNewBytes(current);
        boolean interesting = isInteresting(current);
        return new DiffResult(newBytes, interesting);
    }

    private int computeNewBytes(byte[] current) {
        // 自定义逻辑
    }

    private boolean isInteresting(byte[] current) {
        // 自定义判定
    }
}
```

### 自定义 BitmapSource

实现 `BitmapSource` 接口，支持不同的 SHM 访问方式：

```java
public class FileMmapBitmapSource implements BitmapSource {
    private MappedByteBuffer mmap;

    @Override
    public void attach() {
        // mmap file
    }

    @Override
    public void readInto(byte[] dst) {
        mmap.position(0);
        mmap.get(dst);
    }

    @Override
    public void close() {
        // unmap
    }
}
```

### AFL++ 桶化支持（未来）

实现 hitcount bucket 映射：

```java
public class BucketizedStrategy implements CoverageDiffStrategy {
    private static final byte[] COUNT_LOOKUP = /* AFL++ 桶映射表 */;
    private final byte[] virgin = new byte[mapSize];

    @Override
    public DiffResult diff(byte[] current) {
        int newBytes = 0;
        for (int i = 0; i < mapSize; i++) {
            byte bucket = COUNT_LOOKUP[current[i] & 0xFF];
            if (bucket != 0 && (virgin[i] & bucket) == bucket) {
                virgin[i] &= ~bucket;
                newBytes++;
            }
        }
        return new DiffResult(newBytes, newBytes > 0);
    }
}
```

---

## 故障排查

### 常见问题

**Q: `ShmCoverageMonitor.start()` 抛出 "Environment variable __AFL_SHM_ID not set"**

A: 确保目标程序使用 `afl-cc` 编译，且 AFL++ 运行时注入了环境变量。测试时可手动设置：

```bash
export __AFL_SHM_ID=12345
export AFL_MAP_SIZE=65536
```

**Q: 覆盖率监控不生效，queue 目录为空**

A: 检查以下几点：

1. 目标程序是否使用 `afl-cc` 插装编译
2. `CoverageMonitor` 是否正确传入 `FuzzingEngine` 构造器
3. `CorpusManager` 是否初始化
4. 检查 `StatusPrinter` 输出，确认 `[NEW]` 事件

**Q: 执行速度低（< 100 exec/s）**

A: 优化建议：

1. 减少 `tickSleepMs`（默认 1000ms）
2. 使用 `HashFilteredStrategy` 减少重复判定
3. 检查目标程序是否有文件 I/O 阻塞

**Q: 测试时提示 "AFL++ instrumented binary not found"**

A: 集成测试需要真实的 AFL++ 插装二进制。测试会自动跳过（`assumeTrue`），不影响其他测试。

---

## 参考资料

* **AFL++ 官方文档**: https://github.com/AFLplusplus/AFLplusplus
* **AFL++ SHM 机制**: `docs/technical_details.md`
* **JNA 文档**: https://github.com/java-native-access/jna
* **项目架构说明**: [ARCHITECTURE.md](ARCHITECTURE.md)
* **集成状态**: [INTEGRATION_STATUS.md](INTEGRATION_STATUS.md)

---

## 未来改进

1. **AFL++ 桶化支持**：实现 hitcount bucket 映射，更精确的覆盖率判定
2. **Virgin map 优化**：减少重复路径误判
3. **并发执行支持**：多线程/多进程执行目标程序
4. **覆盖率可视化**：生成覆盖率增长曲线图
5. **JNI 实现**：替代 JNA，进一步提升性能
6. ~~**边级别覆盖详情**~~：✅ 已实现（EdgeSet, CoverageDiffStrategyEx）
7. ~~**全局覆盖数据库**~~：✅ 已实现（CoverageDB）
8. ~~**Favored seeds 支持**~~：✅ 已实现（TopRated/Favored 机制）

---

**最后更新**: 2025年12月22日  
**版本**: v1.1 - Extended Coverage Monitoring for Seed Scheduling
