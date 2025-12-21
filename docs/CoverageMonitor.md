## CoverageMonitor

### Iteration 0：打底（半天～1天）

目标：把项目结构定下来，能“跑一轮执行-拿到结果-写日志”。

* 约定模块：

    * `executor`：负责跑被测程序、收集退出码/耗时/超时
    * `coverage`：负责 attach SHM、读 bitmap、算覆盖统计
    * `corpus`：保存 queue/crashes/hangs（按目录）
    * `fuzzer`：主循环（mutate -> run -> observe -> decide enqueue/save）
* 先不接 SHM：`CoverageMonitor` 用一个 `NoopCoverageMonitor` 返回空 Coverage，保证框架跑通。

验收：能执行 N 次，打印 exec/s，能把崩溃输入保存到 `out/crashes`。

---

### Iteration 1：最小可用 CoverageMonitor（1～2天）

目标：接入 AFL++ SHM bitmap，做**“新增非零字节”**判定。

* 从环境读取 `__AFL_SHM_ID` + `AFL_MAP_SIZE`（或固定 65536）
* JNA/JNI attach `shmat`，读 bitmap
* 维护 `prevBitmap`（或 `seen` bitset），实现：

    * `nonZeroBytes`
    * `newBytes`（相对上一次 prev 的“从 0 变非 0”计数）
    * `interesting = newBytes > 0`
* `Fuzzer` 用 `interesting` 决定是否入队，保存到 `out/queue`

验收：跑一段时间后 queue 会增长；覆盖统计会变化；输出目录齐全。

---

### Iteration 2：更稳的“新覆盖”语义（1～2天）

目标：判定更接近 AFL（但仍保持简单），减少误判。

建议把“比较策略”抽象出来（接口见下方）：

* 增强策略 1：**“相对全局 seen”** 而不是“相对上一次 prev”

    * `seen[i]` 记录是否曾经覆盖过该 byte（或该 edge bucket）
    * `newBytes = count(cur!=0 && !seen)`，并更新 seen
* 增强策略 2（可选）：做一个 `hash` 快速判断“bitmap 是否变化”，没变化就不算。

验收：interesting 的噪声显著降低，queue 增长更合理。

---

### Iteration 3：超时/崩溃/日志与统计（1～2天）

目标：把作业要求的“执行速度 + 保存特殊用例 + 状态日志”完整做好。

* `Executor` 支持 timeout（超时 kill）
* `CoverageMonitor` 只负责 coverage；保存逻辑放到 `CorpusManager`
* `Stats`：`execs`, `execsPerSec`, `paths`, `crashes`, `hangs`, `lastNewPathAt`
* `Logger/StatusPrinter`：每秒/每 N 次打印一行状态

验收：crash/hang/queue 分类保存；状态日志稳定输出。

---

### Iteration 4（加分项）：桶化/virgin map（2～4天）

目标：更像 AFL++ 的“interesting”判断（hitcount bucket + virgin）。

* 把每个 byte 的 hitcount 映射到桶（AFL 的经典桶：1,2,3,4-7,8-15,16-31,32-127,128+）
* `virgin` 保存“从未达到过的桶级别”
* interesting 的含义变成：“是否出现了更高的桶/新边”

验收：paths 的增长更符合覆盖提升，重复 seed 更少。

---

## Java 接口与数据结构（建议直接照抄）

### 1) 执行结果：ExecResult

```java
public enum ExecStatus {
    OK, CRASH, TIMEOUT
}

public record ExecResult(
        ExecStatus status,
        int exitCode,        // OK/CRASH 时可能有意义
        int termSignal,      // 如果你能拿到（Linux 可选）
        long execTimeMicros  // 单次执行耗时
) {}
```

### 2) 覆盖数据：Coverage

> 建议 Coverage 尽量“轻量不可变”，不要默认把整张 bitmap 存进去（除非你要调试/回放）。

```java
public record Coverage(
        long execId,
        long timestampMillis,
        int mapSize,

        int nonZeroBytes,   // 当前 bitmap 非零字节数
        int newBytes,       // 本次新增覆盖（取决于对比策略）
        long bitmapHash,    // 可选：快速判断变化（0 表示未计算）

        boolean interesting // newBytes > 0 或策略判定
) {}
```

### 3) 覆盖对比策略：CoverageDiffStrategy

把“怎么算 newBytes/interesting”单独抽出来，后续你升级桶化不会动主流程。

```java
public interface CoverageDiffStrategy {
    /**
     * @param current  当前 bitmap（复用的 byte[] 缓冲区）
     * @return diff 结果：newBytes + interesting
     */
    DiffResult diff(byte[] current);

    record DiffResult(int newBytes, boolean interesting) {}
}
```

#### 一个最小策略（全局 seen，推荐）

```java
import java.util.BitSet;

public class SeenNonZeroStrategy implements CoverageDiffStrategy {
    private final BitSet seen; // seen[i]=true 表示该 byte 曾经非零
    private final int mapSize;

    public SeenNonZeroStrategy(int mapSize) {
        this.mapSize = mapSize;
        this.seen = new BitSet(mapSize);
    }

    @Override
    public DiffResult diff(byte[] current) {
        int newBytes = 0;
        for (int i = 0; i < mapSize; i++) {
            if ((current[i] & 0xFF) != 0 && !seen.get(i)) {
                seen.set(i);
                newBytes++;
            }
        }
        return new DiffResult(newBytes, newBytes > 0);
    }
}
```

### 4) CoverageMonitor：负责读 SHM、产出 Coverage

```java
public interface CoverageMonitor extends AutoCloseable {
    /** 初始化/attach（从 env 或显式参数） */
    void start() throws Exception;

    /** 每次执行结束后调用，返回本次 coverage 快照 */
    Coverage observe(long execId, ExecResult execResult);

    /** 便于状态面板显示 */
    CoverageStats snapshotStats();

    @Override
    void close();
}

public record CoverageStats(
        long execs,
        double execsPerSec,
        long lastInterestingExecId,
        long lastInterestingAtMillis
) {}
```

### 5) SHM 读取抽象：BitmapSource（强烈建议）

以后你从 JNA 换 JNI 或换文件 mmap，都不会影响上层。

```java
public interface BitmapSource extends AutoCloseable {
    int mapSize();
    /** 把 bitmap 读进 dst（dst.length >= mapSize） */
    void readInto(byte[] dst);
    /** 可选：清零（如果你的流程需要） */
    default void clear() {}
    @Override
    void close();
}
```

### 6) 保存特殊用例：CorpusManager

```java
import java.nio.file.Path;

public interface CorpusManager {
    void saveToQueue(byte[] input, Coverage cov);
    void saveCrash(byte[] input, ExecResult exec);
    void saveHang(byte[] input, ExecResult exec);

    Path outputDir();
}
```

### 7) Fuzzer 主循环需要的最小接口

```java
public interface Mutator {
    byte[] mutate(byte[] seed);
}

public interface SeedScheduler {
    byte[] nextSeed();
    void onInteresting(byte[] input, Coverage cov);
}
```

---

## 推荐的“实现顺序”对应代码落地

1. 先把 `Executor` + `FuzzerLoop` + `CorpusManager` 跑通（Iteration 0）
2. 实现 `BitmapSource` 的一个版本：`SysVShmBitmapSource`（JNA/JNI 都行）
3. 实现 `CoverageMonitorImpl`：内部持有 `BitmapSource + CoverageDiffStrategy + hash(可选)`
4. 替换掉 `NoopCoverageMonitor`，开始真正基于覆盖入队
5. 逐步升级 `CoverageDiffStrategy`（seen -> hash -> bucket）

---

如果你愿意，我也可以直接给你一份**CoverageMonitorImpl + SysVShmBitmapSource(JNA版)** 的完整可编译代码（含错误处理、hash、复用缓冲区、统计 exec/s），你们只要把依赖（JNA）加进 Maven/Gradle 就能跑。
