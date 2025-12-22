# 扩展覆盖监控组件文档

本文档详细介绍为支持种子调度而新增的扩展覆盖监控组件。

---

## 概述

扩展组件在保持向后兼容的同时，为种子调度器提供边级别的覆盖详情：

```
基础组件栈（已有）:
BitmapSource → CoverageDiffStrategy → CoverageMonitor → Coverage

扩展组件栈（新增）:
BitmapSource → CoverageDiffStrategyEx → CoverageMonitorEx → CoverageEx
                         ↓
                    CoverageDB (全局状态)
                         ↓
                    EdgeSet (边索引集合)
```

---

## 1. EdgeSet - 稀疏边索引集合

### 设计理念

AFL++ bitmap 是 65536 字节数组，但实际触发的边通常只有数百到数千个。`EdgeSet` 使用排序的 `int[]` 存储边索引，实现高效的内存占用和快速的集合操作。

### API 参考

```java
public final class EdgeSet implements Iterable<Integer> {
    // 构造方法
    public static EdgeSet fromBitmap(byte[] bitmap);
    public static EdgeSet of(int... indices);
    public static EdgeSet empty();
    
    // 查询
    public int size();
    public boolean isEmpty();
    public boolean contains(int index);
    public int[] toArray();
    public BitSet toBitSet(int mapSize);
    
    // 集合操作（返回新对象，不修改原对象）
    public EdgeSet union(EdgeSet other);
    public EdgeSet intersect(EdgeSet other);
    public EdgeSet subtract(EdgeSet other);
    
    // 迭代
    public Iterator<Integer> iterator();
    public Stream<Integer> stream();
    
    // Object 方法
    public boolean equals(Object obj);
    public int hashCode();
    public String toString();
}
```

### 使用示例

```java
// 从 bitmap 提取边
byte[] bitmap = new byte[65536];
// ... 执行目标程序，bitmap 被填充 ...
EdgeSet hitEdges = EdgeSet.fromBitmap(bitmap);
System.out.println("Hit " + hitEdges.size() + " edges");

// 计算新边（集合差）
EdgeSet seenEdges = EdgeSet.of(10, 20, 30);
EdgeSet newEdges = hitEdges.subtract(seenEdges);
System.out.println("Discovered " + newEdges.size() + " new edges");

// 检查特定边
if (hitEdges.contains(42)) {
    System.out.println("Edge 42 was hit");
}

// 迭代所有边
for (int edge : hitEdges) {
    System.out.println("Edge: " + edge);
}

// 使用 Stream API
double avgFreq = hitEdges.stream()
    .mapToInt(db::getEdgeFrequency)
    .average()
    .orElse(0.0);
```

### 性能特征

- **空间复杂度**: O(n)，n 为非零边数量（通常 << 65536）
- **查找复杂度**: O(log n)，二分查找
- **union/intersect/subtract**: O(n + m)，归并算法
- **fromBitmap**: O(mapSize)，单次遍历

---

## 2. XxHash64 - 快速哈希函数

### 设计理念

用于 bitmap 快速去重，避免重复的覆盖率计算。相比 FNV-1a，xxHash64 速度更快（2-3倍）且碰撞率更低。

### API 参考

```java
public final class XxHash64 {
    // 默认 seed = 0
    public static long hash(byte[] data);
    public static long hash(byte[] data, int offset, int length);
    
    // 自定义 seed
    public static long hash(byte[] data, long seed);
    public static long hash(byte[] data, int offset, int length, long seed);
}
```

### 使用示例

```java
byte[] bitmap = new byte[65536];

// 计算完整 hash
long hash = XxHash64.hash(bitmap);

// 比较两次执行
long hash1 = XxHash64.hash(bitmap);
executor.run(...);  // 第二次执行
long hash2 = XxHash64.hash(bitmap);

if (hash1 == hash2) {
    System.out.println("Bitmap 未变化，可能重复路径");
}

// 使用不同 seed（用于多个 hash 表）
long hashA = XxHash64.hash(bitmap, 0x12345678L);
long hashB = XxHash64.hash(bitmap, 0x87654321L);
```

---

## 3. DiffResultEx - 扩展 Diff 结果

### 设计理念

在基础 `DiffResult(newBytes, interesting)` 之上，增加边索引详情，供调度器使用。

### API 参考

```java
public record DiffResultEx(
    int newCount,           // 新边数量
    EdgeSet newEdges,       // 新边索引
    EdgeSet hitEdges,       // 所有触发的边
    long bitmapHash         // XXHash64
) {
    /** 转为基础 DiffResult（向后兼容） */
    public DiffResult toBasic();
}
```

### 使用示例

```java
CoverageDiffStrategyEx strategy = CoverageDiffStrategyEx.createDefault(mapSize);
DiffResultEx result = strategy.diffEx(bitmap);

if (result.newCount() > 0) {
    System.out.println("New edges: " + result.newEdges());
    System.out.println("All hit edges: " + result.hitEdges());
    System.out.println("Bitmap hash: 0x" + Long.toHexString(result.bitmapHash()));
    
    // 计算稀有度
    double rarity = db.calculateRarityScore(result.hitEdges());
    System.out.println("Rarity score: " + rarity);
}
```

---

## 4. CoverageDiffStrategyEx - 扩展策略接口

### 设计理念

扩展现有 `CoverageDiffStrategy`，提供边级别详情，同时保持向后兼容。

### API 参考

```java
public interface CoverageDiffStrategyEx extends CoverageDiffStrategy {
    /** 扩展 diff，返回边索引详情 */
    DiffResultEx diffEx(byte[] current);
    
    /** 获取全局 seen BitSet（用于 CoverageDB 初始化） */
    BitSet getSeenBitSet();
    
    /** 查询单条边是否已见过 */
    boolean hasSeenEdge(int index);
    
    /** 工厂方法：创建默认策略（SeenNonZeroStrategyEx） */
    static CoverageDiffStrategyEx createDefault(int mapSize);
    
    /** 包装现有策略为扩展策略 */
    static CoverageDiffStrategyEx wrap(CoverageDiffStrategy base, int mapSize);
    
    // 继承自 CoverageDiffStrategy
    @Override
    default DiffResult diff(byte[] current) {
        return diffEx(current).toBasic();
    }
}
```

### 内置实现

#### SeenNonZeroStrategyEx（推荐）

原生扩展实现，维护全局 `seen` BitSet：

```java
public class SeenNonZeroStrategyEx implements CoverageDiffStrategyEx {
    private final BitSet seen;
    
    @Override
    public DiffResultEx diffEx(byte[] current) {
        EdgeSet hitEdges = EdgeSet.fromBitmap(current);
        EdgeSet newEdges = EdgeSet.empty();
        
        // 识别新边
        for (int edge : hitEdges) {
            if (!seen.get(edge)) {
                seen.set(edge);
                newEdges = newEdges.union(EdgeSet.of(edge));
            }
        }
        
        long hash = XxHash64.hash(current);
        return new DiffResultEx(newEdges.size(), newEdges, hitEdges, hash);
    }
}
```

#### WrappedStrategyEx（兼容层）

包装现有策略，提供扩展接口：

```java
CoverageDiffStrategy legacy = new SeenNonZeroStrategy(mapSize);
CoverageDiffStrategyEx extended = CoverageDiffStrategyEx.wrap(legacy, mapSize);
```

---

## 5. CoverageDB - 全局覆盖数据库

### 设计理念

CoverageDB 是连接覆盖监控和种子调度的核心组件，维护全局覆盖状态：

- **edgeFreq[i]**: 边 i 被触发的总次数（用于稀有度计算）
- **topRated[i]**: 触发边 i 的"最优" seed ID
- **favored**: 至少 top-rated 一条边的 seeds 集合

### 核心概念

#### Top-Rated Seeds

对每条边，根据配置的标准选择"最优" seed：

```java
public enum TopRatedCriteria {
    SMALLEST_INPUT,   // 偏好最小输入（默认，减少内存）
    MOST_RECENT,      // 偏好最新发现（探索优先）
    FEWEST_EDGES,     // 偏好覆盖最少边（精准定位）
    FASTEST_EXEC      // 偏好执行最快（吞吐优先）
}
```

#### Favored Seeds

Favored seeds 是至少 top-rated 一条边的 seeds，应优先调度。这些 seeds 代表了当前全局覆盖的"最小子集"。

#### Rarity Score（稀有度分数）

稀有度分数 = Σ(1/freq) over hitEdges

- 稀有边（freq 低）贡献更高分数
- 用于能量分配：高稀有度 → 更多 fuzz 轮数

### API 参考

```java
public class CoverageDB {
    // 构造
    public CoverageDB(int mapSize);
    public CoverageDB(int mapSize, TopRatedCriteria criteria);
    
    // 更新（线程安全）
    public UpdateResult update(int seedId, DiffResultEx diffResult, 
                               int inputSize, long execTimeNanos);
    
    // 查询
    public int getEdgeFrequency(int edge);
    public double calculateRarityScore(EdgeSet edges);
    public int getMinFrequency(EdgeSet edges);
    public boolean isFavored(int seedId);
    public boolean isRedundant(int seedId, EdgeSet edges);
    public int getFavoredCount();
    public int getTotalEdgesSeen();
    
    // 内部状态（调试用）
    public Map<Integer, Integer> getTopRatedMap();
    public Set<Integer> getFavoredSeeds();
}

public record UpdateResult(
    EdgeSet newEdges,           // 全局新边
    EdgeSet becameTopRated,     // 成为 top-rated 的边
    boolean favoredChanged,     // favored 集合是否变化
    boolean isFavored           // 该 seed 是否 favored
) {}
```

### 使用示例

```java
// 创建数据库
CoverageDB db = new CoverageDB(65536, TopRatedCriteria.SMALLEST_INPUT);

// 执行后更新
CoverageEx coverage = monitor.afterRunEx(result);
UpdateResult update = db.update(
    seedId,
    new DiffResultEx(coverage.newBytes(), coverage.newEdges(),
                     coverage.hitEdges(), coverage.bitmapHash()),
    input.length,
    coverage.execTimeNanos()
);

// 处理更新结果
if (update.newEdges().size() > 0) {
    System.out.println("Discovered " + update.newEdges().size() + " global new edges!");
    corpusManager.saveToQueue(input, coverage.toBasic());
}

if (update.isFavored()) {
    System.out.println("Seed " + seedId + " is now favored!");
    System.out.println("Top-rated for " + update.becameTopRated().size() + " edges");
}

if (update.favoredChanged()) {
    System.out.println("Favored set changed, total: " + db.getFavoredCount());
    // 可选：触发 queue culling
}

// 稀有度评分（用于能量分配）
double rarityScore = db.calculateRarityScore(coverage.hitEdges());
int baseEnergy = 100;
int energy = (int) (baseEnergy * Math.min(rarityScore, 10.0));
System.out.println("Assigned energy: " + energy);

// 队列精简（检测冗余）
if (db.isRedundant(seedId, coverage.hitEdges())) {
    System.out.println("Seed " + seedId + " is redundant, can be removed");
}
```

### 线程安全

CoverageDB 使用 `ReentrantLock` 保护更新操作：

```java
private final ReentrantLock lock = new ReentrantLock();

public UpdateResult update(...) {
    lock.lock();
    try {
        // 原子更新 edgeFreq, topRated, favored
    } finally {
        lock.unlock();
    }
}
```

---

## 6. CoverageEx - 扩展覆盖模型

### 设计理念

在基础 `Coverage` 之上增加边索引和执行时间，供调度器使用。

### API 参考

```java
public record CoverageEx(
    // 基础字段
    long execId,
    long timestampMillis,
    int mapSize,
    int nonZeroBytes,
    int newBytes,
    long bitmapHash,
    boolean interesting,
    
    // 扩展字段
    EdgeSet hitEdges,        // 本次触发的边
    EdgeSet newEdges,        // 新发现的边
    long execTimeNanos,      // 执行时间（纳秒）
    boolean stable           // 轨迹是否稳定
) {
    // 工厂方法
    public static CoverageEx empty(RunResult result);
    public static CoverageEx from(DiffResultEx diffResult, RunResult result, int mapSize);
    public static CoverageEx of(...);  // 完整构造
    public static CoverageEx fromBasic(Coverage coverage);
    
    // 转换方法
    public Coverage toBasic();
    public CoverageEx markUnstable();
    
    // 便捷方法
    public DiffResultEx diffResultEx();
}
```

### 使用示例

```java
// 从 DiffResultEx 创建
DiffResultEx diffResult = strategy.diffEx(bitmap);
CoverageEx coverage = CoverageEx.from(diffResult, result, mapSize);

// 访问扩展字段
System.out.println("Hit edges: " + coverage.hitEdges().size());
System.out.println("New edges: " + coverage.newEdges().size());
System.out.println("Exec time: " + coverage.execTimeNanos() / 1_000_000.0 + " ms");
System.out.println("Stable: " + coverage.stable());

// 转为基础 Coverage（向后兼容）
Coverage basic = coverage.toBasic();
corpusManager.saveToQueue(input, basic);

// 从基础 Coverage 升级
Coverage legacy = Coverage.of(...);
CoverageEx extended = CoverageEx.fromBasic(legacy);
```

---

## 7. CoverageMonitorEx - 扩展监控接口

### 设计理念

扩展 `CoverageMonitor` 接口，提供边级别详情和 CoverageDB 访问。

### API 参考

```java
public interface CoverageMonitorEx extends CoverageMonitor {
    /** 返回扩展覆盖信息 */
    CoverageEx afterRunEx(RunResult result);
    
    /** 获取全局覆盖数据库 */
    CoverageDB getCoverageDB();
    
    /** 获取扩展策略 */
    CoverageDiffStrategyEx getStrategyEx();
    
    /** 是否启用稳定性检测 */
    boolean isStabilityDetectionEnabled();
    
    /** 获取全局已见边总数 */
    int getTotalEdgesSeen();
    
    // 继承自 CoverageMonitor
    @Override
    default Coverage afterRun(RunResult result) {
        return afterRunEx(result).toBasic();
    }
}
```

### ShmCoverageMonitorEx 实现

```java
public class ShmCoverageMonitorEx implements CoverageMonitorEx {
    private final BitmapSource bitmapSource;
    private final CoverageDiffStrategyEx strategy;
    private final CoverageDB coverageDB;
    private final boolean enableStabilityDetection;
    
    // 工厂方法
    public static ShmCoverageMonitorEx fromEnvironment();
    public static ShmCoverageMonitorEx forTesting(MockBitmapSource source);
    
    @Override
    public CoverageEx afterRunEx(RunResult result) {
        bitmapSource.readInto(buffer);
        DiffResultEx diffResult = strategy.diffEx(buffer);
        
        // 可选：稳定性检测
        if (enableStabilityDetection && diffResult.newCount() > 0) {
            // 重新执行验证轨迹稳定性
        }
        
        return CoverageEx.from(diffResult, result, mapSize);
    }
}
```

### 使用示例

```java
// 创建扩展监控器
CoverageDiffStrategyEx strategy = CoverageDiffStrategyEx.createDefault(mapSize);
CoverageDB db = new CoverageDB(mapSize);
BitmapSource source = new SysVShmBitmapSource(mapSize, shmId);

CoverageMonitorEx monitor = new ShmCoverageMonitorEx(
    source, 
    strategy, 
    db,
    /* enableStabilityDetection */ true
);

monitor.start();

// 使用扩展接口
monitor.beforeRun();
RunResult result = executor.run(...);
CoverageEx coverage = monitor.afterRunEx(result);

if (coverage.interesting()) {
    // 更新数据库
    UpdateResult update = db.update(
        seedId,
        coverage.diffResultEx(),
        input.length,
        coverage.execTimeNanos()
    );
    
    if (update.isFavored()) {
        System.out.println("Favored seed!");
    }
}

// 查询全局状态
int totalEdges = monitor.getTotalEdgesSeen();
System.out.println("Total edges discovered: " + totalEdges);
```

---

## 集成到 Fuzzing 循环

完整的集成示例：

```java
public class AdvancedFuzzingEngine {
    private final CoverageMonitorEx monitor;
    private final CoverageDB db;
    private final SeedQueue queue;
    private final Mutator mutator;
    private final PowerScheduler powerScheduler;
    
    public void run() throws Exception {
        monitor.start();
        
        while (shouldContinue()) {
            // 1. 选择 seed（优先 favored）
            Seed seed = queue.select(db);
            
            // 2. 计算能量
            int energy = powerScheduler.calculateEnergy(seed, db);
            
            // 3. Fuzz 循环
            for (int i = 0; i < energy; i++) {
                byte[] payload = mutator.mutate(seed.data());
                
                monitor.beforeRun();
                RunResult result = executor.run(targetCmd, payload, timeout, logDir);
                CoverageEx coverage = monitor.afterRunEx(result);
                
                // 4. 处理结果
                if (result.termination() == RunResult.Termination.ERROR) {
                    corpusManager.saveCrash(payload, result);
                } else if (coverage.interesting()) {
                    // 更新数据库
                    int newSeedId = nextSeedId++;
                    UpdateResult update = db.update(
                        newSeedId,
                        coverage.diffResultEx(),
                        payload.length,
                        coverage.execTimeNanos()
                    );
                    
                    // 保存到队列
                    corpusManager.saveToQueue(payload, coverage.toBasic());
                    queue.add(new Seed(newSeedId, payload, coverage));
                    
                    // 队列精简
                    if (update.favoredChanged()) {
                        queue.cull(db);
                    }
                }
            }
            
            seed.markFuzzed();
        }
        
        monitor.close();
    }
}
```

---

## 性能优化建议

1. **复用 EdgeSet**: EdgeSet 是不可变的，可安全共享
2. **批量更新**: 使用 `CoverageDB.update()` 而非多次单边更新
3. **延迟 queue culling**: 不必每次 favoredChanged 都 cull，可定期执行
4. **缓存稀有度分数**: 对同一 EdgeSet 的稀有度可缓存
5. **使用 XxHash64**: 比 FNV-1a 快 2-3 倍

---

## 故障排查

**Q: CoverageDB 内存占用过高**

A: 检查 topRated 标准：
- `SMALLEST_INPUT`: 内存友好
- `MOST_RECENT`: 可能保留更多 seeds
- 定期执行 queue culling 移除冗余 seeds

**Q: 稀有度评分全为 0**

A: 确保 `CoverageDB.update()` 在 `calculateRarityScore()` 之前调用。频率信息需要先更新。

**Q: Favored 集合为空**

A: 检查：
1. 是否有 interesting coverage（newBytes > 0）
2. `DiffResultEx.hitEdges()` 是否非空
3. `TopRatedCriteria` 配置是否合理

**Q: EdgeSet.fromBitmap() 很慢**

A: `fromBitmap()` 需遍历整个 bitmap（65536 字节），这是正常的。如果频繁调用，考虑缓存 EdgeSet。

---

**最后更新**: 2025年12月22日  
**版本**: v1.1
