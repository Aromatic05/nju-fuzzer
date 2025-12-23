package edu.nju.fuzzing.stats;

import edu.nju.fuzzing.model.StatsTick;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class FuzzStats {

    private final String targetName; // [新增]
    private final Instant startTime;
    private final AtomicLong execsTotal = new AtomicLong(0);
    private final AtomicInteger coveredEdges = new AtomicInteger(0); // [新增] 核心指标
    private final AtomicInteger totalPaths = new AtomicInteger(0);   // interesting inputs 数量
    private final AtomicInteger crashes = new AtomicInteger(0);
    private final AtomicInteger hangs = new AtomicInteger(0);
    
    private volatile Instant lastNewPathAt;
    private volatile Instant lastExecAt;
    
    // For exec/sec calculation
    private volatile long lastExecsSnapshot = 0;
    private volatile Instant lastSnapshotTime;

    /**
     * @param targetName The name of the fuzz target (e.g., "target_01")
     */
    public FuzzStats(String targetName) {
        this.targetName = targetName;
        this.startTime = Instant.now();
        this.lastSnapshotTime = startTime;
        this.lastNewPathAt = startTime;
        this.lastExecAt = startTime;
    }

    // [新增] 更新覆盖率数据 (由 CoverageDB 提供)
    public void updateCoveredEdges(int count) {
        this.coveredEdges.set(count);
    }

    public void recordExec() {
        execsTotal.incrementAndGet();
        lastExecAt = Instant.now();
    }
    
    public void recordNewPath() {
        totalPaths.incrementAndGet();
        lastNewPathAt = Instant.now();
    }

    public void recordCrash() { crashes.incrementAndGet(); }
    public void recordHang() { hangs.incrementAndGet(); }

    public double getRecentExecsPerSec() {
        Instant now = Instant.now();
        long currentExecs = execsTotal.get();
        Duration sinceLast = Duration.between(lastSnapshotTime, now);
        
        if (sinceLast.toMillis() < 100) return getExecsPerSec(); // 避免除零或波动
        
        long deltaExecs = currentExecs - lastExecsSnapshot;
        double deltaSeconds = sinceLast.toMillis() / 1000.0;
        
        lastExecsSnapshot = currentExecs;
        lastSnapshotTime = now;
        
        return deltaSeconds > 0 ? deltaExecs / deltaSeconds : 0.0;
    }

    public double getExecsPerSec() {
        // 使用 toMillis() 获取毫秒，然后除以 1000.0 转为浮点数的秒
        long elapsedMillis = Duration.between(startTime, Instant.now()).toMillis();
        
        // 避免除以零
        if (elapsedMillis == 0) {
            return 0.0;
        }
        
        // 计算公式：(总次数 * 1000) / 毫秒数
        return (double) execsTotal.get() * 1000.0 / elapsedMillis;
    }

    public long getElapsedSeconds() {
        return Duration.between(startTime, Instant.now()).toSeconds();
    }

    /**
     * 生成符合日志规范的快照
     */
    public StatsTick toStatsTick(int queueSize) {
        long lastPathSecAgo = Duration.between(lastNewPathAt, Instant.now()).toSeconds();
        
        return new StatsTick(
                targetName,
                getElapsedSeconds(),
                execsTotal.get(),
                coveredEdges.get(),      // [关键数据]
                getRecentExecsPerSec(),  // 使用近期速度更准确
                queueSize,
                crashes.get(),
                hangs.get(),
                lastPathSecAgo
        );
    }
}