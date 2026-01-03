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
    // [新增] 执行时间统计：用于调度的自适应阈值（平均执行时间）
    private final AtomicLong execTimeTotalNanos = new AtomicLong(0);
    private final AtomicInteger coveredEdges = new AtomicInteger(0); // [新增] 核心指标
    private final AtomicInteger totalPaths = new AtomicInteger(0);   // interesting inputs 数量
    private final AtomicInteger crashes = new AtomicInteger(0);
    private final AtomicInteger hangs = new AtomicInteger(0);
    
    private volatile Instant lastNewPathAt;
    
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
    }

    public FuzzStats() {
        this("UNKNOWN");
    }

    // [新增] 更新覆盖率数据 (由 CoverageDB 提供)
    public void updateCoveredEdges(int count) {
        this.coveredEdges.set(count);
    }

    public void recordExec() {
        execsTotal.incrementAndGet();
    }

    /**
     * 记录一次执行，并累计本次执行耗时（纳秒）。
     * 该方法用于支持调度器的“相对平均值”策略；不影响原有 recordExec() 语义。
     */
    public void recordExec(long execTimeNanos) {
        execsTotal.incrementAndGet();
        if (execTimeNanos > 0) {
            execTimeTotalNanos.addAndGet(execTimeNanos);
        }
    }
    
    public void recordNewPath() {
        totalPaths.incrementAndGet();
        lastNewPathAt = Instant.now();
    }

    public int getTotalPaths() {
        return totalPaths.get();
    }

    public void recordCrash() { crashes.incrementAndGet(); }
    public void recordHang() { hangs.incrementAndGet(); }

    public long getExecsTotal() {
        return execsTotal.get();
    }

    /**
     * 全局平均执行时间（纳秒）。
     * 若尚未记录执行时间则返回 0。
     */
    public long getAvgExecTimeNanos() {
        long execs = execsTotal.get();
        long total = execTimeTotalNanos.get();
        if (execs <= 0 || total <= 0) return 0L;
        return total / execs;
    }

    /**
     * 全局平均执行时间（微秒）。
     * 若尚未记录执行时间则返回 0。
     */
    public long getAvgExecTimeUs() {
        long avgNs = getAvgExecTimeNanos();
        if (avgNs <= 0) return 0L;
        return Math.max(1L, avgNs / 1000L);
    }

    public int getCrashes() {
        return crashes.get();
    }

    public int getHangs() {
        return hangs.get();
    }

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
                totalPaths.get(),
                crashes.get(),
                hangs.get(),
                lastPathSecAgo
        );
    }
}