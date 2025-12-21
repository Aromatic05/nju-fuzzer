package edu.nju.fuzzing.stats;

import edu.nju.fuzzing.model.StatsTick;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe statistics tracker for fuzzing sessions.
 * 
 * Tracks:
 * - Total executions
 * - Total paths (interesting inputs)
 * - Crashes and hangs
 * - Timing information
 */
public class FuzzStats {

    private final Instant startTime;
    private final AtomicLong execsTotal = new AtomicLong(0);
    private final AtomicInteger totalPaths = new AtomicInteger(0);
    private final AtomicInteger crashes = new AtomicInteger(0);
    private final AtomicInteger hangs = new AtomicInteger(0);
    private volatile Instant lastNewPathAt;
    private volatile Instant lastExecAt;
    
    // For exec/sec calculation
    private volatile long lastExecsSnapshot = 0;
    private volatile Instant lastSnapshotTime;

    /**
     * Creates a new FuzzStats instance, starting the timer.
     */
    public FuzzStats() {
        this.startTime = Instant.now();
        this.lastSnapshotTime = startTime;
        this.lastNewPathAt = startTime;
        this.lastExecAt = startTime;
    }

    /**
     * Creates a new FuzzStats with a custom start time (for testing).
     */
    public FuzzStats(Instant startTime) {
        this.startTime = startTime;
        this.lastSnapshotTime = startTime;
        this.lastNewPathAt = startTime;
        this.lastExecAt = startTime;
    }

    /**
     * Records a single execution.
     */
    public void recordExec() {
        execsTotal.incrementAndGet();
        lastExecAt = Instant.now();
    }

    /**
     * Records multiple executions.
     */
    public void recordExecs(int count) {
        execsTotal.addAndGet(count);
        lastExecAt = Instant.now();
    }

    /**
     * Records a new interesting path.
     */
    public void recordNewPath() {
        totalPaths.incrementAndGet();
        lastNewPathAt = Instant.now();
    }

    /**
     * Records a crash.
     */
    public void recordCrash() {
        crashes.incrementAndGet();
    }

    /**
     * Records a hang (timeout).
     */
    public void recordHang() {
        hangs.incrementAndGet();
    }

    /**
     * Gets the total number of executions.
     */
    public long getExecsTotal() {
        return execsTotal.get();
    }

    /**
     * Gets the total number of interesting paths discovered.
     */
    public int getTotalPaths() {
        return totalPaths.get();
    }

    /**
     * Gets the total number of crashes.
     */
    public int getCrashes() {
        return crashes.get();
    }

    /**
     * Gets the total number of hangs.
     */
    public int getHangs() {
        return hangs.get();
    }

    /**
     * Gets the elapsed time since fuzzing started.
     */
    public Duration getElapsedTime() {
        return Duration.between(startTime, Instant.now());
    }

    /**
     * Gets the elapsed time in seconds.
     */
    public long getElapsedSeconds() {
        return getElapsedTime().toSeconds();
    }

    /**
     * Gets the time since the last new path was discovered.
     */
    public Duration getTimeSinceLastNewPath() {
        return Duration.between(lastNewPathAt, Instant.now());
    }

    /**
     * Gets the time since the last execution.
     */
    public Duration getTimeSinceLastExec() {
        return Duration.between(lastExecAt, Instant.now());
    }

    /**
     * Calculates the current executions per second.
     */
    public double getExecsPerSec() {
        long elapsed = getElapsedSeconds();
        if (elapsed == 0) {
            return 0.0;
        }
        return (double) execsTotal.get() / elapsed;
    }

    /**
     * Calculates the recent executions per second (since last snapshot).
     */
    public double getRecentExecsPerSec() {
        Instant now = Instant.now();
        long currentExecs = execsTotal.get();
        
        Duration sinceLast = Duration.between(lastSnapshotTime, now);
        if (sinceLast.toMillis() < 100) {
            // Too soon, return overall average
            return getExecsPerSec();
        }
        
        long deltaExecs = currentExecs - lastExecsSnapshot;
        double deltaSeconds = sinceLast.toMillis() / 1000.0;
        
        // Update snapshot
        lastExecsSnapshot = currentExecs;
        lastSnapshotTime = now;
        
        return deltaSeconds > 0 ? deltaExecs / deltaSeconds : 0.0;
    }

    /**
     * Gets the start time.
     */
    public Instant getStartTime() {
        return startTime;
    }

    /**
     * Gets the time when the last new path was discovered.
     */
    public Instant getLastNewPathAt() {
        return lastNewPathAt;
    }

    /**
     * Creates a snapshot of current stats as a StatsTick record.
     */
    public StatsTick toStatsTick(int queueSize) {
        return new StatsTick(
                getElapsedSeconds(),
                execsTotal.get(),
                getExecsPerSec(),
                queueSize,
                crashes.get(),
                hangs.get(),
                totalPaths.get(),
                getTimeSinceLastNewPath().toSeconds()
        );
    }

    @Override
    public String toString() {
        return String.format(
                "FuzzStats[execs=%d, paths=%d, crashes=%d, hangs=%d, elapsed=%ds, exec/s=%.1f]",
                execsTotal.get(),
                totalPaths.get(),
                crashes.get(),
                hangs.get(),
                getElapsedSeconds(),
                getExecsPerSec()
        );
    }
}
