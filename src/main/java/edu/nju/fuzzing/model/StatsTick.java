package edu.nju.fuzzing.model;

/**
 * A snapshot of fuzzer statistics at a point in time.
 * Compliant with the "Fuzzing Logging Specification".
 */
public record StatsTick(
        String targetName,      // [新增] 必填：目标名称
        long elapsedSec,        // [对应 timestamp]
        long execsTotal,        // [对应 exec_count]
        int coveredEdges,       // [新增] 必填：已覆盖边数
        double execsPerSec,     // [对应 execs_per_sec]
        int queueSize,          // [对应 queue_size]
    int totalPaths,         // interesting inputs 数量
        int crashes,            // [对应 crash_count]
        int hangs,              // [对应 hang_count]
        long lastNewPathSecAgo  // [辅助] 距离上次发现新路径的秒数
) {
    /**
     * Backward-compatible constructor (without totalPaths).
     * Older tests/builders construct StatsTick with 9 fields.
     */
    public StatsTick(
            String targetName,
            long elapsedSec,
            long execsTotal,
            int coveredEdges,
            double execsPerSec,
            int queueSize,
            int crashes,
            int hangs,
            long lastNewPathSecAgo
    ) {
        this(targetName, elapsedSec, execsTotal, coveredEdges, execsPerSec, queueSize, 0, crashes, hangs, lastNewPathSecAgo);
    }

    /**
     * Formats as a single-line status string for console output.
     */
    public String toStatusLine() {
        return String.format(
                "[%s][%s] cov: %d | execs: %d | spd: %.0f/s | queue: %d | paths: %d | crash: %d | hang: %d | last: %ds ago",
                targetName,
                formatDuration(elapsedSec),
                coveredEdges,
                execsTotal,
                execsPerSec,
                queueSize,
                totalPaths,
                crashes,
                hangs,
                lastNewPathSecAgo
        );
    }

    private static String formatDuration(long seconds) {
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        long secs = seconds % 60;
        return String.format("%02d:%02d:%02d", hours, minutes, secs);
    }
}