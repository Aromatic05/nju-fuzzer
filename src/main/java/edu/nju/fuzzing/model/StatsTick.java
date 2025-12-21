package edu.nju.fuzzing.model;

/**
 * A snapshot of fuzzer statistics at a point in time.
 * 
 * @param elapsedSec elapsed time in seconds since fuzzing started
 * @param execsTotal total number of executions
 * @param execsPerSec average executions per second
 * @param queueSize current queue size (interesting inputs)
 * @param crashes total number of crashes found
 * @param hangs total number of hangs (timeouts) found
 * @param totalPaths total number of unique paths discovered
 * @param lastNewPathSecAgo seconds since last new path was discovered
 */
public record StatsTick(
        long elapsedSec,
        long execsTotal,
        double execsPerSec,
        int queueSize,
        int crashes,
        int hangs,
        int totalPaths,
        long lastNewPathSecAgo
) {
    /**
     * Creates a StatsTick with default values for new fields (backward compatibility).
     */
    public StatsTick(
            long elapsedSec,
            long execsTotal,
            double execsPerSec,
            int queueSize,
            int crashes,
            int hangs
    ) {
        this(elapsedSec, execsTotal, execsPerSec, queueSize, crashes, hangs, queueSize, 0);
    }

    /**
     * Formats as a single-line status string.
     */
    public String toStatusLine() {
        return String.format(
                "[%s] execs: %d | exec/s: %.1f | paths: %d | crashes: %d | hangs: %d | last_path: %ds ago",
                formatDuration(elapsedSec),
                execsTotal,
                execsPerSec,
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

