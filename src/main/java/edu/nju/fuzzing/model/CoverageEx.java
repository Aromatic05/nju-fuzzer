package edu.nju.fuzzing.model;

import edu.nju.fuzzing.cov.EdgeSet;
import edu.nju.fuzzing.cov.DiffResultEx;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Extended coverage data with edge-level detail for seed scheduling.
 * 
 * This extends the basic Coverage with:
 * - Hit edges (all edges covered in this execution)
 * - New edges (edges that were never seen before)
 * - Stability flag
 * 
 * Used by CoverageDB and PowerScheduler for advanced scheduling.
 */
public record CoverageEx(
        /** Unique execution identifier */
        long execId,

        /** Timestamp when coverage was collected */
        long timestampMillis,

        /** Size of the coverage bitmap */
        int mapSize,

        /** Number of non-zero bytes in current bitmap (total edges hit) */
        int nonZeroBytes,

        /** Number of newly covered bytes/edges */
        int newBytes,

        /** Hash of the bitmap for quick comparison */
        long bitmapHash,

        /** Whether this execution discovered new coverage */
        boolean interesting,

        /** All edges hit in this execution */
        EdgeSet hitEdges,

        /** New edges discovered in this execution (subset of hitEdges) */
        EdgeSet newEdges,

        /** Execution time in nanoseconds (for perf scoring) */
        long execTimeNanos,

        /** Whether this trace is stable (same coverage on re-execution) */
        boolean stable
) {
    private static final AtomicLong EXEC_ID_COUNTER = new AtomicLong(0);

    /** Default map size */
    public static final int DEFAULT_MAP_SIZE = 65536;

    /**
     * Creates an empty coverage (no coverage data available).
     */
    public static CoverageEx empty(RunResult result) {
        return new CoverageEx(
                EXEC_ID_COUNTER.incrementAndGet(),
                System.currentTimeMillis(),
                DEFAULT_MAP_SIZE,
                0, 0, 0L, false,
                EdgeSet.empty(),
                EdgeSet.empty(),
                result != null ? result.execTimeMs() * 1_000_000L : 0L,
                true
        );
    }

    /**
     * Creates CoverageEx from DiffResultEx.
     */
    public static CoverageEx from(DiffResultEx diff, RunResult result, int mapSize) {
        return new CoverageEx(
                EXEC_ID_COUNTER.incrementAndGet(),
                System.currentTimeMillis(),
                mapSize,
                diff.hitEdges().size(),
                diff.newCount(),
                diff.bitmapHash(),
                diff.interesting(),
                diff.hitEdges(),
                diff.newEdges(),
                result != null ? result.execTimeMs() * 1_000_000L : 0L,
                true  // Assume stable by default
        );
    }

    /**
     * Creates CoverageEx with all fields specified.
     */
    public static CoverageEx of(
            int mapSize,
            EdgeSet hitEdges,
            EdgeSet newEdges,
            long bitmapHash,
            long execTimeNanos,
            boolean stable
    ) {
        return new CoverageEx(
                EXEC_ID_COUNTER.incrementAndGet(),
                System.currentTimeMillis(),
                mapSize,
                hitEdges.size(),
                newEdges.size(),
                bitmapHash,
                !newEdges.isEmpty(),
                hitEdges,
                newEdges,
                execTimeNanos,
                stable
        );
    }

    /**
     * Converts to basic Coverage (for backward compatibility).
     */
    public Coverage toBasic() {
        return new Coverage(
                execId,
                timestampMillis,
                mapSize,
                nonZeroBytes,
                newBytes,
                bitmapHash,
                interesting
        );
    }

    /**
     * Creates from basic Coverage (with empty edge sets).
     */
    public static CoverageEx fromBasic(Coverage basic) {
        return new CoverageEx(
                basic.execId(),
                basic.timestampMillis(),
                basic.mapSize(),
                basic.nonZeroBytes(),
                basic.newBytes(),
                basic.bitmapHash(),
                basic.interesting(),
                EdgeSet.empty(),
                EdgeSet.empty(),
                0L,
                true
        );
    }

    /**
     * Returns the edge count (alias for hitEdges.size()).
     */
    public int edgeCount() {
        return hitEdges.size();
    }

    /**
     * Returns the new edge count (alias for newEdges.size()).
     */
    public int newEdgeCount() {
        return newEdges.size();
    }

    /**
     * Marks this coverage as unstable.
     */
    public CoverageEx markUnstable() {
        return new CoverageEx(
                execId, timestampMillis, mapSize,
                nonZeroBytes, newBytes, bitmapHash, interesting,
                hitEdges, newEdges, execTimeNanos,
                false
        );
    }
}
