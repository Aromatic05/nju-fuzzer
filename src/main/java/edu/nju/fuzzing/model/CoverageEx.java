package edu.nju.fuzzing.model;

import edu.nju.fuzzing.cov.EdgeSet;
import edu.nju.fuzzing.cov.DiffResultEx;

/**
 * Extended coverage data with edge-level detail for seed scheduling.
 * 
 * This extends the basic Coverage with:
 * - Hit edges (all edges covered in this execution)
 * - New edges (edges that were never seen before)
 * - Stability flag
 * 
 * Used by CoverageDB and PowerScheduler for advanced scheduling.
 * 
 * IMPORTANT: execId should be generated externally by the execution harness,
 * not internally by this class, to ensure consistency across components.
 */
public record CoverageEx(
        /** Unique execution identifier (from harness) */
        long execId,

        /** Timestamp when coverage was collected */
        long timestampMillis,

        /** Size of the coverage bitmap */
        int mapSize,

        /** Number of non-zero bytes in bitmap (AFL++ style counting) */
        int nonZeroBytes,

        /** Number of newly covered edges */
        int newEdgeCount,

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

        /** Stability status of this trace */
        Stability stability
) {
    /**
     * Stability status for coverage traces.
     */
    public enum Stability {
        /** Stability not yet determined */
        UNKNOWN,
        /** Trace is stable (same coverage on re-execution) */
        STABLE,
        /** Trace is unstable (different coverage on re-execution) */
        UNSTABLE
    }

    /**
     * Creates an empty coverage (no coverage data available).
     * 
     * @param execId Execution ID from harness
     * @param mapSize Coverage map size
     * @param execTimeNanos Execution time in nanoseconds
     */
    public static CoverageEx empty(long execId, int mapSize, long execTimeNanos) {
        return new CoverageEx(
                execId,
                System.currentTimeMillis(),
                mapSize,
                0, 0, 0L, false,
                EdgeSet.empty(),
                EdgeSet.empty(),
                execTimeNanos,
                Stability.UNKNOWN
        );
    }

    /**
     * Creates CoverageEx from DiffResultEx and RunResult.
     * 
     * @param diff Diff result with edge information
     * @param result Run result with execution metadata
     * @param stability Stability status (UNKNOWN if not checked)
     */
    public static CoverageEx from(DiffResultEx diff, RunResult result, Stability stability) {
        return new CoverageEx(
                result.execId(),
                System.currentTimeMillis(),
                result.inputFile() != null ? 65536 : 65536, // TODO: get from monitor
                diff.nonZeroBytes(),
                diff.newCount(),
                diff.bitmapHash(),
                diff.interesting(),
                diff.hitEdges(),
                diff.newEdges(),
                result.execTimeNanos(),
                stability
        );
    }
    
    /**
     * Creates CoverageEx from DiffResultEx and RunResult with UNKNOWN stability.
     */
    public static CoverageEx from(DiffResultEx diff, RunResult result, int mapSize) {
        return new CoverageEx(
                result.execId(),
                System.currentTimeMillis(),
                mapSize,
                diff.nonZeroBytes(),
                diff.newCount(),
                diff.bitmapHash(),
                diff.interesting(),
                diff.hitEdges(),
                diff.newEdges(),
                result.execTimeNanos(),
                Stability.UNKNOWN
        );
    }

    /**
     * Creates CoverageEx with all fields specified.
     */
    public static CoverageEx of(
            long execId,
            int mapSize,
            EdgeSet hitEdges,
            EdgeSet newEdges,
            int nonZeroBytes,
            long bitmapHash,
            long execTimeNanos,
            Stability stability
    ) {
        return new CoverageEx(
                execId,
                System.currentTimeMillis(),
                mapSize,
                nonZeroBytes,
                newEdges.size(),
                bitmapHash,
                !newEdges.isEmpty(),
                hitEdges,
                newEdges,
                execTimeNanos,
                stability
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
                newEdgeCount,
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
                Stability.UNKNOWN
        );
    }

    /**
     * Returns the edge count (alias for hitEdges.size()).
     */
    public int edgeCount() {
        return hitEdges.size();
    }

    /**
     * Marks this coverage as unstable.
     */
    public CoverageEx markUnstable() {
        return new CoverageEx(
                execId, timestampMillis, mapSize,
                nonZeroBytes, newEdgeCount, bitmapHash, interesting,
                hitEdges, newEdges, execTimeNanos,
                Stability.UNSTABLE
        );
    }
    
    /**
     * Marks this coverage as stable.
     */
    public CoverageEx markStable() {
        return new CoverageEx(
                execId, timestampMillis, mapSize,
                nonZeroBytes, newEdgeCount, bitmapHash, interesting,
                hitEdges, newEdges, execTimeNanos,
                Stability.STABLE
        );
    }
    
    /**
     * Checks if this trace is stable.
     */
    public boolean isStable() {
        return stability == Stability.STABLE;
    }
    
    /**
     * Checks if this trace is unstable.
     */
    public boolean isUnstable() {
        return stability == Stability.UNSTABLE;
    }
}
