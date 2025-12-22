package edu.nju.fuzzing.cov;

/**
 * Extended diff result that includes edge-level detail for seed scheduling.
 * 
 * This extends the basic DiffResult with:
 * - New edge indices (not just count)
 * - All hit edge indices
 * - Non-zero bytes count (bitmap-level)
 * 
 * Used by CoverageDB for topRated/favored calculations.
 */
public record DiffResultEx(
        /**
         * Number of newly covered edges in this execution.
         */
        int newCount,

        /**
         * Indices of newly covered edges.
         * Empty if newCount == 0.
         */
        EdgeSet newEdges,

        /**
         * All edges hit in this execution (non-zero bytes in bitmap).
         */
        EdgeSet hitEdges,
        
        /**
         * Number of non-zero bytes in bitmap (AFL++ style counting).
         * This may differ from hitEdges.size() depending on strategy.
         */
        int nonZeroBytes,

        /**
         * Whether this execution discovered new coverage.
         */
        boolean interesting,

        /**
         * Hash of the bitmap for quick comparison.
         * 0 if not computed.
         */
        long bitmapHash
) {
    /**
     * Empty result with no coverage.
     */
    public static final DiffResultEx EMPTY = new DiffResultEx(
            0, EdgeSet.empty(), EdgeSet.empty(), 0, false, 0L
    );

    /**
     * Creates a result from basic diff info (backward compatible).
     */
    public static DiffResultEx fromBasic(int newCount, boolean interesting, int nonZeroBytes) {
        return new DiffResultEx(
                newCount,
                EdgeSet.empty(),  // No edge detail
                EdgeSet.empty(),
                nonZeroBytes,
                interesting,
                0L
        );
    }

    /**
     * Creates a result with full edge information.
     */
    public static DiffResultEx of(EdgeSet newEdges, EdgeSet hitEdges, int nonZeroBytes, long bitmapHash) {
        return new DiffResultEx(
                newEdges.size(),
                newEdges,
                hitEdges,
                nonZeroBytes,
                !newEdges.isEmpty(),
                bitmapHash
        );
    }

    /**
     * Returns the total number of edges hit in this execution.
     */
    public int hitCount() {
        return hitEdges.size();
    }

    /**
     * Converts to basic DiffResult for backward compatibility.
     */
    public CoverageDiffStrategy.DiffResult toBasic() {
        return new CoverageDiffStrategy.DiffResult(newCount, interesting);
    }
}
