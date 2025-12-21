package edu.nju.fuzzing.cov;

/**
 * Strategy interface for comparing coverage bitmaps and determining
 * if new coverage has been discovered.
 *
 * This abstraction allows different comparison strategies:
 * - Simple "non-zero bytes" comparison (SeenNonZeroStrategy)
 * - Hash-filtered comparison for performance (HashFilteredStrategy)
 * - Previous bitmap comparison (PrevBitmapStrategy)
 * - Composite strategies (CompositeStrategy)
 * - Bucket-based hitcount comparison for Iteration 4 (AFL++ style)
 *
 * @see SeenNonZeroStrategy
 * @see HashFilteredStrategy
 * @see PrevBitmapStrategy
 * @see CompositeStrategy
 */
public interface CoverageDiffStrategy {

    /**
     * Compares the current bitmap against previously seen coverage
     * and returns the diff result.
     *
     * @param current the current bitmap (reusable buffer)
     * @return the diff result containing newBytes count and interesting flag
     */
    DiffResult diff(byte[] current);

    /**
     * Resets the strategy state (clears seen coverage).
     */
    void reset();

    /**
     * Returns total unique bytes ever seen.
     *
     * @return count of unique bytes seen
     */
    int totalSeenBytes();

    /**
     * Wraps this strategy with hash-based filtering for improved performance.
     * Executions with identical bitmap hashes will be skipped.
     *
     * @param mapSize the bitmap size
     * @return a hash-filtered version of this strategy
     */
    default CoverageDiffStrategy withHashFilter(int mapSize) {
        return new HashFilteredStrategy(this, mapSize);
    }

    /**
     * Creates a composite strategy combining this strategy with others.
     *
     * @param others additional strategies to combine
     * @return a composite strategy
     */
    default CoverageDiffStrategy combineWith(CoverageDiffStrategy... others) {
        CoverageDiffStrategy[] all = new CoverageDiffStrategy[others.length + 1];
        all[0] = this;
        System.arraycopy(others, 0, all, 1, others.length);
        return new CompositeStrategy(all);
    }

    /**
     * Result of a coverage diff operation.
     *
     * @param newBytes    number of newly covered bytes in this execution
     * @param interesting whether this execution discovered new coverage
     */
    record DiffResult(int newBytes, boolean interesting) {
        public static final DiffResult EMPTY = new DiffResult(0, false);

        /**
         * Combines two diff results, taking the maximum of each field.
         */
        public DiffResult merge(DiffResult other) {
            return new DiffResult(
                    Math.max(this.newBytes, other.newBytes),
                    this.interesting || other.interesting
            );
        }
    }

    /**
     * Factory method to create the recommended strategy for production use.
     * Uses SeenNonZeroStrategy with hash filtering.
     *
     * @param mapSize the bitmap size
     * @return optimized production strategy
     */
    static CoverageDiffStrategy createDefault(int mapSize) {
        return new SeenNonZeroStrategy(mapSize).withHashFilter(mapSize);
    }

    /**
     * Factory method to create a simple strategy without optimizations.
     * Useful for testing and debugging.
     *
     * @param mapSize the bitmap size
     * @return simple SeenNonZeroStrategy
     */
    static CoverageDiffStrategy createSimple(int mapSize) {
        return new SeenNonZeroStrategy(mapSize);
    }
}
