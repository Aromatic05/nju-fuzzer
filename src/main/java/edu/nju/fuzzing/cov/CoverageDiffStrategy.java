package edu.nju.fuzzing.cov;

/**
 * Strategy interface for comparing coverage bitmaps and determining
 * if new coverage has been discovered.
 *
 * This abstraction allows different comparison strategies:
 * - Simple "non-zero bytes" comparison
 * - Global "seen" set comparison
 * - Bucket-based hitcount comparison (AFL++ style)
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
     * Result of a coverage diff operation.
     *
     * @param newBytes    number of newly covered bytes in this execution
     * @param interesting whether this execution discovered new coverage
     */
    record DiffResult(int newBytes, boolean interesting) {
        public static final DiffResult EMPTY = new DiffResult(0, false);
    }
}
