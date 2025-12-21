package edu.nju.fuzzing.cov;

import java.util.BitSet;

/**
 * Coverage diff strategy based on "seen non-zero bytes".
 * Tracks which byte positions have ever been non-zero (covered)
 * and reports new coverage when previously unseen positions become non-zero.
 *
 * This is the recommended strategy for Iteration 1, providing a simple
 * but effective way to detect new coverage.
 */
public class SeenNonZeroStrategy implements CoverageDiffStrategy {

    private final BitSet seen;
    private final int mapSize;

    /**
     * Creates a new strategy with the given map size.
     *
     * @param mapSize the size of the bitmap in bytes
     */
    public SeenNonZeroStrategy(int mapSize) {
        if (mapSize <= 0) {
            throw new IllegalArgumentException("mapSize must be positive: " + mapSize);
        }
        this.mapSize = mapSize;
        this.seen = new BitSet(mapSize);
    }

    @Override
    public DiffResult diff(byte[] current) {
        if (current == null) {
            return DiffResult.EMPTY;
        }

        int effectiveSize = Math.min(mapSize, current.length);
        int newBytes = 0;

        for (int i = 0; i < effectiveSize; i++) {
            // Check if byte is non-zero and not previously seen
            if ((current[i] & 0xFF) != 0 && !seen.get(i)) {
                seen.set(i);
                newBytes++;
            }
        }

        return new DiffResult(newBytes, newBytes > 0);
    }

    @Override
    public void reset() {
        seen.clear();
    }

    @Override
    public int totalSeenBytes() {
        return seen.cardinality();
    }

    /**
     * Returns the map size this strategy was created with.
     */
    public int getMapSize() {
        return mapSize;
    }

    /**
     * Checks if a specific position has been seen.
     *
     * @param index the byte position to check
     * @return true if this position has been non-zero at least once
     */
    public boolean isSeen(int index) {
        if (index < 0 || index >= mapSize) {
            throw new IndexOutOfBoundsException("Index: " + index + ", MapSize: " + mapSize);
        }
        return seen.get(index);
    }
}
