package edu.nju.fuzzing.cov;

import java.util.Arrays;

/**
 * Coverage diff strategy that compares against the previous execution's bitmap.
 *
 * Unlike SeenNonZeroStrategy which tracks all-time coverage, this strategy
 * only compares the current bitmap against the immediately previous one.
 * This can be useful for:
 * - Detecting per-execution coverage changes
 * - Debugging and analysis
 * - Comparison with global seen strategy
 *
 * Note: This strategy may report "interesting" for inputs that don't actually
 * provide new global coverage (e.g., same paths executed in different order).
 * For production fuzzing, SeenNonZeroStrategy is recommended.
 */
public class PrevBitmapStrategy implements CoverageDiffStrategy {

    private final int mapSize;
    private byte[] prevBitmap;
    private int totalSeen;

    /**
     * Creates a new strategy with the given map size.
     *
     * @param mapSize the size of the bitmap in bytes
     */
    public PrevBitmapStrategy(int mapSize) {
        if (mapSize <= 0) {
            throw new IllegalArgumentException("mapSize must be positive: " + mapSize);
        }
        this.mapSize = mapSize;
        this.prevBitmap = null;
        this.totalSeen = 0;
    }

    @Override
    public DiffResult diff(byte[] current) {
        if (current == null) {
            return DiffResult.EMPTY;
        }

        int effectiveSize = Math.min(mapSize, current.length);

        // First run - everything is new
        if (prevBitmap == null) {
            prevBitmap = new byte[mapSize];
            int newBytes = 0;
            for (int i = 0; i < effectiveSize; i++) {
                if ((current[i] & 0xFF) != 0) {
                    newBytes++;
                }
            }
            System.arraycopy(current, 0, prevBitmap, 0, effectiveSize);
            totalSeen = newBytes;
            return new DiffResult(newBytes, newBytes > 0);
        }

        // Compare with previous bitmap
        int newBytes = 0;
        for (int i = 0; i < effectiveSize; i++) {
            int curVal = current[i] & 0xFF;
            int prevVal = prevBitmap[i] & 0xFF;

            // New byte: was zero before, now non-zero
            if (curVal != 0 && prevVal == 0) {
                newBytes++;
            }
        }

        // Update prevBitmap for next comparison
        System.arraycopy(current, 0, prevBitmap, 0, effectiveSize);

        // Update total seen (approximate - for display purposes)
        if (newBytes > 0) {
            totalSeen += newBytes;
        }

        return new DiffResult(newBytes, newBytes > 0);
    }

    @Override
    public void reset() {
        prevBitmap = null;
        totalSeen = 0;
    }

    @Override
    public int totalSeenBytes() {
        return totalSeen;
    }

    /**
     * Returns a copy of the previous bitmap for inspection.
     *
     * @return copy of previous bitmap, or null if no execution yet
     */
    public byte[] getPrevBitmap() {
        return prevBitmap == null ? null : Arrays.copyOf(prevBitmap, mapSize);
    }

    /**
     * Returns the map size.
     */
    public int getMapSize() {
        return mapSize;
    }
}
