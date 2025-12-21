package edu.nju.fuzzing.model;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Represents coverage data collected after a single execution.
 * This record is designed to be lightweight and immutable.
 *
 * @param execId          unique execution identifier
 * @param timestampMillis timestamp when coverage was collected
 * @param mapSize         size of the coverage bitmap
 * @param nonZeroBytes    number of non-zero bytes in current bitmap
 * @param newBytes        number of newly covered bytes (based on diff strategy)
 * @param bitmapHash      optional hash for quick comparison (0 if not computed)
 * @param interesting     whether this execution discovered new coverage
 */
public record Coverage(
        long execId,
        long timestampMillis,
        int mapSize,
        int nonZeroBytes,
        int newBytes,
        long bitmapHash,
        boolean interesting
) {
    private static final AtomicLong EXEC_ID_COUNTER = new AtomicLong(0);

    /**
     * Default map size when no actual coverage is available.
     */
    public static final int DEFAULT_MAP_SIZE = 65536;

    /**
     * Creates an empty coverage result (no coverage data available).
     *
     * @param result the execution result (currently unused, for future extensions)
     * @return an empty Coverage with zero values
     */
    public static Coverage empty(RunResult result) {
        return new Coverage(
                EXEC_ID_COUNTER.incrementAndGet(),
                System.currentTimeMillis(),
                DEFAULT_MAP_SIZE,
                0,
                0,
                0L,
                false
        );
    }

    /**
     * Creates a Coverage with explicit values.
     *
     * @param nonZeroBytes number of non-zero bytes
     * @param newBytes     number of new bytes discovered
     * @param interesting  whether this is interesting coverage
     * @return a new Coverage instance
     */
    public static Coverage of(int nonZeroBytes, int newBytes, boolean interesting) {
        return new Coverage(
                EXEC_ID_COUNTER.incrementAndGet(),
                System.currentTimeMillis(),
                DEFAULT_MAP_SIZE,
                nonZeroBytes,
                newBytes,
                0L,
                interesting
        );
    }

    /**
     * Creates a Coverage with explicit values including map size.
     *
     * @param mapSize      the bitmap size
     * @param nonZeroBytes number of non-zero bytes
     * @param newBytes     number of new bytes discovered
     * @param interesting  whether this is interesting coverage
     * @return a new Coverage instance
     */
    public static Coverage of(int mapSize, int nonZeroBytes, int newBytes, boolean interesting) {
        return new Coverage(
                EXEC_ID_COUNTER.incrementAndGet(),
                System.currentTimeMillis(),
                mapSize,
                nonZeroBytes,
                newBytes,
                0L,
                interesting
        );
    }
}
