package edu.nju.fuzzing.cov;

import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.RunResult;

import java.util.concurrent.atomic.AtomicLong;

/**
 * CoverageMonitor implementation that reads coverage data from AFL++ shared memory.
 * This is the main implementation for Iteration 1, providing:
 * - Attachment to System V shared memory bitmap
 * - Coverage diff calculation using "seen non-zero bytes" strategy
 * - Statistics tracking for monitoring fuzzing progress
 */
public class ShmCoverageMonitor implements CoverageMonitor {

    private final BitmapSource bitmapSource;
    private final CoverageDiffStrategy diffStrategy;
    private final int mapSize;
    private final byte[] bitmapBuffer;

    // Statistics
    private final AtomicLong execCounter = new AtomicLong(0);
    private final AtomicLong lastInterestingExecId = new AtomicLong(0);
    private volatile long lastInterestingAtMillis = 0;
    private volatile long startTimeMillis = 0;

    /**
     * Creates a ShmCoverageMonitor with the given bitmap source and diff strategy.
     *
     * @param bitmapSource the source for reading bitmap data
     * @param diffStrategy the strategy for comparing coverage
     */
    public ShmCoverageMonitor(BitmapSource bitmapSource, CoverageDiffStrategy diffStrategy) {
        this.bitmapSource = bitmapSource;
        this.diffStrategy = diffStrategy;
        this.mapSize = bitmapSource.mapSize();
        this.bitmapBuffer = new byte[mapSize];
    }

    /**
     * Creates a ShmCoverageMonitor from environment variables.
     * Uses __AFL_SHM_ID and AFL_MAP_SIZE environment variables.
     *
     * @return a new ShmCoverageMonitor configured from environment
     */
    public static ShmCoverageMonitor fromEnvironment() {
        SysVShmBitmapSource bitmapSource = SysVShmBitmapSource.fromEnvironment();
        bitmapSource.attach();
        SeenNonZeroStrategy diffStrategy = new SeenNonZeroStrategy(bitmapSource.mapSize());
        return new ShmCoverageMonitor(bitmapSource, diffStrategy);
    }

    /**
     * Creates a ShmCoverageMonitor with explicit shared memory ID.
     *
     * @param shmId   the System V shared memory ID
     * @param mapSize the size of the bitmap
     * @return a new ShmCoverageMonitor
     */
    public static ShmCoverageMonitor create(int shmId, int mapSize) {
        SysVShmBitmapSource bitmapSource = new SysVShmBitmapSource(shmId, mapSize);
        bitmapSource.attach();
        SeenNonZeroStrategy diffStrategy = new SeenNonZeroStrategy(mapSize);
        return new ShmCoverageMonitor(bitmapSource, diffStrategy);
    }

    /**
     * Initializes the monitor and starts tracking.
     */
    public void start() {
        startTimeMillis = System.currentTimeMillis();
        if (bitmapSource instanceof SysVShmBitmapSource shmSource) {
            if (!shmSource.isAttached()) {
                shmSource.attach();
            }
        }
    }

    @Override
    public void beforeRun() {
        // Clear the bitmap before each run if supported
        if (bitmapSource.isAttached()) {
            bitmapSource.clear();
        }
    }

    @Override
    public Coverage afterRun(RunResult result) {
        long execId = execCounter.incrementAndGet();
        long timestamp = System.currentTimeMillis();

        // Read bitmap from shared memory
        int nonZeroBytes = 0;
        int newBytes = 0;
        boolean interesting = false;
        long bitmapHash = 0;

        if (bitmapSource.isAttached()) {
            bitmapSource.readInto(bitmapBuffer);

            // Calculate non-zero bytes and hash
            nonZeroBytes = countNonZeroBytes(bitmapBuffer);
            bitmapHash = calculateHash(bitmapBuffer);

            // Use diff strategy to determine new coverage
            CoverageDiffStrategy.DiffResult diffResult = diffStrategy.diff(bitmapBuffer);
            newBytes = diffResult.newBytes();
            interesting = diffResult.interesting();

            // Update statistics
            if (interesting) {
                lastInterestingExecId.set(execId);
                lastInterestingAtMillis = timestamp;
            }
        }

        return new Coverage(
                execId,
                timestamp,
                mapSize,
                nonZeroBytes,
                newBytes,
                bitmapHash,
                interesting
        );
    }

    /**
     * Returns a snapshot of current coverage statistics.
     */
    public CoverageStats snapshotStats() {
        long execs = execCounter.get();
        long elapsed = System.currentTimeMillis() - startTimeMillis;
        double execsPerSec = elapsed > 0 ? (execs * 1000.0 / elapsed) : 0;

        return new CoverageStats(
                execs,
                execsPerSec,
                lastInterestingExecId.get(),
                lastInterestingAtMillis,
                diffStrategy.totalSeenBytes()
        );
    }

    /**
     * Returns the total number of unique bytes seen across all executions.
     */
    public int getTotalSeenBytes() {
        return diffStrategy.totalSeenBytes();
    }

    /**
     * Returns the map size.
     */
    public int getMapSize() {
        return mapSize;
    }

    @Override
    public void close() {
        bitmapSource.close();
    }

    /**
     * Counts non-zero bytes in the bitmap.
     */
    private int countNonZeroBytes(byte[] bitmap) {
        int count = 0;
        for (int i = 0; i < mapSize && i < bitmap.length; i++) {
            if ((bitmap[i] & 0xFF) != 0) {
                count++;
            }
        }
        return count;
    }

    /**
     * Calculates a simple hash of the bitmap for quick comparison.
     * Uses a variant of FNV-1a hash.
     */
    private long calculateHash(byte[] bitmap) {
        long hash = 0xcbf29ce484222325L; // FNV-1a offset basis
        for (int i = 0; i < mapSize && i < bitmap.length; i++) {
            if ((bitmap[i] & 0xFF) != 0) {
                hash ^= (bitmap[i] & 0xFF);
                hash *= 0x100000001b3L; // FNV-1a prime
            }
        }
        return hash;
    }

    /**
     * Statistics snapshot for coverage monitoring.
     */
    public record CoverageStats(
            long execs,
            double execsPerSec,
            long lastInterestingExecId,
            long lastInterestingAtMillis,
            int totalSeenBytes
    ) {}
}
