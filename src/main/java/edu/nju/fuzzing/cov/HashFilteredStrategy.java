package edu.nju.fuzzing.cov;

/**
 * A strategy decorator that uses bitmap hashing to quickly filter out
 * executions that produce identical coverage to the previous run.
 *
 * This optimization reduces CPU overhead by avoiding full bitmap comparison
 * when the hash indicates no change. Only when the hash differs does it
 * delegate to the wrapped strategy for detailed comparison.
 *
 * Hash collision note: Using a 64-bit hash, collisions are extremely rare
 * but theoretically possible. In practice, this is acceptable for fuzzing
 * as missing a rare interesting input is not critical.
 */
public class HashFilteredStrategy implements CoverageDiffStrategy {

    private final CoverageDiffStrategy delegate;
    private final int mapSize;
    private long prevHash;
    private boolean firstRun;

    /**
     * Creates a hash-filtered wrapper around another strategy.
     *
     * @param delegate the underlying strategy to use when hash differs
     * @param mapSize  the size of the bitmap
     */
    public HashFilteredStrategy(CoverageDiffStrategy delegate, int mapSize) {
        if (delegate == null) {
            throw new IllegalArgumentException("delegate cannot be null");
        }
        if (mapSize <= 0) {
            throw new IllegalArgumentException("mapSize must be positive: " + mapSize);
        }
        this.delegate = delegate;
        this.mapSize = mapSize;
        this.prevHash = 0;
        this.firstRun = true;
    }

    @Override
    public DiffResult diff(byte[] current) {
        if (current == null) {
            return DiffResult.EMPTY;
        }

        long currentHash = calculateHash(current);

        // First run or hash changed - do full comparison
        if (firstRun || currentHash != prevHash) {
            firstRun = false;
            prevHash = currentHash;
            return delegate.diff(current);
        }

        // Hash unchanged - bitmap is (very likely) identical, skip comparison
        return DiffResult.EMPTY;
    }

    @Override
    public void reset() {
        delegate.reset();
        prevHash = 0;
        firstRun = true;
    }

    @Override
    public int totalSeenBytes() {
        return delegate.totalSeenBytes();
    }

    /**
     * Returns the number of times hash comparison saved a full diff.
     * Useful for performance monitoring.
     */
    public long getPrevHash() {
        return prevHash;
    }

    /**
     * Calculates FNV-1a hash of the bitmap (only non-zero bytes contribute).
     * This is the same hash algorithm used in ShmCoverageMonitor.
     */
    private long calculateHash(byte[] bitmap) {
        long hash = 0xcbf29ce484222325L; // FNV-1a offset basis
        int effectiveSize = Math.min(mapSize, bitmap.length);

        for (int i = 0; i < effectiveSize; i++) {
            int val = bitmap[i] & 0xFF;
            if (val != 0) {
                hash ^= val;
                hash *= 0x100000001b3L; // FNV-1a prime
                // Also incorporate position for better distribution
                hash ^= i;
                hash *= 0x100000001b3L;
            }
        }
        return hash;
    }

    /**
     * Returns the underlying delegate strategy.
     */
    public CoverageDiffStrategy getDelegate() {
        return delegate;
    }
}
