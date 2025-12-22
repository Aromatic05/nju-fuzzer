package edu.nju.fuzzing.cov;

import java.util.BitSet;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Extended coverage diff strategy that provides edge-level detail.
 * 
 * This interface extends the basic CoverageDiffStrategy to provide
 * the detailed information needed for seed scheduling:
 * - New edge indices (not just count)
 * - All hit edges
 * - Support for CoverageDB integration
 * 
 * Implementations can extend existing strategies by wrapping them.
 */
public interface CoverageDiffStrategyEx extends CoverageDiffStrategy {

    /**
     * Computes extended diff result with edge-level detail.
     *
     * @param current the current bitmap
     * @return extended diff result with edge indices
     */
    DiffResultEx diffEx(byte[] current);

    /**
     * Default implementation that delegates to diffEx().
     */
    @Override
    default DiffResult diff(byte[] current) {
        return diffEx(current).toBasic();
    }

    /**
     * Returns the global seen edges as a BitSet.
     * Used for CoverageDB initialization.
     */
    BitSet getSeenBitSet();

    /**
     * Checks if a specific edge has been seen.
     */
    boolean hasSeenEdge(int edgeIndex);

    // ========== Factory Methods ==========

    /**
     * Creates the default extended strategy (SeenNonZero with edge tracking).
     */
    static CoverageDiffStrategyEx createDefault(int mapSize) {
        return new SeenNonZeroStrategyEx(mapSize);
    }

    /**
     * Wraps an existing strategy to add extended functionality.
     * The wrapper will track edges but delegate interesting logic to base.
     */
    static CoverageDiffStrategyEx wrap(CoverageDiffStrategy base, int mapSize) {
        if (base instanceof CoverageDiffStrategyEx ex) {
            return ex;
        }
        return new WrappedStrategyEx(base, mapSize);
    }

    // ========== Implementation: SeenNonZero with edge tracking ==========

    /**
     * SeenNonZeroStrategy with full edge tracking support.
     */
    class SeenNonZeroStrategyEx implements CoverageDiffStrategyEx {
        private final int mapSize;
        private final BitSet seen;
        private final AtomicLong totalSeen = new AtomicLong(0);

        public SeenNonZeroStrategyEx(int mapSize) {
            this.mapSize = mapSize;
            this.seen = new BitSet(mapSize);
        }

        @Override
        public DiffResultEx diffEx(byte[] current) {
            if (current == null || current.length < mapSize) {
                return DiffResultEx.EMPTY;
            }

            // Collect hit edges and new edges
            int[] hitBuffer = new int[mapSize];
            int[] newBuffer = new int[mapSize];
            int hitCount = 0;
            int newCount = 0;

            synchronized (seen) {
                for (int i = 0; i < mapSize; i++) {
                    if (current[i] != 0) {
                        hitBuffer[hitCount++] = i;
                        if (!seen.get(i)) {
                            seen.set(i);
                            newBuffer[newCount++] = i;
                            totalSeen.incrementAndGet();
                        }
                    }
                }
            }

            // Build EdgeSets
            EdgeSet hitEdges = hitCount > 0 
                    ? EdgeSet.of(java.util.Arrays.copyOf(hitBuffer, hitCount))
                    : EdgeSet.empty();
            EdgeSet newEdges = newCount > 0
                    ? EdgeSet.of(java.util.Arrays.copyOf(newBuffer, newCount))
                    : EdgeSet.empty();

            // Compute hash
            long hash = XxHash64.hash(current, 0, mapSize);

            return DiffResultEx.of(newEdges, hitEdges, hash);
        }

        @Override
        public void reset() {
            synchronized (seen) {
                seen.clear();
                totalSeen.set(0);
            }
        }

        @Override
        public int totalSeenBytes() {
            return (int) totalSeen.get();
        }

        @Override
        public BitSet getSeenBitSet() {
            synchronized (seen) {
                return (BitSet) seen.clone();
            }
        }

        @Override
        public boolean hasSeenEdge(int edgeIndex) {
            synchronized (seen) {
                return seen.get(edgeIndex);
            }
        }
    }

    // ========== Implementation: Wrapper for existing strategies ==========

    /**
     * Wraps an existing CoverageDiffStrategy to add edge tracking.
     */
    class WrappedStrategyEx implements CoverageDiffStrategyEx {
        private final CoverageDiffStrategy delegate;
        private final int mapSize;
        private final BitSet seen;

        public WrappedStrategyEx(CoverageDiffStrategy delegate, int mapSize) {
            this.delegate = delegate;
            this.mapSize = mapSize;
            this.seen = new BitSet(mapSize);
        }

        @Override
        public DiffResultEx diffEx(byte[] current) {
            // Delegate for interesting logic
            DiffResult basic = delegate.diff(current);

            // Track edges ourselves
            int[] hitBuffer = new int[mapSize];
            int[] newBuffer = new int[mapSize];
            int hitCount = 0;
            int newCount = 0;

            synchronized (seen) {
                for (int i = 0; i < mapSize; i++) {
                    if (current[i] != 0) {
                        hitBuffer[hitCount++] = i;
                        if (!seen.get(i)) {
                            seen.set(i);
                            newBuffer[newCount++] = i;
                        }
                    }
                }
            }

            EdgeSet hitEdges = hitCount > 0 
                    ? EdgeSet.of(java.util.Arrays.copyOf(hitBuffer, hitCount))
                    : EdgeSet.empty();
            EdgeSet newEdges = newCount > 0
                    ? EdgeSet.of(java.util.Arrays.copyOf(newBuffer, newCount))
                    : EdgeSet.empty();

            long hash = XxHash64.hash(current, 0, mapSize);

            // Use delegate's interesting decision
            return new DiffResultEx(
                    basic.newBytes(),
                    newEdges,
                    hitEdges,
                    basic.interesting(),
                    hash
            );
        }

        @Override
        public void reset() {
            delegate.reset();
            synchronized (seen) {
                seen.clear();
            }
        }

        @Override
        public int totalSeenBytes() {
            return delegate.totalSeenBytes();
        }

        @Override
        public BitSet getSeenBitSet() {
            synchronized (seen) {
                return (BitSet) seen.clone();
            }
        }

        @Override
        public boolean hasSeenEdge(int edgeIndex) {
            synchronized (seen) {
                return seen.get(edgeIndex);
            }
        }
    }
}
