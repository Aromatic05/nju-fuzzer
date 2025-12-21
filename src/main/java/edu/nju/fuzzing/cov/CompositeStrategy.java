package edu.nju.fuzzing.cov;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A composite coverage diff strategy that combines multiple strategies.
 *
 * The composite reports "interesting" if ANY of the underlying strategies
 * reports interesting. This allows combining different detection approaches
 * for more robust coverage tracking.
 *
 * Example usage:
 * - Combine SeenNonZeroStrategy with hash filtering
 * - Track both global and per-execution coverage simultaneously
 */
public class CompositeStrategy implements CoverageDiffStrategy {

    private final List<CoverageDiffStrategy> strategies;
    private final CombineMode mode;

    /**
     * Mode for combining strategy results.
     */
    public enum CombineMode {
        /**
         * Report interesting if ANY strategy reports interesting.
         * newBytes is the maximum across all strategies.
         */
        ANY,

        /**
         * Report interesting only if ALL strategies report interesting.
         * newBytes is the minimum across all strategies.
         */
        ALL,

        /**
         * Use only the first strategy's result.
         * Other strategies are still updated for tracking purposes.
         */
        FIRST
    }

    /**
     * Creates a composite strategy with ANY mode.
     *
     * @param strategies the strategies to combine
     */
    public CompositeStrategy(CoverageDiffStrategy... strategies) {
        this(CombineMode.ANY, strategies);
    }

    /**
     * Creates a composite strategy with specified combine mode.
     *
     * @param mode       how to combine results
     * @param strategies the strategies to combine
     */
    public CompositeStrategy(CombineMode mode, CoverageDiffStrategy... strategies) {
        if (strategies == null || strategies.length == 0) {
            throw new IllegalArgumentException("At least one strategy is required");
        }
        this.mode = mode;
        this.strategies = new ArrayList<>(Arrays.asList(strategies));
    }

    @Override
    public DiffResult diff(byte[] current) {
        if (current == null) {
            return DiffResult.EMPTY;
        }

        DiffResult[] results = new DiffResult[strategies.size()];
        for (int i = 0; i < strategies.size(); i++) {
            results[i] = strategies.get(i).diff(current);
        }

        return combineResults(results);
    }

    private DiffResult combineResults(DiffResult[] results) {
        switch (mode) {
            case ANY:
                int maxNewBytes = 0;
                boolean anyInteresting = false;
                for (DiffResult r : results) {
                    maxNewBytes = Math.max(maxNewBytes, r.newBytes());
                    anyInteresting = anyInteresting || r.interesting();
                }
                return new DiffResult(maxNewBytes, anyInteresting);

            case ALL:
                int minNewBytes = Integer.MAX_VALUE;
                boolean allInteresting = true;
                for (DiffResult r : results) {
                    minNewBytes = Math.min(minNewBytes, r.newBytes());
                    allInteresting = allInteresting && r.interesting();
                }
                if (minNewBytes == Integer.MAX_VALUE) {
                    minNewBytes = 0;
                }
                return new DiffResult(minNewBytes, allInteresting);

            case FIRST:
            default:
                return results[0];
        }
    }

    @Override
    public void reset() {
        for (CoverageDiffStrategy strategy : strategies) {
            strategy.reset();
        }
    }

    @Override
    public int totalSeenBytes() {
        // Return max across all strategies
        int max = 0;
        for (CoverageDiffStrategy strategy : strategies) {
            max = Math.max(max, strategy.totalSeenBytes());
        }
        return max;
    }

    /**
     * Returns the number of strategies in this composite.
     */
    public int size() {
        return strategies.size();
    }

    /**
     * Returns the strategy at the given index.
     */
    public CoverageDiffStrategy get(int index) {
        return strategies.get(index);
    }

    /**
     * Returns the combine mode.
     */
    public CombineMode getMode() {
        return mode;
    }

    /**
     * Creates a strategy combining global seen tracking with hash filtering.
     * This is the recommended configuration for Iteration 2.
     *
     * @param mapSize the bitmap size
     * @return optimized strategy with hash filtering
     */
    public static CoverageDiffStrategy createOptimized(int mapSize) {
        SeenNonZeroStrategy seenStrategy = new SeenNonZeroStrategy(mapSize);
        return new HashFilteredStrategy(seenStrategy, mapSize);
    }
}
