package edu.nju.fuzzing.cov;

import java.util.BitSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Global coverage database for seed scheduling and energy calculation.
 * 
 * This component maintains:
 * - Edge frequency: how many times each edge has been hit
 * - Top-rated seeds: for each edge, which seed covers it "best"
 * - Favored set: seeds that are top-rated for at least one edge
 * 
 * This is the "CoverageDB" that sits between CoverageMonitor and Scheduler.
 * 
 * Thread-safe for concurrent updates.
 */
public class CoverageDB {

    /**
     * Criteria for determining "best" seed for an edge.
     */
    public enum TopRatedCriteria {
        /** Prefer seeds with smaller input size (faster execution) */
        SMALLEST_INPUT,
        /** Prefer seeds that were added more recently */
        MOST_RECENT,
        /** Prefer seeds that cover fewer total edges (more focused) */
        FEWEST_EDGES,
        /** Prefer seeds with fastest execution time */
        FASTEST_EXEC
    }

    /**
     * Information about a top-rated seed for an edge.
     */
    public record TopRatedEntry(
            long seedId,
            int inputSize,
            long addedAtMillis,
            int edgeCount,
            long execTimeNanos
    ) {
        /**
         * Compares this entry with another based on the given criteria.
         * Returns true if this entry is "better" than the other.
         */
        public boolean isBetterThan(TopRatedEntry other, TopRatedCriteria criteria) {
            return switch (criteria) {
                case SMALLEST_INPUT -> this.inputSize < other.inputSize;
                case MOST_RECENT -> this.addedAtMillis > other.addedAtMillis;
                case FEWEST_EDGES -> this.edgeCount < other.edgeCount;
                case FASTEST_EXEC -> this.execTimeNanos < other.execTimeNanos;
            };
        }
    }

    /**
     * Result of updating the database with new coverage.
     */
    public record UpdateResult(
            /** Edges that are new (never seen before) */
            EdgeSet newEdges,
            /** Edges where this seed became top-rated */
            EdgeSet becameTopRated,
            /** Whether the favored set changed */
            boolean favoredChanged,
            /** Whether this seed is now favored */
            boolean isFavored
    ) {
        public boolean isInteresting() {
            return !newEdges.isEmpty();
        }
    }

    // ========== State ==========

    private final int mapSize;
    private final TopRatedCriteria criteria;

    /** Global bitmap of all seen edges */
    private final BitSet globalSeen;

    /** How many times each edge has been hit (for rarity calculation) */
    private final AtomicInteger[] edgeFrequency;

    /** For each edge, the top-rated seed covering it */
    private final TopRatedEntry[] topRated;

    /** Set of seed IDs that are currently favored */
    private final Set<Long> favoredSeeds = ConcurrentHashMap.newKeySet();

    /** Total executions processed */
    private final AtomicLong totalExecs = new AtomicLong(0);

    /** Lock for topRated updates */
    private final Object topRatedLock = new Object();

    // ========== Constructor ==========

    public CoverageDB(int mapSize) {
        this(mapSize, TopRatedCriteria.SMALLEST_INPUT);
    }

    public CoverageDB(int mapSize, TopRatedCriteria criteria) {
        this.mapSize = mapSize;
        this.criteria = criteria;
        this.globalSeen = new BitSet(mapSize);
        this.edgeFrequency = new AtomicInteger[mapSize];
        this.topRated = new TopRatedEntry[mapSize];

        for (int i = 0; i < mapSize; i++) {
            edgeFrequency[i] = new AtomicInteger(0);
        }
    }

    // ========== Core Operations ==========

    /**
     * Updates the database with coverage from a new execution.
     * 
     * @param seedId     ID of the seed that was fuzzed
     * @param diffResult extended diff result with edge information
     * @param inputSize  size of the input in bytes
     * @param execTimeNanos execution time in nanoseconds
     * @return update result with changes made
     */
    public UpdateResult update(long seedId, DiffResultEx diffResult, 
                               int inputSize, long execTimeNanos) {
        totalExecs.incrementAndGet();

        EdgeSet hitEdges = diffResult.hitEdges();
        EdgeSet newEdges;
        EdgeSet becameTopRated;
        boolean favoredChanged = false;

        // Track which edges are truly new (vs what strategy thinks)
        int[] newBuffer = new int[hitEdges.size()];
        int newCount = 0;

        int[] topRatedBuffer = new int[hitEdges.size()];
        int topRatedCount = 0;

        TopRatedEntry thisEntry = new TopRatedEntry(
                seedId, inputSize, System.currentTimeMillis(), 
                hitEdges.size(), execTimeNanos
        );

        synchronized (topRatedLock) {
            for (int edge : hitEdges) {
                // Update frequency
                edgeFrequency[edge].incrementAndGet();

                // Check if truly new
                if (!globalSeen.get(edge)) {
                    globalSeen.set(edge);
                    newBuffer[newCount++] = edge;
                }

                // Check if this seed should become top-rated for this edge
                TopRatedEntry current = topRated[edge];
                if (current == null || thisEntry.isBetterThan(current, criteria)) {
                    // Remove old seed from favored if it loses all its edges
                    if (current != null) {
                        // We'll recalculate favored at the end
                        favoredChanged = true;
                    }
                    topRated[edge] = thisEntry;
                    topRatedBuffer[topRatedCount++] = edge;
                    favoredChanged = true;
                }
            }

            // Update favored set if changed
            if (favoredChanged) {
                recalculateFavored();
            }
        }

        newEdges = newCount > 0 
                ? EdgeSet.of(java.util.Arrays.copyOf(newBuffer, newCount))
                : EdgeSet.empty();
        becameTopRated = topRatedCount > 0
                ? EdgeSet.of(java.util.Arrays.copyOf(topRatedBuffer, topRatedCount))
                : EdgeSet.empty();

        boolean isFavored = favoredSeeds.contains(seedId);

        return new UpdateResult(newEdges, becameTopRated, favoredChanged, isFavored);
    }

    /**
     * Recalculates the favored set from topRated entries.
     * Must be called with topRatedLock held.
     */
    private void recalculateFavored() {
        favoredSeeds.clear();
        for (int i = 0; i < mapSize; i++) {
            if (topRated[i] != null) {
                favoredSeeds.add(topRated[i].seedId());
            }
        }
    }

    // ========== Query Methods ==========

    /**
     * Returns the frequency (hit count) for a specific edge.
     * Used for rarity-based scheduling.
     */
    public int getEdgeFrequency(int edgeIndex) {
        if (edgeIndex < 0 || edgeIndex >= mapSize) {
            return 0;
        }
        return edgeFrequency[edgeIndex].get();
    }

    /**
     * Calculates the rarity score for a set of edges.
     * Lower frequency = higher rarity = more valuable.
     * 
     * @param edges the edges to score
     * @return sum of (1.0 / frequency) for each edge
     */
    public double calculateRarityScore(EdgeSet edges) {
        double score = 0.0;
        for (int edge : edges) {
            int freq = edgeFrequency[edge].get();
            if (freq > 0) {
                score += 1.0 / freq;
            }
        }
        return score;
    }

    /**
     * Returns the minimum frequency among the given edges.
     * Used to find "rarest edge" in a seed's coverage.
     */
    public int getMinFrequency(EdgeSet edges) {
        int min = Integer.MAX_VALUE;
        for (int edge : edges) {
            int freq = edgeFrequency[edge].get();
            if (freq < min) {
                min = freq;
            }
        }
        return min == Integer.MAX_VALUE ? 0 : min;
    }

    /**
     * Returns true if the given seed is in the favored set.
     */
    public boolean isFavored(long seedId) {
        return favoredSeeds.contains(seedId);
    }

    /**
     * Returns the current favored seed IDs.
     */
    public Set<Long> getFavoredSeeds() {
        return Set.copyOf(favoredSeeds);
    }

    /**
     * Returns the number of favored seeds.
     */
    public int getFavoredCount() {
        return favoredSeeds.size();
    }

    /**
     * Returns the top-rated entry for a specific edge.
     */
    public TopRatedEntry getTopRated(int edgeIndex) {
        if (edgeIndex < 0 || edgeIndex >= mapSize) {
            return null;
        }
        synchronized (topRatedLock) {
            return topRated[edgeIndex];
        }
    }

    /**
     * Returns the total number of unique edges seen.
     */
    public int getTotalEdgesSeen() {
        return globalSeen.cardinality();
    }

    /**
     * Returns a copy of the global seen bitset.
     */
    public BitSet getGlobalSeenBitSet() {
        synchronized (topRatedLock) {
            return (BitSet) globalSeen.clone();
        }
    }

    /**
     * Checks if a specific edge has ever been seen.
     */
    public boolean hasSeenEdge(int edgeIndex) {
        if (edgeIndex < 0 || edgeIndex >= mapSize) {
            return false;
        }
        return globalSeen.get(edgeIndex);
    }

    /**
     * Returns the total number of executions processed.
     */
    public long getTotalExecs() {
        return totalExecs.get();
    }

    // ========== Queue Culling ==========

    /**
     * Performs queue culling: identifies which seeds are "redundant".
     * A seed is redundant if all its edges are covered by favored seeds.
     * 
     * @param seedId    the seed to check
     * @param seedEdges the edges covered by this seed
     * @return true if this seed is redundant and can be deprioritized
     */
    public boolean isRedundant(long seedId, EdgeSet seedEdges) {
        if (favoredSeeds.contains(seedId)) {
            return false;  // Favored seeds are never redundant
        }

        // Check if all edges are covered by other favored seeds
        synchronized (topRatedLock) {
            for (int edge : seedEdges) {
                TopRatedEntry tr = topRated[edge];
                if (tr == null || tr.seedId() == seedId) {
                    // This seed is the best for this edge
                    return false;
                }
            }
        }

        return true;  // All edges covered by other seeds
    }

    // ========== Statistics ==========

    /**
     * Returns a summary of the coverage database state.
     */
    public CoverageDBStats getStats() {
        int totalEdges = getTotalEdgesSeen();
        int favored = getFavoredCount();
        long execs = getTotalExecs();

        // Calculate average frequency
        double avgFreq = 0;
        int nonZeroCount = 0;
        for (int i = 0; i < mapSize; i++) {
            int freq = edgeFrequency[i].get();
            if (freq > 0) {
                avgFreq += freq;
                nonZeroCount++;
            }
        }
        if (nonZeroCount > 0) {
            avgFreq /= nonZeroCount;
        }

        return new CoverageDBStats(mapSize, totalEdges, favored, execs, avgFreq);
    }

    /**
     * Statistics snapshot for CoverageDB.
     */
    public record CoverageDBStats(
            int mapSize,
            int totalEdgesSeen,
            int favoredCount,
            long totalExecs,
            double avgEdgeFrequency
    ) {}
}
