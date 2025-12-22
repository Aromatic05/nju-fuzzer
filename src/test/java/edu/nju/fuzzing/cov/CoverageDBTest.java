package edu.nju.fuzzing.cov;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for CoverageDB.
 */
class CoverageDBTest {

    private static final int MAP_SIZE = 1000;
    private CoverageDB db;

    @BeforeEach
    void setUp() {
        db = new CoverageDB(MAP_SIZE);
    }

    @Test
    @DisplayName("initial state is empty")
    void initialState_isEmpty() {
        assertEquals(0, db.getTotalEdgesSeen());
        assertEquals(0, db.getFavoredCount());
        assertEquals(0, db.getTotalExecs());
    }

    @Test
    @DisplayName("update with new edges marks them as interesting")
    void update_newEdges_markedInteresting() {
        EdgeSet hitEdges = EdgeSet.of(1, 2, 3);
        DiffResultEx diff = DiffResultEx.of(hitEdges, hitEdges, hitEdges.size(), 123L);

        CoverageDB.UpdateResult result = db.update(1L, diff, 100, 1000L);

        assertTrue(result.isInteresting());
        assertEquals(3, result.newEdges().size());
        assertEquals(3, db.getTotalEdgesSeen());
    }

    @Test
    @DisplayName("update with seen edges is not interesting")
    void update_seenEdges_notInteresting() {
        EdgeSet hitEdges = EdgeSet.of(1, 2, 3);
        DiffResultEx diff1 = DiffResultEx.of(hitEdges, hitEdges, hitEdges.size(), 123L);
        db.update(1L, diff1, 100, 1000L);

        // Second execution with same edges
        DiffResultEx diff2 = DiffResultEx.of(EdgeSet.empty(), hitEdges, hitEdges.size(), 123L);
        CoverageDB.UpdateResult result = db.update(2L, diff2, 100, 1000L);

        assertFalse(result.isInteresting());
        assertEquals(0, result.newEdges().size());
    }

    @Test
    @DisplayName("edge frequency is tracked correctly")
    void edgeFrequency_trackedCorrectly() {
        EdgeSet edges1 = EdgeSet.of(1, 2, 3);
        EdgeSet edges2 = EdgeSet.of(2, 3, 4);
        EdgeSet edges3 = EdgeSet.of(3, 4, 5);

        db.update(1L, DiffResultEx.of(edges1, edges1, edges1.size(), 1L), 100, 1000L);
        db.update(2L, DiffResultEx.of(EdgeSet.empty(), edges2, edges2.size(), 2L), 100, 1000L);
        db.update(3L, DiffResultEx.of(EdgeSet.empty(), edges3, edges3.size(), 3L), 100, 1000L);

        assertEquals(1, db.getEdgeFrequency(1));  // Only in edges1
        assertEquals(2, db.getEdgeFrequency(2));  // In edges1, edges2
        assertEquals(3, db.getEdgeFrequency(3));  // In all three
        assertEquals(2, db.getEdgeFrequency(4));  // In edges2, edges3
        assertEquals(1, db.getEdgeFrequency(5));  // Only in edges3
    }

    @Test
    @DisplayName("topRated prefers smaller input by default")
    void topRated_prefersSmallest() {
        EdgeSet edges = EdgeSet.of(1);

        // First seed with large input
        db.update(1L, DiffResultEx.of(edges, edges, edges.size(), 1L), 1000, 1000L);

        // Second seed with smaller input
        db.update(2L, DiffResultEx.of(EdgeSet.empty(), edges, edges.size(), 2L), 100, 1000L);

        CoverageDB.TopRatedEntry topRated = db.getTopRated(1);
        assertNotNull(topRated);
        assertEquals(2L, topRated.seedId());  // Smaller input wins
    }

    @Test
    @DisplayName("favored set is updated correctly")
    void favoredSet_updatedCorrectly() {
        EdgeSet edges1 = EdgeSet.of(1, 2);
        EdgeSet edges2 = EdgeSet.of(3, 4);

        db.update(1L, DiffResultEx.of(edges1, edges1, edges1.size(), 1L), 100, 1000L);
        db.update(2L, DiffResultEx.of(edges2, edges2, edges2.size(), 2L), 100, 1000L);

        assertTrue(db.isFavored(1L));
        assertTrue(db.isFavored(2L));
        assertEquals(2, db.getFavoredCount());
    }

    @Test
    @DisplayName("calculateRarityScore favors rare edges")
    void calculateRarityScore_favorsRareEdges() {
        // Edge 1 hit 10 times, edge 2 hit once
        for (int i = 0; i < 10; i++) {
            EdgeSet edges = EdgeSet.of(1);
            db.update(i, DiffResultEx.of(i == 0 ? edges : EdgeSet.empty(), edges, edges.size(), i), 100, 1000L);
        }
        EdgeSet rare = EdgeSet.of(2);
        db.update(100L, DiffResultEx.of(rare, rare, rare.size(), 100L), 100, 1000L);

        EdgeSet common = EdgeSet.of(1);
        EdgeSet rareEdge = EdgeSet.of(2);

        double commonScore = db.calculateRarityScore(common);
        double rareScore = db.calculateRarityScore(rareEdge);

        assertTrue(rareScore > commonScore);
    }

    @Test
    @DisplayName("getMinFrequency returns minimum")
    void getMinFrequency_returnsMinimum() {
        EdgeSet edges1 = EdgeSet.of(1);
        EdgeSet edges2 = EdgeSet.of(1, 2);

        // Edge 1 hit twice, edge 2 hit once
        db.update(1L, DiffResultEx.of(edges1, edges1, edges1.size(), 1L), 100, 1000L);
        db.update(2L, DiffResultEx.of(EdgeSet.of(2), edges2, edges2.size(), 2L), 100, 1000L);

        assertEquals(1, db.getMinFrequency(EdgeSet.of(1, 2)));
        assertEquals(2, db.getMinFrequency(EdgeSet.of(1)));
    }

    @Test
    @DisplayName("isRedundant identifies redundant seeds")
    void isRedundant_identifiesRedundant() {
        EdgeSet edges1 = EdgeSet.of(1, 2, 3);
        EdgeSet edges2 = EdgeSet.of(1);  // Subset of edges1

        // Seed 1 covers more with smaller input
        db.update(1L, DiffResultEx.of(edges1, edges1, edges1.size(), 1L), 50, 1000L);

        // Seed 2 covers less
        db.update(2L, DiffResultEx.of(EdgeSet.empty(), edges2, edges2.size(), 2L), 100, 1000L);

        assertFalse(db.isRedundant(1L, edges1));  // Favored, not redundant
        assertTrue(db.isRedundant(2L, edges2));   // All edges covered by seed 1
    }

    @Test
    @DisplayName("getStats returns correct statistics")
    void getStats_returnsCorrectStats() {
        EdgeSet edges = EdgeSet.of(1, 2, 3);
        db.update(1L, DiffResultEx.of(edges, edges, edges.size(), 1L), 100, 1000L);
        db.update(2L, DiffResultEx.of(EdgeSet.empty(), edges, edges.size(), 2L), 100, 1000L);

        CoverageDB.CoverageDBStats stats = db.getStats();

        assertEquals(MAP_SIZE, stats.mapSize());
        assertEquals(3, stats.totalEdgesSeen());
        assertEquals(1, stats.favoredCount());
        assertEquals(2, stats.totalExecs());
    }

    @Test
    @DisplayName("hasSeenEdge returns correct result")
    void hasSeenEdge_returnsCorrect() {
        EdgeSet edges = EdgeSet.of(5, 10, 15);
        db.update(1L, DiffResultEx.of(edges, edges, edges.size(), 1L), 100, 1000L);

        assertTrue(db.hasSeenEdge(5));
        assertTrue(db.hasSeenEdge(10));
        assertTrue(db.hasSeenEdge(15));
        assertFalse(db.hasSeenEdge(1));
        assertFalse(db.hasSeenEdge(100));
    }
}
