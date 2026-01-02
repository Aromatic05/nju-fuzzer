package edu.nju.fuzzing.cov;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for CoverageDiffStrategy interface default methods and factories.
 */
class CoverageDiffStrategyTest {

    private static final int MAP_SIZE = 1024;

    @Test
    void testDiffResultEmpty() {
        CoverageDiffStrategy.DiffResult empty = CoverageDiffStrategy.DiffResult.EMPTY;

        assertEquals(0, empty.newBytes());
        assertFalse(empty.interesting());
    }

    @Test
    void testDiffResultMerge() {
        CoverageDiffStrategy.DiffResult r1 = new CoverageDiffStrategy.DiffResult(5, true);
        CoverageDiffStrategy.DiffResult r2 = new CoverageDiffStrategy.DiffResult(3, false);

        CoverageDiffStrategy.DiffResult merged = r1.merge(r2);

        assertEquals(5, merged.newBytes());  // max(5, 3)
        assertTrue(merged.interesting());     // true || false
    }

    @Test
    void testDiffResultMergeBothNotInteresting() {
        CoverageDiffStrategy.DiffResult r1 = new CoverageDiffStrategy.DiffResult(0, false);
        CoverageDiffStrategy.DiffResult r2 = new CoverageDiffStrategy.DiffResult(0, false);

        CoverageDiffStrategy.DiffResult merged = r1.merge(r2);

        assertEquals(0, merged.newBytes());
        assertFalse(merged.interesting());
    }

    @Test
    void testWithHashFilter() {
        SeenNonZeroStrategy base = new SeenNonZeroStrategy(MAP_SIZE);
        CoverageDiffStrategy filtered = base.withHashFilter(MAP_SIZE);

        assertInstanceOf(HashFilteredStrategy.class, filtered);

        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        // First call
        CoverageDiffStrategy.DiffResult r1 = filtered.diff(bitmap);
        assertEquals(1, r1.newBytes());
        assertTrue(r1.interesting());

        // Second call with same bitmap - should be filtered
        CoverageDiffStrategy.DiffResult r2 = filtered.diff(bitmap);
        assertEquals(0, r2.newBytes());
        assertFalse(r2.interesting());
    }

    @Test
    void testCombineWith() {
        SeenNonZeroStrategy s1 = new SeenNonZeroStrategy(MAP_SIZE);
        SeenNonZeroStrategy s2 = new SeenNonZeroStrategy(MAP_SIZE);
        SeenNonZeroStrategy s3 = new SeenNonZeroStrategy(MAP_SIZE);

        CoverageDiffStrategy combined = s1.combineWith(s2, s3);

        assertInstanceOf(CompositeStrategy.class, combined);
        CompositeStrategy composite = (CompositeStrategy) combined;

        assertEquals(3, composite.size());
        assertSame(s1, composite.get(0));
        assertSame(s2, composite.get(1));
        assertSame(s3, composite.get(2));
    }

    @Test
    void testCreateDefault() {
        CoverageDiffStrategy strategy = CoverageDiffStrategy.createDefault(MAP_SIZE);

        assertInstanceOf(HashFilteredStrategy.class, strategy);

        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);
        assertEquals(1, result.newBytes());
        assertTrue(result.interesting());
    }

    @Test
    void testCreateSimple() {
        CoverageDiffStrategy strategy = CoverageDiffStrategy.createSimple(MAP_SIZE);

        assertInstanceOf(SeenNonZeroStrategy.class, strategy);

        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);
        assertEquals(1, result.newBytes());
        assertTrue(result.interesting());

        // Simple strategy doesn't have hash filtering
        // Second call with same bitmap still updates (but finds no new)
        CoverageDiffStrategy.DiffResult result2 = strategy.diff(bitmap);
        assertEquals(0, result2.newBytes());
        assertFalse(result2.interesting());
    }

    @Test
    void testChainedDecorators() {
        // Create a strategy with multiple decorators
        CoverageDiffStrategy strategy = new SeenNonZeroStrategy(MAP_SIZE)
                .withHashFilter(MAP_SIZE);

        byte[] bitmap1 = new byte[MAP_SIZE];
        bitmap1[0] = 1;

        byte[] bitmap2 = new byte[MAP_SIZE];
        bitmap2[0] = 1;
        bitmap2[100] = 5;

        // First call
        CoverageDiffStrategy.DiffResult r1 = strategy.diff(bitmap1);
        assertEquals(1, r1.newBytes());
        assertTrue(r1.interesting());

        // Same bitmap - filtered
        CoverageDiffStrategy.DiffResult r2 = strategy.diff(bitmap1);
        assertEquals(0, r2.newBytes());
        assertFalse(r2.interesting());

        // Different bitmap - new coverage found
        CoverageDiffStrategy.DiffResult r3 = strategy.diff(bitmap2);
        assertEquals(1, r3.newBytes());  // Only position 100 is new
        assertTrue(r3.interesting());
    }

    @Test
    void testStrategyComparison() {
        // Compare behavior of SeenNonZero vs PrevBitmap
        SeenNonZeroStrategy seenStrategy = new SeenNonZeroStrategy(MAP_SIZE);

        byte[] bitmap1 = new byte[MAP_SIZE];
        bitmap1[0] = 1;

        byte[] bitmap2 = new byte[MAP_SIZE];
        bitmap2[100] = 1;

        byte[] bitmap3 = new byte[MAP_SIZE];
        bitmap3[0] = 1;  // Same as bitmap1

        // First run - both find new coverage
        assertTrue(seenStrategy.diff(bitmap1).interesting());

        // Second run - both find new coverage (different position)
        assertTrue(seenStrategy.diff(bitmap2).interesting());

        // Third run - position 0 again
        // SeenNonZero: NOT interesting (already seen)
        // PrevBitmap: interesting (different from prev which was 100)
        assertFalse(seenStrategy.diff(bitmap3).interesting());
    }
}
