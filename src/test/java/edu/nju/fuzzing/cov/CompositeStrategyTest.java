package edu.nju.fuzzing.cov;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for CompositeStrategy.
 */
class CompositeStrategyTest {

    private static final int MAP_SIZE = 1024;

    @Test
    void testConstructorRequiresAtLeastOneStrategy() {
        assertThrows(IllegalArgumentException.class, () -> new CompositeStrategy());
        assertThrows(IllegalArgumentException.class,
                () -> new CompositeStrategy((CoverageDiffStrategy[]) null));
    }

    @Test
    void testSingleStrategyDelegates() {
        SeenNonZeroStrategy inner = new SeenNonZeroStrategy(MAP_SIZE);
        CompositeStrategy composite = new CompositeStrategy(inner);

        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;
        bitmap[100] = 5;

        CoverageDiffStrategy.DiffResult result = composite.diff(bitmap);

        assertEquals(2, result.newBytes());
        assertTrue(result.interesting());
    }

    @Test
    void testAnyModeReportsIfAnyInteresting() {
        SeenNonZeroStrategy strategy1 = new SeenNonZeroStrategy(MAP_SIZE);
        SeenNonZeroStrategy strategy2 = new SeenNonZeroStrategy(MAP_SIZE);

        // Pre-populate strategy1 so it won't find anything new
        byte[] initial = new byte[MAP_SIZE];
        initial[0] = 1;
        strategy1.diff(initial);

        CompositeStrategy composite = new CompositeStrategy(
                CompositeStrategy.CombineMode.ANY,
                strategy1, strategy2);

        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        CoverageDiffStrategy.DiffResult result = composite.diff(bitmap);

        // strategy1 reports 0 new, strategy2 reports 1 new
        // ANY mode: max(0, 1) = 1, interesting = false || true = true
        assertEquals(1, result.newBytes());
        assertTrue(result.interesting());
    }

    @Test
    void testAllModeRequiresBothInteresting() {
        SeenNonZeroStrategy strategy1 = new SeenNonZeroStrategy(MAP_SIZE);
        SeenNonZeroStrategy strategy2 = new SeenNonZeroStrategy(MAP_SIZE);

        // Pre-populate strategy1
        byte[] initial = new byte[MAP_SIZE];
        initial[0] = 1;
        strategy1.diff(initial);

        CompositeStrategy composite = new CompositeStrategy(
                CompositeStrategy.CombineMode.ALL,
                strategy1, strategy2);

        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        CoverageDiffStrategy.DiffResult result = composite.diff(bitmap);

        // strategy1 reports 0 new (not interesting), strategy2 reports 1 new
        // ALL mode: min(0, 1) = 0, interesting = false && true = false
        assertEquals(0, result.newBytes());
        assertFalse(result.interesting());
    }

    @Test
    void testAllModeBothInteresting() {
        SeenNonZeroStrategy strategy1 = new SeenNonZeroStrategy(MAP_SIZE);
        SeenNonZeroStrategy strategy2 = new SeenNonZeroStrategy(MAP_SIZE);

        CompositeStrategy composite = new CompositeStrategy(
                CompositeStrategy.CombineMode.ALL,
                strategy1, strategy2);

        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        CoverageDiffStrategy.DiffResult result = composite.diff(bitmap);

        // Both report 1 new
        assertEquals(1, result.newBytes());
        assertTrue(result.interesting());
    }

    @Test
    void testFirstModeUsesOnlyFirst() {
        SeenNonZeroStrategy strategy1 = new SeenNonZeroStrategy(MAP_SIZE);
        SeenNonZeroStrategy strategy2 = new SeenNonZeroStrategy(MAP_SIZE);

        // Pre-populate strategy1
        byte[] initial = new byte[MAP_SIZE];
        initial[0] = 1;
        strategy1.diff(initial);

        CompositeStrategy composite = new CompositeStrategy(
                CompositeStrategy.CombineMode.FIRST,
                strategy1, strategy2);

        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        CoverageDiffStrategy.DiffResult result = composite.diff(bitmap);

        // FIRST mode uses strategy1's result (not interesting)
        assertEquals(0, result.newBytes());
        assertFalse(result.interesting());

        // But strategy2 should still have been updated
        assertEquals(1, strategy2.totalSeenBytes());
    }

    @Test
    void testResetResetsAll() {
        SeenNonZeroStrategy strategy1 = new SeenNonZeroStrategy(MAP_SIZE);
        SeenNonZeroStrategy strategy2 = new SeenNonZeroStrategy(MAP_SIZE);
        CompositeStrategy composite = new CompositeStrategy(strategy1, strategy2);

        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;
        composite.diff(bitmap);

        assertEquals(1, strategy1.totalSeenBytes());
        assertEquals(1, strategy2.totalSeenBytes());

        composite.reset();

        assertEquals(0, strategy1.totalSeenBytes());
        assertEquals(0, strategy2.totalSeenBytes());
    }

    @Test
    void testTotalSeenBytesReturnsMax() {
        SeenNonZeroStrategy strategy1 = new SeenNonZeroStrategy(MAP_SIZE);
        SeenNonZeroStrategy strategy2 = new SeenNonZeroStrategy(MAP_SIZE);

        // Pre-populate strategy1 with more bytes
        byte[] initial = new byte[MAP_SIZE];
        initial[0] = 1;
        initial[1] = 1;
        initial[2] = 1;
        strategy1.diff(initial);

        CompositeStrategy composite = new CompositeStrategy(strategy1, strategy2);

        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;
        composite.diff(bitmap);

        // strategy1 has 3, strategy2 has 1
        assertEquals(3, composite.totalSeenBytes());
    }

    @Test
    void testSize() {
        SeenNonZeroStrategy s1 = new SeenNonZeroStrategy(MAP_SIZE);
        SeenNonZeroStrategy s2 = new SeenNonZeroStrategy(MAP_SIZE);
        SeenNonZeroStrategy s3 = new SeenNonZeroStrategy(MAP_SIZE);

        CompositeStrategy composite = new CompositeStrategy(s1, s2, s3);

        assertEquals(3, composite.size());
    }

    @Test
    void testGet() {
        SeenNonZeroStrategy s1 = new SeenNonZeroStrategy(MAP_SIZE);
        SeenNonZeroStrategy s2 = new SeenNonZeroStrategy(MAP_SIZE);

        CompositeStrategy composite = new CompositeStrategy(s1, s2);

        assertSame(s1, composite.get(0));
        assertSame(s2, composite.get(1));
    }

    @Test
    void testGetMode() {
        CompositeStrategy anyMode = new CompositeStrategy(
                CompositeStrategy.CombineMode.ANY,
                new SeenNonZeroStrategy(MAP_SIZE));
        CompositeStrategy allMode = new CompositeStrategy(
                CompositeStrategy.CombineMode.ALL,
                new SeenNonZeroStrategy(MAP_SIZE));

        assertEquals(CompositeStrategy.CombineMode.ANY, anyMode.getMode());
        assertEquals(CompositeStrategy.CombineMode.ALL, allMode.getMode());
    }

    @Test
    void testNullBitmapReturnsEmpty() {
        CompositeStrategy composite = new CompositeStrategy(
                new SeenNonZeroStrategy(MAP_SIZE));

        CoverageDiffStrategy.DiffResult result = composite.diff(null);

        assertEquals(CoverageDiffStrategy.DiffResult.EMPTY, result);
    }

    @Test
    void testCreateOptimized() {
        CoverageDiffStrategy optimized = CompositeStrategy.createOptimized(MAP_SIZE);

        assertNotNull(optimized);
        assertInstanceOf(HashFilteredStrategy.class, optimized);

        // Verify it works
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        CoverageDiffStrategy.DiffResult result = optimized.diff(bitmap);
        assertEquals(1, result.newBytes());
        assertTrue(result.interesting());
    }

    @Test
    void testMixedStrategies() {
        SeenNonZeroStrategy seenStrategy = new SeenNonZeroStrategy(MAP_SIZE);

        CompositeStrategy composite = new CompositeStrategy(seenStrategy);

        byte[] bitmap1 = new byte[MAP_SIZE];
        bitmap1[0] = 1;

        byte[] bitmap2 = new byte[MAP_SIZE];
        bitmap2[100] = 1;

        byte[] bitmap3 = new byte[MAP_SIZE];
        bitmap3[0] = 1;  // Back to position 0

        // First run
        CoverageDiffStrategy.DiffResult r1 = composite.diff(bitmap1);
        assertEquals(1, r1.newBytes());
        assertTrue(r1.interesting());

        // Second run - new position
        CoverageDiffStrategy.DiffResult r2 = composite.diff(bitmap2);
        assertEquals(1, r2.newBytes());
        assertTrue(r2.interesting());

        // Third run - position 0 again
        // seenStrategy: not interesting (already seen 0)
        // prevStrategy: interesting (prev was 100, now 0)
        // CoverageDiffStrategy.DiffResult r3 = composite.diff(bitmap3);
        // assertEquals(1, r3.newBytes());  // From prevStrategy
        // assertTrue(r3.interesting());     // ANY mode
    }
}
