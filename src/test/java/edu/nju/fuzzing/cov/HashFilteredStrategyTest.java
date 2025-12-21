package edu.nju.fuzzing.cov;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for HashFilteredStrategy.
 */
class HashFilteredStrategyTest {

    private static final int MAP_SIZE = 1024;
    private SeenNonZeroStrategy delegate;
    private HashFilteredStrategy strategy;

    @BeforeEach
    void setUp() {
        delegate = new SeenNonZeroStrategy(MAP_SIZE);
        strategy = new HashFilteredStrategy(delegate, MAP_SIZE);
    }

    @Test
    void testConstructorValidation() {
        assertThrows(IllegalArgumentException.class,
                () -> new HashFilteredStrategy(null, MAP_SIZE));
        assertThrows(IllegalArgumentException.class,
                () -> new HashFilteredStrategy(delegate, 0));
        assertThrows(IllegalArgumentException.class,
                () -> new HashFilteredStrategy(delegate, -1));
    }

    @Test
    void testFirstRunAlwaysDelegates() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;
        bitmap[100] = 5;

        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);

        assertEquals(2, result.newBytes());
        assertTrue(result.interesting());
        assertEquals(2, strategy.totalSeenBytes());
    }

    @Test
    void testIdenticalBitmapSkipsComparison() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;
        bitmap[100] = 5;

        // First call
        CoverageDiffStrategy.DiffResult result1 = strategy.diff(bitmap);
        assertEquals(2, result1.newBytes());
        assertTrue(result1.interesting());

        // Second call with identical bitmap - should skip (hash same)
        CoverageDiffStrategy.DiffResult result2 = strategy.diff(bitmap);
        assertEquals(0, result2.newBytes());
        assertFalse(result2.interesting());
    }

    @Test
    void testDifferentBitmapDelegates() {
        byte[] bitmap1 = new byte[MAP_SIZE];
        bitmap1[0] = 1;

        byte[] bitmap2 = new byte[MAP_SIZE];
        bitmap2[0] = 1;
        bitmap2[200] = 10;  // New byte

        // First call
        strategy.diff(bitmap1);

        // Second call with different bitmap
        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap2);
        assertEquals(1, result.newBytes());  // Only position 200 is new
        assertTrue(result.interesting());
    }

    @Test
    void testHashChangesWithDifferentValues() {
        byte[] bitmap1 = new byte[MAP_SIZE];
        bitmap1[0] = 1;

        byte[] bitmap2 = new byte[MAP_SIZE];
        bitmap2[0] = 2;  // Same position, different value

        strategy.diff(bitmap1);
        long hash1 = strategy.getPrevHash();

        strategy.diff(bitmap2);
        long hash2 = strategy.getPrevHash();

        // Hashes should be different (though this is technically value-dependent)
        assertNotEquals(hash1, hash2);
    }

    @Test
    void testResetClearsState() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        strategy.diff(bitmap);
        assertEquals(1, strategy.totalSeenBytes());

        strategy.reset();

        assertEquals(0, strategy.totalSeenBytes());

        // After reset, same bitmap should be interesting again
        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);
        assertEquals(1, result.newBytes());
        assertTrue(result.interesting());
    }

    @Test
    void testNullBitmapReturnsEmpty() {
        CoverageDiffStrategy.DiffResult result = strategy.diff(null);
        assertEquals(CoverageDiffStrategy.DiffResult.EMPTY, result);
    }

    @Test
    void testGetDelegate() {
        assertSame(delegate, strategy.getDelegate());
    }

    @Test
    void testTotalSeenBytesDelegatesToUnderlying() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;
        bitmap[1] = 1;
        bitmap[2] = 1;

        strategy.diff(bitmap);

        assertEquals(3, strategy.totalSeenBytes());
        assertEquals(delegate.totalSeenBytes(), strategy.totalSeenBytes());
    }

    @Test
    void testEmptyBitmapOptimization() {
        byte[] empty1 = new byte[MAP_SIZE];
        byte[] empty2 = new byte[MAP_SIZE];

        // First empty bitmap
        CoverageDiffStrategy.DiffResult result1 = strategy.diff(empty1);
        assertFalse(result1.interesting());

        // Second empty bitmap - hash should be same, skip
        CoverageDiffStrategy.DiffResult result2 = strategy.diff(empty2);
        assertFalse(result2.interesting());
    }

    @Test
    void testChainedHashFiltering() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[50] = 1;

        // Many repeated calls should all return empty after first
        strategy.diff(bitmap);

        for (int i = 0; i < 100; i++) {
            CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);
            assertEquals(0, result.newBytes());
            assertFalse(result.interesting());
        }
    }
}
