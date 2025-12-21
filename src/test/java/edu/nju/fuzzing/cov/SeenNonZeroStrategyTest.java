package edu.nju.fuzzing.cov;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for SeenNonZeroStrategy.
 */
class SeenNonZeroStrategyTest {

    private static final int MAP_SIZE = 1024;
    private SeenNonZeroStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new SeenNonZeroStrategy(MAP_SIZE);
    }

    @Test
    void testConstructorValidatesMapSize() {
        assertThrows(IllegalArgumentException.class, () -> new SeenNonZeroStrategy(0));
        assertThrows(IllegalArgumentException.class, () -> new SeenNonZeroStrategy(-1));
        assertDoesNotThrow(() -> new SeenNonZeroStrategy(1));
    }

    @Test
    void testEmptyBitmapReturnsNoNewBytes() {
        byte[] bitmap = new byte[MAP_SIZE];
        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);

        assertEquals(0, result.newBytes());
        assertFalse(result.interesting());
        assertEquals(0, strategy.totalSeenBytes());
    }

    @Test
    void testNullBitmapReturnsEmptyResult() {
        CoverageDiffStrategy.DiffResult result = strategy.diff(null);

        assertEquals(0, result.newBytes());
        assertFalse(result.interesting());
    }

    @Test
    void testFirstNonZeroBytesAreNew() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;
        bitmap[100] = 5;
        bitmap[500] = (byte) 255;

        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);

        assertEquals(3, result.newBytes());
        assertTrue(result.interesting());
        assertEquals(3, strategy.totalSeenBytes());
    }

    @Test
    void testSameBitmapSecondTimeNotInteresting() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;
        bitmap[100] = 5;

        // First call - new coverage
        CoverageDiffStrategy.DiffResult result1 = strategy.diff(bitmap);
        assertEquals(2, result1.newBytes());
        assertTrue(result1.interesting());

        // Second call with same bitmap - no new coverage
        CoverageDiffStrategy.DiffResult result2 = strategy.diff(bitmap);
        assertEquals(0, result2.newBytes());
        assertFalse(result2.interesting());
    }

    @Test
    void testIncrementalCoverageDetection() {
        byte[] bitmap = new byte[MAP_SIZE];

        // First execution: positions 0, 1
        bitmap[0] = 1;
        bitmap[1] = 1;
        CoverageDiffStrategy.DiffResult result1 = strategy.diff(bitmap);
        assertEquals(2, result1.newBytes());
        assertTrue(result1.interesting());
        assertEquals(2, strategy.totalSeenBytes());

        // Second execution: positions 1, 2 (1 is already seen)
        bitmap[0] = 0;  // position 0 now zero, but still in seen set
        bitmap[2] = 1;  // new position
        CoverageDiffStrategy.DiffResult result2 = strategy.diff(bitmap);
        assertEquals(1, result2.newBytes());  // only position 2 is new
        assertTrue(result2.interesting());
        assertEquals(3, strategy.totalSeenBytes());

        // Third execution: same positions - nothing new
        CoverageDiffStrategy.DiffResult result3 = strategy.diff(bitmap);
        assertEquals(0, result3.newBytes());
        assertFalse(result3.interesting());
        assertEquals(3, strategy.totalSeenBytes());
    }

    @Test
    void testResetClearsSeenSet() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        strategy.diff(bitmap);
        assertEquals(1, strategy.totalSeenBytes());

        strategy.reset();
        assertEquals(0, strategy.totalSeenBytes());

        // After reset, same byte should be new again
        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);
        assertEquals(1, result.newBytes());
        assertTrue(result.interesting());
    }

    @Test
    void testIsSeenMethod() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[50] = 1;

        assertFalse(strategy.isSeen(50));

        strategy.diff(bitmap);

        assertTrue(strategy.isSeen(50));
        assertFalse(strategy.isSeen(51));
    }

    @Test
    void testIsSeenValidatesIndex() {
        assertThrows(IndexOutOfBoundsException.class, () -> strategy.isSeen(-1));
        assertThrows(IndexOutOfBoundsException.class, () -> strategy.isSeen(MAP_SIZE));
        assertDoesNotThrow(() -> strategy.isSeen(0));
        assertDoesNotThrow(() -> strategy.isSeen(MAP_SIZE - 1));
    }

    @Test
    void testBitmapSmallerThanMapSize() {
        byte[] smallBitmap = new byte[100];
        smallBitmap[50] = 1;

        CoverageDiffStrategy.DiffResult result = strategy.diff(smallBitmap);

        assertEquals(1, result.newBytes());
        assertTrue(result.interesting());
    }

    @Test
    void testBitmapLargerThanMapSize() {
        byte[] largeBitmap = new byte[MAP_SIZE * 2];
        largeBitmap[50] = 1;
        largeBitmap[MAP_SIZE + 100] = 1;  // beyond map size, should be ignored

        CoverageDiffStrategy.DiffResult result = strategy.diff(largeBitmap);

        // Only the byte within MAP_SIZE should be counted
        assertEquals(1, result.newBytes());
        assertTrue(result.interesting());
    }

    @Test
    void testAllBytesNonZero() {
        byte[] bitmap = new byte[MAP_SIZE];
        for (int i = 0; i < MAP_SIZE; i++) {
            bitmap[i] = 1;
        }

        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);

        assertEquals(MAP_SIZE, result.newBytes());
        assertTrue(result.interesting());
        assertEquals(MAP_SIZE, strategy.totalSeenBytes());

        // Second call should find nothing new
        CoverageDiffStrategy.DiffResult result2 = strategy.diff(bitmap);
        assertEquals(0, result2.newBytes());
        assertFalse(result2.interesting());
    }

    @Test
    void testGetMapSize() {
        assertEquals(MAP_SIZE, strategy.getMapSize());
    }
}
