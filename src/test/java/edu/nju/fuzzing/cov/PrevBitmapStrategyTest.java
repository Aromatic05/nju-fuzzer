package edu.nju.fuzzing.cov;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for PrevBitmapStrategy.
 */
class PrevBitmapStrategyTest {

    private static final int MAP_SIZE = 1024;
    private PrevBitmapStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new PrevBitmapStrategy(MAP_SIZE);
    }

    @Test
    void testConstructorValidation() {
        assertThrows(IllegalArgumentException.class, () -> new PrevBitmapStrategy(0));
        assertThrows(IllegalArgumentException.class, () -> new PrevBitmapStrategy(-1));
        assertDoesNotThrow(() -> new PrevBitmapStrategy(1));
    }

    @Test
    void testFirstRunAllBytesAreNew() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;
        bitmap[100] = 5;
        bitmap[500] = 10;

        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);

        assertEquals(3, result.newBytes());
        assertTrue(result.interesting());
    }

    @Test
    void testIdenticalBitmapNotInteresting() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;
        bitmap[100] = 5;

        // First call
        strategy.diff(bitmap);

        // Second call with same bitmap
        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);

        assertEquals(0, result.newBytes());
        assertFalse(result.interesting());
    }

    @Test
    void testNewByteInNextRun() {
        byte[] bitmap1 = new byte[MAP_SIZE];
        bitmap1[0] = 1;

        byte[] bitmap2 = new byte[MAP_SIZE];
        bitmap2[0] = 1;
        bitmap2[100] = 5;  // New byte

        strategy.diff(bitmap1);
        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap2);

        assertEquals(1, result.newBytes());
        assertTrue(result.interesting());
    }

    @Test
    void testByteDisappearingNotCounted() {
        byte[] bitmap1 = new byte[MAP_SIZE];
        bitmap1[0] = 1;
        bitmap1[100] = 5;

        byte[] bitmap2 = new byte[MAP_SIZE];
        bitmap2[100] = 5;  // Position 0 is now zero

        strategy.diff(bitmap1);
        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap2);

        // No new bytes, position 0 disappeared but that's not "new"
        assertEquals(0, result.newBytes());
        assertFalse(result.interesting());
    }

    @Test
    void testValueChangeNotCounted() {
        byte[] bitmap1 = new byte[MAP_SIZE];
        bitmap1[0] = 1;

        byte[] bitmap2 = new byte[MAP_SIZE];
        bitmap2[0] = 10;  // Same position, different value

        strategy.diff(bitmap1);
        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap2);

        // Not a new byte, just value change
        assertEquals(0, result.newBytes());
        assertFalse(result.interesting());
    }

    @Test
    void testReset() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        strategy.diff(bitmap);
        assertNotNull(strategy.getPrevBitmap());

        strategy.reset();

        assertNull(strategy.getPrevBitmap());
        assertEquals(0, strategy.totalSeenBytes());

        // After reset, same bitmap should be interesting
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
    void testGetPrevBitmapReturnsCopy() {
        byte[] bitmap = new byte[MAP_SIZE];
        bitmap[0] = 1;

        strategy.diff(bitmap);

        byte[] prev1 = strategy.getPrevBitmap();
        byte[] prev2 = strategy.getPrevBitmap();

        assertNotSame(prev1, prev2);
        assertArrayEquals(prev1, prev2);

        // Modifying returned array doesn't affect internal state
        prev1[0] = 99;
        assertEquals(1, strategy.getPrevBitmap()[0]);
    }

    @Test
    void testGetMapSize() {
        assertEquals(MAP_SIZE, strategy.getMapSize());
    }

    @Test
    void testTotalSeenBytesAccumulates() {
        byte[] bitmap1 = new byte[MAP_SIZE];
        bitmap1[0] = 1;
        bitmap1[1] = 1;

        byte[] bitmap2 = new byte[MAP_SIZE];
        bitmap2[0] = 1;
        bitmap2[1] = 1;
        bitmap2[2] = 1;  // One new

        strategy.diff(bitmap1);
        assertEquals(2, strategy.totalSeenBytes());

        strategy.diff(bitmap2);
        assertEquals(3, strategy.totalSeenBytes());
    }

    @Test
    void testSequentialNewBytesDetection() {
        // Simulate a fuzzing session with multiple runs
        for (int i = 0; i < 10; i++) {
            byte[] bitmap = new byte[MAP_SIZE];
            // Each run adds one more byte
            for (int j = 0; j <= i; j++) {
                bitmap[j] = 1;
            }

            CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap);

            if (i == 0) {
                assertEquals(1, result.newBytes());
            } else {
                assertEquals(1, result.newBytes());  // One new byte each time
            }
            assertTrue(result.interesting());
        }
    }

    @Test
    void testDifferentFromSeenNonZero() {
        // PrevBitmapStrategy should report "interesting" even for
        // previously-seen-globally bytes if they weren't in the prev bitmap

        byte[] bitmap1 = new byte[MAP_SIZE];
        bitmap1[0] = 1;

        byte[] bitmap2 = new byte[MAP_SIZE];
        bitmap2[100] = 1;

        byte[] bitmap3 = new byte[MAP_SIZE];
        bitmap3[0] = 1;  // Back to position 0

        strategy.diff(bitmap1);  // See position 0
        strategy.diff(bitmap2);  // See position 100, prev was 0

        // Position 0 should be "new" relative to previous (100)
        CoverageDiffStrategy.DiffResult result = strategy.diff(bitmap3);
        assertEquals(1, result.newBytes());
        assertTrue(result.interesting());
    }
}
