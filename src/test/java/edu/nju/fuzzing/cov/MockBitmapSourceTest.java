package edu.nju.fuzzing.cov;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for MockBitmapSource.
 */
class MockBitmapSourceTest {

    private static final int MAP_SIZE = 256;
    private MockBitmapSource source;

    @BeforeEach
    void setUp() {
        source = new MockBitmapSource(MAP_SIZE);
    }

    @Test
    void testMapSize() {
        assertEquals(MAP_SIZE, source.mapSize());
    }

    @Test
    void testIsAttachedByDefault() {
        assertTrue(source.isAttached());
    }

    @Test
    void testSetByteAndReadInto() {
        source.setByte(0, 1);
        source.setByte(100, 255);
        source.setByte(MAP_SIZE - 1, 128);

        byte[] dst = new byte[MAP_SIZE];
        source.readInto(dst);

        assertEquals(1, dst[0] & 0xFF);
        assertEquals(255, dst[100] & 0xFF);
        assertEquals(128, dst[MAP_SIZE - 1] & 0xFF);
    }

    @Test
    void testSetBytes() {
        source.setBytes(0, 1, 10, 2, 20, 3);

        byte[] dst = new byte[MAP_SIZE];
        source.readInto(dst);

        assertEquals(1, dst[0] & 0xFF);
        assertEquals(2, dst[10] & 0xFF);
        assertEquals(3, dst[20] & 0xFF);
    }

    @Test
    void testClear() {
        source.setByte(0, 1);
        source.setByte(50, 100);

        source.clear();

        byte[] dst = new byte[MAP_SIZE];
        source.readInto(dst);

        assertEquals(0, dst[0]);
        assertEquals(0, dst[50]);
    }

    @Test
    void testClose() {
        assertTrue(source.isAttached());

        source.close();

        assertFalse(source.isAttached());
    }

    @Test
    void testReadIntoThrowsWhenNotAttached() {
        source.close();

        assertThrows(IllegalStateException.class, () -> {
            source.readInto(new byte[MAP_SIZE]);
        });
    }

    @Test
    void testGetBitmapReturnsClone() {
        source.setByte(0, 1);

        byte[] bitmap1 = source.getBitmap();
        byte[] bitmap2 = source.getBitmap();

        assertNotSame(bitmap1, bitmap2);
        assertEquals(bitmap1[0], bitmap2[0]);

        // Modifying returned array doesn't affect source
        bitmap1[0] = 99;
        assertEquals(1, source.getBitmap()[0]);
    }

    @Test
    void testSetByteOutOfBoundsIgnored() {
        // Should not throw, just be ignored
        assertDoesNotThrow(() -> source.setByte(-1, 1));
        assertDoesNotThrow(() -> source.setByte(MAP_SIZE, 1));
        assertDoesNotThrow(() -> source.setByte(MAP_SIZE + 100, 1));
    }
}
