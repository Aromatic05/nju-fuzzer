package edu.nju.fuzzing.cov;

import edu.nju.fuzzing.model.Coverage;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Coverage record.
 */
class CoverageTest {

    @Test
    void testOfCreatesValidCoverage() {
        Coverage cov = Coverage.of(10, 5, true);

        assertTrue(cov.execId() > 0);
        assertTrue(cov.timestampMillis() > 0);
        assertEquals(Coverage.DEFAULT_MAP_SIZE, cov.mapSize());
        assertEquals(10, cov.nonZeroBytes());
        assertEquals(5, cov.newBytes());
        assertTrue(cov.interesting());
    }

    @Test
    void testOfWithMapSize() {
        Coverage cov = Coverage.of(1024, 50, 10, true);

        assertEquals(1024, cov.mapSize());
        assertEquals(50, cov.nonZeroBytes());
        assertEquals(10, cov.newBytes());
        assertTrue(cov.interesting());
    }

    @Test
    void testExecIdIncrementsAcrossFactoryMethods() {
        Coverage cov1 = Coverage.of(1, 1, true);
        Coverage cov2 = Coverage.of(1024, 2, 2, true);

        assertTrue(cov2.execId() > cov1.execId());
    }

    @Test
    void testDefaultMapSizeConstant() {
        assertEquals(65536, Coverage.DEFAULT_MAP_SIZE);
    }

    @Test
    void testBitmapHashDefaultsToZero() {
        Coverage cov = Coverage.of(10, 5, true);
        assertEquals(0L, cov.bitmapHash());
    }

    @Test
    void testRecordAccessors() {
        Coverage cov = new Coverage(
                1L,
                1234567890L,
                2048,
                100,
                25,
                0xABCDL,
                true
        );

        assertEquals(1L, cov.execId());
        assertEquals(1234567890L, cov.timestampMillis());
        assertEquals(2048, cov.mapSize());
        assertEquals(100, cov.nonZeroBytes());
        assertEquals(25, cov.newBytes());
        assertEquals(0xABCDL, cov.bitmapHash());
        assertTrue(cov.interesting());
    }
}
