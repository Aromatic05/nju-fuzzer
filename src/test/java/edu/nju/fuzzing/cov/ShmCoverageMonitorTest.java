package edu.nju.fuzzing.cov;

import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.RunResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ShmCoverageMonitor.
 * Uses MockBitmapSource to simulate shared memory behavior.
 */
class ShmCoverageMonitorTest {

    private static final int MAP_SIZE = 1024;
    private MockBitmapSource mockBitmapSource;
    private SeenNonZeroStrategy diffStrategy;
    private ShmCoverageMonitor monitor;

    @BeforeEach
    void setUp() {
        mockBitmapSource = new MockBitmapSource(MAP_SIZE);
        diffStrategy = new SeenNonZeroStrategy(MAP_SIZE);
        monitor = new ShmCoverageMonitor(mockBitmapSource, diffStrategy);
        monitor.start();
    }

    private RunResult createNormalResult() {
        return new RunResult(
                Path.of("/tmp/test.bin"),
                100L,
                0,
                false,
                RunResult.Termination.NORMAL,
                Path.of("/tmp/stdout"),
                Path.of("/tmp/stderr")
        );
    }

    @Test
    void testBeforeRunClearsBitmap() {
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(100, 5);

        monitor.beforeRun();

        byte[] bitmap = mockBitmapSource.getBitmap();
        assertEquals(0, bitmap[0]);
        assertEquals(0, bitmap[100]);
    }

    @Test
    void testAfterRunReturnsValidCoverage() {
        RunResult result = createNormalResult();
        Coverage coverage = monitor.afterRun(result);

        assertNotNull(coverage);
        assertTrue(coverage.execId() > 0);
        assertEquals(MAP_SIZE, coverage.mapSize());
    }

    @Test
    void testAfterRunDetectsNewCoverage() {
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(100, 5);
        mockBitmapSource.setByte(500, 10);

        Coverage coverage = monitor.afterRun(createNormalResult());

        assertEquals(3, coverage.nonZeroBytes());
        assertEquals(3, coverage.newBytes());
        assertTrue(coverage.interesting());
    }

    @Test
    void testAfterRunSecondCallNotInteresting() {
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(100, 5);

        // First call
        Coverage cov1 = monitor.afterRun(createNormalResult());
        assertTrue(cov1.interesting());
        assertEquals(2, cov1.newBytes());

        // beforeRun clears bitmap
        monitor.beforeRun();

        // Set same bytes again
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(100, 5);

        // Second call - same coverage, not interesting
        Coverage cov2 = monitor.afterRun(createNormalResult());
        assertEquals(2, cov2.nonZeroBytes());
        assertEquals(0, cov2.newBytes());
        assertFalse(cov2.interesting());
    }

    @Test
    void testAfterRunIncrementalCoverage() {
        // First run: positions 0, 1
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(1, 1);
        Coverage cov1 = monitor.afterRun(createNormalResult());
        assertEquals(2, cov1.newBytes());
        assertTrue(cov1.interesting());

        monitor.beforeRun();

        // Second run: positions 1, 2 (1 seen before, 2 is new)
        mockBitmapSource.setByte(1, 1);
        mockBitmapSource.setByte(2, 1);
        Coverage cov2 = monitor.afterRun(createNormalResult());
        assertEquals(2, cov2.nonZeroBytes());
        assertEquals(1, cov2.newBytes());  // only position 2 is new
        assertTrue(cov2.interesting());
    }

    @Test
    void testExecIdIncrementsCorrectly() {
        long firstId = monitor.afterRun(createNormalResult()).execId();

        for (int i = 1; i <= 5; i++) {
            Coverage cov = monitor.afterRun(createNormalResult());
            assertEquals(firstId + i, cov.execId());
        }
    }

    @Test
    void testBitmapHashCalculation() {
        mockBitmapSource.setByte(0, 1);
        Coverage cov1 = monitor.afterRun(createNormalResult());

        monitor.beforeRun();
        mockBitmapSource.setByte(0, 1);
        Coverage cov2 = monitor.afterRun(createNormalResult());

        // Same bitmap content should produce same hash
        assertEquals(cov1.bitmapHash(), cov2.bitmapHash());

        monitor.beforeRun();
        mockBitmapSource.setByte(0, 2);  // Different value
        Coverage cov3 = monitor.afterRun(createNormalResult());

        // Different content should produce different hash
        assertNotEquals(cov1.bitmapHash(), cov3.bitmapHash());
    }

    @Test
    void testSnapshotStats() throws InterruptedException {
        // Execute a few runs
        mockBitmapSource.setByte(0, 1);
        monitor.afterRun(createNormalResult());

        monitor.beforeRun();
        mockBitmapSource.setByte(1, 1);
        monitor.afterRun(createNormalResult());

        // Wait a tiny bit for time-based calculations
        Thread.sleep(10);

        ShmCoverageMonitor.CoverageStats stats = monitor.snapshotStats();

        assertEquals(2, stats.execs());
        assertTrue(stats.execsPerSec() > 0);
        assertTrue(stats.lastInterestingExecId() > 0);
        assertTrue(stats.lastInterestingAtMillis() > 0);
        assertEquals(2, stats.totalSeenBytes());
    }

    @Test
    void testGetTotalSeenBytes() {
        assertEquals(0, monitor.getTotalSeenBytes());

        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(1, 1);
        mockBitmapSource.setByte(2, 1);
        monitor.afterRun(createNormalResult());

        assertEquals(3, monitor.getTotalSeenBytes());
    }

    @Test
    void testGetMapSize() {
        assertEquals(MAP_SIZE, monitor.getMapSize());
    }

    @Test
    void testCloseDetachesBitmapSource() {
        assertTrue(mockBitmapSource.isAttached());

        monitor.close();

        assertFalse(mockBitmapSource.isAttached());
    }

    @Test
    void testEmptyBitmapNotInteresting() {
        // No bytes set in bitmap
        Coverage coverage = monitor.afterRun(createNormalResult());

        assertEquals(0, coverage.nonZeroBytes());
        assertEquals(0, coverage.newBytes());
        assertFalse(coverage.interesting());
    }

    @Test
    void testTimestampIsRecent() {
        long before = System.currentTimeMillis();
        Coverage coverage = monitor.afterRun(createNormalResult());
        long after = System.currentTimeMillis();

        assertTrue(coverage.timestampMillis() >= before);
        assertTrue(coverage.timestampMillis() <= after);
    }

    @Test
    void testMultipleMonitorsIndependent() {
        MockBitmapSource source2 = new MockBitmapSource(MAP_SIZE);
        SeenNonZeroStrategy strategy2 = new SeenNonZeroStrategy(MAP_SIZE);
        ShmCoverageMonitor monitor2 = new ShmCoverageMonitor(source2, strategy2);

        mockBitmapSource.setByte(0, 1);
        source2.setByte(100, 1);

        Coverage cov1 = monitor.afterRun(createNormalResult());
        Coverage cov2 = monitor2.afterRun(createNormalResult());

        // Each monitor tracks its own coverage
        assertEquals(1, cov1.newBytes());
        assertEquals(1, cov2.newBytes());
        assertEquals(1, monitor.getTotalSeenBytes());
        assertEquals(1, monitor2.getTotalSeenBytes());

        monitor2.close();
    }
}
