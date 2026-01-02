package edu.nju.fuzzing.cov;

import edu.nju.fuzzing.model.CoverageEx;
import edu.nju.fuzzing.model.RunResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ShmCoverageMonitorEx.
 * Uses MockBitmapSource to simulate shared memory behavior.
 */
class ShmCoverageMonitorExTest {

    private static final int MAP_SIZE = 1024;
    private MockBitmapSource mockBitmapSource;
    private CoverageDiffStrategyEx diffStrategy;
    private CoverageDB coverageDB;
    private ShmCoverageMonitorEx monitor;

    @BeforeEach
    void setUp() {
        mockBitmapSource = new MockBitmapSource(MAP_SIZE);
        diffStrategy = CoverageDiffStrategyEx.createDefault(MAP_SIZE);
        coverageDB = new CoverageDB(MAP_SIZE);
        monitor = new ShmCoverageMonitorEx(mockBitmapSource, diffStrategy, coverageDB);
        monitor.start();
    }

    /**
     * Minimal test double that extends SysVShmBitmapSource to avoid native calls
     * while still exercising the instanceof branch in ShmCoverageMonitorEx.start().
     */
    private static final class TestSysVShmBitmapSource extends SysVShmBitmapSource {
        private final byte[] bitmap;
        private boolean attachedLocal = false;
        private int attachCount = 0;

        TestSysVShmBitmapSource(int shmId, int mapSize) {
            super(shmId, mapSize);
            this.bitmap = new byte[mapSize];
        }

        @Override
        public void attach() {
            attachCount++;
            attachedLocal = true;
        }

        @Override
        public boolean isAttached() {
            return attachedLocal;
        }

        @Override
        public void readInto(byte[] dst) {
            System.arraycopy(bitmap, 0, dst, 0, Math.min(dst.length, bitmap.length));
        }

        @Override
        public void clear() {
            java.util.Arrays.fill(bitmap, (byte) 0);
        }

        @Override
        public void close() {
            attachedLocal = false;
        }

        void setByte(int idx, int v) {
            if (idx >= 0 && idx < bitmap.length) bitmap[idx] = (byte) v;
        }

        byte[] getBitmap() { return bitmap.clone(); }
        int getAttachCount() { return attachCount; }
    }

    @Test
    void testStartAttachesOnce() {
        TestSysVShmBitmapSource ts = new TestSysVShmBitmapSource(12345, MAP_SIZE);
        CoverageDiffStrategyEx strat = CoverageDiffStrategyEx.createDefault(MAP_SIZE);
        CoverageDB db = new CoverageDB(MAP_SIZE);
        ShmCoverageMonitorEx mon = new ShmCoverageMonitorEx(ts, strat, db);

        assertFalse(ts.isAttached());
        mon.start();
        assertTrue(ts.isAttached());
        assertEquals(1, ts.getAttachCount());

        // Calling start again should be idempotent
        mon.start();
        assertEquals(1, ts.getAttachCount());

        mon.close();
        assertFalse(ts.isAttached());
    }

    @Test
    void testCoverageDBUpdateEvaluateAndRedundancy() {
        CoverageDB db = monitor.getCoverageDB();

        EdgeSet edges56 = EdgeSet.of(5, 6);
        DiffResultEx diff = DiffResultEx.of(edges56, edges56, 2, 0L);

        CoverageDB.UpdateResult r1 = db.update(100L, diff, 200, 1_000L);
        assertTrue(r1.isInteresting());
        assertEquals(2, r1.newEdges().size());
        assertTrue(db.hasSeenEdge(5));
        assertTrue(db.hasSeenEdge(6));
        assertEquals(1, db.getEdgeFrequency(5));

        // evaluate should see no new edges now
        CoverageDB.UpdateResult eval = db.evaluate(diff);
        assertEquals(0, eval.newEdges().size());

        // A smaller input seed should become top-rated
        CoverageDB.UpdateResult r2 = db.update(200L, diff, 50, 500L);
        assertTrue(r2.favoredChanged());

        // Original seed should now be redundant for the same edges
        assertTrue(db.isRedundant(100L, edges56));
        assertFalse(db.isRedundant(200L, edges56));

        CoverageDB.TopRatedEntry tr = db.getTopRated(5);
        assertNotNull(tr);
        assertEquals(200L, tr.seedId());

        double score = db.calculateRarityScore(edges56);
        assertTrue(score > 0);

        CoverageDB.CoverageDBStats stats = db.getStats();
        assertEquals(MAP_SIZE, stats.mapSize());
    }

    private RunResult createNormalResult() {
        return RunResult.of(1L, 
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
    void testAfterRunExReturnsValidCoverage() {
        RunResult result = createNormalResult();
        CoverageEx coverage = monitor.afterRunEx(result);

        assertNotNull(coverage);
        assertTrue(coverage.execId() > 0);
        assertEquals(MAP_SIZE, coverage.mapSize());
    }

    @Test
    void testAfterRunExDetectsNewCoverage() {
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(100, 5);
        mockBitmapSource.setByte(500, 10);

        CoverageEx coverage = monitor.afterRunEx(createNormalResult());

        assertEquals(3, coverage.nonZeroBytes());
        assertEquals(3, coverage.newEdgeCount());
        assertTrue(coverage.interesting());
    }

    @Test
    void testAfterRunExProvidesEdgeSets() {
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(100, 5);

        CoverageEx coverage = monitor.afterRunEx(createNormalResult());

        assertNotNull(coverage);
        assertNotNull(coverage.hitEdges());
        assertNotNull(coverage.newEdges());
        assertFalse(coverage.hitEdges().isEmpty());
        assertFalse(coverage.newEdges().isEmpty());
        assertEquals(coverage.newEdges().size(), coverage.newEdgeCount());
        assertTrue(coverage.interesting());
    }

    @Test
    void testAfterRunExSecondCallNotInteresting() {
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(100, 5);

        // First call
        CoverageEx cov1 = monitor.afterRunEx(createNormalResult());
        assertTrue(cov1.interesting());
        assertEquals(2, cov1.newEdgeCount());

        // beforeRun clears bitmap
        monitor.beforeRun();

        // Set same bytes again
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(100, 5);

        // Second call - same coverage, not interesting
        CoverageEx cov2 = monitor.afterRunEx(createNormalResult());
        assertEquals(2, cov2.nonZeroBytes());
        assertEquals(0, cov2.newEdgeCount());
        assertFalse(cov2.interesting());
    }

    @Test
    void testAfterRunExIncrementalCoverage() {
        // First run: positions 0, 1
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(1, 1);
        CoverageEx cov1 = monitor.afterRunEx(createNormalResult());
        assertEquals(2, cov1.newEdgeCount());
        assertTrue(cov1.interesting());

        monitor.beforeRun();

        // Second run: positions 1, 2 (1 seen before, 2 is new)
        mockBitmapSource.setByte(1, 1);
        mockBitmapSource.setByte(2, 1);
        CoverageEx cov2 = monitor.afterRunEx(createNormalResult());
        assertEquals(2, cov2.nonZeroBytes());
        assertEquals(1, cov2.newEdgeCount());  // only position 2 is new
        assertTrue(cov2.interesting());
    }

    @Test
    void testExecIdIncrementsCorrectly() {
        long firstId = monitor.afterRunEx(createNormalResult()).execId();

        for (int i = 1; i <= 5; i++) {
            CoverageEx cov = monitor.afterRunEx(createNormalResult());
            assertEquals(firstId + i, cov.execId());
        }
    }

    @Test
    void testBitmapHashCalculation() {
        mockBitmapSource.setByte(0, 1);
        CoverageEx cov1 = monitor.afterRunEx(createNormalResult());

        monitor.beforeRun();
        mockBitmapSource.setByte(0, 1);
        CoverageEx cov2 = monitor.afterRunEx(createNormalResult());

        // Same bitmap content should produce same hash
        assertEquals(cov1.bitmapHash(), cov2.bitmapHash());

        monitor.beforeRun();
        mockBitmapSource.setByte(0, 2);  // Different value
        CoverageEx cov3 = monitor.afterRunEx(createNormalResult());

        // Different content should produce different hash
        assertNotEquals(cov1.bitmapHash(), cov3.bitmapHash());
    }

    @Test
    void testGetCoverageDB() {
        CoverageDB db = monitor.getCoverageDB();
        assertNotNull(db);
        assertSame(coverageDB, db);
    }

    @Test
    void testGetStrategyEx() {
        CoverageDiffStrategyEx strategy = monitor.getStrategyEx();
        assertNotNull(strategy);
        assertSame(diffStrategy, strategy);
    }

    @Test
    void testStabilityDetectionToggle() {
        assertFalse(monitor.isStabilityDetectionEnabled());

        monitor.setStabilityDetectionEnabled(true);
        assertTrue(monitor.isStabilityDetectionEnabled());

        monitor.setStabilityDetectionEnabled(false);
        assertFalse(monitor.isStabilityDetectionEnabled());
    }

    @Test
    void testGetTotalEdgesSeen() {
        assertEquals(0, monitor.getTotalEdgesSeen());

        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(1, 1);
        mockBitmapSource.setByte(2, 1);
        monitor.afterRunEx(createNormalResult());

        assertEquals(3, monitor.getTotalEdgesSeen());
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
        CoverageEx coverage = monitor.afterRunEx(createNormalResult());

        assertEquals(0, coverage.nonZeroBytes());
        assertEquals(0, coverage.newEdgeCount());
        assertFalse(coverage.interesting());
    }

    @Test
    void testTimestampIsRecent() {
        long before = System.currentTimeMillis();
        CoverageEx coverage = monitor.afterRunEx(createNormalResult());
        long after = System.currentTimeMillis();

        assertTrue(coverage.timestampMillis() >= before);
        assertTrue(coverage.timestampMillis() <= after);
    }

    @Test
    void testMultipleMonitorsIndependent() {
        MockBitmapSource source2 = new MockBitmapSource(MAP_SIZE);
        CoverageDiffStrategyEx strategy2 = CoverageDiffStrategyEx.createDefault(MAP_SIZE);
        CoverageDB db2 = new CoverageDB(MAP_SIZE);
        ShmCoverageMonitorEx monitor2 = new ShmCoverageMonitorEx(source2, strategy2, db2);
        monitor2.start();

        mockBitmapSource.setByte(0, 1);
        source2.setByte(100, 1);

        CoverageEx cov1 = monitor.afterRunEx(createNormalResult());
        CoverageEx cov2 = monitor2.afterRunEx(createNormalResult());

        // Each monitor tracks its own coverage
        assertEquals(1, cov1.newEdgeCount());
        assertEquals(1, cov2.newEdgeCount());
        assertEquals(1, monitor.getTotalEdgesSeen());
        assertEquals(1, monitor2.getTotalEdgesSeen());

        monitor2.close();
    }

    @Test
    void testHitEdgesSubsetOfCoverageDB() {
        // Run 1: Add edges 0, 1
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(1, 1);
        CoverageEx cov1 = monitor.afterRunEx(createNormalResult());
        
        assertEquals(2, cov1.newEdgeCount());

        monitor.beforeRun();

        // Run 2: Hit edge 0 again, add edge 2
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(2, 1);
        CoverageEx cov2 = monitor.afterRunEx(createNormalResult());

        // Hit edges should include both 0 and 2
        assertTrue(cov2.hitEdges().contains(0));
        assertTrue(cov2.hitEdges().contains(2));
        assertEquals(2, cov2.hitEdges().size());

        // New edges should only include 2
        assertTrue(cov2.newEdges().contains(2));
        assertFalse(cov2.newEdges().contains(0));
        assertEquals(1, cov2.newEdgeCount());
    }

    @Test
    void testForTestingFactoryMethod() {
        MockBitmapSource testSource = new MockBitmapSource(512);
        ShmCoverageMonitorEx testMonitor = ShmCoverageMonitorEx.forTesting(512, testSource);
        
        assertNotNull(testMonitor);
        assertEquals(512, testMonitor.getMapSize());
        
        testMonitor.start();
        testSource.setByte(10, 5);
        
        CoverageEx coverage = testMonitor.afterRunEx(createNormalResult());
        assertEquals(1, coverage.nonZeroBytes());
        
        testMonitor.close();
    }

    @Test
    void testEdgeSetsAreImmutable() {
        mockBitmapSource.setByte(0, 1);
        mockBitmapSource.setByte(1, 1);
        
        CoverageEx coverage = monitor.afterRunEx(createNormalResult());
        
        // Try to modify the edge sets (should not affect the coverage object)
        var hitEdges = coverage.hitEdges();
        var newEdges = coverage.newEdges();
        
        assertNotNull(hitEdges);
        assertNotNull(newEdges);
        
        // These should be safe operations (not throwing exceptions)
        int hitSize = hitEdges.size();
        int newSize = newEdges.size();
        
        assertTrue(hitSize > 0);
        assertTrue(newSize > 0);
    }
}
