package edu.nju.fuzzing.stats;

import edu.nju.fuzzing.model.StatsTick;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class FuzzStatsTest {

    private FuzzStats stats;
    private static final String TARGET_NAME = "test_target";

    @BeforeEach
    void setUp() {
        stats = new FuzzStats(TARGET_NAME);
    }

    // --- 基础状态测试 ---

    @Test
    void shouldInitializeWithTargetNameAndZeroValues() {
        StatsTick tick = stats.toStatsTick(0);
        assertEquals(TARGET_NAME, tick.targetName());
        assertEquals(0, tick.execsTotal());
        assertEquals(0, tick.coveredEdges());
        assertEquals(0, tick.crashes());
    }

    // --- 执行计数测试 ---

    @Test
    void shouldRecordSingleExec() {
        stats.recordExec();
        assertEquals(1, stats.toStatsTick(0).execsTotal());
    }

    @Test
    void shouldRecordMultipleExecsConcurrent() throws InterruptedException {
        int threads = 10;
        int execsPerThread = 1000;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch latch = new CountDownLatch(threads);

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                for (int j = 0; j < execsPerThread; j++) {
                    stats.recordExec();
                }
                latch.countDown();
            });
        }

        latch.await(5, TimeUnit.SECONDS);
        executor.shutdown();
        
        assertEquals(threads * execsPerThread, stats.toStatsTick(0).execsTotal());
    }

    // --- 覆盖率测试 (New Feature) ---

    @Test
    void shouldUpdateCoveredEdges() {
        stats.updateCoveredEdges(500);
        assertEquals(500, stats.toStatsTick(0).coveredEdges());
        
        stats.updateCoveredEdges(600);
        assertEquals(600, stats.toStatsTick(0).coveredEdges());
    }

    @Test
    void shouldTrackCoveredEdgesIndependentlyOfExecs() {
        stats.recordExec();
        stats.updateCoveredEdges(100);
        
        StatsTick tick = stats.toStatsTick(0);
        assertEquals(1, tick.execsTotal());
        assertEquals(100, tick.coveredEdges());
    }

    // --- 异常状态测试 ---

    @Test
    void shouldRecordCrashes() {
        stats.recordCrash();
        stats.recordCrash();
        assertEquals(2, stats.toStatsTick(0).crashes());
    }

    @Test
    void shouldRecordHangs() {
        stats.recordHang();
        assertEquals(1, stats.toStatsTick(0).hangs());
    }

    @Test
    void shouldRecordNewPathsAndTime() throws InterruptedException {
        stats.recordNewPath();
        Thread.sleep(100); // Wait a bit
        
        StatsTick tick = stats.toStatsTick(5);
        assertTrue(tick.lastNewPathSecAgo() >= 0);
        assertEquals(5, tick.queueSize()); // Queue size is passed externally
    }

    // --- 时间与速率测试 ---

    @Test
    void shouldCalculateExecsPerSec() throws InterruptedException {
        // Mocking time via reflection is hard, so we use a custom constructor trick (if supported)
        // Or simply sleep a bit for integration-style test
        Thread.sleep(100); 
        stats.recordExec(); // 1 exec in >0.1s => <10 exec/s
        
        double rate = stats.getExecsPerSec();
        assertTrue(rate > 0 && rate < 10000, "Rate should be reasonable: " + rate);
    }

    @Test
    void shouldCalculateRecentExecsPerSec() throws InterruptedException {
        // Initial snapshot
        stats.getRecentExecsPerSec(); 
        
        Thread.sleep(200);
        stats.recordExec();
        stats.recordExec();
        
        double recentRate = stats.getRecentExecsPerSec();
        assertTrue(recentRate > 0, "Recent rate should be positive");
    }

    @Test
    void shouldHandleZeroTimeElapsedGracefully() {
        // Create stats and immediately check rate
        FuzzStats instantStats = new FuzzStats(TARGET_NAME);
        assertEquals(0.0, instantStats.getExecsPerSec());
    }

    // --- 快照生成测试 ---

    @Test
    void shouldGenerateCorrectStatsTick() {
        stats.recordExec();
        stats.recordCrash();
        stats.updateCoveredEdges(123);
        
        StatsTick tick = stats.toStatsTick(10);
        
        assertAll("StatsTick consistency",
            () -> assertEquals(TARGET_NAME, tick.targetName()),
            () -> assertEquals(1, tick.execsTotal()),
            () -> assertEquals(1, tick.crashes()),
            () -> assertEquals(123, tick.coveredEdges()),
            () -> assertEquals(10, tick.queueSize())
        );
    }
}