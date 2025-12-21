package edu.nju.fuzzing.stats;

import edu.nju.fuzzing.model.StatsTick;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class FuzzStatsTest {

    private FuzzStats stats;

    @BeforeEach
    void setUp() {
        stats = new FuzzStats();
    }

    @Test
    void shouldStartWithZeroValues() {
        assertEquals(0, stats.getExecsTotal());
        assertEquals(0, stats.getTotalPaths());
        assertEquals(0, stats.getCrashes());
        assertEquals(0, stats.getHangs());
    }

    @Test
    void shouldRecordExecs() {
        stats.recordExec();
        stats.recordExec();
        stats.recordExec();
        
        assertEquals(3, stats.getExecsTotal());
    }

    @Test
    void shouldRecordMultipleExecs() {
        stats.recordExecs(100);
        stats.recordExecs(50);
        
        assertEquals(150, stats.getExecsTotal());
    }

    @Test
    void shouldRecordNewPaths() {
        stats.recordNewPath();
        stats.recordNewPath();
        
        assertEquals(2, stats.getTotalPaths());
    }

    @Test
    void shouldRecordCrashes() {
        stats.recordCrash();
        stats.recordCrash();
        stats.recordCrash();
        
        assertEquals(3, stats.getCrashes());
    }

    @Test
    void shouldRecordHangs() {
        stats.recordHang();
        
        assertEquals(1, stats.getHangs());
    }

    @Test
    void shouldTrackElapsedTime() throws InterruptedException {
        Thread.sleep(100);
        
        Duration elapsed = stats.getElapsedTime();
        assertTrue(elapsed.toMillis() >= 100);
    }

    @Test
    void shouldUpdateLastNewPathTime() throws InterruptedException {
        Instant before = stats.getLastNewPathAt();
        Thread.sleep(50);
        stats.recordNewPath();
        Instant after = stats.getLastNewPathAt();
        
        assertTrue(after.isAfter(before));
    }

    @Test
    void shouldCalculateExecsPerSec() throws InterruptedException {
        // Use custom start time to ensure elapsed time > 0
        Instant startTime = Instant.now().minusSeconds(1);
        FuzzStats customStats = new FuzzStats(startTime);
        
        // Record 100 execs
        customStats.recordExecs(100);
        
        // Should have some exec/sec value (at least 100/2 = 50)
        double execs = customStats.getExecsPerSec();
        assertTrue(execs > 0, "Expected execs/sec > 0, got: " + execs);
    }

    @Test
    void shouldProduceStatsTick() {
        stats.recordExecs(1000);
        stats.recordNewPath();
        stats.recordNewPath();
        stats.recordCrash();
        
        StatsTick tick = stats.toStatsTick(50);
        
        assertEquals(1000, tick.execsTotal());
        assertEquals(50, tick.queueSize());
        assertEquals(1, tick.crashes());
        assertEquals(0, tick.hangs());
        assertEquals(2, tick.totalPaths());
    }

    @Test
    void shouldBeThreadSafe() throws InterruptedException {
        int threads = 10;
        int execsPerThread = 1000;
        
        Thread[] workers = new Thread[threads];
        for (int i = 0; i < threads; i++) {
            workers[i] = new Thread(() -> {
                for (int j = 0; j < execsPerThread; j++) {
                    stats.recordExec();
                }
            });
        }
        
        for (Thread t : workers) t.start();
        for (Thread t : workers) t.join();
        
        assertEquals(threads * execsPerThread, stats.getExecsTotal());
    }

    @Test
    void shouldHaveCorrectToString() {
        stats.recordExecs(100);
        stats.recordNewPath();
        stats.recordCrash();
        
        String str = stats.toString();
        
        assertTrue(str.contains("execs=100"));
        assertTrue(str.contains("paths=1"));
        assertTrue(str.contains("crashes=1"));
    }

    @Test
    void shouldTrackTimeSinceLastNewPath() throws InterruptedException {
        stats.recordNewPath();
        Thread.sleep(100);
        
        Duration since = stats.getTimeSinceLastNewPath();
        assertTrue(since.toMillis() >= 100);
    }

    @Test
    void shouldAllowCustomStartTime() {
        Instant pastTime = Instant.now().minusSeconds(60);
        FuzzStats customStats = new FuzzStats(pastTime);
        
        assertTrue(customStats.getElapsedSeconds() >= 60);
    }
}
