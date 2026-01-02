package edu.nju.fuzzing.corpus;

import edu.nju.fuzzing.cov.*;
import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.RunResult;
import edu.nju.fuzzing.stats.FuzzStats;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test demonstrating the interaction between
 * CorpusManager, CoverageMonitor, and FuzzStats.
 */
class CorpusIntegrationTest {

    @TempDir
    Path tempDir;

    private FileCorpusManager corpusManager;
    private FuzzStats stats;
    private CoverageDiffStrategy strategy;
    private int mapSize = 65536;

    @BeforeEach
    void setUp() throws IOException {
        corpusManager = new FileCorpusManager(tempDir);
        stats = new FuzzStats();
        strategy = CoverageDiffStrategy.createDefault(mapSize);
    }

    @Test
    void shouldSaveInterestingInputsToQueue() {
        // Simulate fuzzing loop
        List<byte[]> inputs = List.of(
                "input1".getBytes(),
                "input2".getBytes(),
                "input3".getBytes()
        );

        // First input - new coverage
        byte[] bitmap1 = new byte[mapSize];
        bitmap1[100] = 1;
        bitmap1[200] = 2;
        CoverageDiffStrategy.DiffResult result1 = strategy.diff(bitmap1);
        assertTrue(result1.interesting());
        
        Coverage cov1 = createCoverage(result1);
        Path saved1 = corpusManager.saveToQueue(inputs.get(0), cov1);
        stats.recordExec();
        stats.recordNewPath();
        
        // Second input - same coverage (not interesting after first)
        byte[] bitmap2 = new byte[mapSize];
        bitmap2[100] = 1;
        bitmap2[200] = 2;
        CoverageDiffStrategy.DiffResult result2 = strategy.diff(bitmap2);
        // Depending on strategy, this may or may not be interesting
        assertFalse(result2.interesting());
        
        // Third input - new coverage
        byte[] bitmap3 = new byte[mapSize];
        bitmap3[300] = 5;
        CoverageDiffStrategy.DiffResult result3 = strategy.diff(bitmap3);
        assertTrue(result3.interesting());
        
        Coverage cov3 = createCoverage(result3);
        Path saved3 = corpusManager.saveToQueue(inputs.get(2), cov3);
        stats.recordExec();
        stats.recordNewPath();
        
        // Verify
        assertEquals(2, corpusManager.getQueueSize());
        assertEquals(2, stats.getTotalPaths());
        assertTrue(Files.exists(saved1));
        assertTrue(Files.exists(saved3));
    }

    @Test
    void shouldTrackCrashesAndHangs() throws IOException {
        // Simulate finding crashes and hangs
        byte[] crashInput = "crash".getBytes();
        byte[] hangInput = "hang".getBytes();
        
        RunResult crashResult = RunResult.of(1L, null, 50, 139, false, 
                RunResult.Termination.ERROR, null, null);
        RunResult hangResult = RunResult.of(1L, null, 5000, -1, true, 
                RunResult.Termination.TIMEOUT, null, null);
        
        Path crashPath = corpusManager.saveCrash(crashInput, crashResult);
        stats.recordCrash();
        
        Path hangPath = corpusManager.saveHang(hangInput, hangResult);
        stats.recordHang();
        
        // Verify
        assertEquals(1, corpusManager.getCrashCount());
        assertEquals(1, corpusManager.getHangCount());
        assertEquals(1, stats.getCrashes());
        assertEquals(1, stats.getHangs());
        
        assertTrue(Files.exists(crashPath));
        assertTrue(Files.exists(hangPath));
        
        // Verify content
        assertArrayEquals(crashInput, Files.readAllBytes(crashPath));
        assertArrayEquals(hangInput, Files.readAllBytes(hangPath));
    }

    @Test
    void shouldProduceCorrectStatsTick() {
        // Simulate some fuzzing activity
        for (int i = 0; i < 100; i++) {
            stats.recordExec();
        }
        stats.recordNewPath();
        stats.recordNewPath();
        stats.recordCrash();
        
        var tick = stats.toStatsTick(corpusManager.getQueueSize());
        
        assertEquals(100, tick.execsTotal());
        assertEquals(0, tick.queueSize()); // No saves to queue
        assertEquals(1, tick.crashes());
        assertEquals(0, tick.hangs());
        assertEquals(2, tick.totalPaths());
    }

    @Test
    void shouldHandleManyInputs() throws IOException {
        int numInputs = 1000;
        List<Path> savedPaths = new ArrayList<>();
        
        for (int i = 0; i < numInputs; i++) {
            byte[] input = ("input_" + i).getBytes();
            Coverage cov = new Coverage(i, System.currentTimeMillis(), mapSize, 
                    10, 1, i * 12345L, true);
            
            savedPaths.add(corpusManager.saveToQueue(input, cov));
            stats.recordExec();
            
            if (i % 100 == 0) {
                stats.recordNewPath();
            }
        }
        
        // Verify
        assertEquals(numInputs, corpusManager.getQueueSize());
        assertEquals(numInputs, stats.getExecsTotal());
        assertEquals(10, stats.getTotalPaths()); // 0, 100, 200, ..., 900
        
        // Verify all files exist
        for (Path path : savedPaths) {
            assertTrue(Files.exists(path));
        }
        
        // Verify directory structure
        long fileCount = Files.list(corpusManager.queueDir()).count();
        assertEquals(numInputs, fileCount);
    }

    private Coverage createCoverage(CoverageDiffStrategy.DiffResult result) {
        return new Coverage(
                System.nanoTime(),
                System.currentTimeMillis(),
                mapSize,
                result.newBytes(),  // use newBytes for nonZeroBytes
                result.newBytes(),
                0L,  // no hash from DiffResult
                result.interesting()
        );
    }
}
