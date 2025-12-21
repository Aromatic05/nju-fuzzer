package edu.nju.fuzzing.corpus;

import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.RunResult;
import edu.nju.fuzzing.model.RunResult.Termination;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FileCorpusManagerTest {

    @TempDir
    Path tempDir;

    private FileCorpusManager manager;

    @BeforeEach
    void setUp() throws IOException {
        manager = new FileCorpusManager(tempDir);
    }

    /**
     * Creates a test Coverage instance.
     */
    private Coverage createCoverage(int newBytes) {
        return new Coverage(1L, System.currentTimeMillis(), 65536, 10, newBytes, 12345L, true);
    }

    /**
     * Creates a test crash RunResult.
     */
    private RunResult createCrashResult(int exitCode) {
        return new RunResult(null, 100, exitCode, false, Termination.ERROR, null, null);
    }

    /**
     * Creates a test hang RunResult.
     */
    private RunResult createHangResult() {
        return new RunResult(null, 5000, -1, true, Termination.TIMEOUT, null, null);
    }

    @Test
    void shouldCreateDirectoriesOnInit() {
        assertTrue(Files.isDirectory(tempDir.resolve("queue")));
        assertTrue(Files.isDirectory(tempDir.resolve("crashes")));
        assertTrue(Files.isDirectory(tempDir.resolve("hangs")));
    }

    @Test
    void shouldSaveInputToQueue() {
        byte[] input = "test input".getBytes();
        Coverage coverage = createCoverage(5);
        
        Path saved = manager.saveToQueue(input, coverage);
        
        assertNotNull(saved);
        assertTrue(Files.exists(saved));
        assertTrue(saved.getFileName().toString().startsWith("id_000001"));
        assertTrue(saved.getFileName().toString().contains("cov_5"));
    }

    @Test
    void shouldSaveMultipleInputsToQueue() {
        Coverage coverage = createCoverage(5);
        
        Path p1 = manager.saveToQueue("input1".getBytes(), coverage);
        Path p2 = manager.saveToQueue("input2".getBytes(), coverage);
        Path p3 = manager.saveToQueue("input3".getBytes(), coverage);
        
        assertTrue(p1.getFileName().toString().contains("id_000001"));
        assertTrue(p2.getFileName().toString().contains("id_000002"));
        assertTrue(p3.getFileName().toString().contains("id_000003"));
        
        assertEquals(3, manager.getQueueSize());
    }

    @Test
    void shouldSaveCrash() {
        byte[] input = "crash input".getBytes();
        RunResult result = createCrashResult(139);
        
        Path saved = manager.saveCrash(input, result);
        
        assertNotNull(saved);
        assertTrue(Files.exists(saved));
        assertTrue(saved.getFileName().toString().startsWith("crash_000001"));
        assertTrue(saved.getFileName().toString().contains("exit_139"));
    }

    @Test
    void shouldSaveHang() {
        byte[] input = "hang input".getBytes();
        RunResult result = createHangResult();
        
        Path saved = manager.saveHang(input, result);
        
        assertNotNull(saved);
        assertTrue(Files.exists(saved));
        assertTrue(saved.getFileName().toString().startsWith("hang_000001"));
    }

    @Test
    void shouldTrackStats() throws IOException {
        Coverage coverage = createCoverage(5);
        RunResult crash = createCrashResult(139);
        RunResult hang = createHangResult();
        
        manager.saveToQueue("q1".getBytes(), coverage);
        manager.saveToQueue("q2".getBytes(), coverage);
        manager.saveCrash("c1".getBytes(), crash);
        manager.saveHang("h1".getBytes(), hang);
        manager.saveHang("h2".getBytes(), hang);
        
        CorpusManager.CorpusStats stats = manager.stats();
        
        assertEquals(2, stats.queueSize());
        assertEquals(1, stats.crashCount());
        assertEquals(2, stats.hangCount());
        assertTrue(stats.totalBytes() > 0);
    }

    @Test
    void shouldReturnCorrectDirectories() {
        assertEquals(tempDir, manager.outputDir());
        assertEquals(tempDir.resolve("queue"), manager.queueDir());
        assertEquals(tempDir.resolve("crashes"), manager.crashesDir());
        assertEquals(tempDir.resolve("hangs"), manager.hangsDir());
    }

    @Test
    void shouldPreserveInputContent() throws IOException {
        byte[] input = new byte[]{0x00, 0x01, (byte) 0xFF, 0x7F};
        Coverage coverage = createCoverage(5);
        
        Path saved = manager.saveToQueue(input, coverage);
        byte[] read = Files.readAllBytes(saved);
        
        assertArrayEquals(input, read);
    }

    @Test
    void shouldGenerateUniqueFilenames() {
        Coverage coverage = createCoverage(5);
        
        // Same content should still get different IDs
        Path p1 = manager.saveToQueue("same".getBytes(), coverage);
        Path p2 = manager.saveToQueue("same".getBytes(), coverage);
        
        assertNotEquals(p1, p2);
        assertTrue(p1.getFileName().toString().contains("id_000001"));
        assertTrue(p2.getFileName().toString().contains("id_000002"));
    }

    @Test
    void shouldListQueueFiles() throws IOException {
        Coverage coverage = createCoverage(5);
        manager.saveToQueue("input1".getBytes(), coverage);
        manager.saveToQueue("input2".getBytes(), coverage);
        
        List<Path> files = Files.list(manager.queueDir()).toList();
        
        assertEquals(2, files.size());
    }
}
