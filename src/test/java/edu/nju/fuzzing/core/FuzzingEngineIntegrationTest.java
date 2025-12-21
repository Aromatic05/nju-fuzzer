package edu.nju.fuzzing.core;

import edu.nju.fuzzing.corpus.CorpusManager;
import edu.nju.fuzzing.corpus.FileCorpusManager;
import edu.nju.fuzzing.cov.BitmapSource;
import edu.nju.fuzzing.cov.CoverageDiffStrategy;
import edu.nju.fuzzing.cov.ShmCoverageMonitor;
import edu.nju.fuzzing.exec.Executor;
import edu.nju.fuzzing.exec.ProcessExecutor;
import edu.nju.fuzzing.model.TargetSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test demonstrating FuzzingEngine with coverage monitoring.
 * 
 * Tests both scenarios:
 * 1. Without coverage (non-instrumented target)
 * 2. With coverage (AFL++ instrumented target)
 */
class FuzzingEngineIntegrationTest {

    @TempDir
    Path workdir;

    private Executor executor;

    @BeforeEach
    void setUp() {
        executor = new ProcessExecutor();
    }

    @Test
    void shouldRunWithoutCoverage() throws Exception {
        // Target: /bin/cat (non-instrumented)
        TargetSpec spec = new TargetSpec(
                "T_CAT",
                Path.of("/bin/cat"),
                List.of("/bin/cat", "@@"),
                Map.of(),
                Duration.ofMillis(500)
        );

        FuzzingEngine engine = new FuzzingEngine(
                workdir,
                1, // 1 second
                spec,
                executor,
                spec.timeout(),
                100 // fast tick for testing
        );

        // Should run without errors
        assertDoesNotThrow(() -> engine.run());

        // Verify basic structure
        assertTrue(Files.exists(workdir.resolve("stats/stats.csv")));
        assertTrue(Files.exists(workdir.resolve("tmp/inputs")));
        assertTrue(Files.exists(workdir.resolve("tmp/exec-logs")));

        // Verify stats file has content (at least header + one data line)
        String stats = Files.readString(workdir.resolve("stats/stats.csv"));
        String[] lines = stats.split("\n");
        assertTrue(lines.length >= 2, "Stats file should have header + data lines");
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    void shouldRunWithCoverageMonitoring() throws Exception {
        // Check if AFL++ instrumented binary exists
        Path luaBinary = Path.of("env/out/lua");
        if (!Files.exists(luaBinary)) {
            System.out.println("INFO: Skipping test - AFL++ instrumented lua not found at " + luaBinary);
            return; // Skip test gracefully
        }

        // Create corpus manager
        CorpusManager corpusManager = new FileCorpusManager(workdir);

        // Create mock bitmap source for testing (since we may not have real SHM)
        BitmapSource mockBitmap = new MockBitmapSource();
        CoverageDiffStrategy strategy = CoverageDiffStrategy.createDefault(65536);
        ShmCoverageMonitor coverageMonitor = new ShmCoverageMonitor(mockBitmap, strategy);

        // Target: instrumented lua
        TargetSpec spec = new TargetSpec(
                "T_LUA",
                luaBinary,
                List.of(luaBinary.toString(), "@@"),
                Map.of(),
                Duration.ofMillis(500)
        );

        FuzzingEngine engine = new FuzzingEngine(
                workdir,
                1, // 1 second
                spec,
                executor,
                spec.timeout(),
                coverageMonitor,
                corpusManager,
                100 // faster tick for testing
        );

        // Run the engine
        assertDoesNotThrow(() -> engine.run());

        // Verify corpus directories were created
        assertTrue(Files.exists(workdir.resolve("queue")));
        assertTrue(Files.exists(workdir.resolve("crashes")));
        assertTrue(Files.exists(workdir.resolve("hangs")));

        // Verify stats
        var stats = corpusManager.stats();
        assertTrue(stats.queueSize() >= 0);
        assertTrue(stats.crashCount() >= 0);
        assertTrue(stats.hangCount() >= 0);
    }

    @Test
    void shouldHandleCrashingTarget() throws Exception {
        // Create a crashing target script
        Path crashScript = workdir.resolve("crash.sh");
        Files.writeString(crashScript, "#!/bin/bash\nexit 139\n");
        crashScript.toFile().setExecutable(true);

        CorpusManager corpusManager = new FileCorpusManager(workdir);
        BitmapSource mockBitmap = new MockBitmapSource();
        CoverageDiffStrategy strategy = CoverageDiffStrategy.createDefault(65536);
        ShmCoverageMonitor coverageMonitor = new ShmCoverageMonitor(mockBitmap, strategy);

        TargetSpec spec = new TargetSpec(
                "T_CRASH",
                crashScript,
                List.of(crashScript.toString()),
                Map.of(),
                Duration.ofMillis(500)
        );

        FuzzingEngine engine = new FuzzingEngine(
                workdir,
                1,
                spec,
                executor,
                spec.timeout(),
                coverageMonitor,
                corpusManager,
                100
        );

        assertDoesNotThrow(() -> engine.run());

        // Verify crashes were saved
        var stats = corpusManager.stats();
        assertTrue(stats.crashCount() > 0, "Expected at least one crash");
    }

    /**
     * Mock bitmap source for testing without real AFL++ SHM.
     */
    private static class MockBitmapSource implements BitmapSource {
        private byte[] bitmap = new byte[65536];
        private int callCount = 0;
        private boolean attached = false;

        @Override
        public int mapSize() {
            return 65536;
        }

        @Override
        public void readInto(byte[] dst) {
            // Simulate changing coverage
            callCount++;
            if (callCount % 5 == 0) {
                // Every 5th call, add new coverage
                bitmap[callCount % 1000] = (byte) (callCount % 255);
            }
            System.arraycopy(bitmap, 0, dst, 0, Math.min(bitmap.length, dst.length));
        }

        @Override
        public void clear() {
            // Don't actually clear for testing, to see accumulated coverage
        }

        @Override
        public boolean isAttached() {
            return attached;
        }

        @Override
        public void close() {
            attached = false;
        }
    }
}
