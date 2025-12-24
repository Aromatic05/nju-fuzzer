package edu.nju.fuzzing.core;

import edu.nju.fuzzing.cov.NullCoverageMonitor;
import edu.nju.fuzzing.exec.CrashOracle;
import edu.nju.fuzzing.exec.Executor;
import edu.nju.fuzzing.exec.TargetCommand;
import edu.nju.fuzzing.model.RunResult;
import edu.nju.fuzzing.model.TargetSpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class FuzzingEngineCrashOracleIntegrationTest {

    @TempDir
    Path tempDir;

    @Test
    void engine_shouldNotTreatWhitelistedExitCodesAsCrash() throws Exception {
        Path workdir = tempDir.resolve("wd");
        Files.createDirectories(workdir);

        // Executor always returns exitCode=2 (commonly used by parsers for "invalid input")
        Executor executor = new Executor() {
            private long id = 0;

            @Override
            public RunResult run(TargetCommand cmd, byte[] stdinData, Duration timeout, Path outDir) throws Exception {
                long execId = ++id;
                Files.createDirectories(outDir);
                Path stdout = outDir.resolve("stdout_" + execId + ".log");
                Path stderr = outDir.resolve("stderr_" + execId + ".log");
                Files.writeString(stdout, "");
                Files.writeString(stderr, "");

                return new RunResult(
                        execId,
                        null,
                        1,
                        1_000_000L,
                        2,
                        false,
                        RunResult.Termination.ERROR,
                        stdout,
                        stderr
                );
            }
        };

        TargetSpec spec = new TargetSpec(
                "T",
                Path.of("/bin/true"),
                List.of("/bin/true"),
                Map.of(),
                Duration.ofMillis(100)
        );

        CrashOracle oracle = CrashOracle.withNonCrashExitCodes(Set.of(2));

        FuzzingEngine engine = new FuzzingEngine(
                workdir,
                workdir.resolve("seeds"),
                1,
                spec,
                executor,
                Duration.ofMillis(100),
                new NullCoverageMonitor(65536),
                null,
                oracle,
                0
        );

        engine.run();

        // crashes dir should remain empty
        Path crashesDir = workdir.resolve("crashes");
        assertTrue(Files.isDirectory(crashesDir));
        try (Stream<Path> s = Files.list(crashesDir)) {
            assertEquals(0, s.count(), "crashes dir should be empty when exit code is whitelisted");
        }

        // stats.csv crash_count should be 0
        Path stats = workdir.resolve("stats/stats.csv");
        assertTrue(Files.exists(stats));
        var lines = Files.readAllLines(stats);
        String last = lines.get(lines.size() - 1);
        // csv columns end with crash_count,hang_count
        String[] parts = last.split(",");
        int crashCount = Integer.parseInt(parts[parts.length - 2]);
        assertEquals(0, crashCount);
    }
}
