package edu.nju.fuzzing.core;

import edu.nju.fuzzing.cov.CoverageMonitor;
import edu.nju.fuzzing.cov.NullCoverageMonitor;
import edu.nju.fuzzing.exec.CommandResolver;
import edu.nju.fuzzing.exec.Executor;
import edu.nju.fuzzing.exec.ProcessExecutor;
import edu.nju.fuzzing.exec.TargetCommand;
import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.CoverageEx;
import edu.nju.fuzzing.model.ExecInput;
import edu.nju.fuzzing.model.ExecResult;
import edu.nju.fuzzing.model.RunResult;
import edu.nju.fuzzing.model.TargetSpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for ExecutorHarness and related components.
 */
class ExecutorHarnessTest {
    
    @TempDir
    Path tempDir;
    
    @Test
    @DisplayName("InstrumentedExecutorHarness executes without coverage")
    void harness_withNullMonitor_executesSuccessfully() throws Exception {
        // Setup
        Executor executor = new ProcessExecutor();
        CoverageMonitor monitor = new NullCoverageMonitor(65536);
        ExecutorHarness harness = new InstrumentedExecutorHarness(executor, monitor);
        
        Path inputFile = tempDir.resolve("input.txt");
        Files.writeString(inputFile, "hello world");
        
        TargetSpec spec = new TargetSpec(
            "FILE",
            Path.of("/bin/cat"),
            List.of("/bin/cat", "@@"),
            Map.of(),
            Duration.ofSeconds(1)
        );
        TargetCommand cmd = CommandResolver.resolve(spec, inputFile);
        
        ExecInput input = ExecInput.of(cmd, null, Duration.ofSeconds(1), tempDir.resolve("logs"));
        
        // Execute
        harness.start();
        try {
            ExecResult result = harness.execute(input);
            
            // Verify
            assertNotNull(result);
            assertNotNull(result.run());
            assertNotNull(result.coverage());
            assertTrue(result.isNormal());
            assertFalse(result.isInteresting());  // No coverage monitor
            assertEquals(0, result.run().exitCode());
        } finally {
            harness.close();
        }
    }
    
    @Test
    @DisplayName("ExecResult provides convenient status checks")
    void execResult_providesStatusChecks() {
        // This would be populated by actual execution
        // Here we just verify the convenience methods exist
        Path dummyFile = tempDir.resolve("dummy");
        
        var normalRun = RunResult.of(
            1L, dummyFile, 100L,
            0, false, RunResult.Termination.NORMAL,
            dummyFile, dummyFile
        );
        
        var errorRun = RunResult.of(
            2L, dummyFile, 100L,
            139, false, RunResult.Termination.ERROR,
            dummyFile, dummyFile
        );
        
        var timeoutRun = RunResult.of(
            3L, dummyFile, 1000L,
            -1, true, RunResult.Termination.TIMEOUT,
            dummyFile, dummyFile
        );
        
        var normalCov = CoverageEx.fromBasic(Coverage.empty(normalRun));
        var errorCov = CoverageEx.fromBasic(Coverage.empty(errorRun));
        var timeoutCov = CoverageEx.fromBasic(Coverage.empty(timeoutRun));
        
        ExecResult normalResult = new ExecResult(normalRun, normalCov);
        ExecResult errorResult = new ExecResult(errorRun, errorCov);
        ExecResult timeoutResult = new ExecResult(timeoutRun, timeoutCov);
        
        assertTrue(normalResult.isNormal());
        assertFalse(normalResult.isCrash());
        assertFalse(normalResult.isTimeout());
        
        assertFalse(errorResult.isNormal());
        assertTrue(errorResult.isCrash());
        assertFalse(errorResult.isTimeout());
        
        assertFalse(timeoutResult.isNormal());
        assertFalse(timeoutResult.isCrash());
        assertTrue(timeoutResult.isTimeout());
    }
    
    @Test
    @DisplayName("ExecInput factory methods work correctly")
    void execInput_factoryMethods() {
        Path dummyFile = tempDir.resolve("dummy");
        TargetSpec spec = new TargetSpec(
            "FILE",
            Path.of("/bin/cat"),
            List.of("/bin/cat", "@@"),
            Map.of(),
            Duration.ofSeconds(1)
        );
        TargetCommand cmd = CommandResolver.resolve(spec, dummyFile);
        
        // Default (no logs)
        ExecInput input1 = ExecInput.of(cmd, null, Duration.ofSeconds(1), tempDir);
        assertFalse(input1.saveLogs());
        
        // With logs
        ExecInput input2 = ExecInput.withLogs(cmd, null, Duration.ofSeconds(1), tempDir);
        assertTrue(input2.saveLogs());
    }
    
    @Test
    @DisplayName("NullCoverageMonitor returns empty coverage")
    void nullMonitor_returnsEmptyCoverage() throws Exception {
        try (CoverageMonitor monitor = new NullCoverageMonitor(65536)) {
            Path dummyFile = tempDir.resolve("dummy");
            var run = RunResult.of(
                1L, dummyFile, 100L,
                0, false, RunResult.Termination.NORMAL,
                dummyFile, dummyFile
            );
            
            Coverage coverage = monitor.afterRun(run);
            
            assertNotNull(coverage);
            assertEquals(0, coverage.newBytes());
            assertFalse(coverage.interesting());
            assertEquals(65536, coverage.mapSize());
        }
    }
}
