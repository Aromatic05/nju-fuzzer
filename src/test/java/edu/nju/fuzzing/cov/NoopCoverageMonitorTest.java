package edu.nju.fuzzing.cov;
import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.RunResult;
import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;
class NoopCoverageMonitorTest {
    @Test
    void testBeforeRunDoesNotThrow() {
        CoverageMonitor monitor = new NoopCoverageMonitor();
        assertDoesNotThrow(monitor::beforeRun);
    }
    @Test
    void testAfterRunReturnsEmptyCoverage() {
        CoverageMonitor monitor = new NoopCoverageMonitor();
        RunResult result = new RunResult(
                Path.of("/tmp/test.bin"),
                1000L,
                0,
                false,
                RunResult.Termination.NORMAL,
                Path.of("/tmp/stdout"),
                Path.of("/tmp/stderr")
        );
        Coverage coverage = monitor.afterRun(result);
        assertNotNull(coverage);
        assertTrue(coverage.execId() > 0);
        assertEquals(0, coverage.nonZeroBytes());
        assertEquals(0, coverage.newBytes());
        assertFalse(coverage.interesting());
    }
    @Test
    void testMultipleCallsReturnConsistentResults() {
        CoverageMonitor monitor = new NoopCoverageMonitor();
        long firstExecId = -1;
        for (int i = 0; i < 10; i++) {
            RunResult result = new RunResult(
                    Path.of("/tmp/test_" + i + ".bin"),
                    1000L,
                    0,
                    false,
                    RunResult.Termination.NORMAL,
                    Path.of("/tmp/stdout"),
                    Path.of("/tmp/stderr")
            );
            Coverage coverage = monitor.afterRun(result);
            if (i == 0) {
                firstExecId = coverage.execId();
            }
            // execId should increment
            assertEquals(firstExecId + i, coverage.execId());
            assertFalse(coverage.interesting());
        }
    }
}
