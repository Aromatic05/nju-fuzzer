package edu.nju.fuzzing.exec;

import edu.nju.fuzzing.model.RunResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ProcessExecutorTest {

    @TempDir
    Path tempDir;

    @Test
    void run_fileMode_catFile_shouldEchoFileToStdout() throws Exception {
        // Arrange
        Path input = tempDir.resolve("input.txt");
        byte[] payload = "hello-file\n".getBytes(StandardCharsets.UTF_8);
        Files.write(input, payload);

        TargetCommand cmd = new TargetCommand(
                List.of("/bin/cat", input.toAbsolutePath().toString()), // already resolved argv
                InputMode.FILE,
                input,
                Map.of()
        );

        ProcessExecutor executor = new ProcessExecutor();
        Path outDir = tempDir.resolve("out-file");

        // Act
        RunResult rr = executor.run(cmd, null, Duration.ofSeconds(1), outDir);

        // Assert
        assertFalse(rr.timedOut());
        assertEquals(RunResult.Termination.NORMAL, rr.termination());
        assertEquals(0, rr.exitCode());

        byte[] stdout = Files.readAllBytes(rr.stdoutFile());
        assertArrayEquals(payload, stdout);

        assertTrue(Files.exists(rr.stderrFile()));
    }

    @Test
    void run_stdinMode_cat_shouldEchoStdinToStdout() throws Exception {
        // Arrange
        byte[] payload = "hello-stdin\n".getBytes(StandardCharsets.UTF_8);

        TargetCommand cmd = new TargetCommand(
                List.of("/bin/cat"),
                InputMode.STDIN,
                null,
                Map.of()
        );

        ProcessExecutor executor = new ProcessExecutor();
        Path outDir = tempDir.resolve("out-stdin");

        // Act
        RunResult rr = executor.run(cmd, payload, Duration.ofSeconds(1), outDir);

        // Assert
        assertFalse(rr.timedOut());
        assertEquals(RunResult.Termination.NORMAL, rr.termination());
        assertEquals(0, rr.exitCode());

        byte[] stdout = Files.readAllBytes(rr.stdoutFile());
        assertArrayEquals(payload, stdout);
    }

    @Test
    void run_timeout_sleep_shouldReturnTimeout() throws Exception {
        // Arrange
        TargetCommand cmd = new TargetCommand(
                List.of("/bin/sleep", "5"),
                InputMode.STDIN, // stdin irrelevant here
                null,
                Map.of()
        );

        ProcessExecutor executor = new ProcessExecutor();
        Path outDir = tempDir.resolve("out-timeout");

        // Act
        RunResult rr = executor.run(cmd, null, Duration.ofMillis(100), outDir);

        // Assert
        assertTrue(rr.timedOut());
        assertEquals(RunResult.Termination.TIMEOUT, rr.termination());
        assertEquals(-1, rr.exitCode());
    }

    @Test
    void run_nonZeroExit_false_shouldReturnError() throws Exception {
        // Arrange
        TargetCommand cmd = new TargetCommand(
                List.of("/bin/false"),
                InputMode.STDIN,
                null,
                Map.of()
        );

        ProcessExecutor executor = new ProcessExecutor();
        Path outDir = tempDir.resolve("out-error");

        // Act
        RunResult rr = executor.run(cmd, null, Duration.ofSeconds(1), outDir);

        // Assert
        assertFalse(rr.timedOut());
        assertEquals(RunResult.Termination.ERROR, rr.termination());
        assertNotEquals(0, rr.exitCode());
    }
}
