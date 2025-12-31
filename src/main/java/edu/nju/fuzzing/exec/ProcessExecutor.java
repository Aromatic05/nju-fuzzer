package edu.nju.fuzzing.exec;

import edu.nju.fuzzing.model.RunResult;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class ProcessExecutor implements Executor {

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(1);
    private static final long KILL_GRACE_MS = 100;
    private static final long FORCE_KILL_GRACE_MS = 200;

    private final AtomicLong execIdCounter = new AtomicLong(0);

    private enum ExecLogMode {
        ALL,
        NONE
    }

    private static ExecLogMode execLogMode() {
        String raw = System.getProperty("nju.fuzzer.execLogs", "all");
        if (raw == null) return ExecLogMode.ALL;
        String v = raw.trim().toLowerCase();
        return switch (v) {
            case "none", "off", "disable", "disabled", "0", "false" -> ExecLogMode.NONE;
            default -> ExecLogMode.ALL;
        };
    }

    @Override
    public RunResult run(TargetCommand cmd, byte[] stdinData, Duration timeout, Path outDir) throws Exception {
        if (cmd == null) throw new IllegalArgumentException("cmd is null");
        if (outDir == null) throw new IllegalArgumentException("outDir is null");

        long execId = execIdCounter.incrementAndGet();
        Duration effectiveTimeout = (timeout == null) ? DEFAULT_TIMEOUT : timeout;

        // Avoid zero/negative timeouts causing immediate waitFor(0)
        long timeoutMs = Math.max(1L, effectiveTimeout.toMillis());

        ExecLogMode logMode = execLogMode();

        Path stdoutFile = null;
        Path stderrFile = null;
        if (logMode == ExecLogMode.ALL) {
            Files.createDirectories(outDir);
            // logs: include execId to avoid overwriting across runs
            stdoutFile = outDir.resolve("stdout_" + execId + ".log");
            stderrFile = outDir.resolve("stderr_" + execId + ".log");
        }

        ProcessBuilder pb = new ProcessBuilder(cmd.argv());

        // stdout/stderr redirection
        if (logMode == ExecLogMode.ALL) {
            pb.redirectOutput(stdoutFile.toFile());
            pb.redirectError(stderrFile.toFile());
        } else {
            pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
        }

        // Ensure we can write stdin (PIPE) when needed; we'll close it otherwise
        pb.redirectInput(ProcessBuilder.Redirect.PIPE);

        // env
        Map<String, String> env = pb.environment();
        if (cmd.env() != null && !cmd.env().isEmpty()) {
            env.putAll(cmd.env());
        }

        long startNs = System.nanoTime();
        Process p = null;

        try {
            p = pb.start();

            // stdin handling
            if (cmd.inputMode() == InputMode.STDIN) {
                byte[] data = (stdinData == null) ? new byte[0] : stdinData;

                try (OutputStream os = p.getOutputStream()) {
                    try {
                        os.write(data);
                        os.flush();
                    } catch (java.io.IOException ignored) {
                        // Child may crash/exit before or during write (broken pipe). Ignore and proceed.
                    }
                } catch (Exception ignored) {
                    // Ignore close/write exceptions to avoid masking target failures.
                }
            } else {
                // FILE mode: close stdin to avoid target blocking on stdin
                try {
                    p.getOutputStream().close();
                } catch (Exception ignored) {
                }
            }

            boolean finished = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            long execTimeNs = System.nanoTime() - startNs;
            long execTimeMs = execTimeNs / 1_000_000;

            if (!finished) {
                // timeout: kill process
                terminateProcess(p);

                return new RunResult(
                        execId,
                        cmd.inputFile(),
                        execTimeMs,
                        execTimeNs,
                        -1,
                        true,
                        RunResult.Termination.TIMEOUT,
                        stdoutFile,
                        stderrFile
                );
            }

            int exitCode = p.exitValue();
            RunResult.Termination term = (exitCode == 0)
                    ? RunResult.Termination.NORMAL
                    : RunResult.Termination.ERROR;

            return new RunResult(
                    execId,
                    cmd.inputFile(),
                    execTimeMs,
                    execTimeNs,
                    exitCode,
                    false,
                    term,
                    stdoutFile,
                    stderrFile
            );

        } catch (Exception e) {
            // If the process was started but we failed mid-way, ensure it's cleaned up.
            if (p != null) {
                try {
                    terminateProcess(p);
                } catch (Exception ignored) {
                }
            }
            throw e;
        }
    }

    private static void terminateProcess(Process p) {
        if (!p.isAlive()) return;

        // Try graceful
        p.destroy();
        try {
            if (p.waitFor(KILL_GRACE_MS, TimeUnit.MILLISECONDS)) return;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }

        // Force kill
        p.destroyForcibly();
        try {
            p.waitFor(FORCE_KILL_GRACE_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
}
