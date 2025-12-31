package edu.nju.fuzzing.exec;

import edu.nju.fuzzing.model.RunResult;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
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
        INTERESTING,
        NONE
    }

    private static long execLogsMaxBytes() {
        String raw = System.getProperty("nju.fuzzer.execLogsMaxBytes", "1048576");
        if (raw == null || raw.isBlank()) return 1_048_576L;
        try {
            return Math.max(0L, Long.parseLong(raw.trim()));
        } catch (NumberFormatException ignored) {
            return 1_048_576L;
        }
    }

    private static final class LimitedBuffer {
        private final long limit;
        private final ByteArrayOutputStream buf;

        LimitedBuffer(long limit) {
            this.limit = Math.max(0L, limit);
            this.buf = new ByteArrayOutputStream((int) Math.min(this.limit, 8192L));
        }

        void append(byte[] bytes, int off, int len) {
            if (limit == 0L) return;
            int remain = (int) Math.max(0L, limit - buf.size());
            if (remain <= 0) return;
            buf.write(bytes, off, Math.min(remain, len));
        }

        int size() {
            return buf.size();
        }

        byte[] toByteArray() {
            return buf.toByteArray();
        }
    }

    private static LimitedBuffer drainStream(java.io.InputStream is, long limit) {
        LimitedBuffer out = new LimitedBuffer(limit);
        byte[] buf = new byte[8192];
        try (is) {
            int n;
            while ((n = is.read(buf)) >= 0) {
                if (n == 0) continue;
                out.append(buf, 0, n);
            }
        } catch (Exception ignored) {
            // best-effort
        }
        return out;
    }

    private static ExecLogMode execLogMode() {
        String raw = System.getProperty("nju.fuzzer.execLogs", "interesting");
        if (raw == null) return ExecLogMode.ALL;
        String v = raw.trim().toLowerCase();
        return switch (v) {
            case "interesting" -> ExecLogMode.INTERESTING;
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

        List<String> argv = new ArrayList<>(cmd.argv());
        // If argv[0] is a relative path containing '/', make it absolute before we change cwd.
        // This keeps integrations/tests working when they pass e.g. "env/out/lua".
        if (!argv.isEmpty()) {
            String exe = argv.get(0);
            if (exe != null && exe.contains("/")) {
                try {
                    Path exePath = Path.of(exe);
                    if (!exePath.isAbsolute()) {
                        Path base = Path.of(System.getProperty("user.dir", ".")).toAbsolutePath().normalize();
                        argv.set(0, base.resolve(exePath).normalize().toString());
                    }
                } catch (Exception ignored) {
                    // best-effort
                }
            }
        }

        ProcessBuilder pb = new ProcessBuilder(argv);

        // IMPORTANT: set working directory for the child process.
        // Otherwise it inherits the launcher CWD (often repo root), and targets/scripts using relative
        // file paths may create files like "xxx.lua" in the repository root.
        // We best-effort anchor it under this run's workdir (derived from outDir=workdir/tmp/exec-logs).
        try {
            Path wd = outDir;
            if (outDir.getParent() != null && outDir.getParent().getParent() != null) {
                wd = outDir.getParent().getParent();
            }
            Files.createDirectories(wd);
            pb.directory(wd.toFile());
        } catch (Exception ignored) {
            // best-effort
        }

        // stdout/stderr redirection
        if (logMode == ExecLogMode.ALL) {
            pb.redirectOutput(ProcessBuilder.Redirect.PIPE);
            pb.redirectError(ProcessBuilder.Redirect.PIPE);
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

            final Process proc = p;

            java.util.concurrent.Future<LimitedBuffer> stdoutFuture = null;
            java.util.concurrent.Future<LimitedBuffer> stderrFuture = null;
            java.util.concurrent.ExecutorService ioPool = null;
            long maxLogBytes = execLogsMaxBytes();
            if (logMode == ExecLogMode.ALL) {
                ioPool = java.util.concurrent.Executors.newFixedThreadPool(2, r -> {
                    Thread t = new Thread(r, "nju-fuzzer-exec-io");
                    t.setDaemon(true);
                    return t;
                });
                stdoutFuture = ioPool.submit(() -> drainStream(proc.getInputStream(), maxLogBytes));
                stderrFuture = ioPool.submit(() -> drainStream(proc.getErrorStream(), maxLogBytes));
            }

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

            LimitedBuffer stdoutBuf = null;
            LimitedBuffer stderrBuf = null;
            if (logMode == ExecLogMode.ALL) {
                try {
                    stdoutBuf = (stdoutFuture == null) ? null : stdoutFuture.get(200, TimeUnit.MILLISECONDS);
                } catch (Exception ignored) {
                }
                try {
                    stderrBuf = (stderrFuture == null) ? null : stderrFuture.get(200, TimeUnit.MILLISECONDS);
                } catch (Exception ignored) {
                }
                if (ioPool != null) {
                    ioPool.shutdownNow();
                }

                // Only persist non-empty logs.
                if (stdoutBuf != null && stdoutBuf.size() > 0) {
                    Files.createDirectories(outDir);
                    stdoutFile = outDir.resolve("stdout_" + execId + ".log");
                    Files.write(stdoutFile, stdoutBuf.toByteArray());
                }
                if (stderrBuf != null && stderrBuf.size() > 0) {
                    Files.createDirectories(outDir);
                    stderrFile = outDir.resolve("stderr_" + execId + ".log");
                    Files.write(stderrFile, stderrBuf.toByteArray());
                }
            }

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
