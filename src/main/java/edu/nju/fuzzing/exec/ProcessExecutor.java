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
    
    private final AtomicLong execIdCounter = new AtomicLong(0);

    @Override
    public RunResult run(TargetCommand cmd, byte[] stdinData, Duration timeout, Path outDir) throws Exception {
        long execId = execIdCounter.incrementAndGet();
        
        if (cmd == null) throw new IllegalArgumentException("cmd is null");
        if (timeout == null) timeout = Duration.ofSeconds(1);
        if (outDir == null) throw new IllegalArgumentException("outDir is null");

        Files.createDirectories(outDir);

        // logs
        Path stdoutFile = outDir.resolve("stdout.log");
        Path stderrFile = outDir.resolve("stderr.log");

        ProcessBuilder pb = new ProcessBuilder(cmd.argv());
        pb.redirectOutput(stdoutFile.toFile());
        pb.redirectError(stderrFile.toFile());

        // env
        Map<String, String> env = pb.environment();
        env.putAll(cmd.env());

        long startNs = System.nanoTime();
        Process p = pb.start();

        // stdin handling
        if (cmd.inputMode() == InputMode.STDIN) {
            // stdinData may be null -> treat as empty
            byte[] data = (stdinData == null) ? new byte[0] : stdinData;
            OutputStream os = p.getOutputStream();
            try {
                try {
                    os.write(data);
                    os.flush();
                } catch (java.io.IOException e) {
                    // Child process may have exited (e.g. crashed) before or during write.
                    // This manifests as a Broken pipe on some platforms/CI. Ignore and proceed.
                }
            } finally {
                try {
                    os.close();
                } catch (Exception ignored) {
                    // ignore close errors (Broken pipe may surface here on some platforms)
                }
            }
        } else {
            // FILE mode: no stdin required; close to avoid target waiting on stdin
            try {
                p.getOutputStream().close();
            } catch (Exception ignored) {}
        }

        boolean finished = p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
        long execTimeNs = System.nanoTime() - startNs;
        long execTimeMs = execTimeNs / 1_000_000;

        if (!finished) {
            // timeout: kill process
            p.destroy();
            // give it a short grace period
            boolean exited = p.waitFor(100, TimeUnit.MILLISECONDS);
            if (!exited) {
                p.destroyForcibly();
                p.waitFor(200, TimeUnit.MILLISECONDS);
            }
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
        RunResult.Termination term = (exitCode == 0) ? RunResult.Termination.NORMAL : RunResult.Termination.ERROR;

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
    }
}
