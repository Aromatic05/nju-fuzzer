package edu.nju.fuzzing.core;

import edu.nju.fuzzing.exec.CommandResolver;
import edu.nju.fuzzing.exec.Executor;
import edu.nju.fuzzing.exec.InputMode;
import edu.nju.fuzzing.exec.TargetCommand;
import edu.nju.fuzzing.model.RunResult;
import edu.nju.fuzzing.model.StatsTick;
import edu.nju.fuzzing.model.TargetSpec;
import edu.nju.fuzzing.stats.StatsWriter;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

public class FuzzingEngine {

    private final Path workdir;
    private final int durationSec;
    private final TargetSpec targetSpec;
    private final Executor executor;
    private final Duration timeout;

    // 仅用于测试：让循环不 sleep，提高稳定性
    private final long tickSleepMs;

    private final AtomicLong testcaseSeq = new AtomicLong(0);

    public FuzzingEngine(Path workdir,
                         int durationSec,
                         TargetSpec targetSpec,
                         Executor executor,
                         Duration timeout) {
        this(workdir, durationSec, targetSpec, executor, timeout, 1000);
    }

    public FuzzingEngine(Path workdir,
                         int durationSec,
                         TargetSpec targetSpec,
                         Executor executor,
                         Duration timeout,
                         long tickSleepMs) {
        this.workdir = workdir;
        this.durationSec = durationSec;
        this.targetSpec = targetSpec;
        this.executor = executor;
        this.timeout = timeout;
        this.tickSleepMs = tickSleepMs;
    }

    public void run() throws Exception {
        Path statsFile = workdir.resolve("stats/stats.csv");
        Path inputsDir = workdir.resolve("tmp/inputs");
        Path logsDir = workdir.resolve("tmp/exec-logs");

        Files.createDirectories(inputsDir);
        Files.createDirectories(logsDir);

        long startSec = Instant.now().getEpochSecond();
        long execsTotal = 0;

        try (StatsWriter writer = new StatsWriter(statsFile)) {
            while (true) {
                long nowSec = Instant.now().getEpochSecond();
                long elapsed = nowSec - startSec;
                if (elapsed >= durationSec) break;

                // 生成一个 testcase 文件（可复现）
                long id = testcaseSeq.incrementAndGet();
                String tcId = String.format("tc_%06d", id);
                Path inputFile = inputsDir.resolve(tcId + ".bin");

                byte[] payload = ("hello-from-engine " + tcId + "\n").getBytes();
                Files.write(inputFile, payload);

                // 解析命令（自动 FILE/STDIN）
                TargetCommand cmd = CommandResolver.resolve(targetSpec, inputFile);

                // 根据输入模式决定 stdinData
                byte[] stdinData = null;
                if (cmd.inputMode() == InputMode.STDIN) {
                    stdinData = payload; // STDIN 模式：写入 stdin（也保留文件）
                }

                // 每个 testcase 单独的日志目录
                Path tcLogDir = logsDir.resolve(tcId);
                Files.createDirectories(tcLogDir);

                RunResult rr = executor.run(cmd, stdinData, timeout, tcLogDir);
                execsTotal++;

                // Skeleton：coverage/queue 等先写 0
                StatsTick tick = new StatsTick(
                        elapsed,
                        execsTotal,
                        execsTotal / Math.max(1.0, elapsed + 1e-9), // 避免 0 除
                        0,
                        0,
                        0
                );
                writer.tick(tick);

                if (tickSleepMs > 0) Thread.sleep(tickSleepMs);
            }
        }
    }
}
