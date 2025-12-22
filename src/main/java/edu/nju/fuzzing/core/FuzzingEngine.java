package edu.nju.fuzzing.core;

import edu.nju.fuzzing.corpus.CorpusManager;
import edu.nju.fuzzing.cov.CoverageMonitor;
import edu.nju.fuzzing.cov.ShmCoverageMonitor;
import edu.nju.fuzzing.exec.CommandResolver;
import edu.nju.fuzzing.exec.Executor;
import edu.nju.fuzzing.exec.InputMode;
import edu.nju.fuzzing.exec.TargetCommand;
import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.RunResult;
import edu.nju.fuzzing.model.StatsTick;
import edu.nju.fuzzing.model.TargetSpec;
import edu.nju.fuzzing.stats.FuzzStats;
import edu.nju.fuzzing.stats.StatusPrinter;
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

    // Coverage monitoring (optional, can be null for non-instrumented targets)
    private final CoverageMonitor coverageMonitor;
    private final CorpusManager corpusManager;
    private final FuzzStats fuzzStats;
    private final StatusPrinter statusPrinter;
    
    // 仅用于测试：让循环不 sleep，提高稳定性
    private final long tickSleepMs;

    private final AtomicLong testcaseSeq = new AtomicLong(0);

    /**
     * Creates a FuzzingEngine without coverage monitoring (for non-instrumented targets).
     */
    public FuzzingEngine(Path workdir,
                         int durationSec,
                         TargetSpec targetSpec,
                         Executor executor,
                         Duration timeout) {
        this(workdir, durationSec, targetSpec, executor, timeout, null, null, 1000);
    }

    /**
     * Creates a FuzzingEngine without coverage monitoring with custom tick sleep (for testing).
     */
    public FuzzingEngine(Path workdir,
                         int durationSec,
                         TargetSpec targetSpec,
                         Executor executor,
                         Duration timeout,
                         long tickSleepMs) {
        this(workdir, durationSec, targetSpec, executor, timeout, null, null, tickSleepMs);
    }

    /**
     * Creates a FuzzingEngine with coverage monitoring.
     */
    public FuzzingEngine(Path workdir,
                         int durationSec,
                         TargetSpec targetSpec,
                         Executor executor,
                         Duration timeout,
                         CoverageMonitor coverageMonitor,
                         CorpusManager corpusManager) {
        this(workdir, durationSec, targetSpec, executor, timeout, coverageMonitor, corpusManager, 1000);
    }

    /**
     * Full constructor with all parameters (for testing).
     */
    public FuzzingEngine(Path workdir,
                         int durationSec,
                         TargetSpec targetSpec,
                         Executor executor,
                         Duration timeout,
                         CoverageMonitor coverageMonitor,
                         CorpusManager corpusManager,
                         long tickSleepMs) {
        this.workdir = workdir;
        this.durationSec = durationSec;
        this.targetSpec = targetSpec;
        this.executor = executor;
        this.timeout = timeout;
        this.coverageMonitor = coverageMonitor;
        this.corpusManager = corpusManager;
        this.tickSleepMs = tickSleepMs;
        this.fuzzStats = new FuzzStats();
        
        // Create status printer if we have coverage monitoring
        if (coverageMonitor != null && corpusManager != null) {
            this.statusPrinter = StatusPrinter.builder()
                    .statsSupplier(() -> fuzzStats.toStatsTick(corpusManager.stats().queueSize()))
                    .intervalSeconds(1)
                    .build();
        } else {
            this.statusPrinter = null;
        }
    }

    public void run() throws Exception {
        Path statsFile = workdir.resolve("stats/stats.csv");
        Path inputsDir = workdir.resolve("tmp/inputs");
        Path logsDir = workdir.resolve("tmp/exec-logs");

        Files.createDirectories(inputsDir);
        Files.createDirectories(logsDir);

        // Start status printer if available
        if (statusPrinter != null) {
            statusPrinter.start();
        }

        long startSec = Instant.now().getEpochSecond();

        try (StatsWriter writer = new StatsWriter(statsFile)) {
            // If we have a ShmCoverageMonitor, start it
            if (coverageMonitor instanceof ShmCoverageMonitor shmMonitor) {
                shmMonitor.start();
            }

            try {
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

                    // Clear bitmap before execution
                    if (coverageMonitor != null) {
                        coverageMonitor.beforeRun();
                    }

                    // Execute target
                    RunResult rr = executor.run(cmd, stdinData, timeout, tcLogDir);
                    fuzzStats.recordExec();

                    // Collect coverage after execution
                    Coverage coverage = null;
                    if (coverageMonitor != null) {
                        coverage = coverageMonitor.afterRun(rr);
                    } else {
                        coverage = Coverage.empty(rr);
                    }

                    // Handle execution result
                    handleResult(payload, rr, coverage, tcId);

                    // Write stats
                    StatsTick tick = fuzzStats.toStatsTick(
                            corpusManager != null ? corpusManager.stats().queueSize() : 0
                    );
                    writer.tick(tick);

                    if (tickSleepMs > 0) Thread.sleep(tickSleepMs);
                }
            } finally {
                if (coverageMonitor != null) {
                    coverageMonitor.close();
                }
            }
        } finally {
            // Stop status printer
            if (statusPrinter != null) {
                statusPrinter.stop();
            }
        }
    }

    /**
     * Handles the execution result: saves interesting inputs, crashes, hangs.
     */
    private void handleResult(byte[] input, RunResult result, Coverage coverage, String tcId) {
        if (corpusManager == null) {
            return; // No corpus management
        }

        // Check for crashes
        if (result.termination() == RunResult.Termination.ERROR) {
            Path crashPath = corpusManager.saveCrash(input, result);
            fuzzStats.recordCrash();
            if (statusPrinter != null) {
                statusPrinter.printCrash(corpusManager.stats().crashCount(), 
                        "exit_" + result.exitCode());
            }
            return;
        }

        // Check for hangs (timeouts)
        if (result.timedOut()) {
            Path hangPath = corpusManager.saveHang(input, result);
            fuzzStats.recordHang();
            if (statusPrinter != null) {
                statusPrinter.printHang(corpusManager.stats().hangCount(), result.execTimeMs());
            }
            return;
        }

        // Check for interesting coverage
        if (coverage != null && coverage.interesting()) {
            Path queuePath = corpusManager.saveToQueue(input, coverage);
            fuzzStats.recordNewPath();
            if (statusPrinter != null) {
                statusPrinter.printNewPath(corpusManager.stats().queueSize(), coverage.newBytes());
            }
        }
    }
}
