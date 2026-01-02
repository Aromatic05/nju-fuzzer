package edu.nju.fuzzing.core;

import edu.nju.fuzzing.corpus.CorpusManager;
import edu.nju.fuzzing.corpus.FileCorpusManager;
import edu.nju.fuzzing.cov.CoverageDB;
import edu.nju.fuzzing.cov.DiffResultEx;
import edu.nju.fuzzing.cov.CoverageMonitor;
import edu.nju.fuzzing.cov.CoverageMonitorEx;
import edu.nju.fuzzing.cov.EdgeSet;
import edu.nju.fuzzing.cov.NullCoverageMonitor;
import edu.nju.fuzzing.exec.CommandResolver;
import edu.nju.fuzzing.exec.CrashOracle;
import edu.nju.fuzzing.exec.Executor;
import edu.nju.fuzzing.model.ExecResult;
import edu.nju.fuzzing.model.ExecInput;
import edu.nju.fuzzing.model.CoverageEx;
import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.StatsTick;
import edu.nju.fuzzing.model.TargetSpec;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.Mutator;
import edu.nju.fuzzing.mutate.MutatorFactory;
import edu.nju.fuzzing.queue.SeedQueue;
import edu.nju.fuzzing.schedule.PowerScheduler;
import edu.nju.fuzzing.schedule.SeedPrioritizer;
import edu.nju.fuzzing.stats.FuzzStats;
import edu.nju.fuzzing.stats.StatusPrinter;
import edu.nju.fuzzing.stats.StatsWriter;
import edu.nju.fuzzing.stats.StatsCurveWriter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardOpenOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 核心模糊测试引擎。
 * 负责主循环的流程控制：选种 -> 调度 -> 变异 -> 执行 -> 评估 -> 持久化。
 */
public class FuzzingEngine {

    // --- 核心配置 ---
    private final Path workdir;
    private final int durationSec;
    private final TargetSpec targetSpec;

    // --- 组件依赖 (Dependency Injection) ---
    private final ExecutorHarness harness;      // 执行环境 (Executor + Monitor)
    private final SeedQueue seedQueue;          // 种子队列
    private final SeedPrioritizer prioritizer;  // 种子选择器
    private final PowerScheduler scheduler;     // 能量调度器
    private final Mutator mutator;              // 变异器
    private final CoverageDB coverageDB;        // 覆盖率裁判
    private final CorpusManager corpusManager;  // 语料库管理
    private final FuzzStats fuzzStats;          // 统计组件

    // Crash classification policy
    private final CrashOracle crashOracle;

    // --- 辅助组件 ---
    private final StatusPrinter statusPrinter;
    
    // 初始种子目录
    private final Path initialSeedDir;

    // Stats tick interval (0 = every exec)
    private final int tickIntervalMs;

    // Map Seed.getId() (filename) -> stable numeric ID for CoverageDB.
    // Seed currently only exposes String id, but CoverageDB uses long IDs.
    private final AtomicLong seedIdCounter = new AtomicLong(0);
    private final Map<String, Long> numericSeedIds = new HashMap<>();

    /**
     * 全参构造函数，组装所有组件。
     */
    public FuzzingEngine(
            Path workdir,
            Path initialSeedDir,
            int durationSec,
            TargetSpec targetSpec,
            ExecutorHarness harness,
            SeedQueue seedQueue,
            SeedPrioritizer prioritizer,
            PowerScheduler scheduler,
            Mutator mutator,
            CoverageDB coverageDB,
            CorpusManager corpusManager,
            FuzzStats fuzzStats,
            CrashOracle crashOracle) {
        
        this.workdir = workdir;
        this.initialSeedDir = initialSeedDir;
        this.durationSec = durationSec;
        this.targetSpec = targetSpec;
        
        this.harness = harness;
        this.seedQueue = seedQueue;
        this.prioritizer = prioritizer;
        this.scheduler = scheduler;
        this.mutator = mutator;
        this.coverageDB = chooseCoverageDB(harness, coverageDB);
        this.corpusManager = corpusManager;
        this.fuzzStats = fuzzStats;

        this.crashOracle = (crashOracle != null) ? crashOracle : CrashOracle.defaultOracle();

        this.tickIntervalMs = 0;

        // 初始化状态打印机 (每秒刷新)
        this.statusPrinter = StatusPrinter.builder()
                .output(System.out)
                .statsSupplier(() -> fuzzStats.toStatsTick(seedQueue.size()))
                .intervalSeconds(1)
                .build();
    }

    // ===== Legacy constructors (for tests / CLI) =====

    public FuzzingEngine(Path workdir, int durationSec, TargetSpec targetSpec, Executor executor, Duration timeout)
            throws IOException {
        this(workdir, durationSec, targetSpec, executor, timeout, 0);
    }

    public FuzzingEngine(Path workdir, int durationSec, TargetSpec targetSpec, Executor executor, Duration timeout, int tickIntervalMs)
            throws IOException {
        this(
            workdir,
            workdir.resolve("seeds"),
            durationSec,
            targetSpec,
            new InstrumentedExecutorHarness(executor, new NullCoverageMonitor(65536)),
            new SeedQueue(),
            new SeedPrioritizer(),
            new PowerScheduler(),
            defaultEngineMutator(),
            null,
            new FileCorpusManager(workdir),
            new FuzzStats(targetSpec.tid()),
            CrashOracle.defaultOracle(),
            tickIntervalMs
        );
    }

    public FuzzingEngine(
            Path workdir,
            int durationSec,
            TargetSpec targetSpec,
            Executor executor,
            Duration timeout,
            CoverageMonitor coverageMonitor,
            CorpusManager corpusManager,
            int tickIntervalMs
    ) throws IOException {
        this(
            workdir,
            workdir.resolve("seeds"),
            durationSec,
            targetSpec,
            new InstrumentedExecutorHarness(executor, coverageMonitor),
                new SeedQueue(),
            new SeedPrioritizer(),
            new PowerScheduler(),
                defaultEngineMutator(),
            null,
            corpusManager,
            new FuzzStats(targetSpec.tid()),
            CrashOracle.defaultOracle(),
            tickIntervalMs
        );
    }

    /**
     * CLI-friendly constructor: allows selecting seedsDir, coverage monitor, and CoverageDB.
     *
     * Default behavior remains compatible:
     * - If you pass a NullCoverageMonitor, you can pass coverageDB as null.
     * - If you pass a SHM-based monitor, pass a non-null CoverageDB to enable global judging.
     */
    public FuzzingEngine(
            Path workdir,
            Path initialSeedDir,
            int durationSec,
            TargetSpec targetSpec,
            Executor executor,
            Duration timeout,
            CoverageMonitor coverageMonitor,
            CoverageDB coverageDB,
            int tickIntervalMs
    ) throws IOException {
        this(
                workdir,
                initialSeedDir,
                durationSec,
                targetSpec,
                new InstrumentedExecutorHarness(executor, coverageMonitor),
                new SeedQueue(),
                new SeedPrioritizer(),
                new PowerScheduler(),
                defaultEngineMutator(),
                coverageDB,
                new FileCorpusManager(workdir),
            new FuzzStats(targetSpec.tid()),
            CrashOracle.defaultOracle(),
            tickIntervalMs
        );
    }

        /**
         * CLI-friendly constructor with configurable crash classification.
         */
        public FuzzingEngine(
            Path workdir,
            Path initialSeedDir,
            int durationSec,
            TargetSpec targetSpec,
            Executor executor,
            Duration timeout,
            CoverageMonitor coverageMonitor,
            CoverageDB coverageDB,
            CrashOracle crashOracle,
            int tickIntervalMs
        ) throws IOException {
        this(
            workdir,
            initialSeedDir,
            durationSec,
            targetSpec,
            new InstrumentedExecutorHarness(executor, coverageMonitor),
            new SeedQueue(),
            new SeedPrioritizer(),
            new PowerScheduler(),
            defaultEngineMutator(),
            coverageDB,
            new FileCorpusManager(workdir),
            new FuzzStats(targetSpec.tid()),
            crashOracle,
            tickIntervalMs
        );
        }

    private static CoverageDB chooseCoverageDB(ExecutorHarness harness, CoverageDB injected) {
        if (injected != null) return injected;
        if (harness instanceof InstrumentedExecutorHarness ih
                && ih.getCoverageMonitor() instanceof CoverageMonitorEx ex) {
            return ex.getCoverageDB();
        }
        return null;
    }

    private FuzzingEngine(
            Path workdir,
            Path initialSeedDir,
            int durationSec,
            TargetSpec targetSpec,
            ExecutorHarness harness,
            SeedQueue seedQueue,
            SeedPrioritizer prioritizer,
            PowerScheduler scheduler,
            Mutator mutator,
            CoverageDB coverageDB,
            CorpusManager corpusManager,
            FuzzStats fuzzStats,
            CrashOracle crashOracle,
            int tickIntervalMs
    ) {
        this.workdir = workdir;
        this.initialSeedDir = initialSeedDir;
        this.durationSec = durationSec;
        this.targetSpec = targetSpec;
        this.harness = harness;
        this.seedQueue = seedQueue;
        this.prioritizer = prioritizer;
        this.scheduler = scheduler;
        this.mutator = mutator;
        this.coverageDB = coverageDB;
        this.corpusManager = corpusManager;
        this.fuzzStats = fuzzStats;
        this.crashOracle = (crashOracle != null) ? crashOracle : CrashOracle.defaultOracle();
        this.tickIntervalMs = Math.max(0, tickIntervalMs);

        this.statusPrinter = StatusPrinter.builder()
                .output(System.out)
                .statsSupplier(() -> fuzzStats.toStatsTick(seedQueue.size()))
                .intervalSeconds(1)
                .build();
    }

    /**
     * Default mutator for the engine: format-aware mutators with a Havoc fallback.
     *
     * To keep the pipeline stable (tests/CLI demos), we always run one identity testcase
     * per seed first, then spend the remaining energy on the selected mutator.
     */
    private static Mutator defaultEngineMutator() {
        // Keep this constructor-friendly (no need to access the live SeedQueue here).
        // Format-aware selection is based on the current seed's SeedType.
        // Havoc mutator's splicing uses a corpus list; we pass an empty list here to
        // avoid constructor wiring complexity and keep behavior deterministic in tests.
        MutatorFactory factory = new MutatorFactory(java.util.List.of());
        return (seed, energy) -> new Iterator<>() {
            private boolean emittedIdentity = false;
            private final int total = Math.max(1, energy);
            private final Iterator<Testcase> delegate = factory
                    .createMutator(seed)
                    .mutate(seed, Math.max(0, total - 1));

            @Override
            public boolean hasNext() {
                return !emittedIdentity || delegate.hasNext();
            }

            @Override
            public Testcase next() {
                if (!emittedIdentity) {
                    emittedIdentity = true;
                    return new Testcase(seed.getDataCopy(), seed, "identity");
                }
                return delegate.next();
            }
        };
    }

    public void run() throws Exception {
        // 1. 准备环境
        Path statsFile = workdir.resolve("stats/stats.csv");
        Path curveFile = workdir.resolve("stats/curve.csv");
        Files.createDirectories(statsFile.getParent());

        long curveBucketSec = 1;
        try {
            String v = System.getProperty("nju.fuzzer.curveBucketSec");
            if (v != null && !v.isBlank()) {
                curveBucketSec = Long.parseLong(v.trim());
            }
        } catch (NumberFormatException ignored) {
            curveBucketSec = 1;
        }

        String execLogsMode = System.getProperty("nju.fuzzer.execLogs", "interesting");
        String execLogsModeNorm = (execLogsMode == null) ? "interesting" : execLogsMode.trim().toLowerCase();

        boolean requireTmpfsInputs = true;
        try {
            String raw = System.getProperty("nju.fuzzer.requireTmpfsInputs", "true");
            requireTmpfsInputs = raw == null || raw.isBlank() || !raw.trim().equalsIgnoreCase("false");
        } catch (Exception ignored) {
            requireTmpfsInputs = true;
        }

        String tmpInputsRootRaw = System.getProperty("nju.fuzzer.tmpInputsDir", "");
        Path tmpInputsDir = (tmpInputsRootRaw == null || tmpInputsRootRaw.isBlank())
            ? defaultTmpInputsDir(workdir, requireTmpfsInputs)
            : Path.of(tmpInputsRootRaw.trim());

        if (requireTmpfsInputs && !isTmpfsPath(tmpInputsDir)) {
            throw new IllegalStateException(
                "tmpInputsDir must be on tmpfs when nju.fuzzer.requireTmpfsInputs=true. " +
                "Got: " + tmpInputsDir + ". " +
                "Either set -Dnju.fuzzer.tmpInputsDir to a tmpfs path (e.g. under /dev/shm) " +
                "or disable with -Dnju.fuzzer.requireTmpfsInputs=false"
            );
        }

        Path execLogsDir = workdir.resolve("tmp/exec-logs");

        Files.createDirectories(tmpInputsDir);
        if (execLogsModeNorm.equals("all")) {
            Files.createDirectories(execLogsDir);
        }

        // Reused input file to avoid creating millions of temp files.
        Path currentInputFile = tmpInputsDir.resolve(".cur_input");
        
        // 2. 加载初始种子
        statusPrinter.printEvent("Loading initial seeds from " + initialSeedDir);
        int loaded = 0;
        if (initialSeedDir != null && Files.exists(initialSeedDir) && Files.isDirectory(initialSeedDir)) {
            loaded = seedQueue.loadInitialSeeds(initialSeedDir);
        }
        statusPrinter.printEvent("Loaded " + loaded + " initial seeds.");
        
        if (loaded == 0) {
            statusPrinter.printEvent("WARNING: No initial seeds found. Starting with dummy seed.");
            Seed dummy = createAndAddDummySeed(workdir.resolve("tmp/seeds"));
            seedQueue.addSeed(dummy);
        }

        // 3. 启动执行环境 (Attach SHM)
        harness.start();

        // 3.1 如果 CoverageDB 可用：对初始队列做一次基线执行，填充 globalSeen/topRated/frequency
        // 这样 favored/rarity/redundant 对调度才有意义。
        if (coverageDB != null) {
            calibrateInitialQueueSeeds(currentInputFile, execLogsDir);
        }

        statusPrinter.start();

        long startSec = Instant.now().getEpochSecond();

        try (StatsWriter writer = new StatsWriter(statsFile);
             StatsCurveWriter curveWriter = new StatsCurveWriter(curveFile, curveBucketSec)) {
            long lastTickAt = System.currentTimeMillis();

            // --- 主循环 (Fuzzing Loop) ---
            outer:
            while (true) {
                long nowSec = Instant.now().getEpochSecond();
                if (nowSec - startSec >= durationSec) {
                    statusPrinter.printEvent("Time up! Stopping fuzzing.");
                    break;
                }

                Seed parentSeed = prioritizer.pick(seedQueue.getSeeds());
                if (parentSeed == null) {
                    // Should not normally happen, but fail-safe to avoid NPE.
                    continue;
                }

                int energy = Math.max(1, scheduler.assignEnergy(parentSeed));
                Iterator<Testcase> mutations = mutator.mutate(parentSeed, energy);

                while (mutations.hasNext()) {
                    nowSec = Instant.now().getEpochSecond();
                    if (nowSec - startSec >= durationSec) {
                        statusPrinter.printEvent("Time up! Stopping fuzzing.");
                        break outer;
                    }

                    Testcase tc = mutations.next();

                    ExecInput input = buildExecInput(targetSpec, tc, currentInputFile, execLogsDir);
                    ExecResult result = harness.execute(input);
                    fuzzStats.recordExec();

                    long nowMs = System.currentTimeMillis();
                    if (tickIntervalMs == 0 || nowMs - lastTickAt >= tickIntervalMs) {
                        StatsTick tick = fuzzStats.toStatsTick(seedQueue.size());
                        writer.tick(tick);
                        curveWriter.tick(tick);
                        lastTickAt = nowMs;
                    }

                    if (crashOracle.isCrash(result.run())) {
                        handleCrash(tc, result);
                        continue;
                    }
                    if (result.isTimeout()) {
                        handleHang(tc, result);
                        continue;
                    }

                    handleNormalExecution(tc, result, parentSeed, currentInputFile, execLogsDir, execLogsModeNorm);

                    if (tickIntervalMs > 0) {
                        try {
                            Thread.sleep(tickIntervalMs);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            break outer;
                        }
                    }
                }

                parentSeed.markAsFuzzed();
                parentSeed.setEnergy(energy);
                parentSeed.decreaseHandicap();

                StatsTick tick = fuzzStats.toStatsTick(seedQueue.size());
                writer.tick(tick);
                curveWriter.tick(tick);
            }
        } finally {
            // 清理资源
            statusPrinter.stop();
            harness.close();
            corpusManager.close();
        }
    }

    // --- 辅助处理方法 ---

    private void handleCrash(Testcase tc, ExecResult result) {
        fuzzStats.recordCrash();
        corpusManager.saveCrash(tc.getData(), result.run());
        statusPrinter.printCrash(fuzzStats.getCrashes(), "exit_" + result.run().exitCode());
    }

    private void handleHang(Testcase tc, ExecResult result) {
        fuzzStats.recordHang();
        corpusManager.saveHang(tc.getData(), result.run());
        statusPrinter.printHang(fuzzStats.getHangs(), result.run().execTimeMs());
    }

        private void handleNormalExecution(
            Testcase tc,
            ExecResult result,
            Seed parentSeed,
            Path currentInputFile,
            Path execLogsDir,
            String execLogsModeNorm
        ) {
        // 1. 快速检查：本次执行是否发现了新边 (Local diff)
        // Harness 返回的 CoverageEx 已经包含了基于 Monitor 视角的 newEdges
        boolean interesting = result.coverage().interesting();

        // 2. 如果 Monitor 认为 Interesting，进一步通过 CoverageDB 确认 (Global check)
        // 甚至可以直接在这里入队，然后让 DB 更新全局状态
        
        if (!interesting) return;

        // 2. 全局确认：避免仅依赖局部 diff 策略造成误判
        // 只有当 CoverageDB 认为存在“真正全局新边”时，才晋升入队。
        if (coverageDB != null && !result.coverage().hitEdges().isEmpty()) {
            DiffResultEx localDiff = DiffResultEx.of(
                    result.coverage().newEdges(),
                    result.coverage().hitEdges(),
                    result.coverage().nonZeroBytes(),
                    result.coverage().bitmapHash()
            );
            CoverageDB.UpdateResult global = coverageDB.evaluate(localDiff);
            if (!global.isInteresting()) {
                return;
            }
        }

        // 2.1 稳定性确认（可选）：如果启用，则对候选输入重复执行，标记 STABLE/UNSTABLE。
        CoverageEx.Stability stability = CoverageEx.Stability.UNKNOWN;
        if (isStabilityConfirmationEnabled() && !result.coverage().hitEdges().isEmpty()) {
            stability = confirmStability(tc, currentInputFile, execLogsDir);
        }

        // Optional: only keep stdout/stderr logs for promoted (interesting) inputs.
        if ("interesting".equals(execLogsModeNorm)) {
            try {
                Files.createDirectories(execLogsDir);
                withSystemProperty("nju.fuzzer.execLogs", "all", () -> {
                    ExecInput logInput = buildExecInput(targetSpec, tc, currentInputFile, execLogsDir);
                    harness.execute(logInput);
                });
            } catch (Exception ignored) {
                // Best-effort: logging must not block promotion.
            }
        }

        // A. 持久化 (Promotion)
        Path saved = corpusManager.saveToQueue(tc.getData(), result.coverage().toBasic());
        Seed newSeed = new Seed(saved.toFile(), tc);
        newSeed.setExecutionTime(result.run().execTimeNanos());
        newSeed.setBitmapSize(result.coverage().nonZeroBytes());
        newSeed.setStability(stability);
        newSeed.setEdges(result.coverage().hitEdges());

        // B. 更新统计
        fuzzStats.recordNewPath();
        statusPrinter.printNewPath(seedQueue.size() + 1, result.coverage().edgeCount());

        // C. 更新全局数据库 (CoverageDB)
        // 仅当我们确实拿到了 edge-level 的信息时才更新。
        if (coverageDB != null && !result.coverage().hitEdges().isEmpty()) {
            long seedNumericId = getOrAssignNumericSeedId(newSeed);
            DiffResultEx diff = DiffResultEx.of(
                    result.coverage().newEdges(),
                    result.coverage().hitEdges(),
                    result.coverage().nonZeroBytes(),
                    result.coverage().bitmapHash()
            );
            CoverageDB.UpdateResult update = coverageDB.update(seedNumericId, diff, tc.getData().length, result.run().execTimeNanos());

            // Sync scheduling hints onto the Seed.
            newSeed.setFavored(update.isFavored());
            newSeed.setRarityScore(coverageDB.calculateRarityScore(newSeed.getEdges()));
            newSeed.setMinEdgeFrequency(coverageDB.getMinFrequency(newSeed.getEdges()));
            newSeed.setRedundant(coverageDB.isRedundant(seedNumericId, newSeed.getEdges()));

            if (update.favoredChanged()) {
                refreshQueueSchedulingHints();
            }

            fuzzStats.updateCoveredEdges(coverageDB.getTotalEdgesSeen());
        }

        // D. 入队
        seedQueue.addSeed(newSeed);
    }

    private void calibrateInitialQueueSeeds(Path currentInputFile, Path execLogsDir) {
        // Only possible when we can resolve a stable numeric ID and the monitor provides edge sets.
        for (Seed seed : seedQueue.getSeeds()) {
            try {
                Testcase tc = new Testcase(seed.getDataCopy(), seed, "calibrate");
                ExecInput input = buildExecInput(targetSpec, tc, currentInputFile, execLogsDir);
                ExecResult res = harness.execute(input);
                if (res == null || res.coverage() == null) continue;

                seed.setExecutionTime(res.run().execTimeNanos());
                seed.setBitmapSize(res.coverage().nonZeroBytes());
                seed.setEdges(res.coverage().hitEdges());

                if (res.coverage().hitEdges().isEmpty()) continue;

                long seedNumericId = getOrAssignNumericSeedId(seed);
                DiffResultEx diff = DiffResultEx.of(
                        res.coverage().newEdges(),
                        res.coverage().hitEdges(),
                        res.coverage().nonZeroBytes(),
                        res.coverage().bitmapHash()
                );

                CoverageDB.UpdateResult update = coverageDB.update(seedNumericId, diff, seed.getData().length, res.run().execTimeNanos());

                seed.setFavored(update.isFavored());
                seed.setRarityScore(coverageDB.calculateRarityScore(seed.getEdges()));
                seed.setMinEdgeFrequency(coverageDB.getMinFrequency(seed.getEdges()));
                seed.setRedundant(coverageDB.isRedundant(seedNumericId, seed.getEdges()));

            } catch (Exception ignored) {
                // Calibration is best-effort; don't fail the whole fuzzing session.
            }
        }
        refreshQueueSchedulingHints();
        fuzzStats.updateCoveredEdges(coverageDB.getTotalEdgesSeen());
    }

    private void refreshQueueSchedulingHints() {
        if (coverageDB == null) return;
        for (Seed seed : seedQueue.getSeeds()) {
            EdgeSet edges = seed.getEdges();
            if (edges == null || edges.isEmpty()) continue;
            long id = getOrAssignNumericSeedId(seed);
            seed.setFavored(coverageDB.isFavored(id));
            seed.setRarityScore(coverageDB.calculateRarityScore(edges));
            seed.setMinEdgeFrequency(coverageDB.getMinFrequency(edges));
            seed.setRedundant(coverageDB.isRedundant(id, edges));
        }
    }

    private boolean isStabilityConfirmationEnabled() {
        if (!(harness instanceof InstrumentedExecutorHarness ih)) return false;
        if (!(ih.getCoverageMonitor() instanceof CoverageMonitorEx ex)) return false;
        return ex.isStabilityDetectionEnabled();
    }

    private CoverageEx.Stability confirmStability(Testcase tc, Path currentInputFile, Path execLogsDir) {
        // Minimal stability check: run the same input a few more times and compare trace signature.
        // If it differs, mark UNSTABLE; else STABLE.
        final int repeats = 2;

        long refHash = -1L;
        int[] refEdges = null;

        for (int i = 0; i < repeats; i++) {
            try {
                // We reuse the same currentInputFile/outDir behavior via buildExecInput.
                ExecInput input = buildExecInput(targetSpec, tc, currentInputFile, execLogsDir);
                ExecResult res = harness.execute(input);
                if (res == null || res.coverage() == null || res.coverage().hitEdges().isEmpty()) {
                    return CoverageEx.Stability.UNKNOWN;
                }

                long h = res.coverage().bitmapHash();
                int[] edges = res.coverage().hitEdges().toArray();

                if (i == 0) {
                    refHash = h;
                    refEdges = edges;
                } else {
                    if (h != refHash || !java.util.Arrays.equals(refEdges, edges)) {
                        return CoverageEx.Stability.UNSTABLE;
                    }
                }
            } catch (Exception e) {
                return CoverageEx.Stability.UNKNOWN;
            }
        }

        return CoverageEx.Stability.STABLE;
    }

    private static void withSystemProperty(String key, String value, ThrowingRunnable action) throws Exception {
        String prev = System.getProperty(key);
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
        try {
            action.run();
        } finally {
            if (prev == null) {
                System.clearProperty(key);
            } else {
                System.setProperty(key, prev);
            }
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private long getOrAssignNumericSeedId(Seed seed) {
        String id = seed.getId();
        Long existing = numericSeedIds.get(id);
        if (existing != null) return existing;
        long assigned = seedIdCounter.incrementAndGet();
        numericSeedIds.put(id, assigned);
        return assigned;
    }

    private static ExecInput buildExecInput(
            TargetSpec spec,
            Testcase tc,
            Path currentInputFile,
            Path execLogsDir
    ) throws IOException {
        if (spec == null) throw new IllegalArgumentException("spec is null");
        if (tc == null) throw new IllegalArgumentException("tc is null");

        boolean usesFile = spec.argvTemplate().stream().anyMatch("@@"::equals);

        boolean persistTmpInputs = false;
        String rawPersist = System.getProperty("nju.fuzzer.persistTmpInputs", "false");
        if (rawPersist != null && !rawPersist.isBlank()) {
            persistTmpInputs = !rawPersist.trim().equalsIgnoreCase("false");
        }

        boolean requireTmpfsInputs = true;
        try {
            String raw = System.getProperty("nju.fuzzer.requireTmpfsInputs", "true");
            requireTmpfsInputs = raw == null || raw.isBlank() || !raw.trim().equalsIgnoreCase("false");
        } catch (Exception ignored) {
            requireTmpfsInputs = true;
        }

        // Overwrite a fixed file each time to avoid inode explosion.
        // For FILE mode (@@), this is required.
        // For STDIN mode, this is optional and can be disabled.
        if (usesFile || persistTmpInputs) {
            if (currentInputFile == null) {
                throw new IllegalArgumentException("currentInputFile is null");
            }
            if (requireTmpfsInputs && !isTmpfsPath(currentInputFile.getParent())) {
                throw new IllegalStateException(
                    "Refusing to write .cur_input to non-tmpfs path when nju.fuzzer.requireTmpfsInputs=true: " + currentInputFile
                );
            }
            Files.write(
                    currentInputFile,
                    tc.getData(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING
            );
        }

        Path inputFile = usesFile ? currentInputFile : null;
        byte[] stdinData = usesFile ? null : tc.getData();

        var cmd = CommandResolver.resolve(spec, inputFile);
        Duration timeout = (spec.timeout() != null) ? spec.timeout() : Duration.ofSeconds(1);
        return ExecInput.of(cmd, stdinData, timeout, execLogsDir);
    }

    private static Path defaultTmpInputsDir(Path workdir, boolean requireTmpfsInputs) {
        // Prefer tmpfs to avoid disk writes for the rotating input file.
        try {
            Path shm = Path.of("/dev/shm");
            if (Files.isDirectory(shm) && Files.isWritable(shm)) {
                String pid = java.lang.management.ManagementFactory.getRuntimeMXBean().getName();
                // pid may look like "12345@host"; keep it filesystem-friendly.
                String runId = pid.replace('@', '-');
                return shm.resolve("nju-fuzzer").resolve(runId).resolve("inputs");
            }
        } catch (Exception ignored) {
        }
        if (requireTmpfsInputs) {
            throw new IllegalStateException(
                "tmpfs inputs required (nju.fuzzer.requireTmpfsInputs=true), but /dev/shm is not usable. " +
                "Set -Dnju.fuzzer.tmpInputsDir to a tmpfs path, or disable strict mode with -Dnju.fuzzer.requireTmpfsInputs=false"
            );
        }
        // Fallback: workdir/tmp/inputs (may write to disk)
        return workdir.resolve("tmp/inputs");
    }

    private static boolean isTmpfsPath(Path path) {
        if (path == null) return false;
        try {
            Path abs = path.toAbsolutePath().normalize();
            // Fast-path for the common tmpfs mount.
            if (abs.startsWith(Path.of("/dev/shm"))) return true;

            Path existing = abs;
            while (existing != null && !Files.exists(existing)) {
                existing = existing.getParent();
            }
            if (existing == null) return false;

            String type = Files.getFileStore(existing).type();
            if (type == null) return false;
            String t = type.trim().toLowerCase();
            return t.equals("tmpfs") || t.equals("ramfs");
        } catch (Exception ignored) {
            return false;
        }
    }

    private static Seed createAndAddDummySeed(Path seedDir) throws IOException {
        Files.createDirectories(seedDir);
        Path seedFile = seedDir.resolve("seed_000001");
        byte[] data = "hello-from-engine".getBytes(StandardCharsets.UTF_8);
        Files.write(seedFile, data, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        return Seed.loadWithMetadata(seedFile.toFile(), data);
    }
}