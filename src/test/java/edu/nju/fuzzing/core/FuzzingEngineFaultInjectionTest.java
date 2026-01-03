package edu.nju.fuzzing.core;

import edu.nju.fuzzing.corpus.CorpusManager;
import edu.nju.fuzzing.corpus.FileCorpusManager;
import edu.nju.fuzzing.cov.EdgeSet;
import edu.nju.fuzzing.exec.CrashOracle;
import edu.nju.fuzzing.model.CoverageEx;
import edu.nju.fuzzing.model.ExecInput;
import edu.nju.fuzzing.model.ExecResult;
import edu.nju.fuzzing.model.RunResult;
import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.TargetSpec;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.Mutator;
import edu.nju.fuzzing.queue.SeedQueue;
import edu.nju.fuzzing.schedule.PowerScheduler;
import edu.nju.fuzzing.schedule.SeedPrioritizer;
import edu.nju.fuzzing.stats.FuzzStats;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class FuzzingEngineFaultInjectionTest {

    @TempDir
    Path tempDir;

    @Test
    void engine_shouldSurviveInjectedFaultsAcrossStages() throws Exception {
        Path workdir = tempDir.resolve("workdir");
        Files.createDirectories(workdir);

        // Track that each injected fault actually happened (avoid false positives).
        AtomicBoolean pickFault = new AtomicBoolean(false);
        AtomicBoolean energyFault = new AtomicBoolean(false);
        AtomicBoolean mutateFault = new AtomicBoolean(false);
        AtomicBoolean iterHasNextFault = new AtomicBoolean(false);
        AtomicBoolean iterNextFault = new AtomicBoolean(false);
        AtomicBoolean execFault = new AtomicBoolean(false);
        AtomicBoolean promoteFault = new AtomicBoolean(false);

        // Keep the run deterministic and avoid tmpfs requirements in tests.
        Map<String, String> sysProps = Map.of(
                "nju.fuzzer.faultTolerant", "true",
                "nju.fuzzer.fatalOnOom", "false",
                "nju.fuzzer.faultBackoffMs", "0",
                "nju.fuzzer.execLogs", "none",
                "nju.fuzzer.requireTmpfsInputs", "false",
                "nju.fuzzer.tmpInputsDir", workdir.resolve("tmp/inputs").toString(),
                "nju.fuzzer.persistTmpInputs", "false"
        );

        withSystemProperties(sysProps, () -> {
            try {
                TargetSpec spec = new TargetSpec(
                        "T_FAULTS",
                        Path.of("/bin/cat"),
                        List.of("/bin/cat"),
                        Map.of(),
                        Duration.ofMillis(200)
                );

                SeedQueue seedQueue = new SeedQueue();

                SeedPrioritizer prioritizer = new SeedPrioritizer() {
                    private boolean first = true;

                    @Override
                    public Seed pick(List<Seed> seeds) {
                        if (first) {
                            first = false;
                            pickFault.set(true);
                            throw new RuntimeException("simulated pick failure");
                        }
                        return super.pick(seeds);
                    }
                };

                PowerScheduler scheduler = new PowerScheduler() {
                    private boolean first = true;

                    @Override
                    public int assignEnergy(Seed seed) {
                        if (first) {
                            first = false;
                            energyFault.set(true);
                            throw new IllegalStateException("simulated scheduler failure");
                        }
                        return 1; // keep inner loop short
                    }
                };

                Mutator mutator = new ScriptedMutator(iterHasNextFault, iterNextFault, mutateFault);

                ExecutorHarness harness = new ScriptedHarness(execFault);

                CorpusManager corpusManager = new OneShotFailingCorpusManager(new FileCorpusManager(workdir), promoteFault);

                FuzzStats stats = new FuzzStats(spec.tid());

                // Use default crash oracle; we only care about "engine must not crash".
                CrashOracle oracle = CrashOracle.defaultOracle();

                // Make initialSeedDir null to force dummy seed path; this exercises SeedQueue.addSeed().
                FuzzingEngine engine = new FuzzingEngine(
                        workdir,
                        null,
                        1,
                        spec,
                        harness,
                        seedQueue,
                        prioritizer,
                        scheduler,
                        mutator,
                        null,
                        corpusManager,
                        stats,
                        oracle
                );

                assertDoesNotThrow(engine::run);

                assertTrue(pickFault.get(), "expected pickSeed fault to be triggered");
                assertTrue(energyFault.get(), "expected assignEnergy fault to be triggered");
                assertTrue(mutateFault.get(), "expected mutate(seed) OOM fault to be triggered");
                assertTrue(iterHasNextFault.get(), "expected mutator.hasNext fault to be triggered");
                assertTrue(iterNextFault.get(), "expected mutator.next fault to be triggered");
                assertTrue(execFault.get(), "expected harness.execute fault to be triggered");
                assertTrue(promoteFault.get(), "expected promotion (saveToQueue) fault to be triggered");

                // Basic artifact existence (engine should have set up workdir structure).
                assertTrue(Files.exists(workdir.resolve("stats/stats.csv")), "stats.csv should exist");
            } catch (Exception e) {
                fail(e);
            }
        });
    }

    private static final class ScriptedMutator implements Mutator {
        private final AtomicInteger mutateCalls = new AtomicInteger(0);
        private final AtomicBoolean iterHasNextFault;
        private final AtomicBoolean iterNextFault;
        private final AtomicBoolean mutateFault;

        private ScriptedMutator(AtomicBoolean iterHasNextFault, AtomicBoolean iterNextFault, AtomicBoolean mutateFault) {
            this.iterHasNextFault = iterHasNextFault;
            this.iterNextFault = iterNextFault;
            this.mutateFault = mutateFault;
        }

        @Override
        public Iterator<Testcase> mutate(Seed seed, int energy) {
            int call = mutateCalls.incrementAndGet();

            // 1) mutator.mutate throws simulated OOM (single-shot)
            if (call == 1) {
                mutateFault.set(true);
                throw new OutOfMemoryError("simulated OOM from mutate(seed)");
            }

            // 2) iterator.hasNext throws
            if (call == 2) {
                return new Iterator<>() {
                    private boolean first = true;

                    @Override
                    public boolean hasNext() {
                        if (first) {
                            first = false;
                            iterHasNextFault.set(true);
                            throw new RuntimeException("simulated hasNext failure");
                        }
                        return false;
                    }

                    @Override
                    public Testcase next() {
                        throw new AssertionError("should not be called");
                    }
                };
            }

            // 3) iterator.next throws an Error
            if (call == 3) {
                return new Iterator<>() {
                    private boolean first = true;

                    @Override
                    public boolean hasNext() {
                        return first;
                    }

                    @Override
                    public Testcase next() {
                        if (first) {
                            first = false;
                            iterNextFault.set(true);
                            throw new StackOverflowError("simulated Error from next()");
                        }
                        return new Testcase(new byte[]{'x'}, seed, "unreachable");
                    }
                };
            }

            // 4+) normal: one testcase
            return new Iterator<>() {
                private boolean emitted = false;

                @Override
                public boolean hasNext() {
                    return !emitted;
                }

                @Override
                public Testcase next() {
                    emitted = true;
                    return new Testcase("A".getBytes(), seed, "scripted");
                }
            };
        }
    }

    private static final class ScriptedHarness implements ExecutorHarness {
        private final AtomicLong execId = new AtomicLong(0);
        private final AtomicBoolean execFault;
        private final AtomicInteger executeCalls = new AtomicInteger(0);

        private ScriptedHarness(AtomicBoolean execFault) {
            this.execFault = execFault;
        }

        @Override
        public void start() {
            // no-op
        }

        @Override
        public ExecResult execute(ExecInput input) throws Exception {
            int call = executeCalls.incrementAndGet();

            // 1) Throw from harness.execute
            if (call == 1) {
                execFault.set(true);
                throw new RuntimeException("simulated execute() failure");
            }

            long id = execId.incrementAndGet();
            RunResult run = RunResult.of(
                    id,
                    null,
                    1,
                    0,
                    false,
                    RunResult.Termination.NORMAL,
                    null,
                    null
            );

            // 2) Non-interesting execution
            if (call == 2) {
                CoverageEx cov = CoverageEx.empty(id, 65536, run.execTimeNanos());
                return new ExecResult(run, cov);
            }

            // 3) Interesting execution -> triggers promotion
            EdgeSet hit = EdgeSet.of(1);
            EdgeSet news = EdgeSet.of(1);
            CoverageEx cov = CoverageEx.of(
                    id,
                    65536,
                    hit,
                    news,
                    1,
                    1234L,
                    run.execTimeNanos(),
                    CoverageEx.Stability.UNKNOWN
            );
            return new ExecResult(run, cov);
        }

        @Override
        public void close() {
            // no-op
        }
    }

    private static final class OneShotFailingCorpusManager implements CorpusManager {
        private final CorpusManager delegate;
        private final AtomicBoolean promoteFault;
        private final AtomicBoolean failedOnce = new AtomicBoolean(false);

        private OneShotFailingCorpusManager(CorpusManager delegate, AtomicBoolean promoteFault) {
            this.delegate = delegate;
            this.promoteFault = promoteFault;
        }

        @Override
        public Path saveToQueue(byte[] input, edu.nju.fuzzing.model.Coverage coverage) {
            if (failedOnce.compareAndSet(false, true)) {
                promoteFault.set(true);
                throw new RuntimeException("simulated saveToQueue failure");
            }
            return delegate.saveToQueue(input, coverage);
        }

        @Override
        public Path saveCrash(byte[] input, RunResult result) {
            return delegate.saveCrash(input, result);
        }

        @Override
        public Path saveHang(byte[] input, RunResult result) {
            return delegate.saveHang(input, result);
        }

        @Override
        public Path outputDir() {
            return delegate.outputDir();
        }

        @Override
        public Path queueDir() {
            return delegate.queueDir();
        }

        @Override
        public Path crashesDir() {
            return delegate.crashesDir();
        }

        @Override
        public Path hangsDir() {
            return delegate.hangsDir();
        }

        @Override
        public CorpusStats stats() {
            return delegate.stats();
        }

        @Override
        public void close() {
            delegate.close();
        }
    }

    private static void withSystemProperties(Map<String, String> props, Runnable action) {
        java.util.HashMap<String, String> prev = new java.util.HashMap<>();
        for (var e : props.entrySet()) {
            prev.put(e.getKey(), System.getProperty(e.getKey()));
            if (e.getValue() == null) {
                System.clearProperty(e.getKey());
            } else {
                System.setProperty(e.getKey(), e.getValue());
            }
        }
        try {
            action.run();
        } finally {
            for (var e : prev.entrySet()) {
                if (e.getValue() == null) {
                    System.clearProperty(e.getKey());
                } else {
                    System.setProperty(e.getKey(), e.getValue());
                }
            }
        }
    }
}
