package edu.nju.fuzzing.cli;

import edu.nju.fuzzing.cov.CoverageDB;
import edu.nju.fuzzing.cov.CoverageMonitor;
import edu.nju.fuzzing.cov.CoverageMonitorEx;
import edu.nju.fuzzing.cov.NullCoverageMonitor;
import edu.nju.fuzzing.cov.ShmCoverageMonitor;
import edu.nju.fuzzing.cov.ShmCoverageMonitorEx;
import edu.nju.fuzzing.cov.SysVShmBitmapSource;
import edu.nju.fuzzing.cov.SysVShmSegment;
import edu.nju.fuzzing.core.FuzzingEngine;
import edu.nju.fuzzing.exec.Executor;
import edu.nju.fuzzing.exec.ProcessExecutor;
import edu.nju.fuzzing.model.TargetSpec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

public class FuzzerMain {

    public static void main(String[] args) throws Exception {
        CliArgs cli = CliParser.parse(args);

        Path workdir = cli.workdir();
        Path seedsDir = cli.seedsDir();
        int duration = cli.durationSec();
        int timeoutMs = cli.timeoutMs();

        // workdir layout
        Files.createDirectories(workdir.resolve("queue"));
        Files.createDirectories(workdir.resolve("crashes"));
        Files.createDirectories(workdir.resolve("hangs"));
        Files.createDirectories(workdir.resolve("stats"));
        Files.createDirectories(workdir.resolve("tmp"));

        System.out.println("NJUFuzzer skeleton started.");
        System.out.println("workdir = " + workdir.toAbsolutePath());
        System.out.println("duration = " + duration + "s");
        System.out.println("timeout  = " + timeoutMs + "ms");
        System.out.println("tid      = " + cli.tid());
        System.out.println("cmd      = " + cli.cmdLine());
        System.out.println("seeds    = " + seedsDir.toAbsolutePath());
        System.out.println("coverage = " + cli.coverage());

        // parse cmdline into argv template
        List<String> argvTemplate = CmdLineTokenizer.tokenize(cli.cmdLine());

        // binary: use argv[0] as path-like string; keep as Path for later
        Path binary = Path.of(argvTemplate.get(0));

        CoverageSetup coverage = setupCoverage(cli.coverage());
        // Ensure any auto-created SHM segment is cleaned up on exit.
        if (coverage.cleanup != null) {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try {
                    coverage.monitor.close();
                } catch (Exception ignored) {
                }
                try {
                    coverage.cleanup.close();
                } catch (Exception ignored) {
                }
            }, "nju-fuzzer-shm-cleanup"));
        }

        TargetSpec spec = new TargetSpec(
                cli.tid(),
                binary,
                argvTemplate,
                coverage.targetEnv,
                Duration.ofMillis(timeoutMs)
        );

        Executor executor = new ProcessExecutor();

        CoverageMonitor monitor = coverage.monitor;
        CoverageDB coverageDB = (monitor instanceof NullCoverageMonitor)
            ? null
            : new CoverageDB(coverage.mapSize);

        FuzzingEngine engine = new FuzzingEngine(
            workdir,
            seedsDir,
            duration,
            spec,
            executor,
            Duration.ofMillis(timeoutMs),
            monitor,
            coverageDB,
            0
        );
        engine.run();

        System.out.println("NJUFuzzer skeleton finished.");
    }

    private static final class CoverageSetup {
        private final CoverageMonitor monitor;
        private final Map<String, String> targetEnv;
        private final int mapSize;
        private final AutoCloseable cleanup;

        private CoverageSetup(CoverageMonitor monitor, Map<String, String> targetEnv, int mapSize, AutoCloseable cleanup) {
            this.monitor = monitor;
            this.targetEnv = targetEnv;
            this.mapSize = mapSize;
            this.cleanup = cleanup;
        }
    }

    private static CoverageSetup setupCoverage(String modeRaw) {
        String mode = (modeRaw == null) ? "none" : modeRaw.trim().toLowerCase();
        return switch (mode) {
            case "none" -> new CoverageSetup(new NullCoverageMonitor(SysVShmBitmapSource.DEFAULT_MAP_SIZE), Map.of(),
                    SysVShmBitmapSource.DEFAULT_MAP_SIZE, null);

            case "shm", "shmex" -> {
                String shmIdStr = System.getenv(SysVShmBitmapSource.ENV_SHM_ID);

                // If user already provided __AFL_SHM_ID, use it and still forward it explicitly to the child env.
                if (shmIdStr != null && !shmIdStr.isBlank()) {
                    CoverageMonitor monitor = mode.equals("shm")
                            ? ShmCoverageMonitor.fromEnvironment()
                            : ShmCoverageMonitorEx.fromEnvironment();

                    int mapSize = (monitor instanceof CoverageMonitorEx ex)
                            ? ex.getMapSize()
                            : SysVShmBitmapSource.DEFAULT_MAP_SIZE;

                    Map<String, String> env = Map.of(
                            SysVShmBitmapSource.ENV_SHM_ID, shmIdStr.trim(),
                            SysVShmBitmapSource.ENV_MAP_SIZE, String.valueOf(mapSize)
                    );

                    yield new CoverageSetup(monitor, env, mapSize, null);
                }

                // Otherwise: auto-create a new SysV SHM segment and inject into target env.
                int mapSize = parseIntOrDefault(System.getenv(SysVShmBitmapSource.ENV_MAP_SIZE),
                        SysVShmBitmapSource.DEFAULT_MAP_SIZE);
                SysVShmSegment seg = SysVShmSegment.create(mapSize);

                CoverageMonitor monitor = mode.equals("shm")
                        ? ShmCoverageMonitor.create(seg.shmId(), mapSize)
                        : ShmCoverageMonitorEx.create(seg.shmId(), mapSize);

                Map<String, String> env = Map.of(
                        SysVShmBitmapSource.ENV_SHM_ID, String.valueOf(seg.shmId()),
                        SysVShmBitmapSource.ENV_MAP_SIZE, String.valueOf(mapSize)
                );

                System.out.println("[coverage] auto-created SysV SHM: " + SysVShmBitmapSource.ENV_SHM_ID + "=" + seg.shmId()
                        + ", " + SysVShmBitmapSource.ENV_MAP_SIZE + "=" + mapSize);

                yield new CoverageSetup(monitor, env, mapSize, seg);
            }

            default -> throw new IllegalArgumentException("Unknown --coverage mode: " + modeRaw +
                    " (expected: none|shm|shmex)");
        };
    }

    private static int parseIntOrDefault(String raw, int defaultValue) {
        if (raw == null) return defaultValue;
        String s = raw.trim();
        if (s.isEmpty()) return defaultValue;
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException ignored) {
            return defaultValue;
        }
    }
}
