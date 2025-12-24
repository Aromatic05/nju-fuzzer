package edu.nju.fuzzing.cli;

import edu.nju.fuzzing.cov.CoverageDB;
import edu.nju.fuzzing.cov.CoverageMonitor;
import edu.nju.fuzzing.cov.CoverageMonitorEx;
import edu.nju.fuzzing.cov.NullCoverageMonitor;
import edu.nju.fuzzing.cov.ShmCoverageMonitor;
import edu.nju.fuzzing.cov.ShmCoverageMonitorEx;
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

        TargetSpec spec = new TargetSpec(
                cli.tid(),
                binary,
                argvTemplate,
                Map.of(),
                Duration.ofMillis(timeoutMs)
        );

        Executor executor = new ProcessExecutor();

        CoverageMonitor monitor = createCoverageMonitor(cli.coverage());
        CoverageDB coverageDB = null;
        if (!(monitor instanceof NullCoverageMonitor)) {
            int mapSize = (monitor instanceof CoverageMonitorEx ex) ? ex.getMapSize() : 65536;
            coverageDB = new CoverageDB(mapSize);
        }

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

    private static CoverageMonitor createCoverageMonitor(String modeRaw) {
        String mode = (modeRaw == null) ? "none" : modeRaw.trim().toLowerCase();
        return switch (mode) {
            case "none" -> new NullCoverageMonitor(65536);
            case "shm" -> ShmCoverageMonitor.fromEnvironment();
            case "shmex" -> ShmCoverageMonitorEx.fromEnvironment();
            default -> throw new IllegalArgumentException("Unknown --coverage mode: " + modeRaw +
                    " (expected: none|shm|shmex)");
        };
    }
}
