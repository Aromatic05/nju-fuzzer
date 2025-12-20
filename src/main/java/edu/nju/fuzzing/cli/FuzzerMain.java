package edu.nju.fuzzing.cli;

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

        FuzzingEngine engine = new FuzzingEngine(
                workdir,
                duration,
                spec,
                executor,
                Duration.ofMillis(timeoutMs)
        );
        engine.run();

        System.out.println("NJUFuzzer skeleton finished.");
    }
}
