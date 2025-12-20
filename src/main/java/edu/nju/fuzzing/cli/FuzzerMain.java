package edu.nju.fuzzing.cli;

import edu.nju.fuzzing.core.FuzzingEngine;
import edu.nju.fuzzing.exec.Executor;
import edu.nju.fuzzing.exec.ProcessExecutor;
import edu.nju.fuzzing.model.TargetSpec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FuzzerMain {

    public static void main(String[] args) throws Exception {
        Map<String, String> argMap = parseArgs(args);

        Path workdir = Path.of(argMap.getOrDefault("--workdir", "workdir"));
        int duration = Integer.parseInt(argMap.getOrDefault("--duration", "3"));
        int timeoutMs = Integer.parseInt(argMap.getOrDefault("--timeout", "1000"));

        // 创建 workdir 结构
        Files.createDirectories(workdir.resolve("queue"));
        Files.createDirectories(workdir.resolve("crashes"));
        Files.createDirectories(workdir.resolve("hangs"));
        Files.createDirectories(workdir.resolve("stats"));
        Files.createDirectories(workdir.resolve("tmp"));

        System.out.println("NJUFuzzer skeleton started.");
        System.out.println("workdir = " + workdir.toAbsolutePath());
        System.out.println("duration = " + duration + "s");
        System.out.println("timeout  = " + timeoutMs + "ms");

        // Skeleton 阶段：默认跑 /bin/cat（STDIN 模式）
        TargetSpec spec = new TargetSpec(
                "DEMO",
                Path.of("/bin/cat"),
                List.of("/bin/cat"),
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

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < args.length - 1; i += 2) {
            map.put(args[i], args[i + 1]);
        }
        return map;
    }
}
