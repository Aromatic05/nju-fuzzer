package edu.nju.fuzzing.cli;

import edu.nju.fuzzing.core.FuzzingEngine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public class FuzzerMain {

    public static void main(String[] args) throws Exception {
        Map<String, String> argMap = parseArgs(args);

        Path workdir = Path.of(argMap.getOrDefault("--workdir", "workdir"));
        int duration = Integer.parseInt(argMap.getOrDefault("--duration", "3"));
        int timeout = Integer.parseInt(argMap.getOrDefault("--timeout", "1000"));

        // 创建 workdir 结构
        Files.createDirectories(workdir.resolve("queue"));
        Files.createDirectories(workdir.resolve("crashes"));
        Files.createDirectories(workdir.resolve("hangs"));
        Files.createDirectories(workdir.resolve("stats"));
        Files.createDirectories(workdir.resolve("tmp"));

        System.out.println("NJUFuzzer skeleton started.");
        System.out.println("workdir = " + workdir.toAbsolutePath());
        System.out.println("duration = " + duration + "s");
        System.out.println("timeout  = " + timeout + "ms");

        FuzzingEngine engine = new FuzzingEngine(workdir, duration);
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
