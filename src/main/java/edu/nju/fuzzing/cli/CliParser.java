package edu.nju.fuzzing.cli;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public final class CliParser {

    private CliParser() {}

    public static CliArgs parse(String[] args) {
        Map<String, String> m = parseArgs(args);

        Path workdir = Path.of(m.getOrDefault("--workdir", "workdir"));
        Path seedsDir = Path.of(m.getOrDefault("--seeds", workdir.resolve("seeds").toString()));
        int duration = Integer.parseInt(m.getOrDefault("--duration", "3"));
        int timeoutMs = Integer.parseInt(m.getOrDefault("--timeout", "1000"));
        String tid = m.getOrDefault("--tid", "DEMO");
        String cmd = m.getOrDefault("--cmd", "/bin/cat"); // default demo
        String coverage = m.getOrDefault("--coverage", "none");

        return new CliArgs(workdir, seedsDir, duration, timeoutMs, tid, cmd, coverage);
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> map = new HashMap<>();
        // 最小骨架：按 key value 成对解析
        for (int i = 0; i < args.length - 1; i += 2) {
            map.put(args[i], args[i + 1]);
        }
        return map;
    }
}
