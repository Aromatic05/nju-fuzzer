package edu.nju.fuzzing.cli;

import edu.nju.fuzzing.model.SeedType;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

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
        SeedType seedType = parseSeedType(m.getOrDefault("--seedType", SeedType.UNKNOWN.name()));
        Set<Integer> nonCrashExitCodes = parseExitCodes(m.get("--nonCrashExitCodes"));

        return new CliArgs(workdir, seedsDir, duration, timeoutMs, tid, cmd, coverage, seedType, nonCrashExitCodes);
    }

    private static SeedType parseSeedType(String raw) {
        if (raw == null) return SeedType.UNKNOWN;
        String s = raw.trim();
        if (s.isEmpty()) return SeedType.UNKNOWN;

        // Convenience aliases (keep minimal)
        if (s.equalsIgnoreCase("c++")) return SeedType.CXX;

        try {
            return SeedType.valueOf(s.toUpperCase());
        } catch (IllegalArgumentException ignored) {
            return SeedType.UNKNOWN;
        }
    }

    private static Set<Integer> parseExitCodes(String raw) {
        if (raw == null) return Set.of();
        String s = raw.trim();
        if (s.isEmpty()) return Set.of();

        Set<Integer> out = new TreeSet<>();
        for (String part : s.split("[\\s,]+")) {
            if (part == null) continue;
            String p = part.trim();
            if (p.isEmpty()) continue;
            try {
                out.add(Integer.parseInt(p));
            } catch (NumberFormatException ignored) {
                // Ignore invalid tokens to keep CLI parser minimal & robust.
            }
        }
        return Set.copyOf(out);
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
