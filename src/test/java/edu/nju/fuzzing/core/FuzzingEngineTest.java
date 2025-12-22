package edu.nju.fuzzing.core;

import edu.nju.fuzzing.exec.Executor;
import edu.nju.fuzzing.exec.ProcessExecutor;
import edu.nju.fuzzing.model.TargetSpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import java.util.stream.Stream;

class FuzzingEngineTest {

    @TempDir
    Path tempDir;

    @Test
    void engine_shouldExecuteCommand_andPersistArtifacts() throws Exception {
        Path workdir = tempDir.resolve("workdir");
        Files.createDirectories(workdir);

        TargetSpec spec = new TargetSpec(
                "DEMO",
                Path.of("/bin/cat"),
                List.of("/bin/cat"), // no @@ -> STDIN mode
                Map.of(),
                Duration.ofMillis(500)
        );

        Executor executor = new ProcessExecutor();

        // durationSec=1 + tickSleepMs=0，让测试更稳定（不依赖 sleep）
        FuzzingEngine engine = new FuzzingEngine(
                workdir,
                1,
                spec,
                executor,
                Duration.ofMillis(500),
                0
        );

        engine.run();

        // 1) stats 文件存在且有数据行
        Path stats = workdir.resolve("stats/stats.csv");
        assertTrue(Files.exists(stats), "stats.csv should exist");
        var lines = Files.readAllLines(stats);
        assertTrue(lines.size() >= 2, "stats.csv should contain header + at least one tick");

        // 2) inputs 目录至少有一个 testcase
        Path inputsDir = workdir.resolve("tmp/inputs");
        assertTrue(Files.isDirectory(inputsDir), "inputs dir should exist");
        try (Stream<Path> s = Files.list(inputsDir)) {
            var inputs = s.collect(Collectors.toList());
            assertFalse(inputs.isEmpty(), "inputs should not be empty");
        }

        // 3) exec logs 目录至少有一个 stdout_<id>.log 且包含关键字
        Path logsDir = workdir.resolve("tmp/exec-logs");
        assertTrue(Files.isDirectory(logsDir), "exec-logs dir should exist");

        List<Path> stdoutLogs;
        try (Stream<Path> w = Files.walk(logsDir)) {
            stdoutLogs = w
                    .filter(Files::isRegularFile)
                    .filter(p -> {
                        String name = p.getFileName().toString();
                        return name.startsWith("stdout_") && name.endsWith(".log");
                    })
                    .collect(Collectors.toList());
        }

        assertFalse(stdoutLogs.isEmpty(), "should produce stdout_<id>.log");

        boolean foundExpected = false;
        for (Path p : stdoutLogs) {
            String stdout = Files.readString(p, StandardCharsets.UTF_8);
            if (stdout.contains("hello-from-engine")) {
                foundExpected = true;
                break;
            }
        }
        assertTrue(foundExpected, "stdout should contain expected payload");
    }
}
