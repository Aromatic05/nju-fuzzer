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
        assertTrue(Files.exists(stats));
        var lines = Files.readAllLines(stats);
        assertTrue(lines.size() >= 2, "stats.csv should contain header + at least one tick");

        // 2) inputs 目录至少有一个 testcase
        Path inputsDir = workdir.resolve("tmp/inputs");
        assertTrue(Files.isDirectory(inputsDir));
        var inputs = Files.list(inputsDir).collect(Collectors.toList());
        assertFalse(inputs.isEmpty(), "inputs should not be empty");

        // 3) exec logs 目录至少有一个 stdout.log 且包含关键字
        Path logsDir = workdir.resolve("tmp/exec-logs");
        assertTrue(Files.isDirectory(logsDir));

        // 找到任意一个 stdout.log
        var stdoutLogs = Files.walk(logsDir)
                .filter(p -> p.getFileName().toString().equals("stdout.log"))
                .collect(Collectors.toList());

        assertFalse(stdoutLogs.isEmpty(), "should produce stdout.log");

        String stdout = Files.readString(stdoutLogs.get(0), StandardCharsets.UTF_8);
        assertTrue(stdout.contains("hello-from-engine"), "stdout should contain expected payload");
    }
}
