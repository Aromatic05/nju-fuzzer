package edu.nju.fuzzing.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class FuzzerMainCmdSmokeTest {

    @TempDir
    Path tempDir;

    @Test
    void main_withCmdCat_shouldRunInStdinModeAndPersistLogs() throws Exception {
        Path workdir = tempDir.resolve("w1");

        FuzzerMain.main(new String[]{
                "--workdir", workdir.toString(),
                "--duration", "1",
                "--timeout", "500",
                "--tid", "T_STDIN",
                "--cmd", "/bin/cat"
        });

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

        boolean found = false;
        for (Path p : stdoutLogs) {
            String stdout = Files.readString(p, StandardCharsets.UTF_8);
            if (stdout.contains("hello-from-engine")) {
                found = true;
                break;
            }
        }
        assertTrue(found, "stdout should contain payload in STDIN mode");
    }

    @Test
    void main_withCmdCatAtAt_shouldRunInFileModeAndPersistLogs() throws Exception {
        Path workdir = tempDir.resolve("w2");

        FuzzerMain.main(new String[]{
                "--workdir", workdir.toString(),
                "--duration", "1",
                "--timeout", "500",
                "--tid", "T_FILE",
                "--cmd", "/bin/cat @@"
        });

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

        boolean found = false;
        for (Path p : stdoutLogs) {
            String stdout = Files.readString(p, StandardCharsets.UTF_8);
            if (stdout.contains("hello-from-engine")) {
                found = true;
                break;
            }
        }
        assertTrue(found, "stdout should contain file content in FILE mode");
    }
}
