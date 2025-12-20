package edu.nju.fuzzing.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class FuzzerMainCmdSmokeTest {

    @TempDir
    Path tempDir;

    @Test
    void main_withCmdCat_shouldRunInStdinModeAndPersistLogs() throws Exception {
        Path workdir = tempDir.resolve("w1");

        FuzzerMain.main(new String[] {
                "--workdir", workdir.toString(),
                "--duration", "1",
                "--timeout", "500",
                "--tid", "T_STDIN",
                "--cmd", "/bin/cat"
        });

        var stdoutLogs = Files.walk(workdir.resolve("tmp/exec-logs"))
                .filter(p -> p.getFileName().toString().equals("stdout.log"))
                .collect(Collectors.toList());

        assertFalse(stdoutLogs.isEmpty());
        String stdout = Files.readString(stdoutLogs.get(0), StandardCharsets.UTF_8);
        assertTrue(stdout.contains("hello-from-engine"), "stdout should contain payload in STDIN mode");
    }

    @Test
    void main_withCmdCatAtAt_shouldRunInFileModeAndPersistLogs() throws Exception {
        Path workdir = tempDir.resolve("w2");

        FuzzerMain.main(new String[] {
                "--workdir", workdir.toString(),
                "--duration", "1",
                "--timeout", "500",
                "--tid", "T_FILE",
                "--cmd", "/bin/cat @@"
        });

        var stdoutLogs = Files.walk(workdir.resolve("tmp/exec-logs"))
                .filter(p -> p.getFileName().toString().equals("stdout.log"))
                .collect(Collectors.toList());

        assertFalse(stdoutLogs.isEmpty());
        String stdout = Files.readString(stdoutLogs.get(0), StandardCharsets.UTF_8);
        assertTrue(stdout.contains("hello-from-engine"), "stdout should contain file content in FILE mode");
    }
}
