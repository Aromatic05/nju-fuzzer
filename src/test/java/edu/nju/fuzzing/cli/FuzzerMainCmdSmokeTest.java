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

        String prevExecLogs = System.getProperty("nju.fuzzer.execLogs");
        String prevPersistTmpInputs = System.getProperty("nju.fuzzer.persistTmpInputs");
        String prevTmpInputsDir = System.getProperty("nju.fuzzer.tmpInputsDir");
        String prevRequireTmpfsInputs = System.getProperty("nju.fuzzer.requireTmpfsInputs");
        System.setProperty("nju.fuzzer.execLogs", "all");
        System.setProperty("nju.fuzzer.persistTmpInputs", "true");
        System.setProperty("nju.fuzzer.tmpInputsDir", workdir.resolve("tmp/inputs").toString());
        System.setProperty("nju.fuzzer.requireTmpfsInputs", "false");

        try {
            FuzzerMain.main(new String[]{
                    "--workdir", workdir.toString(),
                    "--duration", "1",
                    "--timeout", "500",
                    "--tid", "T_STDIN",
                    "--cmd", "/bin/cat"
            });
        } finally {
            if (prevExecLogs == null) System.clearProperty("nju.fuzzer.execLogs"); else System.setProperty("nju.fuzzer.execLogs", prevExecLogs);
            if (prevPersistTmpInputs == null) System.clearProperty("nju.fuzzer.persistTmpInputs"); else System.setProperty("nju.fuzzer.persistTmpInputs", prevPersistTmpInputs);
            if (prevTmpInputsDir == null) System.clearProperty("nju.fuzzer.tmpInputsDir"); else System.setProperty("nju.fuzzer.tmpInputsDir", prevTmpInputsDir);
            if (prevRequireTmpfsInputs == null) System.clearProperty("nju.fuzzer.requireTmpfsInputs"); else System.setProperty("nju.fuzzer.requireTmpfsInputs", prevRequireTmpfsInputs);
        }

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

        byte[] needle = "hello-from-engine".getBytes(StandardCharsets.UTF_8);
        boolean found = false;
        for (Path p : stdoutLogs) {
            byte[] stdoutBytes = Files.readAllBytes(p);
            if (containsSubsequence(stdoutBytes, needle)) {
                found = true;
                break;
            }
        }
        assertTrue(found, "stdout should contain payload in STDIN mode");
    }

    @Test
    void main_withCmdCatAtAt_shouldRunInFileModeAndPersistLogs() throws Exception {
        Path workdir = tempDir.resolve("w2");

        String prevExecLogs = System.getProperty("nju.fuzzer.execLogs");
        String prevPersistTmpInputs = System.getProperty("nju.fuzzer.persistTmpInputs");
        String prevTmpInputsDir = System.getProperty("nju.fuzzer.tmpInputsDir");
        String prevRequireTmpfsInputs = System.getProperty("nju.fuzzer.requireTmpfsInputs");
        System.setProperty("nju.fuzzer.execLogs", "all");
        System.setProperty("nju.fuzzer.persistTmpInputs", "true");
        System.setProperty("nju.fuzzer.tmpInputsDir", workdir.resolve("tmp/inputs").toString());
        System.setProperty("nju.fuzzer.requireTmpfsInputs", "false");

        try {
            FuzzerMain.main(new String[]{
                    "--workdir", workdir.toString(),
                    "--duration", "1",
                    "--timeout", "500",
                    "--tid", "T_FILE",
                    "--cmd", "/bin/cat @@"
            });
        } finally {
            if (prevExecLogs == null) System.clearProperty("nju.fuzzer.execLogs"); else System.setProperty("nju.fuzzer.execLogs", prevExecLogs);
            if (prevPersistTmpInputs == null) System.clearProperty("nju.fuzzer.persistTmpInputs"); else System.setProperty("nju.fuzzer.persistTmpInputs", prevPersistTmpInputs);
            if (prevTmpInputsDir == null) System.clearProperty("nju.fuzzer.tmpInputsDir"); else System.setProperty("nju.fuzzer.tmpInputsDir", prevTmpInputsDir);
            if (prevRequireTmpfsInputs == null) System.clearProperty("nju.fuzzer.requireTmpfsInputs"); else System.setProperty("nju.fuzzer.requireTmpfsInputs", prevRequireTmpfsInputs);
        }

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

        byte[] needle = "hello-from-engine".getBytes(StandardCharsets.UTF_8);
        boolean found = false;
        for (Path p : stdoutLogs) {
            byte[] stdoutBytes = Files.readAllBytes(p);
            if (containsSubsequence(stdoutBytes, needle)) {
                found = true;
                break;
            }
        }
        assertTrue(found, "stdout should contain file content in FILE mode");
    }

    @Test
    void main_withSeedsOverride_shouldUseThatSeedContent() throws Exception {
        Path workdir = tempDir.resolve("w3");
        Path seedsDir = tempDir.resolve("seeds");
        Files.createDirectories(seedsDir);

        byte[] payload = "from-custom-seeds".getBytes(StandardCharsets.UTF_8);
        Files.write(seedsDir.resolve("seed1"), payload);

        String prevExecLogs = System.getProperty("nju.fuzzer.execLogs");
        String prevPersistTmpInputs = System.getProperty("nju.fuzzer.persistTmpInputs");
        String prevTmpInputsDir = System.getProperty("nju.fuzzer.tmpInputsDir");
        String prevRequireTmpfsInputs = System.getProperty("nju.fuzzer.requireTmpfsInputs");
        System.setProperty("nju.fuzzer.execLogs", "all");
        System.setProperty("nju.fuzzer.persistTmpInputs", "true");
        System.setProperty("nju.fuzzer.tmpInputsDir", workdir.resolve("tmp/inputs").toString());
        System.setProperty("nju.fuzzer.requireTmpfsInputs", "false");

        try {
            FuzzerMain.main(new String[]{
                "--workdir", workdir.toString(),
                "--seeds", seedsDir.toString(),
                "--duration", "1",
                "--timeout", "500",
                "--tid", "T_SEEDS",
                "--cmd", "/bin/cat",
                "--coverage", "none"
            });
        } finally {
            if (prevExecLogs == null) System.clearProperty("nju.fuzzer.execLogs"); else System.setProperty("nju.fuzzer.execLogs", prevExecLogs);
            if (prevPersistTmpInputs == null) System.clearProperty("nju.fuzzer.persistTmpInputs"); else System.setProperty("nju.fuzzer.persistTmpInputs", prevPersistTmpInputs);
            if (prevTmpInputsDir == null) System.clearProperty("nju.fuzzer.tmpInputsDir"); else System.setProperty("nju.fuzzer.tmpInputsDir", prevTmpInputsDir);
            if (prevRequireTmpfsInputs == null) System.clearProperty("nju.fuzzer.requireTmpfsInputs"); else System.setProperty("nju.fuzzer.requireTmpfsInputs", prevRequireTmpfsInputs);
        }

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
            byte[] stdoutBytes = Files.readAllBytes(p);
            if (containsSubsequence(stdoutBytes, payload)) {
                found = true;
                break;
            }
        }
        assertTrue(found, "stdout should contain custom seed payload");
    }

    @Test
    void main_withInvalidCoverage_shouldFailFast() {
        Path workdir = tempDir.resolve("w4");

        assertThrows(IllegalArgumentException.class, () -> FuzzerMain.main(new String[]{
                "--workdir", workdir.toString(),
                "--duration", "1",
                "--timeout", "500",
                "--tid", "T_BAD_COV",
                "--cmd", "/bin/cat",
                "--coverage", "nope"
        }));
    }

    private static boolean containsSubsequence(byte[] haystack, byte[] needle) {
        if (haystack == null || needle == null) return false;
        if (needle.length == 0) return true;
        if (haystack.length < needle.length) return false;

        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }
}
