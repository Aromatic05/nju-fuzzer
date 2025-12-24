package edu.nju.fuzzing.cli;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class CliParserTest {

    @Test
    void parse_defaultsShouldBeStable() {
        CliArgs cli = CliParser.parse(new String[]{});

        assertEquals(Path.of("workdir"), cli.workdir());
        assertEquals(Path.of("workdir").resolve("seeds"), cli.seedsDir());
        assertEquals(3, cli.durationSec());
        assertEquals(1000, cli.timeoutMs());
        assertEquals("DEMO", cli.tid());
        assertEquals("/bin/cat", cli.cmdLine());
        assertEquals("none", cli.coverage());
    }

    @Test
    void parse_seedsDefaultShouldFollowWorkdir() {
        CliArgs cli = CliParser.parse(new String[]{
                "--workdir", "/tmp/mywd",
                "--duration", "1",
                "--timeout", "500",
                "--tid", "T1",
                "--cmd", "/bin/cat",
                "--coverage", "none"
        });

        assertEquals(Path.of("/tmp/mywd"), cli.workdir());
        assertEquals(Path.of("/tmp/mywd").resolve("seeds"), cli.seedsDir());
    }

    @Test
    void parse_seedsOverrideShouldWin() {
        CliArgs cli = CliParser.parse(new String[]{
                "--workdir", "/tmp/mywd",
                "--seeds", "/tmp/seeds",
                "--duration", "1",
                "--timeout", "500",
                "--tid", "T1",
                "--cmd", "/bin/cat",
                "--coverage", "none"
        });

        assertEquals(Path.of("/tmp/seeds"), cli.seedsDir());
    }
}
