package edu.nju.fuzzing.cli;

import edu.nju.fuzzing.model.SeedType;
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
        assertEquals(SeedType.UNKNOWN, cli.seedType());
        assertTrue(cli.nonCrashExitCodes().isEmpty());
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
        assertTrue(cli.nonCrashExitCodes().isEmpty());
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

    @Test
    void parse_nonCrashExitCodes_shouldParseCommaOrSpaceSeparated() {
        CliArgs cli = CliParser.parse(new String[]{
                "--workdir", "/tmp/mywd",
                "--duration", "1",
                "--timeout", "500",
                "--tid", "T1",
                "--cmd", "/bin/cat",
                "--coverage", "none",
                "--nonCrashExitCodes", "1, 2 4"
        });

        assertEquals(java.util.Set.of(1, 2, 4), cli.nonCrashExitCodes());
    }

    @Test
    void parse_seedType_shouldBeCaseInsensitive() {
        CliArgs cli = CliParser.parse(new String[]{
                "--workdir", "/tmp/mywd",
                "--duration", "1",
                "--timeout", "500",
                "--tid", "T1",
                "--cmd", "/bin/cat",
                "--coverage", "none",
                "--seedType", "xml"
        });

        assertEquals(SeedType.XML, cli.seedType());
    }
}
