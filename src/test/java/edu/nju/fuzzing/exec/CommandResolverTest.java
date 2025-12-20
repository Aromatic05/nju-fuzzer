package edu.nju.fuzzing.exec;

import edu.nju.fuzzing.model.TargetSpec;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CommandResolverTest {

    @Test
    void resolve_singleAtAt_shouldUseFileMode() {
        TargetSpec spec = new TargetSpec(
                "T05",
                Path.of("/usr/bin/djpeg"),
                List.of("djpeg", "@@"),
                Map.of(),
                Duration.ofSeconds(1)
        );

        Path input = Path.of("/tmp/input.jpg");

        TargetCommand cmd = CommandResolver.resolve(spec, input);

        assertEquals(InputMode.FILE, cmd.inputMode());
        assertEquals(input, cmd.inputFile());
        assertEquals(
                List.of("djpeg", input.toAbsolutePath().toString()),
                cmd.argv()
        );
    }

    @Test
    void resolve_multipleAtAt_shouldReplaceAll() {
        TargetSpec spec = new TargetSpec(
                "T02",
                Path.of("/usr/bin/readelf"),
                List.of("readelf", "-a", "@@", "@@"),
                Map.of(),
                Duration.ofSeconds(2)
        );

        Path input = Path.of("/tmp/a.out");

        TargetCommand cmd = CommandResolver.resolve(spec, input);

        assertEquals(InputMode.FILE, cmd.inputMode());
        assertEquals(
                List.of(
                        "readelf",
                        "-a",
                        input.toAbsolutePath().toString(),
                        input.toAbsolutePath().toString()
                ),
                cmd.argv()
        );
    }

    @Test
    void resolve_noAtAt_shouldUseStdinMode() {
        TargetSpec spec = new TargetSpec(
                "T01",
                Path.of("/usr/bin/cxxfilt"),
                List.of("cxxfilt"),
                Map.of(),
                Duration.ofSeconds(1)
        );

        TargetCommand cmd = CommandResolver.resolve(spec, null);

        assertEquals(InputMode.STDIN, cmd.inputMode());
        assertNull(cmd.inputFile());
        assertEquals(List.of("cxxfilt"), cmd.argv());
    }
}

