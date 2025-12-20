package edu.nju.fuzzing.exec;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public record TargetCommand(
        List<String> argv,
        InputMode inputMode,
        Path inputFile,               // FILE 模式下不为 null
        Map<String, String> env
) {
    public TargetCommand {
        if (argv == null || argv.isEmpty()) throw new IllegalArgumentException("argv is empty");
        if (inputMode == null) throw new IllegalArgumentException("inputMode is null");
        if (env == null) env = Map.of();
        if (inputMode == InputMode.FILE && inputFile == null) {
            throw new IllegalArgumentException("inputFile is required for FILE mode");
        }
    }
}
