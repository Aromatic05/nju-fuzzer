package edu.nju.fuzzing.cli;

import java.nio.file.Path;

public record CliArgs(
        Path workdir,
        Path seedsDir,
        int durationSec,
        int timeoutMs,
        String tid,
        String cmdLine,
        String coverage
) {}
