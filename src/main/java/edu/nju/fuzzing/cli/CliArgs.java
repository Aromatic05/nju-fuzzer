package edu.nju.fuzzing.cli;

import java.nio.file.Path;
import java.util.Set;

public record CliArgs(
        Path workdir,
        Path seedsDir,
        int durationSec,
        int timeoutMs,
        String tid,
        String cmdLine,
        String coverage,
        Set<Integer> nonCrashExitCodes
) {}
