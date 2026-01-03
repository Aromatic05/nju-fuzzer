package edu.nju.fuzzing.cli;

import edu.nju.fuzzing.model.SeedType;

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
        SeedType seedType,
        Set<Integer> nonCrashExitCodes
) {}
