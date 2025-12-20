package edu.nju.fuzzing.model;

import java.nio.file.Path;

public record RunResult(
        Path inputFile,
        long execTimeMs,
        int exitCode,
        boolean timedOut,
        Termination termination,
        Path stdoutFile,
        Path stderrFile
) {
    public enum Termination { NORMAL, TIMEOUT, ERROR }
}
