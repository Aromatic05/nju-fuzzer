package edu.nju.fuzzing.model;

import java.nio.file.Path;

public record RunResult(
        long execId,
        Path inputFile,
        long execTimeMs,
        long execTimeNanos,
        int exitCode,
        boolean timedOut,
        Termination termination,
        Path stdoutFile,
        Path stderrFile
) {
    public enum Termination { NORMAL, TIMEOUT, ERROR }
    
    /**
     * Creates RunResult with execTimeNanos derived from execTimeMs (backward compatible).
     */
    public static RunResult of(long execId, Path inputFile, long execTimeMs,
                               int exitCode, boolean timedOut, Termination termination,
                               Path stdoutFile, Path stderrFile) {
        return new RunResult(execId, inputFile, execTimeMs, execTimeMs * 1_000_000L,
                           exitCode, timedOut, termination, stdoutFile, stderrFile);
    }
}
