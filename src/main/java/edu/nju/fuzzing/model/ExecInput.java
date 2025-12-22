package edu.nju.fuzzing.model;

import edu.nju.fuzzing.exec.TargetCommand;

import java.nio.file.Path;
import java.time.Duration;

/**
 * Input parameters for a single execution.
 * 
 * This encapsulates all the information needed to execute the target program
 * once, including the command, input data, timeout, and logging options.
 */
public record ExecInput(
        /** Target command to execute */
        TargetCommand cmd,
        
        /** Data to write to stdin (null if using file input) */
        byte[] stdinData,
        
        /** Execution timeout */
        Duration timeout,
        
        /** Directory for output logs (stdout/stderr) */
        Path outDir,
        
        /** Whether to save stdout/stderr logs (usually only for crash/hang/debug) */
        boolean saveLogs
) {
    /**
     * Creates ExecInput with default settings (no logs).
     */
    public static ExecInput of(TargetCommand cmd, byte[] stdinData, Duration timeout, Path outDir) {
        return new ExecInput(cmd, stdinData, timeout, outDir, false);
    }
    
    /**
     * Creates ExecInput with logs enabled (for crash/hang analysis).
     */
    public static ExecInput withLogs(TargetCommand cmd, byte[] stdinData, Duration timeout, Path outDir) {
        return new ExecInput(cmd, stdinData, timeout, outDir, true);
    }
}
