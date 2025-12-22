package edu.nju.fuzzing.core;

import edu.nju.fuzzing.model.ExecInput;
import edu.nju.fuzzing.model.ExecResult;

/**
 * Standard execution environment that integrates execution and coverage monitoring.
 * 
 * This interface provides a unified abstraction for executing instrumented targets
 * with coverage feedback. It handles the lifecycle of coverage monitoring (start/close)
 * and ensures correct sequencing of bitmap clearing, execution, and coverage collection.
 * 
 * Implementations can support both instrumented (with coverage) and non-instrumented
 * (without coverage) targets, providing a consistent API regardless of the underlying
 * execution mode.
 * 
 * Typical usage:
 * <pre>{@code
 * ExecutorHarness harness = new InstrumentedExecutorHarness(executor, monitor);
 * harness.start();
 * try {
 *     ExecInput input = ExecInput.of(cmd, stdinData, timeout, outDir);
 *     ExecResult result = harness.execute(input);
 *     
 *     if (result.isCrash()) {
 *         // Handle crash
 *     } else if (result.isInteresting()) {
 *         // Handle new coverage
 *     }
 * } finally {
 *     harness.close();
 * }
 * }</pre>
 */
public interface ExecutorHarness extends AutoCloseable {
    
    /**
     * Initializes the execution environment.
     * 
     * For instrumented targets, this typically attaches to AFL++ shared memory.
     * Must be called before execute().
     * 
     * @throws Exception if initialization fails (e.g., SHM not available)
     */
    void start() throws Exception;
    
    /**
     * Executes the target program once and collects coverage.
     * 
     * This method ensures correct sequencing:
     * 1. Clear coverage bitmap (monitor.beforeRun())
     * 2. Execute target program (executor.run())
     * 3. Collect coverage data (monitor.afterRun())
     * 
     * @param input execution parameters (command, stdin, timeout, logs)
     * @return combined result (RunResult + CoverageEx)
     * @throws Exception if execution fails
     */
    ExecResult execute(ExecInput input) throws Exception;
    
    /**
     * Releases resources used by the execution environment.
     * 
     * For instrumented targets, this typically detaches from AFL++ shared memory.
     * Must be called after all executions complete.
     */
    @Override
    void close();
}
