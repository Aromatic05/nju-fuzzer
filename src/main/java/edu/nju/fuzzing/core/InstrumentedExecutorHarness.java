package edu.nju.fuzzing.core;

import edu.nju.fuzzing.cov.CoverageMonitor;
import edu.nju.fuzzing.exec.Executor;
import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.CoverageEx;
import edu.nju.fuzzing.model.ExecInput;
import edu.nju.fuzzing.model.ExecResult;
import edu.nju.fuzzing.model.RunResult;

/**
 * Standard executor harness that integrates execution and coverage monitoring.
 * 
 * This implementation combines a generic Executor (e.g., ProcessExecutor) with
 * a CoverageMonitor (e.g., ShmCoverageMonitor or NullCoverageMonitor) to provide
 * unified execution with optional coverage feedback.
 * 
 * The harness ensures correct sequencing:
 * 1. monitor.beforeRun() - clear coverage bitmap
 * 2. executor.run() - execute target program
 * 3. monitor.afterRun() - collect and diff coverage
 * 
 * This design allows the main fuzzing loop to use a single execution path
 * regardless of whether coverage monitoring is enabled.
 * 
 * Example usage:
 * <pre>{@code
 * // With coverage
 * CoverageMonitor monitor = ShmCoverageMonitor.fromEnvironment();
 * ExecutorHarness harness = new InstrumentedExecutorHarness(executor, monitor);
 * 
 * // Without coverage
 * CoverageMonitor nullMonitor = new NullCoverageMonitor(65536);
 * ExecutorHarness harness = new InstrumentedExecutorHarness(executor, nullMonitor);
 * 
 * harness.start();
 * try {
 *     ExecResult result = harness.execute(input);
 *     // Process result...
 * } finally {
 *     harness.close();
 * }
 * }</pre>
 */
public final class InstrumentedExecutorHarness implements ExecutorHarness {
    
    private final Executor executor;
    private final CoverageMonitor coverageMonitor;
    private final int mapSize;
    
    /**
     * Creates an instrumented executor harness.
     * 
     * @param executor underlying executor (e.g., ProcessExecutor)
     * @param coverageMonitor coverage monitor (ShmCoverageMonitor or NullCoverageMonitor)
     * @param mapSize coverage map size (for creating empty CoverageEx)
     */
    public InstrumentedExecutorHarness(Executor executor, CoverageMonitor coverageMonitor, int mapSize) {
        this.executor = executor;
        this.coverageMonitor = coverageMonitor;
        this.mapSize = mapSize;
    }
    
    /**
     * Creates an instrumented executor harness with default map size.
     */
    public InstrumentedExecutorHarness(Executor executor, CoverageMonitor coverageMonitor) {
        this(executor, coverageMonitor, 65536);
    }
    
    @Override
    public void start() throws Exception {
        // If monitor is ShmCoverageMonitor, start it (attach SHM)
        if (coverageMonitor instanceof AutoCloseable) {
            // Check if it has a start() method via reflection or specific type
            if (coverageMonitor.getClass().getName().contains("ShmCoverageMonitor")) {
                try {
                    var startMethod = coverageMonitor.getClass().getMethod("start");
                    startMethod.invoke(coverageMonitor);
                } catch (NoSuchMethodException e) {
                    // No start method, ignore
                } catch (Exception e) {
                    throw new Exception("Failed to start coverage monitor", e);
                }
            }
        }
    }
    
    @Override
    public ExecResult execute(ExecInput input) throws Exception {
        // 1. Clear bitmap before execution
        coverageMonitor.beforeRun();
        
        // 2. Execute target program
        RunResult run = executor.run(
            input.cmd(),
            input.stdinData(),
            input.timeout(),
            input.outDir()
        );
        
        // 3. Collect coverage after execution
        Coverage coverage = coverageMonitor.afterRun(run);
        
        // 4. Convert to CoverageEx (upgrade from basic Coverage)
        CoverageEx coverageEx = CoverageEx.fromBasic(coverage);
        
        return new ExecResult(run, coverageEx);
    }
    
    @Override
    public void close() {
        try {
            coverageMonitor.close();
        } catch (Exception e) {
            // Log but don't propagate close errors
            System.err.println("Warning: Failed to close coverage monitor: " + e.getMessage());
        }
    }
    
    /**
     * Returns the underlying executor.
     */
    public Executor getExecutor() {
        return executor;
    }
    
    /**
     * Returns the coverage monitor.
     */
    public CoverageMonitor getCoverageMonitor() {
        return coverageMonitor;
    }
    
    /**
     * Returns the map size.
     */
    public int getMapSize() {
        return mapSize;
    }
}
