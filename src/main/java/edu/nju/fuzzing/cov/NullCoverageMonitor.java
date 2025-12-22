package edu.nju.fuzzing.cov;

import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.RunResult;

/**
 * No-op coverage monitor for non-instrumented targets.
 * 
 * This monitor provides empty coverage data and allows the execution pipeline
 * to use a unified code path regardless of whether coverage monitoring is enabled.
 * All methods are no-ops except afterRun(), which returns empty coverage.
 * 
 * Usage:
 * <pre>{@code
 * CoverageMonitor monitor = new NullCoverageMonitor(65536);
 * monitor.beforeRun();  // no-op
 * RunResult result = executor.run(...);
 * Coverage coverage = monitor.afterRun(result);  // returns empty coverage
 * }</pre>
 */
public final class NullCoverageMonitor implements CoverageMonitor {
    
    private final int mapSize;
    
    /**
     * Creates a null coverage monitor with the specified map size.
     * 
     * @param mapSize coverage map size (typically 65536)
     */
    public NullCoverageMonitor(int mapSize) {
        this.mapSize = mapSize;
    }
    
    @Override
    public void beforeRun() {
        // No-op: no bitmap to clear
    }
    
    @Override
    public Coverage afterRun(RunResult result) {
        // Return empty coverage
        return Coverage.empty(result);
    }
    
    /**
     * Returns the map size.
     */
    public int getMapSize() {
        return mapSize;
    }

    @Override
    public void close() {
        // No resources to clean up
    }
}

