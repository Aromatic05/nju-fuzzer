package edu.nju.fuzzing.cov;

import edu.nju.fuzzing.model.CoverageEx;
import edu.nju.fuzzing.model.RunResult;

/**
 * Extended CoverageMonitor interface that provides edge-level coverage data.
 * 
 * This extends the basic CoverageMonitor to support:
 * - Extended coverage with edge indices (CoverageEx)
 * - CoverageDB integration for scheduling
 * - Stability detection
 * 
 * Use this interface when you need seed scheduling support.
 * Use basic CoverageMonitor when you only need interesting detection.
 */
public interface CoverageMonitorEx extends CoverageMonitor {

    /**
     * Returns extended coverage data after execution.
     * This includes edge indices needed for scheduling.
     *
     * @param result the execution result
     * @return extended coverage with edge-level detail
     */
    CoverageEx afterRunEx(RunResult result);

    /**
     * Default implementation that wraps afterRunEx().
     */
    @Override
    default edu.nju.fuzzing.model.Coverage afterRun(RunResult result) {
        return afterRunEx(result).toBasic();
    }

    /**
     * Returns the CoverageDB used by this monitor.
     * May return null if no CoverageDB is configured.
     */
    CoverageDB getCoverageDB();

    /**
     * Returns the extended diff strategy.
     */
    CoverageDiffStrategyEx getStrategyEx();

    /**
     * Checks if stability detection is enabled.
     */
    boolean isStabilityDetectionEnabled();

    /**
     * Enables or disables stability detection.
     * When enabled, interesting inputs may be re-executed to verify stability.
     */
    void setStabilityDetectionEnabled(boolean enabled);

    /**
     * Returns the total number of unique edges ever seen.
     */
    int getTotalEdgesSeen();

    /**
     * Returns the map size.
     */
    int getMapSize();
}
