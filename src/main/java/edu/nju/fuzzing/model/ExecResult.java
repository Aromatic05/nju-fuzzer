package edu.nju.fuzzing.core;

import edu.nju.fuzzing.model.CoverageEx;
import edu.nju.fuzzing.model.RunResult;

/**
 * Result of a single execution, combining runtime result and coverage information.
 * 
 * This unified result type simplifies the execution pipeline by packaging both
 * the execution outcome (exit code, timing, termination) and coverage data
 * (edges hit, new edges, stability) into a single object.
 */
public record ExecResult(
        /** Execution result (exit code, timing, termination) */
        RunResult run,
        
        /** Coverage information (edges hit, new edges, stability) */
        CoverageEx coverage
) {
    /**
     * Returns whether this execution discovered new coverage.
     */
    public boolean isInteresting() {
        return coverage.interesting();
    }
    
    /**
     * Returns whether this execution crashed.
     */
    public boolean isCrash() {
        return run.termination() == RunResult.Termination.ERROR;
    }
    
    /**
     * Returns whether this execution timed out.
     */
    public boolean isTimeout() {
        return run.timedOut();
    }
    
    /**
     * Returns whether this execution completed normally.
     */
    public boolean isNormal() {
        return run.termination() == RunResult.Termination.NORMAL;
    }
}
