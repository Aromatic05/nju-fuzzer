package edu.nju.fuzzing.cov;
import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.RunResult;
/**
 * No-operation coverage monitor for initial framework setup.
 * Returns empty coverage to ensure the fuzzing loop runs smoothly.
 */
public class NoopCoverageMonitor implements CoverageMonitor {
    @Override
    public void beforeRun() {
        // No operation needed
    }
    @Override
    public Coverage afterRun(RunResult result) {
        return Coverage.empty(result);
    }

    @Override
    public void close() {
        // No resources to clean up
    }
}
