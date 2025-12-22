package edu.nju.fuzzing.cov;

import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.RunResult;

public interface CoverageMonitor extends AutoCloseable {
    void beforeRun();
    Coverage afterRun(RunResult result);
}

