package edu.nju.fuzzing.exec;

import edu.nju.fuzzing.model.RunResult;

import java.nio.file.Path;

public interface Executor {
    RunResult run(Path inputFile) throws Exception;
}

