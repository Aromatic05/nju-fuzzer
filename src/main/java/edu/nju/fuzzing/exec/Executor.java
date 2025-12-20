package edu.nju.fuzzing.exec;

import edu.nju.fuzzing.model.RunResult;

import java.nio.file.Path;
import java.time.Duration;

public interface Executor {
    RunResult run(TargetCommand cmd, byte[] stdinData, Duration timeout, Path outDir) throws Exception;
}

