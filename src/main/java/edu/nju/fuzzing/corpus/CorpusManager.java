package edu.nju.fuzzing.corpus;

import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.RunResult;

import java.nio.file.Path;

/**
 * Interface for managing the fuzzing corpus (queue, crashes, hangs).
 * 
 * Responsibilities:
 * - Save interesting inputs to queue for further mutation
 * - Save crash-inducing inputs for analysis
 * - Save timeout/hang inputs for analysis
 * - Track corpus statistics
 */
public interface CorpusManager extends AutoCloseable {

    /**
     * Saves an interesting input to the queue.
     *
     * @param input the input bytes
     * @param coverage the coverage data for this input
     * @return the saved file path
     */
    Path saveToQueue(byte[] input, Coverage coverage);

    /**
     * Saves a crash-inducing input.
     *
     * @param input the input bytes
     * @param result the execution result
     * @return the saved file path
     */
    Path saveCrash(byte[] input, RunResult result);

    /**
     * Saves a hang/timeout input.
     *
     * @param input the input bytes
     * @param result the execution result
     * @return the saved file path
     */
    Path saveHang(byte[] input, RunResult result);

    /**
     * Returns the output directory root.
     */
    Path outputDir();

    /**
     * Returns the queue directory.
     */
    Path queueDir();

    /**
     * Returns the crashes directory.
     */
    Path crashesDir();

    /**
     * Returns the hangs directory.
     */
    Path hangsDir();

    /**
     * Returns current corpus statistics.
     */
    CorpusStats stats();

    @Override
    void close();

    /**
     * Corpus statistics snapshot.
     */
    record CorpusStats(
            int queueSize,
            int crashCount,
            int hangCount,
            long totalBytes
    ) {}
}
