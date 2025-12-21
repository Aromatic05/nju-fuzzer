package edu.nju.fuzzing.corpus;

import edu.nju.fuzzing.model.Coverage;
import edu.nju.fuzzing.model.RunResult;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Default implementation of CorpusManager that saves inputs to disk.
 * 
 * Directory structure:
 * - outputDir/
 *   - queue/       - interesting inputs for further fuzzing
 *   - crashes/     - inputs that caused crashes
 *   - hangs/       - inputs that caused timeouts
 */
public class FileCorpusManager implements CorpusManager {

    private final Path outputDir;
    private final Path queueDir;
    private final Path crashesDir;
    private final Path hangsDir;

    private final AtomicInteger queueCounter = new AtomicInteger(0);
    private final AtomicInteger crashCounter = new AtomicInteger(0);
    private final AtomicInteger hangCounter = new AtomicInteger(0);
    private final AtomicLong totalBytes = new AtomicLong(0);

    /**
     * Creates a new FileCorpusManager with the given output directory.
     *
     * @param outputDir the root output directory
     * @throws IOException if directories cannot be created
     */
    public FileCorpusManager(Path outputDir) throws IOException {
        this.outputDir = outputDir;
        this.queueDir = outputDir.resolve("queue");
        this.crashesDir = outputDir.resolve("crashes");
        this.hangsDir = outputDir.resolve("hangs");

        // Create directories
        Files.createDirectories(queueDir);
        Files.createDirectories(crashesDir);
        Files.createDirectories(hangsDir);
    }

    @Override
    public Path saveToQueue(byte[] input, Coverage coverage) {
        int id = queueCounter.incrementAndGet();
        String hash = shortHash(input);
        String filename = String.format("id_%06d_cov_%d_%s", id, coverage.newBytes(), hash);
        
        return saveInput(queueDir, filename, input);
    }

    @Override
    public Path saveCrash(byte[] input, RunResult result) {
        int id = crashCounter.incrementAndGet();
        String hash = shortHash(input);
        String filename = String.format("crash_%06d_exit_%d_%s", id, result.exitCode(), hash);
        
        return saveInput(crashesDir, filename, input);
    }

    @Override
    public Path saveHang(byte[] input, RunResult result) {
        int id = hangCounter.incrementAndGet();
        String hash = shortHash(input);
        String filename = String.format("hang_%06d_%s", id, hash);
        
        return saveInput(hangsDir, filename, input);
    }

    private Path saveInput(Path dir, String filename, byte[] input) {
        Path file = dir.resolve(filename);
        try {
            Files.write(file, input);
            totalBytes.addAndGet(input.length);
            return file;
        } catch (IOException e) {
            throw new RuntimeException("Failed to save input: " + file, e);
        }
    }

    /**
     * Calculates a short hash of the input for filename uniqueness.
     */
    private String shortHash(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input);
            // Take first 4 bytes (8 hex chars)
            return HexFormat.of().formatHex(hash, 0, 4);
        } catch (NoSuchAlgorithmException e) {
            // Fallback to simple hash
            return String.format("%08x", java.util.Arrays.hashCode(input));
        }
    }

    @Override
    public Path outputDir() {
        return outputDir;
    }

    @Override
    public Path queueDir() {
        return queueDir;
    }

    @Override
    public Path crashesDir() {
        return crashesDir;
    }

    @Override
    public Path hangsDir() {
        return hangsDir;
    }

    @Override
    public CorpusStats stats() {
        return new CorpusStats(
                queueCounter.get(),
                crashCounter.get(),
                hangCounter.get(),
                totalBytes.get()
        );
    }

    @Override
    public void close() {
        // Nothing to close for file-based implementation
    }

    /**
     * Returns the current queue size.
     */
    public int getQueueSize() {
        return queueCounter.get();
    }

    /**
     * Returns the current crash count.
     */
    public int getCrashCount() {
        return crashCounter.get();
    }

    /**
     * Returns the current hang count.
     */
    public int getHangCount() {
        return hangCounter.get();
    }
}
