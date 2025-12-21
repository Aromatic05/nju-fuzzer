package edu.nju.fuzzing.stats;

import edu.nju.fuzzing.model.StatsTick;

import java.io.PrintStream;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Periodically prints fuzzer status to the console.
 * 
 * Can be configured to print every N seconds or every N executions.
 */
public class StatusPrinter implements AutoCloseable {

    private final PrintStream out;
    private final Supplier<StatsTick> statsSupplier;
    private final ScheduledExecutorService scheduler;
    private final long intervalMs;
    private volatile boolean running = false;
    private volatile Instant lastPrintTime;

    /**
     * Creates a StatusPrinter that prints every intervalSeconds seconds.
     *
     * @param out the output stream to print to
     * @param statsSupplier a supplier that provides current stats
     * @param intervalSeconds the interval between prints in seconds
     */
    public StatusPrinter(PrintStream out, Supplier<StatsTick> statsSupplier, int intervalSeconds) {
        this.out = out;
        this.statsSupplier = statsSupplier;
        this.intervalMs = intervalSeconds * 1000L;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "status-printer");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Creates a StatusPrinter that prints to stdout every second.
     */
    public StatusPrinter(Supplier<StatsTick> statsSupplier) {
        this(System.out, statsSupplier, 1);
    }

    /**
     * Starts the periodic status printing.
     */
    public void start() {
        if (running) {
            return;
        }
        running = true;
        lastPrintTime = Instant.now();
        
        scheduler.scheduleAtFixedRate(this::printStatus, intervalMs, intervalMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Stops the periodic status printing.
     */
    public void stop() {
        running = false;
        scheduler.shutdown();
        try {
            scheduler.awaitTermination(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Prints the current status immediately.
     */
    public void printNow() {
        try {
            StatsTick stats = statsSupplier.get();
            out.println(stats.toStatusLine());
            lastPrintTime = Instant.now();
        } catch (Exception e) {
            out.println("[STATUS ERROR] " + e.getMessage());
        }
    }

    private void printStatus() {
        if (!running) {
            return;
        }
        try {
            StatsTick stats = statsSupplier.get();
            out.println(stats.toStatusLine());
            lastPrintTime = Instant.now();
        } catch (Exception e) {
            // Don't let exceptions stop the printer
            out.println("[STATUS ERROR] " + e.getMessage());
        }
    }

    /**
     * Prints a special event message (e.g., new crash found).
     */
    public void printEvent(String event) {
        out.println("[EVENT] " + event);
    }

    /**
     * Prints a message indicating a new path was found.
     */
    public void printNewPath(int pathId, int coverage) {
        out.printf("[NEW PATH] id=%d, coverage=%d%n", pathId, coverage);
    }

    /**
     * Prints a message indicating a crash was found.
     */
    public void printCrash(int crashId, String reason) {
        out.printf("[CRASH] id=%d, reason=%s%n", crashId, reason);
    }

    /**
     * Prints a message indicating a hang was found.
     */
    public void printHang(int hangId, long timeoutMs) {
        out.printf("[HANG] id=%d, timeout=%dms%n", hangId, timeoutMs);
    }

    /**
     * Returns the last time a status was printed.
     */
    public Instant getLastPrintTime() {
        return lastPrintTime;
    }

    @Override
    public void close() {
        stop();
    }

    /**
     * Builder for creating StatusPrinter instances.
     */
    public static class Builder {
        private PrintStream out = System.out;
        private Supplier<StatsTick> statsSupplier;
        private int intervalSeconds = 1;

        public Builder output(PrintStream out) {
            this.out = out;
            return this;
        }

        public Builder statsSupplier(Supplier<StatsTick> supplier) {
            this.statsSupplier = supplier;
            return this;
        }

        public Builder intervalSeconds(int seconds) {
            this.intervalSeconds = seconds;
            return this;
        }

        public StatusPrinter build() {
            if (statsSupplier == null) {
                throw new IllegalStateException("statsSupplier must be set");
            }
            return new StatusPrinter(out, statsSupplier, intervalSeconds);
        }
    }

    /**
     * Creates a new Builder.
     */
    public static Builder builder() {
        return new Builder();
    }
}
