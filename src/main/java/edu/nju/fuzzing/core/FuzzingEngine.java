package edu.nju.fuzzing.core;

import edu.nju.fuzzing.model.StatsTick;
import edu.nju.fuzzing.stats.StatsWriter;

import java.nio.file.Path;
import java.time.Instant;

public class FuzzingEngine {

    private final Path workdir;
    private final int durationSec;

    public FuzzingEngine(Path workdir, int durationSec) {
        this.workdir = workdir;
        this.durationSec = durationSec;
    }

    public void run() throws Exception {
        Path statsFile = workdir.resolve("stats/stats.csv");
        long start = Instant.now().getEpochSecond();

        long execs = 0;

        try (StatsWriter writer = new StatsWriter(statsFile)) {
            while (true) {
                long now = Instant.now().getEpochSecond();
                long elapsed = now - start;
                if (elapsed >= durationSec) {
                    break;
                }

                // skeleton：假装执行了一次
                execs++;

                StatsTick tick = new StatsTick(
                        elapsed,
                        execs,
                        execs / Math.max(1.0, elapsed),
                        0,  // queue size
                        0,  // crashes
                        0   // hangs
                );

                writer.tick(tick);
                Thread.sleep(1000);
            }
        }
    }
}

