package edu.nju.fuzzing.stats;

import edu.nju.fuzzing.model.StatsTick;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class StatsWriter implements AutoCloseable {

    private final BufferedWriter writer;

    public StatsWriter(Path statsFile) throws IOException {
        Files.createDirectories(statsFile.getParent());
        boolean exists = Files.exists(statsFile);
        writer = Files.newBufferedWriter(
                statsFile,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
        );
        if (!exists) {
            writer.write("time_sec,execs_total,execs_per_sec,queue_size,crashes,hangs\n");
            writer.flush();
        }
    }

    public void tick(StatsTick t) throws IOException {
        writer.write(String.format(
                "%d,%d,%.2f,%d,%d,%d%n",
                t.elapsedSec(),
                t.execsTotal(),
                t.execsPerSec(),
                t.queueSize(),
                t.crashes(),
                t.hangs()
        ));
        writer.flush();
    }

    @Override
    public void close() throws IOException {
        writer.close();
    }
}
