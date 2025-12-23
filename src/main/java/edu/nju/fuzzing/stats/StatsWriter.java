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
        
        // [严格对齐规范] 写入 CSV Header
        if (!exists) {
            writer.write("timestamp,target_name,exec_count,covered_edges,execs_per_sec,queue_size,crash_count\n");
            writer.flush();
        }
    }

    public void tick(StatsTick t) throws IOException {
        // [严格对齐规范] 写入数据行
        writer.write(String.format(
                "%d,%s,%d,%d,%.2f,%d,%d%n",
                t.elapsedSec(),
                t.targetName(),
                t.execsTotal(),
                t.coveredEdges(),
                t.execsPerSec(),
                t.queueSize(),
                t.crashes()
        ));
        writer.flush();
    }

    @Override
    public void close() throws IOException {
        writer.close();
    }
}