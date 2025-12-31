package edu.nju.fuzzing.stats;

import edu.nju.fuzzing.model.StatsTick;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class StatsWriter implements AutoCloseable {

    private final BufferedWriter writer;
    private final int flushEvery;
    private int pending = 0;
    private boolean closed = false;

    public StatsWriter(Path statsFile) throws IOException {
        Files.createDirectories(statsFile.getParent());
        boolean exists = Files.exists(statsFile);
        writer = Files.newBufferedWriter(
                statsFile,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
        );

        int fe = 100;
        try {
            String raw = System.getProperty("nju.fuzzer.statsFlushEvery", "100");
            if (raw != null && !raw.isBlank()) {
                fe = Integer.parseInt(raw.trim());
            }
        } catch (Exception ignored) {
            fe = 100;
        }
        // <=0 means "flush only on close".
        this.flushEvery = (fe <= 0) ? Integer.MAX_VALUE : fe;
        
        // [修改] Header 增加 total_paths 和 hang_count
        if (!exists) {
            writer.write("timestamp,target_name,exec_count,covered_edges,execs_per_sec,queue_size,total_paths,crash_count,hang_count\n");
            writer.flush();
        }
    }

    public void tick(StatsTick t) throws IOException {
        // [修改] 写入数据增加 t.totalPaths() 和 t.hangs()
        writer.write(String.format(
                "%d,%s,%d,%d,%.2f,%d,%d,%d,%d%n",
                t.elapsedSec(),
                t.targetName(),
                t.execsTotal(),
                t.coveredEdges(),
                t.execsPerSec(),
                t.queueSize(),
                t.totalPaths(), // [新增]
                t.crashes(),
                t.hangs()       // [新增]
        ));

        pending++;
        if (pending >= flushEvery) {
            writer.flush();
            pending = 0;
        }
    }

    @Override
    public void close() throws IOException {
        if (closed) return;
        closed = true;
        try {
            writer.flush();
        } finally {
            writer.close();
        }
    }
}