package edu.nju.fuzzing.stats;

import edu.nju.fuzzing.model.StatsTick;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Writes a per-second growth curve derived from StatsTick.
 *
 * One row per second (elapsedSec) with deltas of covered_edges and total_paths.
 */
public class StatsCurveWriter implements AutoCloseable {

    private final BufferedWriter writer;

    private final long bucketSeconds;

    private long currentBucketStartSec = -1;
    private String currentTargetName;
    private long currentExecsTotal;
    private int currentCoveredEdges;
    private int currentTotalPaths;
    private int currentCrashes;
    private int currentHangs;

    private int prevCoveredEdges = 0;
    private int prevTotalPaths = 0;
    private long prevExecsTotal = 0;
    private int prevCrashes = 0;
    private int prevHangs = 0;

    public StatsCurveWriter(Path curveFile) throws IOException {
        this(curveFile, 1);
    }

    public StatsCurveWriter(Path curveFile, long bucketSeconds) throws IOException {
        this.bucketSeconds = bucketSeconds <= 0 ? 1 : bucketSeconds;
        Files.createDirectories(curveFile.getParent());
        boolean exists = Files.exists(curveFile);
        writer = Files.newBufferedWriter(
                curveFile,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
        );
        if (!exists) {
            writer.write("timestamp,target_name,covered_edges,total_paths,new_edges,new_paths,exec_count,new_execs,crash_count,new_crashes,hang_count,new_hangs\n");
            writer.flush();
        }
    }

    public void tick(StatsTick t) throws IOException {
        long bucketStart = (t.elapsedSec() / bucketSeconds) * bucketSeconds;

        if (currentBucketStartSec == -1) {
            currentBucketStartSec = bucketStart;
            currentTargetName = t.targetName();
            currentExecsTotal = t.execsTotal();
            currentCoveredEdges = t.coveredEdges();
            currentTotalPaths = t.totalPaths();
            currentCrashes = t.crashes();
            currentHangs = t.hangs();
            prevCoveredEdges = t.coveredEdges();
            prevTotalPaths = t.totalPaths();
            prevExecsTotal = t.execsTotal();
            prevCrashes = t.crashes();
            prevHangs = t.hangs();
            return;
        }

        if (bucketStart == currentBucketStartSec) {
            currentTargetName = t.targetName();
            currentExecsTotal = t.execsTotal();
            currentCoveredEdges = t.coveredEdges();
            currentTotalPaths = t.totalPaths();
            currentCrashes = t.crashes();
            currentHangs = t.hangs();
            return;
        }

        if (bucketStart > currentBucketStartSec) {
            writeCurrentRow();

            currentBucketStartSec = bucketStart;
            currentTargetName = t.targetName();
            currentExecsTotal = t.execsTotal();
            currentCoveredEdges = t.coveredEdges();
            currentTotalPaths = t.totalPaths();
            currentCrashes = t.crashes();
            currentHangs = t.hangs();
        }
    }

    private void writeCurrentRow() throws IOException {
        int newEdges = currentCoveredEdges - prevCoveredEdges;
        int newPaths = currentTotalPaths - prevTotalPaths;
        long newExecs = currentExecsTotal - prevExecsTotal;
        int newCrashes = currentCrashes - prevCrashes;
        int newHangs = currentHangs - prevHangs;
        if (newEdges < 0) newEdges = 0;
        if (newPaths < 0) newPaths = 0;
        if (newExecs < 0) newExecs = 0;
        if (newCrashes < 0) newCrashes = 0;
        if (newHangs < 0) newHangs = 0;

        writer.write(String.format(
                "%d,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d%n",
                currentBucketStartSec,
                currentTargetName,
                currentCoveredEdges,
                currentTotalPaths,
                newEdges,
                newPaths,
                currentExecsTotal,
                newExecs,
                currentCrashes,
                newCrashes,
                currentHangs,
                newHangs
        ));
        writer.flush();

        prevCoveredEdges = currentCoveredEdges;
        prevTotalPaths = currentTotalPaths;
        prevExecsTotal = currentExecsTotal;
        prevCrashes = currentCrashes;
        prevHangs = currentHangs;
    }

    @Override
    public void close() throws IOException {
        if (currentBucketStartSec != -1) {
            writeCurrentRow();
        }
        writer.close();
    }
}
