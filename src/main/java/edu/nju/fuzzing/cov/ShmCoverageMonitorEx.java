package edu.nju.fuzzing.cov;

import edu.nju.fuzzing.model.CoverageEx;
import edu.nju.fuzzing.model.RunResult;

/**
 * Extended ShmCoverageMonitor that provides edge-level coverage data.
 * 
 * This implementation:
 * - Uses CoverageDiffStrategyEx for edge tracking
 * - Integrates with CoverageDB for scheduling support
 * - Supports stability detection
 */
public class ShmCoverageMonitorEx implements CoverageMonitorEx {

    private final BitmapSource bitmapSource;
    private final CoverageDiffStrategyEx strategy;
    private final CoverageDB coverageDB;
    private final int mapSize;
    private final byte[] buffer;

    private volatile boolean stabilityDetectionEnabled = false;
    private volatile boolean started = false;

    /**
     * Creates a monitor with a new CoverageDB.
     */
    public ShmCoverageMonitorEx(BitmapSource bitmapSource, CoverageDiffStrategyEx strategy) {
        this(bitmapSource, strategy, new CoverageDB(bitmapSource.mapSize()));
    }

    /**
     * Creates a monitor with an existing CoverageDB.
     */
    public ShmCoverageMonitorEx(BitmapSource bitmapSource, 
                                 CoverageDiffStrategyEx strategy,
                                 CoverageDB coverageDB) {
        this.bitmapSource = bitmapSource;
        this.strategy = strategy;
        this.coverageDB = coverageDB;
        this.mapSize = bitmapSource.mapSize();
        this.buffer = new byte[mapSize];
    }

    /**
     * Starts the monitor (attaches to shared memory if needed).
     */
    public void start() {
        if (started) return;
        // Attach to shared memory if needed.
        if (bitmapSource instanceof SysVShmBitmapSource shmSource && !shmSource.isAttached()) {
            shmSource.attach();
        }
        started = true;
    }

    @Override
    public void beforeRun() {
        bitmapSource.clear();
    }

    @Override
    public CoverageEx afterRunEx(RunResult result) {
        // Read bitmap
        bitmapSource.readInto(buffer);

        // Compute diff with edge-level detail
        DiffResultEx diff = strategy.diffEx(buffer);

        // Create extended coverage
        return CoverageEx.from(diff, result, mapSize);
    }

    @Override
    public CoverageDB getCoverageDB() {
        return coverageDB;
    }

    @Override
    public CoverageDiffStrategyEx getStrategyEx() {
        return strategy;
    }

    @Override
    public boolean isStabilityDetectionEnabled() {
        return stabilityDetectionEnabled;
    }

    @Override
    public void setStabilityDetectionEnabled(boolean enabled) {
        this.stabilityDetectionEnabled = enabled;
    }

    @Override
    public int getTotalEdgesSeen() {
        return strategy.totalSeenBytes();
    }

    @Override
    public int getMapSize() {
        return mapSize;
    }

    @Override
    public void close() {
        if (bitmapSource != null) {
            bitmapSource.close();
        }
        started = false;
    }

    // ========== Factory Methods ==========

    /**
     * Creates a monitor from environment variables (AFL++ style).
     * Reads __AFL_SHM_ID and AFL_MAP_SIZE from environment.
     */
    public static ShmCoverageMonitorEx fromEnvironment() {
        String shmIdStr = System.getenv("__AFL_SHM_ID");
        if (shmIdStr == null) {
            throw new IllegalStateException("Environment variable __AFL_SHM_ID not set");
        }

        int shmId = Integer.parseInt(shmIdStr);
        int mapSize = 65536; // Default AFL++ map size

        String mapSizeStr = System.getenv("AFL_MAP_SIZE");
        if (mapSizeStr != null) {
            mapSize = Integer.parseInt(mapSizeStr);
        }

        SysVShmBitmapSource source = new SysVShmBitmapSource(shmId, mapSize);
        source.attach();
        CoverageDiffStrategyEx strategy = CoverageDiffStrategyEx.createDefault(mapSize);
        
        return new ShmCoverageMonitorEx(source, strategy);
    }

    /**
     * Creates a monitor with a mock bitmap source (for testing).
     * Note: MockBitmapSource should be created in the test package.
     */
    public static ShmCoverageMonitorEx forTesting(int mapSize, BitmapSource mockSource) {
        CoverageDiffStrategyEx strategy = CoverageDiffStrategyEx.createDefault(mapSize);
        return new ShmCoverageMonitorEx(mockSource, strategy);
    }
}
