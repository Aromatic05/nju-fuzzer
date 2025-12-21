package edu.nju.fuzzing.cov;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * System V shared memory bitmap source implementation using JNA.
 * This class attaches to an AFL++ shared memory segment and provides
 * read access to the coverage bitmap.
 */
public class SysVShmBitmapSource implements BitmapSource {

    /**
     * Default AFL++ map size (64KB).
     */
    public static final int DEFAULT_MAP_SIZE = 65536;

    /**
     * Environment variable for shared memory ID.
     */
    public static final String ENV_SHM_ID = "__AFL_SHM_ID";

    /**
     * Environment variable for map size.
     */
    public static final String ENV_MAP_SIZE = "AFL_MAP_SIZE";

    private final int shmId;
    private final int mapSize;
    private Pointer shmPtr;
    private volatile boolean attached;

    /**
     * Creates a bitmap source from environment variables.
     *
     * @return a new SysVShmBitmapSource configured from environment
     * @throws IllegalStateException if __AFL_SHM_ID is not set
     */
    public static SysVShmBitmapSource fromEnvironment() {
        String shmIdStr = System.getenv(ENV_SHM_ID);
        if (shmIdStr == null || shmIdStr.isEmpty()) {
            throw new IllegalStateException(
                    ENV_SHM_ID + " environment variable is not set. " +
                    "Make sure the target is instrumented with AFL++."
            );
        }

        int shmId;
        try {
            shmId = Integer.parseInt(shmIdStr);
        } catch (NumberFormatException e) {
            throw new IllegalStateException(
                    "Invalid " + ENV_SHM_ID + " value: " + shmIdStr, e
            );
        }

        String mapSizeStr = System.getenv(ENV_MAP_SIZE);
        int mapSize = DEFAULT_MAP_SIZE;
        if (mapSizeStr != null && !mapSizeStr.isEmpty()) {
            try {
                mapSize = Integer.parseInt(mapSizeStr);
            } catch (NumberFormatException e) {
                // Use default if parsing fails
            }
        }

        return new SysVShmBitmapSource(shmId, mapSize);
    }

    /**
     * Creates a bitmap source with explicit parameters.
     *
     * @param shmId   the System V shared memory ID
     * @param mapSize the size of the bitmap in bytes
     */
    public SysVShmBitmapSource(int shmId, int mapSize) {
        if (mapSize <= 0) {
            throw new IllegalArgumentException("mapSize must be positive: " + mapSize);
        }
        this.shmId = shmId;
        this.mapSize = mapSize;
        this.attached = false;
    }

    /**
     * Attaches to the shared memory segment.
     *
     * @throws RuntimeException if attachment fails
     */
    public void attach() {
        if (attached) {
            return;
        }

        // shmat(shmId, NULL, 0) - attach at system-chosen address, read-write
        Pointer ptr = CLibrary.INSTANCE.shmat(shmId, null, 0);

        // Check for error: shmat returns (void*)-1 on failure
        if (ptr == null || Pointer.nativeValue(ptr) == -1L) {
            int errno = Native.getLastError();
            throw new RuntimeException(
                    "Failed to attach to shared memory segment " + shmId +
                    ", errno=" + errno
            );
        }

        this.shmPtr = ptr;
        this.attached = true;
    }

    @Override
    public int mapSize() {
        return mapSize;
    }

    @Override
    public void readInto(byte[] dst) {
        if (!attached) {
            throw new IllegalStateException("Not attached to shared memory");
        }
        if (dst.length < mapSize) {
            throw new IllegalArgumentException(
                    "Destination buffer too small: " + dst.length + " < " + mapSize
            );
        }
        shmPtr.read(0, dst, 0, mapSize);
    }

    @Override
    public void clear() {
        if (!attached) {
            throw new IllegalStateException("Not attached to shared memory");
        }
        // Clear the bitmap by writing zeros
        byte[] zeros = new byte[mapSize];
        shmPtr.write(0, zeros, 0, mapSize);
    }

    @Override
    public boolean isAttached() {
        return attached;
    }

    @Override
    public void close() {
        if (attached && shmPtr != null) {
            int result = CLibrary.INSTANCE.shmdt(shmPtr);
            if (result == -1) {
                // Log warning but don't throw
                System.err.println("Warning: Failed to detach from shared memory, errno="
                        + Native.getLastError());
            }
            attached = false;
            shmPtr = null;
        }
    }

    /**
     * Returns the shared memory ID.
     */
    public int getShmId() {
        return shmId;
    }

    /**
     * JNA interface for System V shared memory functions.
     */
    interface CLibrary extends com.sun.jna.Library {
        CLibrary INSTANCE = Native.load("c", CLibrary.class);

        /**
         * Attach to a shared memory segment.
         *
         * @param shmid  shared memory identifier
         * @param shmaddr desired attach address (null for system choice)
         * @param shmflg attachment flags
         * @return pointer to attached segment, or (void*)-1 on error
         */
        Pointer shmat(int shmid, Pointer shmaddr, int shmflg);

        /**
         * Detach from a shared memory segment.
         *
         * @param shmaddr pointer to attached segment
         * @return 0 on success, -1 on error
         */
        int shmdt(Pointer shmaddr);

        /**
         * Create or get a shared memory segment (used for testing).
         *
         * @param key    key for the segment
         * @param size   size of the segment
         * @param shmflg flags (IPC_CREAT, permissions, etc.)
         * @return shared memory identifier, or -1 on error
         */
        int shmget(int key, NativeLong size, int shmflg);

        /**
         * Control operations on shared memory segment.
         *
         * @param shmid shared memory identifier
         * @param cmd   command (IPC_RMID to remove, etc.)
         * @param buf   buffer for operations (null for IPC_RMID)
         * @return 0 on success, -1 on error
         */
        int shmctl(int shmid, int cmd, Pointer buf);
    }
}
