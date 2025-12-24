package edu.nju.fuzzing.cov;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;

/**
 * Minimal System V shared memory segment manager for AFL-style coverage bitmap.
 *
 * <p>Creates a private SHM segment via shmget(IPC_PRIVATE, size, IPC_CREAT|0600)
 * and marks it for removal via shmctl(IPC_RMID) on close.
 */
public final class SysVShmSegment implements AutoCloseable {

    // System V IPC constants (Linux)
    private static final int IPC_PRIVATE = 0;
    private static final int IPC_CREAT = 01000;
    private static final int PERM_0600 = 0600;
    private static final int IPC_RMID = 0;

    private final int shmId;
    private final int size;
    private volatile boolean removed;

    private SysVShmSegment(int shmId, int size) {
        this.shmId = shmId;
        this.size = size;
        this.removed = false;
    }

    public static SysVShmSegment create(int size) {
        if (size <= 0) throw new IllegalArgumentException("size must be positive: " + size);

        int flags = IPC_CREAT | PERM_0600;
        int id = SysVShmBitmapSource.CLibrary.INSTANCE.shmget(IPC_PRIVATE, new NativeLong(size), flags);
        if (id == -1) {
            int errno = Native.getLastError();
            throw new IllegalStateException(
                    "Failed to create SysV SHM segment (shmget), errno=" + errno +
                    ". You can also pre-create SHM and export " + SysVShmBitmapSource.ENV_SHM_ID +
                    " (and optionally " + SysVShmBitmapSource.ENV_MAP_SIZE + ") before running."
            );
        }
        return new SysVShmSegment(id, size);
    }

    public int shmId() {
        return shmId;
    }

    public int size() {
        return size;
    }

    /**
     * Mark the segment for removal. The kernel will delete it after all attaches are detached.
     */
    public void markForRemoval() {
        if (removed) return;
        int res = SysVShmBitmapSource.CLibrary.INSTANCE.shmctl(shmId, IPC_RMID, null);
        if (res == -1) {
            int errno = Native.getLastError();
            throw new IllegalStateException("Failed to mark SysV SHM segment for removal (shmctl IPC_RMID), shmId="
                    + shmId + ", errno=" + errno);
        }
        removed = true;
    }

    @Override
    public void close() {
        try {
            markForRemoval();
        } catch (Exception ignored) {
        }
    }
}
