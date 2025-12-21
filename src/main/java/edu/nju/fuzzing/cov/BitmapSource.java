package edu.nju.fuzzing.cov;

/**
 * Abstraction for reading AFL++ shared memory bitmap.
 * This interface allows switching between different implementations
 * (JNA, JNI, or file-based mmap) without affecting the upper layers.
 */
public interface BitmapSource extends AutoCloseable {

    /**
     * Returns the size of the bitmap in bytes.
     *
     * @return the map size
     */
    int mapSize();

    /**
     * Reads the bitmap content into the destination buffer.
     * The destination buffer must have a length >= mapSize().
     *
     * @param dst the destination buffer to read into
     */
    void readInto(byte[] dst);

    /**
     * Clears the bitmap (sets all bytes to 0).
     * Optional operation, may not be supported by all implementations.
     */
    default void clear() {
        // Default: no-op
    }

    /**
     * Checks if the bitmap source is attached and ready.
     *
     * @return true if ready to read
     */
    boolean isAttached();

    @Override
    void close();
}
