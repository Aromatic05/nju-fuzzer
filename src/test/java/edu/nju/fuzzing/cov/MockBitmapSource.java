package edu.nju.fuzzing.cov;

/**
 * A mock BitmapSource implementation for testing purposes.
 * Allows setting bitmap data programmatically without actual shared memory.
 */
public class MockBitmapSource implements BitmapSource {

    private final int mapSize;
    private final byte[] bitmap;
    private boolean attached;

    public MockBitmapSource(int mapSize) {
        this.mapSize = mapSize;
        this.bitmap = new byte[mapSize];
        this.attached = true;
    }

    @Override
    public int mapSize() {
        return mapSize;
    }

    @Override
    public void readInto(byte[] dst) {
        if (!attached) {
            throw new IllegalStateException("Not attached");
        }
        System.arraycopy(bitmap, 0, dst, 0, Math.min(mapSize, dst.length));
    }

    @Override
    public void clear() {
        java.util.Arrays.fill(bitmap, (byte) 0);
    }

    @Override
    public boolean isAttached() {
        return attached;
    }

    @Override
    public void close() {
        attached = false;
    }

    /**
     * Sets a byte value at the specified index.
     */
    public void setByte(int index, int value) {
        if (index >= 0 && index < mapSize) {
            bitmap[index] = (byte) value;
        }
    }

    /**
     * Sets multiple bytes at once.
     */
    public void setBytes(int... indexValuePairs) {
        for (int i = 0; i + 1 < indexValuePairs.length; i += 2) {
            setByte(indexValuePairs[i], indexValuePairs[i + 1]);
        }
    }

    /**
     * Gets the underlying bitmap for inspection.
     */
    public byte[] getBitmap() {
        return bitmap.clone();
    }
}
