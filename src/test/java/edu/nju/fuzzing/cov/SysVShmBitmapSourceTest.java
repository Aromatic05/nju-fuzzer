package edu.nju.fuzzing.cov;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SysVShmBitmapSourceTest {

    // Test double to avoid invoking native JNA functions
    private static final class LocalSysV extends SysVShmBitmapSource {
        private final byte[] bitmap;
        private boolean attached = false;

        LocalSysV(int shmId, int mapSize) {
            super(shmId, mapSize);
            this.bitmap = new byte[mapSize];
        }

        @Override
        public void attach() {
            attached = true;
        }

        @Override
        public boolean isAttached() {
            return attached;
        }

        @Override
        public void readInto(byte[] dst) {
            System.arraycopy(bitmap, 0, dst, 0, Math.min(dst.length, bitmap.length));
        }

        @Override
        public void clear() {
            java.util.Arrays.fill(bitmap, (byte) 0);
        }

        @Override
        public void close() {
            attached = false;
        }

        void setByte(int idx, int val) {
            bitmap[idx] = (byte) val;
        }

        byte[] getBitmap() { return bitmap.clone(); }
    }

    @Test
    void constructorRejectsInvalidSize() {
        assertThrows(IllegalArgumentException.class, () -> new SysVShmBitmapSource(1, 0));
        assertThrows(IllegalArgumentException.class, () -> new SysVShmBitmapSource(1, -5));
    }

    @Test
    void attachReadClearCloseFlow() {
        LocalSysV src = new LocalSysV(42, 64);
        assertFalse(src.isAttached());

        src.attach();
        assertTrue(src.isAttached());

        src.setByte(0, 7);
        src.setByte(10, 11);

        byte[] buf = new byte[64];
        src.readInto(buf);

        assertEquals(7, buf[0] & 0xFF);
        assertEquals(11, buf[10] & 0xFF);

        src.clear();
        byte[] buf2 = new byte[64];
        src.readInto(buf2);
        for (byte b : buf2) {
            assertEquals(0, b & 0xFF);
        }

        src.close();
        assertFalse(src.isAttached());
    }
}
