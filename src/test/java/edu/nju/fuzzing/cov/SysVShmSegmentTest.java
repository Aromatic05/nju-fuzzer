package edu.nju.fuzzing.cov;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;

import static org.junit.jupiter.api.Assertions.*;

class SysVShmSegmentTest {

    @Test
    void createWithInvalidSizeThrows() {
        assertThrows(IllegalArgumentException.class, () -> SysVShmSegment.create(0));
        assertThrows(IllegalArgumentException.class, () -> SysVShmSegment.create(-1));
    }

    @Test
    void closeSwallowsNativeErrors() throws Exception {
        // Use reflection to construct an instance without calling native shmget
        Constructor<SysVShmSegment> ctor = SysVShmSegment.class.getDeclaredConstructor(int.class, int.class);
        ctor.setAccessible(true);
        SysVShmSegment seg = ctor.newInstance(-99999, 128);

        // close() should not throw even if underlying native call would fail
        assertDoesNotThrow(seg::close);
    }
}
