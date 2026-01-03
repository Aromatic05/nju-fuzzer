package edu.nju.fuzzing.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * SeedTypeTest
 * NOTE: SeedType.detect() 已按设计移除；同一次 run 的类型由 CLI 统一指定。
 */
class SeedTypeTest {
    @Test
    @DisplayName("SeedType.valueOf should work")
    void valueOf_shouldParseEnumNames() {
        Assertions.assertEquals(SeedType.XML, SeedType.valueOf("XML"));
        Assertions.assertEquals(SeedType.UNKNOWN, SeedType.valueOf("UNKNOWN"));
    }

    @Test
    @DisplayName("SeedType should include UNKNOWN")
    void shouldContainUnknown() {
        boolean found = false;
        for (SeedType t : SeedType.values()) {
            if (t == SeedType.UNKNOWN) {
                found = true;
                break;
            }
        }
        Assertions.assertTrue(found);
    }
}