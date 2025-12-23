package edu.nju.fuzzing.mutate;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class MutationOpsTest {

    // 辅助方法：检查数组包含
    private boolean containsSubArray(byte[] source, byte[] sub) {
        if (sub.length == 0) return true;
        for (int i = 0; i <= source.length - sub.length; i++) {
            boolean match = true;
            for (int j = 0; j < sub.length; j++) {
                if (source[i + j] != sub[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    // ==========================================
    // 第一类：原地变异测试 (In-Place Mutation)
    // ==========================================

    @Test
    @DisplayName("Test 1: flipBit - 应该改变原数组内容且保持长度不变")
    void testFlipBit() {
        byte[] original = {0, 0, 0, 0};
        byte[] data = original.clone();

        MutationOps.flipBit(data);

        assertEquals(original.length, data.length, "长度不应改变");
        assertFalse(Arrays.equals(original, data), "位翻转后数据应发生变化");
    }

    @Test
    @DisplayName("Test 2: flipByte - 应该对字节进行异或操作")
    void testFlipByte() {
        byte[] data = {0x00}; // 0000 0000
        MutationOps.flipByte(data);
        // 0x00 ^ 0xFF = 0xFF (-1)
        assertEquals((byte) 0xFF, data[0], "0x00 flip 应该是 0xFF");
    }

    @Test
    @DisplayName("Test 3: arithByte/Short/Int - 算术运算应改变数值")
    void testArithOps() {
        // Arith Byte
        byte[] dataB = {10};
        byte[] copyB = dataB.clone();
        MutationOps.arithByte(dataB);
        assertNotEquals(copyB[0], dataB[0], "ArithByte 应该改变数值");

        // Arith Short (需至少2字节)
        byte[] dataS = {0, 0, 0, 0};
        byte[] copyS = dataS.clone();
        MutationOps.arithShort(dataS);
        assertFalse(Arrays.equals(copyS, dataS), "ArithShort 应该改变数组内容");

        // Arith Int (需至少4字节)
        byte[] dataI = {0, 0, 0, 0, 0, 0};
        byte[] copyI = dataI.clone();
        MutationOps.arithInt(dataI);
        assertFalse(Arrays.equals(copyI, dataI), "ArithInt 应该改变数组内容");
    }

    @Test
    @DisplayName("Test 4: swapBytes - 交换后元素集合不变(Sum不变)")
    void testSwapBytes() {
        byte[] data = {1, 2, 3, 4, 5};
        long sumBefore = 0;
        for (byte b : data) sumBefore += b;

        // 多次运行以确保覆盖随机逻辑
        for (int i = 0; i < 5; i++) {
            MutationOps.swapBytes(data);
        }

        long sumAfter = 0;
        for (byte b : data) sumAfter += b;

        assertEquals(sumBefore, sumAfter, "交换字节不应改变字节总和");
    }

    @Test
    @DisplayName("Test 5: setInteresting - 应该将值修改为预定义的魔法数")
    void testSetInteresting() {
        byte[] data = {0, 0, 0, 0};
        // 运行多次增加命中不同 interesting value 的概率
        boolean changed = false;
        for (int i = 0; i < 10; i++) {
            byte[] attempt = data.clone();
            MutationOps.setInteresting(attempt);
            if (!Arrays.equals(data, attempt)) {
                changed = true;
                break;
            }
        }
        assertTrue(changed, "SetInteresting 应该修改数组内容");
    }

    @Test
    @DisplayName("Test 6: overwriteBlock - 应该覆盖一段数据")
    void testOverwriteBlock() {
        byte[] data = new byte[100]; // 全0
        MutationOps.overwriteBlock(data);

        boolean hasNonZero = false;
        for (byte b : data) {
            if (b != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "OverwriteBlock 应该引入非零数据");
    }

    @Test
    @DisplayName("Test 7: overwriteToken - 应该包含指定的 Token")
    void testOverwriteToken() {
        byte[] data = {0, 0, 0, 0, 0, 0};
        byte[] token = {1, 2, 3}; // 长度小于 data

        MutationOps.overwriteToken(data, token);

        assertTrue(containsSubArray(data, token), "数组应包含被覆写的 Token");
        assertEquals(6, data.length, "覆写不应改变数组长度");
    }

    // ==========================================
    // 第二类：结构变异测试 (Structural Mutation)
    // ==========================================

    @Test
    @DisplayName("Test 8: deleteBlock - 数组长度应变短")
    void testDeleteBlock() {
        byte[] data = {1, 2, 3, 4, 5, 6, 7, 8};
        byte[] mutated = MutationOps.deleteBlock(data);

        assertTrue(mutated.length < data.length, "删除块后长度应减小");
        assertNotSame(data, mutated, "结构变异应返回新对象");
    }

    @Test
    @DisplayName("Test 9: insertBlock - 数组长度应变长")
    void testInsertBlock() {
        byte[] data = {1, 2, 3};
        byte[] mutated = MutationOps.insertBlock(data);

        assertTrue(mutated.length > data.length, "插入块后长度应增加");
    }

    @Test
    @DisplayName("Test 10: cloneBlock - 数组长度应变长且包含重复数据")
    void testCloneBlock() {
        byte[] data = {1, 2, 3, 4};
        byte[] mutated = MutationOps.cloneBlock(data);

        assertTrue(mutated.length > data.length, "克隆块插入后长度应增加");

        // 验证原数据依然存在（虽然位置可能变了）
        // 这是一个宽松检查
        int foundCount = 0;
        for (byte b : data) {
            for (byte m : mutated) {
                if (b == m) {
                    foundCount++;
                    break;
                }
            }
        }
        assertEquals(data.length, foundCount, "原数据的所有元素应仍存在于变异后的数组中");
    }

    @Test
    @DisplayName("Test 11: insertToken - 长度增加且包含Token")
    void testInsertToken() {
        byte[] data = {9, 9, 9};
        byte[] token = {1, 1};

        byte[] mutated = MutationOps.insertToken(data, token);

        assertEquals(data.length + token.length, mutated.length, "长度应为 原长度+Token长度");
        assertTrue(containsSubArray(mutated, token), "变异后的数组应包含插入的 Token");
    }

    // ==========================================
    // 第三类：边界情况与健壮性测试
    // ==========================================

    @Test
    @DisplayName("Test 12: Empty Array Handling - 空数组不应抛出异常")
    void testEmptyArrayRobustness() {
        byte[] empty = new byte[0];

        // 验证所有 In-Place 操作不抛异常
        assertDoesNotThrow(() -> MutationOps.flipBit(empty));
        assertDoesNotThrow(() -> MutationOps.flipByte(empty));
        assertDoesNotThrow(() -> MutationOps.arithByte(empty));
        assertDoesNotThrow(() -> MutationOps.arithShort(empty));
        assertDoesNotThrow(() -> MutationOps.arithInt(empty));
        assertDoesNotThrow(() -> MutationOps.swapBytes(empty));
        assertDoesNotThrow(() -> MutationOps.setInteresting(empty));
        assertDoesNotThrow(() -> MutationOps.overwriteBlock(empty));
        assertDoesNotThrow(() -> MutationOps.overwriteToken(empty, new byte[]{1}));

        // 验证所有 Structural 操作不抛异常且逻辑合理
        assertDoesNotThrow(() -> {
            byte[] res = MutationOps.deleteBlock(empty);
            assertEquals(0, res.length); // 空数组删无可删
        });

        assertDoesNotThrow(() -> {
            byte[] res = MutationOps.insertBlock(empty);
            assertTrue(res.length > 0); // 空数组插入后变长
        });

        assertDoesNotThrow(() -> {
            byte[] res = MutationOps.insertToken(empty, new byte[]{1, 2});
            assertArrayEquals(new byte[]{1, 2}, res); // 空数组插入Token等于Token
        });
    }

    @Test
    @DisplayName("Test 13: Small Array Fallback - 短数组算术运算自动降级")
    void testSmallArrayFallback() {
        // 测试 arithShort 在长度为 1 的数组上是否安全（应降级为 arithByte）
        byte[] oneByte = {10};
        byte[] copy = oneByte.clone();

        MutationOps.arithShort(oneByte); // 应该不报错
        assertNotEquals(copy[0], oneByte[0], "长度不足时应降级处理并成功修改");

        // 测试 arithInt 在长度为 3 的数组上是否安全（应降级）
        byte[] threeBytes = {1, 2, 3};
        byte[] copy3 = threeBytes.clone();

        MutationOps.arithInt(threeBytes); // 应该不报错
        assertFalse(Arrays.equals(copy3, threeBytes), "长度不足时应降级处理并成功修改");
    }
}