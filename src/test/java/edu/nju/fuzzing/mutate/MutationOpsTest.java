package edu.nju.fuzzing.mutate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * 验证 MutationOps 底层算子的正确性
 */
class MutationOpsTest {

    private final byte[] data = "Hello World, this is a fuzzing test string.".getBytes();

    @Test
    void testFlipBit_ShouldChangeOneBit() {
        byte[] mutated = MutationOps.flipBit(data);
        Assertions.assertEquals(data.length, mutated.length, "BitFlip 不应改变长度");
        Assertions.assertFalse(Arrays.equals(data, mutated), "变异后内容应不同");

        // 验证是否只改变了 1 个 bit (Hamming Distance)
        int diffBits = 0;
        for (int i = 0; i < data.length; i++) {
            diffBits += Integer.bitCount(data[i] ^ mutated[i]);
        }
        Assertions.assertEquals(1, diffBits, "BitFlip 应该只翻转 1 个位");
    }

    @Test
    void testFlipByte_ShouldChangeOneByte() {
        byte[] mutated = MutationOps.flipByte(data);
        Assertions.assertEquals(data.length, mutated.length);

        int diffBytes = 0;
        for (int i = 0; i < data.length; i++) {
            if (data[i] != mutated[i]) diffBytes++;
        }
        Assertions.assertEquals(1, diffBytes, "ByteFlip 应该只改变 1 个字节");
    }

    @Test
    void testArithByte_ShouldSmallChange() {
        byte[] zeros = new byte[]{10, 10, 10};
        byte[] mutated = MutationOps.arithByte(zeros);

        Assertions.assertFalse(Arrays.equals(zeros, mutated));
        int diffIdx = -1;
        for(int i=0; i<zeros.length; i++) {
            if (zeros[i] != mutated[i]) diffIdx = i;
        }
        Assertions.assertTrue(diffIdx != -1);

        int diff = Math.abs(zeros[diffIdx] - mutated[diffIdx]);
        // 变异范围是加减 1-35
        Assertions.assertTrue(diff >= 1 && diff <= 35, "算术变异幅度应在 1-35 之间 (忽略溢出情况)");
    }

    @RepeatedTest(10)
    void testSetInteresting_ShouldInsertMagicValues() {
        // 由于是随机替换 8/16/32 位，我们验证数据确实变了
        byte[] mutated = MutationOps.setInteresting(data);
        Assertions.assertFalse(Arrays.equals(data, mutated));
        Assertions.assertEquals(data.length, mutated.length);
    }

    @Test
    void testDeleteBlock_ShouldReduceLength() {
        byte[] mutated = MutationOps.deleteBlock(data);
        Assertions.assertTrue(mutated.length < data.length, "删除块后长度应变小");
        Assertions.assertTrue(mutated.length > 0, "不应删成空 (除非原数据很小)");
    }

    @Test
    void testInsertBlock_ShouldIncreaseLength() {
        byte[] mutated = MutationOps.insertBlock(data);
        Assertions.assertTrue(mutated.length > data.length, "插入块后长度应变大");
    }

    @Test
    void testOverwriteBlock_ShouldKeepLength() {
        byte[] mutated = MutationOps.overwriteBlock(data);
        Assertions.assertEquals(data.length, mutated.length, "覆写块不应改变长度");
        Assertions.assertFalse(Arrays.equals(data, mutated), "内容应发生变化");
    }

    @Test
    void testEmptyInput_ShouldHandleGracefully() {
        byte[] empty = new byte[0];
        Assertions.assertArrayEquals(empty, MutationOps.flipBit(empty));
        Assertions.assertArrayEquals(empty, MutationOps.deleteBlock(empty));
        // Insert 可能会增加长度，取决于实现，通常 Insert 对空输入也能工作
        byte[] inserted = MutationOps.insertBlock(empty);
        Assertions.assertTrue(inserted.length >= 0);
    }

    @Test
    void testSmallInput_DeleteBlock() {
        byte[] small = new byte[]{1};
        // 长度为1时，deleteBlock 可能不操作或删成空
        byte[] mutated = MutationOps.deleteBlock(small);
        Assertions.assertTrue(mutated.length <= 1);
    }

    @Test
    void testSanityCheck_InterestingValues() {
        // 验证 MutationOps 内部并没有抛出异常
        for (int i = 0; i < 100; i++) {
            MutationOps.setInteresting(data);
        }
    }
    // === 新增测试样例 ===

    private final byte[] token = "TEST".getBytes(StandardCharsets.UTF_8);
    @Test
    void testOverwriteToken_ShouldReplaceBytes() {
        // data: Hello World (11 bytes)
        // token: TEST (4 bytes)
        byte[] mutated = MutationOps.overwriteToken(data, token);

        Assertions.assertEquals(data.length, mutated.length, "OverwriteToken 不应改变长度");
        String s = new String(mutated);
        // 应该包含 "TEST"
        Assertions.assertTrue(s.contains("TEST"), "结果中应包含 Token");
    }

    @Test
    void testOverwriteToken_DataTooShort() {
        // 只有 1 个字节，塞不进 4 个字节的 Token
        byte[] smallData = new byte[]{'A'};
        byte[] mutated = MutationOps.overwriteToken(smallData, token);

        // 期望：原样返回，不报错
        Assertions.assertArrayEquals(smallData, mutated);
    }

    @Test
    void testInsertToken_ShouldIncreaseLength() {
        byte[] mutated = MutationOps.insertToken(data, token);

        Assertions.assertEquals(data.length + token.length, mutated.length, "InsertToken 后长度应增加");
        String s = new String(mutated);
        Assertions.assertTrue(s.contains("TEST"));
    }

    @Test
    void testInsertToken_IntoEmpty() {
        byte[] empty = new byte[0];
        byte[] mutated = MutationOps.insertToken(empty, token);

        Assertions.assertArrayEquals(token, mutated, "插入空数组应等于 Token 本身");
    }

    @Test
    void testTokenSanity() {
        // 验证大量随机调用不会抛出 IndexOutOfBoundsException
        for (int i = 0; i < 100; i++) {
            MutationOps.overwriteToken(data, token);
            MutationOps.insertToken(data, token);
        }
    }
}