package edu.nju.fuzzing.mutate.binary;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * StructureMutator 单元测试
 * 
 * 验证点：
 * 1. 长度字段变异
 * 2. 偏移字段变异
 * 3. 计数字段变异
 * 4. 标志字段变异
 * 5. 块操作 (删除/复制/交换)
 * 6. 位翻转
 */
class StructureMutatorTest {

    private ThreadLocalRandom rand;

    @BeforeEach
    void setUp() {
        rand = ThreadLocalRandom.current();
    }

    // ==========================================
    // 长度字段变异测试
    // ==========================================

    @Test
    @DisplayName("mutateLength() - 变异长度字段")
    void testMutateLength() {
        byte[] data = new byte[100];
        ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).putInt(0, 50);

        FieldMapping field = new FieldMapping(0, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "test_length", 50);

        byte[] result = StructureMutator.mutateLength(data, field, rand);

        // 值应该被改变
        int newValue = ByteBuffer.wrap(result).order(ByteOrder.BIG_ENDIAN).getInt(0);
        // 大多数情况下值会改变（除非随机到了相同值）
        assertNotNull(result);
        assertEquals(data.length, result.length);
    }

    @Test
    @DisplayName("mutateLength() - 多次变异产生不同结果")
    void testMutateLengthDiversity() {
        byte[] data = new byte[100];
        ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).putInt(0, 50);

        FieldMapping field = new FieldMapping(0, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "test_length", 50);

        java.util.Set<Integer> values = new java.util.HashSet<>();
        for (int i = 0; i < 100; i++) {
            byte[] result = StructureMutator.mutateLength(data.clone(), field, rand);
            int value = ByteBuffer.wrap(result).order(ByteOrder.BIG_ENDIAN).getInt(0);
            values.add(value);
        }

        // 应该产生多种不同的值
        assertTrue(values.size() > 5, "应该产生多种不同的长度值");
    }

    // ==========================================
    // 偏移字段变异测试
    // ==========================================

    @Test
    @DisplayName("mutateOffset() - 变异偏移字段")
    void testMutateOffset() {
        byte[] data = new byte[100];
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putInt(0, 50);

        FieldMapping field = new FieldMapping(0, 4, FieldType.OFFSET, ByteOrder.LITTLE_ENDIAN, "test_offset", 50);

        byte[] result = StructureMutator.mutateOffset(data, field, rand);

        assertNotNull(result);
        assertEquals(data.length, result.length);
    }

    @Test
    @DisplayName("mutateOffset() - 可能产生越界偏移")
    void testMutateOffsetOob() {
        byte[] data = new byte[100];
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putInt(0, 50);

        FieldMapping field = new FieldMapping(0, 4, FieldType.OFFSET, ByteOrder.LITTLE_ENDIAN, "test_offset", 50);

        boolean foundOob = false;
        for (int i = 0; i < 100; i++) {
            byte[] result = StructureMutator.mutateOffset(data.clone(), field, rand);
            int value = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).getInt(0);
            if (value < 0 || value > data.length) {
                foundOob = true;
                break;
            }
        }

        // 应该有概率产生越界偏移
        assertTrue(foundOob, "应该能产生越界偏移值");
    }

    // ==========================================
    // 计数字段变异测试
    // ==========================================

    @Test
    @DisplayName("mutateCount() - 变异计数字段")
    void testMutateCount() {
        byte[] data = new byte[100];
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putShort(0, (short) 5);

        FieldMapping field = new FieldMapping(0, 2, FieldType.COUNT, ByteOrder.LITTLE_ENDIAN, "test_count", 5);

        byte[] result = StructureMutator.mutateCount(data, field, rand);

        assertNotNull(result);
        assertEquals(data.length, result.length);
    }

    @Test
    @DisplayName("mutateCount() - 可能产生极端值")
    void testMutateCountExtremeValues() {
        byte[] data = new byte[100];

        FieldMapping field = new FieldMapping(0, 2, FieldType.COUNT, ByteOrder.LITTLE_ENDIAN, "test_count", 5);

        java.util.Set<Integer> values = new java.util.HashSet<>();
        for (int i = 0; i < 100; i++) {
            byte[] result = StructureMutator.mutateCount(data.clone(), field, rand);
            int value = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).getShort(0) & 0xFFFF;
            values.add(value);
        }

        // 应该包含 0 或 0xFFFF 等极端值
        assertTrue(values.contains(0) || values.contains(0xFFFF), "应该产生极端值");
    }

    // ==========================================
    // 标志字段变异测试
    // ==========================================

    @Test
    @DisplayName("mutateFlags() - 变异标志字段")
    void testMutateFlags() {
        byte[] data = new byte[100];
        data[0] = 0x0F;

        FieldMapping field = new FieldMapping(0, 1, FieldType.FLAGS, ByteOrder.BIG_ENDIAN, "test_flags");

        byte[] result = StructureMutator.mutateFlags(data, field, rand);

        assertNotNull(result);
        assertEquals(data.length, result.length);
    }

    @Test
    @DisplayName("mutateFlags() - 产生多种模式")
    void testMutateFlagsPatterns() {
        byte[] data = new byte[100];
        data[0] = 0x0F;

        FieldMapping field = new FieldMapping(0, 1, FieldType.FLAGS, ByteOrder.BIG_ENDIAN, "test_flags");

        java.util.Set<Byte> values = new java.util.HashSet<>();
        for (int i = 0; i < 100; i++) {
            byte[] result = StructureMutator.mutateFlags(data.clone(), field, rand);
            values.add(result[0]);
        }

        // 应该产生多种不同的标志值
        assertTrue(values.size() > 3, "应该产生多种不同的标志值");
    }

    // ==========================================
    // 块操作测试
    // ==========================================

    @Test
    @DisplayName("deleteChunk() - 删除非关键块")
    void testDeleteNonCriticalChunk() {
        byte[] data = "AABBBBCC".getBytes();

        byte[] chunkData = "BBBB".getBytes();
        BinaryChunk chunk = new BinaryChunk(2, 4, "TEST", chunkData);
        chunk.setCritical(false);

        byte[] result = StructureMutator.deleteChunk(data, chunk);

        assertEquals(4, result.length);
        assertEquals("AACC", new String(result));
    }

    @Test
    @DisplayName("deleteChunk() - 关键块只清空数据")
    void testDeleteCriticalChunk() {
        byte[] data = "AABBBBCC".getBytes();

        byte[] chunkData = "BBBB".getBytes();
        BinaryChunk chunk = new BinaryChunk(2, 4, "TEST", chunkData);
        chunk.setCritical(true);
        chunk.setDataOffset(0);
        chunk.setDataLength(4);

        byte[] result = StructureMutator.deleteChunk(data, chunk);

        // 长度不变，但数据被清空
        assertEquals(8, result.length);
        assertEquals("AA\0\0\0\0CC", new String(result));
    }

    @Test
    @DisplayName("duplicateChunk() - 复制块")
    void testDuplicateChunk() {
        byte[] data = "AABBCC".getBytes();

        byte[] chunkData = "BB".getBytes();
        BinaryChunk chunk = new BinaryChunk(2, 2, "TEST", chunkData);

        byte[] result = StructureMutator.duplicateChunk(data, chunk);

        assertEquals(8, result.length);
        assertEquals("AABBBBCC", new String(result));
    }

    @Test
    @DisplayName("duplicateChunk() - 复制多次")
    void testDuplicateChunkMultipleTimes() {
        byte[] data = "AABBCC".getBytes();

        byte[] chunkData = "BB".getBytes();
        BinaryChunk chunk = new BinaryChunk(2, 2, "TEST", chunkData);

        byte[] result = StructureMutator.duplicateChunk(data, chunk, 3);

        assertEquals(12, result.length);
        assertEquals("AABBBBBBBBCC", new String(result));
    }

    @Test
    @DisplayName("swapChunks() - 交换两个块")
    void testSwapChunks() {
        byte[] data = "AABBXXCC".getBytes();

        byte[] chunk1Data = "BB".getBytes();
        BinaryChunk chunk1 = new BinaryChunk(2, 2, "TEST1", chunk1Data);

        byte[] chunk2Data = "CC".getBytes();
        BinaryChunk chunk2 = new BinaryChunk(6, 2, "TEST2", chunk2Data);

        byte[] result = StructureMutator.swapChunks(data, chunk1, chunk2);

        assertEquals(8, result.length);
        assertEquals("AACCXXBB", new String(result));
    }

    @Test
    @DisplayName("swapChunks() - 重叠块不交换")
    void testSwapOverlappingChunks() {
        byte[] data = "AABBCC".getBytes();

        byte[] chunk1Data = "ABBC".getBytes();
        BinaryChunk chunk1 = new BinaryChunk(1, 4, "TEST1", chunk1Data);

        byte[] chunk2Data = "CC".getBytes();
        BinaryChunk chunk2 = new BinaryChunk(4, 2, "TEST2", chunk2Data);

        byte[] result = StructureMutator.swapChunks(data, chunk1, chunk2);

        // 重叠时返回原数据
        assertArrayEquals(data, result);
    }

    // ==========================================
    // 位翻转测试
    // ==========================================

    @Test
    @DisplayName("bitFlipDataRegion() - 翻转数据位")
    void testBitFlipDataRegion() {
        byte[] data = new byte[100];

        byte[] result = StructureMutator.bitFlipDataRegion(data, 10, 50, rand);

        assertNotNull(result);
        assertEquals(data.length, result.length);

        // 至少有一位被翻转
        boolean hasDifference = false;
        for (int i = 10; i < 60; i++) {
            if (result[i] != data[i]) {
                hasDifference = true;
                break;
            }
        }
        assertTrue(hasDifference, "应该至少翻转一位");

        // 范围外的数据不变
        for (int i = 0; i < 10; i++) {
            assertEquals(data[i], result[i], "范围外数据不应改变");
        }
        for (int i = 60; i < 100; i++) {
            assertEquals(data[i], result[i], "范围外数据不应改变");
        }
    }

    @Test
    @DisplayName("randomizeRegion() - 随机化区域")
    void testRandomizeRegion() {
        byte[] data = new byte[100];

        byte[] result = StructureMutator.randomizeRegion(data, 10, 20, rand);

        assertNotNull(result);
        assertEquals(data.length, result.length);

        // 范围外的数据不变
        for (int i = 0; i < 10; i++) {
            assertEquals(data[i], result[i]);
        }
        for (int i = 30; i < 100; i++) {
            assertEquals(data[i], result[i]);
        }
    }

    // ==========================================
    // 辅助方法测试
    // ==========================================

    @Test
    @DisplayName("writeInteger() - 写入整数")
    void testWriteInteger() {
        byte[] data = new byte[8];

        StructureMutator.writeInteger(data, 0, 4, 0x12345678, ByteOrder.BIG_ENDIAN);
        assertEquals(0x12345678, ByteBuffer.wrap(data, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt());

        StructureMutator.writeInteger(data, 4, 4, 0x12345678, ByteOrder.LITTLE_ENDIAN);
        assertEquals(0x12345678, ByteBuffer.wrap(data, 4, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
    }

    @Test
    @DisplayName("readInteger() - 读取整数")
    void testReadInteger() {
        byte[] data = new byte[8];
        ByteBuffer.wrap(data, 0, 4).order(ByteOrder.BIG_ENDIAN).putInt(0x12345678);
        ByteBuffer.wrap(data, 4, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(0x12345678);

        assertEquals(0x12345678, StructureMutator.readInteger(data, 0, 4, ByteOrder.BIG_ENDIAN));
        assertEquals(0x12345678, StructureMutator.readInteger(data, 4, 4, ByteOrder.LITTLE_ENDIAN));
    }

    @Test
    @DisplayName("selectRandomChunk() - 选择随机块")
    void testSelectRandomChunk() {
        List<BinaryChunk> chunks = new ArrayList<>();
        chunks.add(new BinaryChunk(0, 10, "A", new byte[10]));
        chunks.add(new BinaryChunk(10, 10, "B", new byte[10]));
        chunks.get(0).setCritical(true);
        chunks.get(1).setCritical(false);

        // 测试优先选择非关键块
        int nonCriticalCount = 0;
        for (int i = 0; i < 100; i++) {
            BinaryChunk selected = StructureMutator.selectRandomChunk(chunks, true, rand);
            if (!selected.isCritical()) {
                nonCriticalCount++;
            }
        }

        // 大多数情况应该选择非关键块
        assertTrue(nonCriticalCount > 80, "应该优先选择非关键块");
    }
}
