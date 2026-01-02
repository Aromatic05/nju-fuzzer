package edu.nju.fuzzing.mutate.binary;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * 二进制数据类单元测试
 * 
 * 覆盖: BinaryChunk, FieldMapping, ScanResult
 */
class BinaryDataClassesTest {

    // ==========================================
    // FieldMapping 测试
    // ==========================================

    @Nested
    @DisplayName("FieldMapping 测试")
    class FieldMappingTests {

        @Test
        @DisplayName("基础构造和 getter")
        void testBasicConstruction() {
            FieldMapping field = new FieldMapping(10, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "length_field");

            assertEquals(10, field.getOffset());
            assertEquals(4, field.getLength());
            assertEquals(FieldType.LENGTH, field.getType());
            assertEquals(ByteOrder.BIG_ENDIAN, field.getByteOrder());
            assertEquals("length_field", field.getName());
            assertEquals(0, field.getOriginalValue()); // 默认值
        }

        @Test
        @DisplayName("带原始值构造")
        void testConstructionWithValue() {
            FieldMapping field = new FieldMapping(0, 8, FieldType.OFFSET, ByteOrder.LITTLE_ENDIAN, "ptr", 0x12345678L);

            assertEquals(0x12345678L, field.getOriginalValue());
            assertEquals(8, field.getEndOffset());
        }

        @Test
        @DisplayName("getEndOffset 计算")
        void testEndOffset() {
            FieldMapping field = new FieldMapping(100, 16, FieldType.DATA, ByteOrder.BIG_ENDIAN, "data");
            assertEquals(116, field.getEndOffset());
        }

        @Test
        @DisplayName("contains 边界检查")
        void testContains() {
            FieldMapping field = new FieldMapping(10, 4, FieldType.CHECKSUM, ByteOrder.BIG_ENDIAN, "crc");

            assertFalse(field.contains(9)); // 之前
            assertTrue(field.contains(10)); // 起始
            assertTrue(field.contains(11)); // 中间
            assertTrue(field.contains(13)); // 结束前
            assertFalse(field.contains(14)); // 结束后
        }

        @Test
        @DisplayName("overlaps 重叠检查")
        void testOverlaps() {
            FieldMapping field = new FieldMapping(10, 4, FieldType.MAGIC, ByteOrder.BIG_ENDIAN, "magic");
            // field 范围: [10, 14)

            assertTrue(field.overlaps(8, 12)); // 部分重叠（前）
            assertTrue(field.overlaps(12, 16)); // 部分重叠（后）
            assertTrue(field.overlaps(10, 14)); // 完全重叠
            assertTrue(field.overlaps(11, 13)); // 包含
            assertTrue(field.overlaps(8, 20)); // 被包含
            assertFalse(field.overlaps(0, 10)); // 之前不重叠
            assertFalse(field.overlaps(14, 20)); // 之后不重叠
        }

        @Test
        @DisplayName("toString 格式")
        void testToString() {
            FieldMapping field = new FieldMapping(10, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "len", 100);
            String str = field.toString();

            assertTrue(str.contains("len"));
            assertTrue(str.contains("LENGTH"));
            assertTrue(str.contains("10"));
        }

        @Test
        @DisplayName("所有 FieldType 类型")
        void testAllFieldTypes() {
            for (FieldType type : FieldType.values()) {
                FieldMapping field = new FieldMapping(0, 4, type, ByteOrder.BIG_ENDIAN, type.name());
                assertEquals(type, field.getType());
            }
        }
    }

    // ==========================================
    // BinaryChunk 测试
    // ==========================================

    @Nested
    @DisplayName("BinaryChunk 测试")
    class BinaryChunkTests {

        @Test
        @DisplayName("基础构造和 getter")
        void testBasicConstruction() {
            byte[] data = { 0x00, 0x01, 0x02, 0x03 };
            BinaryChunk chunk = new BinaryChunk(100, 50, "IHDR", data);

            assertEquals(100, chunk.getStartOffset());
            assertEquals(50, chunk.getTotalLength());
            assertEquals(150, chunk.getEndOffset());
            assertEquals("IHDR", chunk.getChunkType());
            assertEquals(data, chunk.getRawData());
            assertFalse(chunk.isCritical()); // 默认值
            assertFalse(chunk.hasChecksum()); // 默认值
        }

        @Test
        @DisplayName("critical 属性")
        void testCriticalProperty() {
            BinaryChunk chunk = new BinaryChunk(0, 10, "IEND", new byte[10]);

            assertFalse(chunk.isCritical());
            chunk.setCritical(true);
            assertTrue(chunk.isCritical());
        }

        @Test
        @DisplayName("checksum 属性")
        void testChecksumProperty() {
            BinaryChunk chunk = new BinaryChunk(0, 20, "IDAT", new byte[20]);

            assertFalse(chunk.hasChecksum());
            assertEquals(-1, chunk.getChecksumOffset());

            chunk.setChecksumOffset(16);
            assertTrue(chunk.hasChecksum());
            assertEquals(16, chunk.getChecksumOffset());

            // 设置 hasChecksum 为 false
            chunk.setHasChecksum(false);
            assertFalse(chunk.hasChecksum());
        }

        @Test
        @DisplayName("dataOffset 和 dataLength")
        void testDataProperties() {
            BinaryChunk chunk = new BinaryChunk(0, 100, "DATA", new byte[100]);

            // 默认值
            assertEquals(0, chunk.getDataOffset());
            assertEquals(100, chunk.getDataLength());

            chunk.setDataOffset(8);
            chunk.setDataLength(80);
            assertEquals(8, chunk.getDataOffset());
            assertEquals(80, chunk.getDataLength());
        }

        @Test
        @DisplayName("getDataSection 获取数据区")
        void testGetDataSection() {
            byte[] raw = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
            BinaryChunk chunk = new BinaryChunk(0, 10, "TEST", raw);

            chunk.setDataOffset(2);
            chunk.setDataLength(5);

            byte[] data = chunk.getDataSection();
            assertEquals(5, data.length);
            assertEquals(0x02, data[0]);
            assertEquals(0x06, data[4]);
        }

        @Test
        @DisplayName("getDataSection 边界条件 - null 数据")
        void testGetDataSectionNullData() {
            BinaryChunk chunk = new BinaryChunk(0, 10, "TEST", null);
            byte[] data = chunk.getDataSection();
            assertEquals(0, data.length);
        }

        @Test
        @DisplayName("getDataSection 边界条件 - offset 超出范围")
        void testGetDataSectionOffsetOutOfRange() {
            byte[] raw = { 0x00, 0x01, 0x02 };
            BinaryChunk chunk = new BinaryChunk(0, 3, "TEST", raw);
            chunk.setDataOffset(10); // 超出范围

            byte[] data = chunk.getDataSection();
            assertEquals(0, data.length);
        }

        @Test
        @DisplayName("Field 管理")
        void testFieldManagement() {
            BinaryChunk chunk = new BinaryChunk(0, 50, "CHUNK", new byte[50]);

            assertTrue(chunk.getFields().isEmpty());

            FieldMapping f1 = new FieldMapping(0, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "len");
            FieldMapping f2 = new FieldMapping(4, 4, FieldType.MAGIC, ByteOrder.BIG_ENDIAN, "type");
            FieldMapping f3 = new FieldMapping(8, 4, FieldType.CHECKSUM, ByteOrder.BIG_ENDIAN, "crc");

            chunk.addField(f1);
            chunk.addField(f2);
            chunk.addField(f3);

            assertEquals(3, chunk.getFields().size());
        }

        @Test
        @DisplayName("getFieldsByType 按类型筛选")
        void testGetFieldsByType() {
            BinaryChunk chunk = new BinaryChunk(0, 50, "CHUNK", new byte[50]);

            chunk.addField(new FieldMapping(0, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "len1"));
            chunk.addField(new FieldMapping(4, 4, FieldType.MAGIC, ByteOrder.BIG_ENDIAN, "magic"));
            chunk.addField(new FieldMapping(8, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "len2"));

            List<FieldMapping> lengths = chunk.getFieldsByType(FieldType.LENGTH);
            assertEquals(2, lengths.size());

            List<FieldMapping> magics = chunk.getFieldsByType(FieldType.MAGIC);
            assertEquals(1, magics.size());

            List<FieldMapping> checksums = chunk.getFieldsByType(FieldType.CHECKSUM);
            assertEquals(0, checksums.size());
        }

        @Test
        @DisplayName("getFieldAt 按偏移查找")
        void testGetFieldAt() {
            BinaryChunk chunk = new BinaryChunk(0, 50, "CHUNK", new byte[50]);

            FieldMapping f1 = new FieldMapping(0, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "len");
            FieldMapping f2 = new FieldMapping(8, 8, FieldType.DATA, ByteOrder.BIG_ENDIAN, "data");

            chunk.addField(f1);
            chunk.addField(f2);

            assertEquals(f1, chunk.getFieldAt(0));
            assertEquals(f1, chunk.getFieldAt(2));
            assertNull(chunk.getFieldAt(5)); // 在字段之间
            assertEquals(f2, chunk.getFieldAt(10));
            assertNull(chunk.getFieldAt(20)); // 没有字段
        }

        @Test
        @DisplayName("toString 格式")
        void testToString() {
            BinaryChunk chunk = new BinaryChunk(100, 50, "IHDR", new byte[50]);
            chunk.setCritical(true);
            chunk.addField(new FieldMapping(0, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "len"));

            String str = chunk.toString();
            assertTrue(str.contains("IHDR"));
            assertTrue(str.contains("100"));
            assertTrue(str.contains("50"));
            assertTrue(str.contains("critical=true"));
            assertTrue(str.contains("fields=1"));
        }
    }

    // ==========================================
    // ScanResult 测试
    // ==========================================

    @Nested
    @DisplayName("ScanResult 测试")
    class ScanResultTests {

        private ScanResult createTestScanResult() {
            List<BinaryChunk> chunks = new ArrayList<>();
            BinaryChunk ihdr = new BinaryChunk(8, 25, "IHDR", new byte[25]);
            ihdr.setCritical(true);
            BinaryChunk idat = new BinaryChunk(33, 100, "IDAT", new byte[100]);
            idat.setCritical(true);
            BinaryChunk text = new BinaryChunk(133, 50, "tEXt", new byte[50]);
            BinaryChunk iend = new BinaryChunk(183, 12, "IEND", new byte[12]);
            iend.setCritical(true);

            chunks.add(ihdr);
            chunks.add(idat);
            chunks.add(text);
            chunks.add(iend);

            List<FieldMapping> globalFields = new ArrayList<>();
            globalFields.add(new FieldMapping(0, 8, FieldType.MAGIC, ByteOrder.BIG_ENDIAN, "png_magic"));

            return new ScanResult(true, "PNG", new byte[200], chunks, globalFields);
        }

        @Test
        @DisplayName("基础构造和 getter")
        void testBasicConstruction() {
            ScanResult result = createTestScanResult();

            assertTrue(result.isValid());
            assertEquals("PNG", result.getFormatType());
            assertNotNull(result.getOriginalData());
            assertEquals(4, result.getChunks().size());
            assertEquals(1, result.getGlobalFields().size());
        }

        @Test
        @DisplayName("byteOrder 属性")
        void testByteOrderProperty() {
            ScanResult result = createTestScanResult();

            // 默认值
            assertEquals(ByteOrder.BIG_ENDIAN, result.getByteOrder());

            result.setByteOrder(ByteOrder.LITTLE_ENDIAN);
            assertEquals(ByteOrder.LITTLE_ENDIAN, result.getByteOrder());
        }

        @Test
        @DisplayName("headerSize 属性")
        void testHeaderSizeProperty() {
            ScanResult result = createTestScanResult();

            assertEquals(0, result.getHeaderSize()); // 默认值

            result.setHeaderSize(64);
            assertEquals(64, result.getHeaderSize());
        }

        @Test
        @DisplayName("is64Bit 属性")
        void testIs64BitProperty() {
            ScanResult result = createTestScanResult();

            assertFalse(result.is64Bit()); // 默认值

            result.setIs64Bit(true);
            assertTrue(result.is64Bit());
        }

        @Test
        @DisplayName("findChunkByType 查找单个块")
        void testFindChunkByType() {
            ScanResult result = createTestScanResult();

            BinaryChunk ihdr = result.findChunkByType("IHDR");
            assertNotNull(ihdr);
            assertEquals("IHDR", ihdr.getChunkType());

            BinaryChunk notFound = result.findChunkByType("zTXt");
            assertNull(notFound);
        }

        @Test
        @DisplayName("findAllChunksByType 查找所有匹配块")
        void testFindAllChunksByType() {
            // 创建有多个相同类型块的结果
            List<BinaryChunk> chunks = new ArrayList<>();
            chunks.add(new BinaryChunk(0, 25, "IDAT", new byte[25]));
            chunks.add(new BinaryChunk(25, 30, "IDAT", new byte[30]));
            chunks.add(new BinaryChunk(55, 20, "tEXt", new byte[20]));
            chunks.add(new BinaryChunk(75, 25, "IDAT", new byte[25]));

            ScanResult result = new ScanResult(true, "PNG", new byte[100], chunks, new ArrayList<>());

            List<BinaryChunk> idats = result.findAllChunksByType("IDAT");
            assertEquals(3, idats.size());

            List<BinaryChunk> texts = result.findAllChunksByType("tEXt");
            assertEquals(1, texts.size());

            List<BinaryChunk> notFound = result.findAllChunksByType("zTXt");
            assertEquals(0, notFound.size());
        }

        @Test
        @DisplayName("getCriticalChunks 获取关键块")
        void testGetCriticalChunks() {
            ScanResult result = createTestScanResult();

            List<BinaryChunk> critical = result.getCriticalChunks();
            assertEquals(3, critical.size()); // IHDR, IDAT, IEND

            for (BinaryChunk chunk : critical) {
                assertTrue(chunk.isCritical());
            }
        }

        @Test
        @DisplayName("getNonCriticalChunks 获取非关键块")
        void testGetNonCriticalChunks() {
            ScanResult result = createTestScanResult();

            List<BinaryChunk> nonCritical = result.getNonCriticalChunks();
            assertEquals(1, nonCritical.size()); // tEXt
            assertEquals("tEXt", nonCritical.get(0).getChunkType());
        }

        @Test
        @DisplayName("toString 格式")
        void testToString() {
            ScanResult result = createTestScanResult();
            String str = result.toString();

            assertTrue(str.contains("PNG"));
            assertTrue(str.contains("valid=true"));
            assertTrue(str.contains("chunks=4"));
            assertTrue(str.contains("globalFields=1"));
        }

        @Test
        @DisplayName("无效结果")
        void testInvalidResult() {
            ScanResult result = new ScanResult(false, "UNKNOWN", new byte[0],
                    new ArrayList<>(), new ArrayList<>());

            assertFalse(result.isValid());
            assertEquals("UNKNOWN", result.getFormatType());
            assertEquals(0, result.getChunks().size());
        }
    }
}
