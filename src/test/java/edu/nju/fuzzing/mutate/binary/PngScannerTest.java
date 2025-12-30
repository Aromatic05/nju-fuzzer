package edu.nju.fuzzing.mutate.binary;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteOrder;
import java.util.List;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * PngScanner 单元测试
 * 
 * 验证点：
 * 1. Magic 识别
 * 2. Chunk 解析 (IHDR, IDAT, IEND)
 * 3. 字段映射正确性
 * 4. 无效数据处理
 */
class PngScannerTest {

    private PngScanner scanner;
    private static final byte[] PNG_MAGIC = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

    @BeforeEach
    void setUp() {
        scanner = new PngScanner();
    }

    // ==========================================
    // Magic 识别测试
    // ==========================================

    @Test
    @DisplayName("matches() - 有效 PNG 签名")
    void testMatchesValidPng() {
        byte[] validPng = createMinimalPng();
        assertTrue(scanner.matches(validPng));
    }

    @Test
    @DisplayName("matches() - 无效签名被拒绝")
    void testMatchesInvalidSignature() {
        byte[] invalid = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        assertFalse(scanner.matches(invalid));
    }

    @Test
    @DisplayName("matches() - 空数据被拒绝")
    void testMatchesEmptyData() {
        assertFalse(scanner.matches(new byte[0]));
        assertFalse(scanner.matches(null));
    }

    @Test
    @DisplayName("matches() - 太短的数据被拒绝")
    void testMatchesTooShort() {
        byte[] tooShort = {(byte) 0x89, 0x50, 0x4E, 0x47};
        assertFalse(scanner.matches(tooShort));
    }

    // ==========================================
    // Chunk 解析测试
    // ==========================================

    @Test
    @DisplayName("scan() - 解析最小 PNG (IHDR + IDAT + IEND)")
    void testScanMinimalPng() {
        byte[] png = createMinimalPng();
        ScanResult result = scanner.scan(png);

        assertTrue(result.isValid());
        assertEquals("PNG", result.getFormatType());
        assertEquals(ByteOrder.BIG_ENDIAN, result.getByteOrder());

        List<BinaryChunk> chunks = result.getChunks();
        assertTrue(chunks.size() >= 3, "应该至少有 3 个 chunk");

        // 验证 chunk 类型
        assertEquals("IHDR", chunks.get(0).getChunkType());
        assertEquals("IDAT", chunks.get(1).getChunkType());
        assertEquals("IEND", chunks.get(chunks.size() - 1).getChunkType());
    }

    @Test
    @DisplayName("scan() - IHDR 被标记为关键块")
    void testIhdrIsCritical() {
        byte[] png = createMinimalPng();
        ScanResult result = scanner.scan(png);

        BinaryChunk ihdr = result.findChunkByType("IHDR");
        assertNotNull(ihdr);
        assertTrue(ihdr.isCritical(), "IHDR 应该是关键块");
    }

    @Test
    @DisplayName("scan() - IEND 被标记为关键块")
    void testIendIsCritical() {
        byte[] png = createMinimalPng();
        ScanResult result = scanner.scan(png);

        BinaryChunk iend = result.findChunkByType("IEND");
        assertNotNull(iend);
        assertTrue(iend.isCritical(), "IEND 应该是关键块");
    }

    @Test
    @DisplayName("scan() - 字段映射正确")
    void testFieldMappings() {
        byte[] png = createMinimalPng();
        ScanResult result = scanner.scan(png);

        BinaryChunk ihdr = result.findChunkByType("IHDR");
        assertNotNull(ihdr);

        List<FieldMapping> fields = ihdr.getFields();
        assertFalse(fields.isEmpty(), "IHDR 应该有字段映射");

        // 查找宽度字段
        boolean hasWidth = fields.stream()
            .anyMatch(f -> "width".equals(f.getName()) && f.getType() == FieldType.LENGTH);
        assertTrue(hasWidth, "应该有 width 字段");

        // 查找高度字段
        boolean hasHeight = fields.stream()
            .anyMatch(f -> "height".equals(f.getName()) && f.getType() == FieldType.LENGTH);
        assertTrue(hasHeight, "应该有 height 字段");
    }

    @Test
    @DisplayName("scan() - 无效数据返回无效结果")
    void testScanInvalidData() {
        byte[] invalid = {0x00, 0x01, 0x02, 0x03};
        ScanResult result = scanner.scan(invalid);
        assertFalse(result.isValid());
    }

    // ==========================================
    // 边界条件测试
    // ==========================================

    @Test
    @DisplayName("scan() - 处理截断的 PNG")
    void testScanTruncatedPng() {
        byte[] png = createMinimalPng();
        // 截断一半
        byte[] truncated = new byte[png.length / 2];
        System.arraycopy(png, 0, truncated, 0, truncated.length);

        ScanResult result = scanner.scan(truncated);
        // 应该能解析部分 chunk
        assertNotNull(result);
    }

    @Test
    @DisplayName("getFormatName() - 返回 PNG")
    void testGetFormatName() {
        assertEquals("PNG", scanner.getFormatName());
    }

    // ==========================================
    // 辅助方法
    // ==========================================

    private byte[] createMinimalPng() {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(baos);

            // PNG Signature
            out.write(PNG_MAGIC);

            // IHDR Chunk
            ByteArrayOutputStream ihdrBody = new ByteArrayOutputStream();
            DataOutputStream ihdrOut = new DataOutputStream(ihdrBody);
            ihdrOut.writeInt(8);   // Width
            ihdrOut.writeInt(8);   // Height
            ihdrOut.write(8);      // Bit Depth
            ihdrOut.write(2);      // Color Type (RGB)
            ihdrOut.write(0);      // Compression
            ihdrOut.write(0);      // Filter
            ihdrOut.write(0);      // Interlace
            writeChunk(out, "IHDR", ihdrBody.toByteArray());

            // IDAT Chunk (minimal compressed data)
            byte[] scanlines = new byte[8 * 3 * 8 + 8]; // 8 rows, 3 bytes per pixel, 1 filter byte per row
            byte[] compressed = compress(scanlines);
            writeChunk(out, "IDAT", compressed);

            // IEND Chunk
            writeChunk(out, "IEND", new byte[0]);

            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void writeChunk(DataOutputStream out, String type, byte[] data) throws IOException {
        out.writeInt(data.length);
        byte[] typeBytes = type.getBytes("US-ASCII");
        out.write(typeBytes);
        out.write(data);

        CRC32 crc = new CRC32();
        crc.update(typeBytes);
        crc.update(data);
        out.writeInt((int) crc.getValue());
    }

    private byte[] compress(byte[] data) {
        Deflater deflater = new Deflater();
        deflater.setInput(data);
        deflater.finish();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            baos.write(buffer, 0, count);
        }
        deflater.end();
        return baos.toByteArray();
    }
}
