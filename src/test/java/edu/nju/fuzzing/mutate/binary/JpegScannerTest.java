package edu.nju.fuzzing.mutate.binary;

import java.io.ByteArrayOutputStream;
import java.nio.ByteOrder;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * JpegScanner 单元测试
 * 
 * 验证点：
 * 1. Magic 识别 (SOI marker)
 * 2. Marker Segment 解析
 * 3. 段长度解析
 * 4. 无效数据处理
 */
class JpegScannerTest {

    private JpegScanner scanner;

    @BeforeEach
    void setUp() {
        scanner = new JpegScanner();
    }

    // ==========================================
    // Magic 识别测试
    // ==========================================

    @Test
    @DisplayName("matches() - 有效 JPEG 签名")
    void testMatchesValidJpeg() {
        byte[] jpeg = createMinimalJpeg();
        assertTrue(scanner.matches(jpeg));
    }

    @Test
    @DisplayName("matches() - SOI marker 识别")
    void testMatchesSoiMarker() {
        byte[] validSoi = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0};
        assertTrue(scanner.matches(validSoi));
    }

    @Test
    @DisplayName("matches() - 无效签名被拒绝")
    void testMatchesInvalidSignature() {
        byte[] invalid = {0x00, 0x01, 0x02, 0x03};
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
        byte[] tooShort = {(byte) 0xFF};
        assertFalse(scanner.matches(tooShort));
    }

    // ==========================================
    // Segment 解析测试
    // ==========================================

    @Test
    @DisplayName("scan() - 解析最小 JPEG")
    void testScanMinimalJpeg() {
        byte[] jpeg = createMinimalJpeg();
        ScanResult result = scanner.scan(jpeg);

        assertTrue(result.isValid());
        assertEquals("JPEG", result.getFormatType());
        assertEquals(ByteOrder.BIG_ENDIAN, result.getByteOrder());

        List<BinaryChunk> chunks = result.getChunks();
        assertFalse(chunks.isEmpty(), "应该有 marker segments");
    }

    @Test
    @DisplayName("scan() - SOI 和 EOI 识别")
    void testSoiAndEoiDetection() {
        byte[] jpeg = createMinimalJpeg();
        ScanResult result = scanner.scan(jpeg);

        // SOI 是作为全局字段添加的
        boolean hasSoi = result.getGlobalFields().stream()
            .anyMatch(f -> f.getName().contains("SOI"));
        assertTrue(hasSoi, "应该有 SOI marker 作为全局字段");

        // EOI 是作为 chunk 添加的
        List<BinaryChunk> chunks = result.getChunks();
        boolean hasEoi = chunks.stream()
            .anyMatch(c -> c.getChunkType().contains("EOI"));
        assertTrue(hasEoi, "应该有 EOI marker");
    }

    @Test
    @DisplayName("scan() - APP0 段解析")
    void testApp0Parsing() {
        byte[] jpeg = createJpegWithApp0();
        ScanResult result = scanner.scan(jpeg);

        boolean hasApp0 = result.getChunks().stream()
            .anyMatch(c -> c.getChunkType().contains("APP0"));
        assertTrue(hasApp0, "应该识别 APP0 marker");
    }

    @Test
    @DisplayName("scan() - DQT 段解析")
    void testDqtParsing() {
        byte[] jpeg = createJpegWithDqt();
        ScanResult result = scanner.scan(jpeg);

        boolean hasDqt = result.getChunks().stream()
            .anyMatch(c -> c.getChunkType().contains("DQT"));
        assertTrue(hasDqt, "应该识别 DQT marker");
    }

    @Test
    @DisplayName("scan() - 无效数据返回无效结果")
    void testScanInvalidData() {
        byte[] invalid = {0x00, 0x01, 0x02, 0x03};
        ScanResult result = scanner.scan(invalid);
        assertFalse(result.isValid());
    }

    // ==========================================
    // 字段映射测试
    // ==========================================

    @Test
    @DisplayName("scan() - 段长度字段正确")
    void testSegmentLengthFields() {
        byte[] jpeg = createJpegWithApp0();
        ScanResult result = scanner.scan(jpeg);

        for (BinaryChunk chunk : result.getChunks()) {
            if (chunk.getChunkType().contains("APP0")) {
                List<FieldMapping> fields = chunk.getFields();
                boolean hasLength = fields.stream()
                    .anyMatch(f -> f.getType() == FieldType.LENGTH);
                assertTrue(hasLength, "APP0 段应该有长度字段");
                break;
            }
        }
    }

    // ==========================================
    // 边界条件测试
    // ==========================================

    @Test
    @DisplayName("scan() - 处理截断的 JPEG")
    void testScanTruncatedJpeg() {
        byte[] jpeg = createMinimalJpeg();
        byte[] truncated = new byte[jpeg.length / 2];
        System.arraycopy(jpeg, 0, truncated, 0, truncated.length);

        ScanResult result = scanner.scan(truncated);
        // 应该能解析部分 segments
        assertNotNull(result);
    }

    @Test
    @DisplayName("getFormatName() - 返回 JPEG")
    void testGetFormatName() {
        assertEquals("JPEG", scanner.getFormatName());
    }

    // ==========================================
    // 辅助方法
    // ==========================================

    private byte[] createMinimalJpeg() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // SOI
        baos.write(0xFF);
        baos.write(0xD8);
        
        // EOI
        baos.write(0xFF);
        baos.write(0xD9);
        
        return baos.toByteArray();
    }

    private byte[] createJpegWithApp0() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // SOI
        baos.write(0xFF);
        baos.write(0xD8);
        
        // APP0 (JFIF)
        baos.write(0xFF);
        baos.write(0xE0);
        baos.write(0x00);  // Length high
        baos.write(0x10);  // Length low (16)
        writeBytes(baos, "JFIF\0".getBytes());  // Identifier
        writeBytes(baos, new byte[9]);  // Padding to make 16 bytes
        
        // EOI
        baos.write(0xFF);
        baos.write(0xD9);
        
        return baos.toByteArray();
    }

    private byte[] createJpegWithDqt() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        
        // SOI
        baos.write(0xFF);
        baos.write(0xD8);
        
        // DQT
        baos.write(0xFF);
        baos.write(0xDB);
        baos.write(0x00);  // Length high
        baos.write(0x43);  // Length low (67 = 2 + 1 + 64)
        baos.write(0x00);  // Table info
        writeBytes(baos, new byte[64]);  // Quantization table
        
        // EOI
        baos.write(0xFF);
        baos.write(0xD9);
        
        return baos.toByteArray();
    }

    private void writeBytes(ByteArrayOutputStream out, byte[] data) {
        out.write(data, 0, data.length);
    }
}
