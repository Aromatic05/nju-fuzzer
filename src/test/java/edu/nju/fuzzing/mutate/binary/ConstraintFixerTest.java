package edu.nju.fuzzing.mutate.binary;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * ConstraintFixer 单元测试
 * 
 * 验证点：
 * 1. PNG CRC 修复
 * 2. IP Checksum 计算和修复
 * 3. Magic 恢复
 * 4. JPEG EOI 确保
 */
class ConstraintFixerTest {

    private static final byte[] PNG_MAGIC = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    private static final byte[] JPEG_MAGIC = {(byte) 0xFF, (byte) 0xD8};
    private static final byte[] ELF_MAGIC = {0x7F, 'E', 'L', 'F'};

    // ==========================================
    // PNG CRC 修复测试
    // ==========================================

    @Test
    @DisplayName("fixPngChunkCrc() - 修复单个 chunk 的 CRC")
    void testFixPngChunkCrc() throws IOException {
        byte[] png = createPngWithBadCrc();
        
        // 原始 CRC 是错误的
        int originalCrc = ByteBuffer.wrap(png, png.length - 4, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        
        byte[] fixed = ConstraintFixer.fixPngChunkCrc(png, 8);  // IHDR 从偏移 8 开始
        
        // 计算期望的 CRC
        CRC32 crc = new CRC32();
        crc.update(fixed, 12, 4 + 13);  // Type + Data
        int expectedCrc = (int) crc.getValue();
        
        int fixedCrc = ByteBuffer.wrap(fixed, 8 + 4 + 4 + 13, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        assertEquals(expectedCrc, fixedCrc, "CRC 应该被修复");
    }

    @Test
    @DisplayName("fixAllPngCrcs() - 修复所有 PNG chunks 的 CRC")
    void testFixAllPngCrcs() throws IOException {
        byte[] png = createMinimalPng();
        
        // 破坏 CRC
        png[png.length - 4] ^= 0xFF;
        
        byte[] fixed = ConstraintFixer.fixAllPngCrcs(png);
        
        assertNotNull(fixed);
        // 验证最后一个 chunk (IEND) 的 CRC
        CRC32 crc = new CRC32();
        int iendStart = fixed.length - 12;
        crc.update(fixed, iendStart + 4, 4);  // "IEND"
        int expectedCrc = (int) crc.getValue();
        int actualCrc = ByteBuffer.wrap(fixed, fixed.length - 4, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        assertEquals(expectedCrc, actualCrc);
    }

    // ==========================================
    // IP Checksum 测试
    // ==========================================

    @Test
    @DisplayName("calculateIpChecksum() - 计算 IP 校验和")
    void testCalculateIpChecksum() {
        // 标准 IP 头部示例
        byte[] header = new byte[20];
        header[0] = 0x45;  // Version + IHL
        header[1] = 0x00;  // TOS
        header[2] = 0x00;  // Total Length high
        header[3] = 0x28;  // Total Length low (40)
        // ID, Flags, Fragment, TTL, Protocol
        header[8] = 0x40;  // TTL
        header[9] = 0x06;  // Protocol (TCP)
        // Checksum = 0 for calculation
        header[10] = 0x00;
        header[11] = 0x00;
        // Source IP: 192.168.1.1
        header[12] = (byte) 0xC0;
        header[13] = (byte) 0xA8;
        header[14] = 0x01;
        header[15] = 0x01;
        // Dest IP: 192.168.1.2
        header[16] = (byte) 0xC0;
        header[17] = (byte) 0xA8;
        header[18] = 0x01;
        header[19] = 0x02;

        int checksum = ConstraintFixer.calculateIpChecksum(header, 0, 20);
        
        // 校验和应该非零
        assertNotEquals(0, checksum);
        // 校验和应该是 16 位
        assertTrue(checksum >= 0 && checksum <= 0xFFFF);
    }

    @Test
    @DisplayName("fixIpChecksum() - 修复 IP 校验和")
    void testFixIpChecksum() {
        byte[] data = new byte[60];  // Ethernet + IP
        int ipOffset = 14;
        
        // IP Header
        data[ipOffset] = 0x45;  // Version + IHL
        data[ipOffset + 2] = 0x00;
        data[ipOffset + 3] = 0x28;
        data[ipOffset + 8] = 0x40;  // TTL
        data[ipOffset + 9] = 0x06;  // Protocol
        
        byte[] fixed = ConstraintFixer.fixIpChecksum(data, ipOffset, 5);
        
        // 校验和字段不应为零
        int checksum = ((fixed[ipOffset + 10] & 0xFF) << 8) | (fixed[ipOffset + 11] & 0xFF);
        assertNotEquals(0, checksum);
    }

    // ==========================================
    // Magic 恢复测试
    // ==========================================

    @Test
    @DisplayName("restorePngMagic() - 恢复 PNG Magic")
    void testRestorePngMagic() {
        byte[] data = new byte[100];
        // 破坏 magic
        data[0] = 0x00;
        
        byte[] fixed = ConstraintFixer.restorePngMagic(data);
        
        for (int i = 0; i < 8; i++) {
            assertEquals(PNG_MAGIC[i], fixed[i], "PNG magic 第 " + i + " 字节应该正确");
        }
    }

    @Test
    @DisplayName("restoreJpegMagic() - 恢复 JPEG Magic")
    void testRestoreJpegMagic() {
        byte[] data = new byte[100];
        // 破坏 magic
        data[0] = 0x00;
        data[1] = 0x00;
        
        byte[] fixed = ConstraintFixer.restoreJpegMagic(data);
        
        assertEquals(JPEG_MAGIC[0], fixed[0]);
        assertEquals(JPEG_MAGIC[1], fixed[1]);
    }

    @Test
    @DisplayName("restoreElfMagic() - 恢复 ELF Magic")
    void testRestoreElfMagic() {
        byte[] data = new byte[100];
        // 破坏 magic
        data[0] = 0x00;
        
        byte[] fixed = ConstraintFixer.restoreElfMagic(data);
        
        for (int i = 0; i < 4; i++) {
            assertEquals(ELF_MAGIC[i], fixed[i], "ELF magic 第 " + i + " 字节应该正确");
        }
    }

    @Test
    @DisplayName("restorePcapMagic() - 恢复 PCAP Magic (Little Endian)")
    void testRestorePcapMagicLe() {
        byte[] data = new byte[100];
        
        byte[] fixed = ConstraintFixer.restorePcapMagic(data, false);
        
        // 0xD4C3B2A1 in little endian
        assertEquals((byte) 0xD4, fixed[0]);
        assertEquals((byte) 0xC3, fixed[1]);
        assertEquals((byte) 0xB2, fixed[2]);
        assertEquals((byte) 0xA1, fixed[3]);
    }

    @Test
    @DisplayName("restorePcapMagic() - 恢复 PCAP Magic (Big Endian)")
    void testRestorePcapMagicBe() {
        byte[] data = new byte[100];
        
        byte[] fixed = ConstraintFixer.restorePcapMagic(data, true);
        
        // 0xA1B2C3D4 in big endian
        assertEquals((byte) 0xA1, fixed[0]);
        assertEquals((byte) 0xB2, fixed[1]);
        assertEquals((byte) 0xC3, fixed[2]);
        assertEquals((byte) 0xD4, fixed[3]);
    }

    @Test
    @DisplayName("restoreMagic() - 根据格式类型恢复 Magic")
    void testRestoreMagicByType() {
        byte[] data = new byte[100];
        
        byte[] pngFixed = ConstraintFixer.restoreMagic(data.clone(), "PNG");
        assertEquals(PNG_MAGIC[0], pngFixed[0]);
        
        byte[] jpegFixed = ConstraintFixer.restoreMagic(data.clone(), "JPEG");
        assertEquals(JPEG_MAGIC[0], jpegFixed[0]);
        
        byte[] elfFixed = ConstraintFixer.restoreMagic(data.clone(), "ELF");
        assertEquals(ELF_MAGIC[0], elfFixed[0]);
    }

    // ==========================================
    // JPEG EOI 测试
    // ==========================================

    @Test
    @DisplayName("ensureJpegEoi() - 添加缺失的 EOI")
    void testEnsureJpegEoiAddsMarker() {
        byte[] data = {(byte) 0xFF, (byte) 0xD8, 0x00, 0x00};  // SOI + data, no EOI
        
        byte[] fixed = ConstraintFixer.ensureJpegEoi(data);
        
        assertEquals(6, fixed.length);
        assertEquals((byte) 0xFF, fixed[fixed.length - 2]);
        assertEquals((byte) 0xD9, fixed[fixed.length - 1]);
    }

    @Test
    @DisplayName("ensureJpegEoi() - 已有 EOI 不重复添加")
    void testEnsureJpegEoiNoDoubleAdd() {
        byte[] data = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xD9};  // SOI + EOI
        
        byte[] fixed = ConstraintFixer.ensureJpegEoi(data);
        
        assertEquals(4, fixed.length);  // 长度不变
    }

    // ==========================================
    // 长度修复测试
    // ==========================================

    @Test
    @DisplayName("fixPngChunkLength() - 修复 PNG chunk 长度")
    void testFixPngChunkLength() throws IOException {
        byte[] png = createMinimalPng();
        int ihdrStart = 8;
        
        byte[] fixed = ConstraintFixer.fixPngChunkLength(png, ihdrStart, 20);
        
        int newLength = ByteBuffer.wrap(fixed, ihdrStart, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        assertEquals(20, newLength);
    }

    @Test
    @DisplayName("fixJpegSegmentLength() - 修复 JPEG 段长度")
    void testFixJpegSegmentLength() {
        byte[] data = {(byte) 0xFF, (byte) 0xE0, 0x00, 0x10, 0x00, 0x00};  // APP0 with length 16
        
        // 传入数据长度 30，方法会存储 30 + 2 = 32 作为段长度
        byte[] fixed = ConstraintFixer.fixJpegSegmentLength(data, 0, 30);
        
        // JPEG 段长度字段包含长度字段自身的 2 字节
        int newLength = ((fixed[2] & 0xFF) << 8) | (fixed[3] & 0xFF);
        assertEquals(32, newLength);  // 30 + 2 = 32
    }

    // ==========================================
    // 边界条件测试
    // ==========================================

    @Test
    @DisplayName("边界条件 - 空数据处理")
    void testEmptyDataHandling() {
        byte[] empty = new byte[0];
        
        // 不应该抛出异常
        assertDoesNotThrow(() -> ConstraintFixer.restorePngMagic(empty));
        assertDoesNotThrow(() -> ConstraintFixer.restoreJpegMagic(empty));
        assertDoesNotThrow(() -> ConstraintFixer.restoreElfMagic(empty));
    }

    @Test
    @DisplayName("边界条件 - 太短的数据")
    void testTooShortData() {
        byte[] tooShort = {0x00, 0x01};
        
        // 应该返回原数据或安全处理
        byte[] result = ConstraintFixer.restorePngMagic(tooShort);
        assertNotNull(result);
    }

    // ==========================================
    // 辅助方法
    // ==========================================

    private byte[] createMinimalPng() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(baos);

        out.write(PNG_MAGIC);

        // IHDR
        ByteArrayOutputStream ihdrBody = new ByteArrayOutputStream();
        DataOutputStream ihdrOut = new DataOutputStream(ihdrBody);
        ihdrOut.writeInt(8);
        ihdrOut.writeInt(8);
        ihdrOut.write(8);
        ihdrOut.write(2);
        ihdrOut.write(0);
        ihdrOut.write(0);
        ihdrOut.write(0);
        writeChunk(out, "IHDR", ihdrBody.toByteArray());

        // IDAT
        byte[] scanlines = new byte[8 * 3 * 8 + 8];
        writeChunk(out, "IDAT", compress(scanlines));

        // IEND
        writeChunk(out, "IEND", new byte[0]);

        return baos.toByteArray();
    }

    private byte[] createPngWithBadCrc() throws IOException {
        byte[] png = createMinimalPng();
        // 破坏 IHDR 的 CRC
        png[8 + 4 + 4 + 13] ^= 0xFF;
        return png;
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
