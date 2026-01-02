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
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    private static final byte[] PNG_MAGIC = { (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    private static final byte[] JPEG_MAGIC = { (byte) 0xFF, (byte) 0xD8 };
    private static final byte[] ELF_MAGIC = { 0x7F, 'E', 'L', 'F' };

    // ==========================================
    // PNG CRC 修复测试
    // ==========================================

    @Test
    @DisplayName("fixPngChunkCrc() - 修复单个 chunk 的 CRC")
    void testFixPngChunkCrc() throws IOException {
        byte[] png = createPngWithBadCrc();

        // 原始 CRC 是错误的
        int originalCrc = ByteBuffer.wrap(png, png.length - 4, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        assertNotEquals(0x12345678, originalCrc, "原始 CRC 应该是错误的");

        byte[] fixed = ConstraintFixer.fixPngChunkCrc(png, 8); // IHDR 从偏移 8 开始

        // 计算期望的 CRC
        CRC32 crc = new CRC32();
        crc.update(fixed, 12, 4 + 13); // Type + Data
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
        crc.update(fixed, iendStart + 4, 4); // "IEND"
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
        header[0] = 0x45; // Version + IHL
        header[1] = 0x00; // TOS
        header[2] = 0x00; // Total Length high
        header[3] = 0x28; // Total Length low (40)
        // ID, Flags, Fragment, TTL, Protocol
        header[8] = 0x40; // TTL
        header[9] = 0x06; // Protocol (TCP)
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
        byte[] data = new byte[60]; // Ethernet + IP
        int ipOffset = 14;

        // IP Header
        data[ipOffset] = 0x45; // Version + IHL
        data[ipOffset + 2] = 0x00;
        data[ipOffset + 3] = 0x28;
        data[ipOffset + 8] = 0x40; // TTL
        data[ipOffset + 9] = 0x06; // Protocol

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
        byte[] data = { (byte) 0xFF, (byte) 0xD8, 0x00, 0x00 }; // SOI + data, no EOI

        byte[] fixed = ConstraintFixer.ensureJpegEoi(data);

        assertEquals(6, fixed.length);
        assertEquals((byte) 0xFF, fixed[fixed.length - 2]);
        assertEquals((byte) 0xD9, fixed[fixed.length - 1]);
    }

    @Test
    @DisplayName("ensureJpegEoi() - 已有 EOI 不重复添加")
    void testEnsureJpegEoiNoDoubleAdd() {
        byte[] data = { (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xD9 }; // SOI + EOI

        byte[] fixed = ConstraintFixer.ensureJpegEoi(data);

        assertEquals(4, fixed.length); // 长度不变
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
        byte[] data = { (byte) 0xFF, (byte) 0xE0, 0x00, 0x10, 0x00, 0x00 }; // APP0 with length 16

        // 传入数据长度 30，方法会存储 30 + 2 = 32 作为段长度
        byte[] fixed = ConstraintFixer.fixJpegSegmentLength(data, 0, 30);

        // JPEG 段长度字段包含长度字段自身的 2 字节
        int newLength = ((fixed[2] & 0xFF) << 8) | (fixed[3] & 0xFF);
        assertEquals(32, newLength); // 30 + 2 = 32
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
        byte[] tooShort = { 0x00, 0x01 };

        // 应该返回原数据或安全处理
        byte[] result = ConstraintFixer.restorePngMagic(tooShort);
        assertNotNull(result);
    }

    // ==========================================
    // ELF Header 修复测试
    // ==========================================

    @Test
    @DisplayName("fixElfHeaderEssentials() - 修复 ELF 必需字段")
    void testFixElfHeaderEssentials() {
        byte[] data = new byte[100];
        // 破坏所有关键字段
        data[0] = 0x00;
        data[4] = 0x00; // 无效 CLASS
        data[5] = 0x00; // 无效 DATA
        data[6] = 0x00; // 无效 VERSION

        byte[] fixed = ConstraintFixer.fixElfHeaderEssentials(data, false);

        // 验证 Magic
        assertEquals(0x7F, fixed[0]);
        assertEquals('E', fixed[1]);
        assertEquals('L', fixed[2]);
        assertEquals('F', fixed[3]);

        // 验证 CLASS (应该默认为 64位)
        assertEquals(2, fixed[4]);

        // 验证 DATA (应该默认为小端)
        assertEquals(1, fixed[5]);

        // 验证 VERSION
        assertEquals(1, fixed[6]);
    }

    @Test
    @DisplayName("fixElfHeaderEssentials() - 保留有效 CLASS")
    void testFixElfHeaderPreserveClass() {
        byte[] data = new byte[100];
        data[4] = 1; // 32位
        data[5] = 1; // 小端

        byte[] fixed = ConstraintFixer.fixElfHeaderEssentials(data, true);

        // 应该保留原有的 32位
        assertEquals(1, fixed[4]);
    }

    @Test
    @DisplayName("fixElfHeaderEssentials() - 默认参数版本")
    void testFixElfHeaderEssentialsDefault() {
        byte[] data = new byte[100];
        data[4] = 2; // 64位
        data[5] = 1; // 小端

        byte[] fixed = ConstraintFixer.fixElfHeaderEssentials(data);

        assertEquals(0x7F, fixed[0]);
        assertEquals(2, fixed[4]); // 保留 64位
    }

    // ==========================================
    // ELF Header 计数更新测试
    // ==========================================

    @Test
    @DisplayName("updateElfPhnum() - 更新 Program Header 计数 (64位)")
    void testUpdateElfPhnum64() {
        byte[] data = new byte[100];
        data[5] = 1; // 小端序

        byte[] fixed = ConstraintFixer.updateElfPhnum(data, 5, true);

        int phnum = ByteBuffer.wrap(fixed).order(ByteOrder.LITTLE_ENDIAN).getShort(56) & 0xFFFF;
        assertEquals(5, phnum);
    }

    @Test
    @DisplayName("updateElfPhnum() - 更新 Program Header 计数 (32位)")
    void testUpdateElfPhnum32() {
        byte[] data = new byte[100];
        data[5] = 1; // 小端序

        byte[] fixed = ConstraintFixer.updateElfPhnum(data, 3, false);

        int phnum = ByteBuffer.wrap(fixed).order(ByteOrder.LITTLE_ENDIAN).getShort(44) & 0xFFFF;
        assertEquals(3, phnum);
    }

    @Test
    @DisplayName("updateElfShnum() - 更新 Section Header 计数 (64位)")
    void testUpdateElfShnum64() {
        byte[] data = new byte[100];
        data[5] = 1; // 小端序

        byte[] fixed = ConstraintFixer.updateElfShnum(data, 10, true);

        int shnum = ByteBuffer.wrap(fixed).order(ByteOrder.LITTLE_ENDIAN).getShort(60) & 0xFFFF;
        assertEquals(10, shnum);
    }

    @Test
    @DisplayName("updateElfShnum() - 更新 Section Header 计数 (32位)")
    void testUpdateElfShnum32() {
        byte[] data = new byte[100];
        data[5] = 1; // 小端序

        byte[] fixed = ConstraintFixer.updateElfShnum(data, 7, false);

        int shnum = ByteBuffer.wrap(fixed).order(ByteOrder.LITTLE_ENDIAN).getShort(48) & 0xFFFF;
        assertEquals(7, shnum);
    }

    @Test
    @DisplayName("incrementElfPhnum() - 递增 Program Header 计数")
    void testIncrementElfPhnum() {
        byte[] data = new byte[100];
        data[5] = 1; // 小端序
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putShort(56, (short) 5);

        byte[] fixed = ConstraintFixer.incrementElfPhnum(data, true);

        int phnum = ByteBuffer.wrap(fixed).order(ByteOrder.LITTLE_ENDIAN).getShort(56) & 0xFFFF;
        assertEquals(6, phnum);
    }

    @Test
    @DisplayName("decrementElfPhnum() - 递减 Program Header 计数")
    void testDecrementElfPhnum() {
        byte[] data = new byte[100];
        data[5] = 1;
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putShort(56, (short) 5);

        byte[] fixed = ConstraintFixer.decrementElfPhnum(data, true);

        int phnum = ByteBuffer.wrap(fixed).order(ByteOrder.LITTLE_ENDIAN).getShort(56) & 0xFFFF;
        assertEquals(4, phnum);
    }

    @Test
    @DisplayName("decrementElfPhnum() - 不能小于0")
    void testDecrementElfPhnumMinZero() {
        byte[] data = new byte[100];
        data[5] = 1;
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putShort(56, (short) 0);

        byte[] fixed = ConstraintFixer.decrementElfPhnum(data, true);

        int phnum = ByteBuffer.wrap(fixed).order(ByteOrder.LITTLE_ENDIAN).getShort(56) & 0xFFFF;
        assertEquals(0, phnum);
    }

    @Test
    @DisplayName("incrementElfShnum() - 递增 Section Header 计数")
    void testIncrementElfShnum() {
        byte[] data = new byte[100];
        data[5] = 1;
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putShort(60, (short) 10);

        byte[] fixed = ConstraintFixer.incrementElfShnum(data, true);

        int shnum = ByteBuffer.wrap(fixed).order(ByteOrder.LITTLE_ENDIAN).getShort(60) & 0xFFFF;
        assertEquals(11, shnum);
    }

    @Test
    @DisplayName("decrementElfShnum() - 递减 Section Header 计数")
    void testDecrementElfShnum() {
        byte[] data = new byte[100];
        data[5] = 1;
        ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).putShort(60, (short) 8);

        byte[] fixed = ConstraintFixer.decrementElfShnum(data, true);

        int shnum = ByteBuffer.wrap(fixed).order(ByteOrder.LITTLE_ENDIAN).getShort(60) & 0xFFFF;
        assertEquals(7, shnum);
    }

    // ==========================================
    // ELF Section Size 测试
    // ==========================================

    @Test
    @DisplayName("fixElfSectionSize() - 修复 Section 大小 (64位)")
    void testFixElfSectionSize64() {
        byte[] data = new byte[100];
        int shOffset = 0;

        byte[] fixed = ConstraintFixer.fixElfSectionSize(data, shOffset, 0x1234L, true);

        long size = ByteBuffer.wrap(fixed, 32, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
        assertEquals(0x1234L, size);
    }

    @Test
    @DisplayName("fixElfSectionSize() - 修复 Section 大小 (32位)")
    void testFixElfSectionSize32() {
        byte[] data = new byte[100];
        int shOffset = 0;

        byte[] fixed = ConstraintFixer.fixElfSectionSize(data, shOffset, 0x5678L, false);

        int size = ByteBuffer.wrap(fixed, 20, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        assertEquals(0x5678, size);
    }

    // ==========================================
    // PCAP 测试
    // ==========================================

    @Test
    @DisplayName("fixPcapPacketLength() - 修复 PCAP 包长度")
    void testFixPcapPacketLength() {
        byte[] data = new byte[50];
        int offset = 0;

        byte[] fixed = ConstraintFixer.fixPcapPacketLength(data, offset, 100, 150, false);

        ByteBuffer bb = ByteBuffer.wrap(fixed, 8, 8).order(ByteOrder.LITTLE_ENDIAN);
        assertEquals(100, bb.getInt());
        assertEquals(150, bb.getInt());
    }

    @Test
    @DisplayName("restorePcapMagic() - 自动检测字节序 (大端)")
    void testRestorePcapMagicAutoDetectBe() {
        byte[] data = new byte[100];
        // 设置大端序标志
        data[0] = (byte) 0xA1;
        data[1] = (byte) 0xB2;
        data[2] = (byte) 0xC3;
        data[3] = (byte) 0xD4;

        byte[] fixed = ConstraintFixer.restorePcapMagic(data);

        assertEquals((byte) 0xA1, fixed[0]);
        assertEquals((byte) 0xB2, fixed[1]);
    }

    @Test
    @DisplayName("restorePcapMagic() - 自动检测字节序 (小端)")
    void testRestorePcapMagicAutoDetectLe() {
        byte[] data = new byte[100];
        // 未知/小端序
        data[0] = 0x00;

        byte[] fixed = ConstraintFixer.restorePcapMagic(data);

        // 应该使用小端序
        assertEquals((byte) 0xD4, fixed[0]);
        assertEquals((byte) 0xC3, fixed[1]);
    }

    // ==========================================
    // PNG 增强修复测试
    // ==========================================

    @Test
    @DisplayName("isValidPngBitDepthCombo() - 验证合法组合")
    void testIsValidPngBitDepthCombo() {
        // 合法组合
        assertTrue(ConstraintFixer.isValidPngBitDepthCombo(0, 1)); // Grayscale
        assertTrue(ConstraintFixer.isValidPngBitDepthCombo(0, 8));
        assertTrue(ConstraintFixer.isValidPngBitDepthCombo(2, 8)); // TrueColor
        assertTrue(ConstraintFixer.isValidPngBitDepthCombo(2, 16));
        assertTrue(ConstraintFixer.isValidPngBitDepthCombo(3, 4)); // Indexed
        assertTrue(ConstraintFixer.isValidPngBitDepthCombo(4, 8)); // Grayscale+Alpha
        assertTrue(ConstraintFixer.isValidPngBitDepthCombo(6, 8)); // TrueColor+Alpha

        // 非法组合
        assertFalse(ConstraintFixer.isValidPngBitDepthCombo(0, 3)); // 无效 bit depth
        assertFalse(ConstraintFixer.isValidPngBitDepthCombo(2, 4)); // TrueColor 不支持 4
        assertFalse(ConstraintFixer.isValidPngBitDepthCombo(5, 8)); // 无效 color type
        assertFalse(ConstraintFixer.isValidPngBitDepthCombo(-1, 8)); // 无效 color type
    }

    @Test
    @DisplayName("fixPngIhdrBitDepth() - 修复非法 BitDepth")
    void testFixPngIhdrBitDepth() throws IOException {
        byte[] png = createMinimalPng();
        int ihdrOffset = 8;

        // 破坏 bitDepth 为非法值
        png[ihdrOffset + 8 + 8] = 3; // bitDepth 位置，设为非法值 3

        byte[] fixed = ConstraintFixer.fixPngIhdrBitDepth(png, ihdrOffset);

        // 应该修复为合法值
        int newBitDepth = fixed[ihdrOffset + 8 + 8] & 0xFF;
        int colorType = fixed[ihdrOffset + 8 + 9] & 0xFF;
        assertTrue(ConstraintFixer.isValidPngBitDepthCombo(colorType, newBitDepth));
    }

    @Test
    @DisplayName("fixPngIhdrDimensions() - 修复非法尺寸")
    void testFixPngIhdrDimensions() throws IOException {
        byte[] png = createMinimalPng();
        int ihdrOffset = 8;

        // 设置非法尺寸
        ByteBuffer.wrap(png, ihdrOffset + 8, 8).order(ByteOrder.BIG_ENDIAN)
                .putInt(0) // width = 0 (非法)
                .putInt(-100); // height < 0 (非法)

        byte[] fixed = ConstraintFixer.fixPngIhdrDimensions(png, ihdrOffset, 1000);

        ByteBuffer bb = ByteBuffer.wrap(fixed, ihdrOffset + 8, 8).order(ByteOrder.BIG_ENDIAN);
        int width = bb.getInt();
        int height = bb.getInt();

        assertTrue(width >= 1 && width <= 1000);
        assertTrue(height >= 1 && height <= 1000);
    }

    @Test
    @DisplayName("fixPngIhdrDimensions() - 默认最大值")
    void testFixPngIhdrDimensionsDefault() throws IOException {
        byte[] png = createMinimalPng();
        int ihdrOffset = 8;

        // 设置超大尺寸
        ByteBuffer.wrap(png, ihdrOffset + 8, 8).order(ByteOrder.BIG_ENDIAN)
                .putInt(1000000);

        byte[] fixed = ConstraintFixer.fixPngIhdrDimensions(png, ihdrOffset);

        ByteBuffer bb = ByteBuffer.wrap(fixed, ihdrOffset + 8, 4).order(ByteOrder.BIG_ENDIAN);
        int width = bb.getInt();
        assertTrue(width <= 65535);
    }

    @Test
    @DisplayName("ensurePngIend() - 添加缺失的 IEND")
    void testEnsurePngIend() throws IOException {
        byte[] png = createMinimalPng();
        // 截断掉 IEND
        byte[] noIend = new byte[png.length - 12];
        System.arraycopy(png, 0, noIend, 0, noIend.length);

        byte[] fixed = ConstraintFixer.ensurePngIend(noIend);

        // 验证结尾有 IEND
        assertEquals(noIend.length + 12, fixed.length);
        ByteBuffer bb = ByteBuffer.wrap(fixed, fixed.length - 12, 12).order(ByteOrder.BIG_ENDIAN);
        assertEquals(0, bb.getInt()); // length
        assertEquals('I', bb.get());
        assertEquals('E', bb.get());
        assertEquals('N', bb.get());
        assertEquals('D', bb.get());
    }

    @Test
    @DisplayName("ensurePngIend() - 已有 IEND 不重复添加")
    void testEnsurePngIendNoDouble() throws IOException {
        byte[] png = createMinimalPng();
        int originalLength = png.length;

        byte[] fixed = ConstraintFixer.ensurePngIend(png);

        assertEquals(originalLength, fixed.length);
    }

    @Test
    @DisplayName("syncPngChunkLength() - 同步块长度")
    void testSyncPngChunkLength() throws IOException {
        byte[] png = createMinimalPng();
        int ihdrOffset = 8;

        byte[] fixed = ConstraintFixer.syncPngChunkLength(png, ihdrOffset, 20);

        int newLength = ByteBuffer.wrap(fixed, ihdrOffset, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        assertEquals(20, newLength);
    }

    // ==========================================
    // fullFix 综合修复测试
    // ==========================================

    @Test
    @DisplayName("fullFix() - PNG 综合修复")
    void testFullFixPng() throws IOException {
        byte[] png = createMinimalPng();
        // 破坏 magic 和 CRC
        png[0] = 0x00;
        png[png.length - 4] ^= 0xFF;

        PngScanner scanner = new PngScanner();
        ScanResult scanResult = scanner.scan(png);

        byte[] fixed = ConstraintFixer.fullFix(png, scanResult, true);

        // 验证 magic 恢复
        assertEquals((byte) 0x89, fixed[0]);
        assertEquals('P', fixed[1]);
    }

    @Test
    @DisplayName("fullFix() - 未知格式不修改")
    void testFullFixUnknownFormat() {
        byte[] data = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
        ScanResult scanResult = new ScanResult(false, "UNKNOWN", data,
                new java.util.ArrayList<>(), new java.util.ArrayList<>());

        byte[] fixed = ConstraintFixer.fullFix(data, scanResult, false);

        // 未知格式应该返回原数据
        assertEquals(data.length, fixed.length);
    }

    @Test
    @DisplayName("restoreMagic() - PCAP 格式")
    void testRestoreMagicPcap() {
        byte[] data = new byte[100];

        byte[] fixed = ConstraintFixer.restoreMagic(data, "PCAP");

        // 应该使用小端序
        assertEquals((byte) 0xD4, fixed[0]);
    }

    @Test
    @DisplayName("restoreMagic() - 未知格式")
    void testRestoreMagicUnknown() {
        byte[] data = { 0x00, 0x01, 0x02, 0x03 };

        byte[] fixed = ConstraintFixer.restoreMagic(data, "UNKNOWN");

        // 应该返回原数据
        assertEquals(data[0], fixed[0]);
    }

    // ==========================================
    // 边界条件 - 数据太短
    // ==========================================

    @Test
    @DisplayName("边界条件 - ELF 数据太短")
    void testElfDataTooShort() {
        byte[] tooShort = new byte[20];

        // 所有这些方法都应该安全返回原数据
        byte[] result1 = ConstraintFixer.fixElfHeaderEssentials(tooShort);
        byte[] result2 = ConstraintFixer.updateElfPhnum(tooShort, 5, true);
        byte[] result3 = ConstraintFixer.updateElfShnum(tooShort, 5, true);
        byte[] result4 = ConstraintFixer.incrementElfPhnum(tooShort, true);
        byte[] result5 = ConstraintFixer.decrementElfPhnum(tooShort, true);
        byte[] result6 = ConstraintFixer.incrementElfShnum(tooShort, true);
        byte[] result7 = ConstraintFixer.decrementElfShnum(tooShort, true);

        assertEquals(tooShort, result1);
        assertEquals(tooShort, result2);
        assertEquals(tooShort, result3);
        assertEquals(tooShort, result4);
        assertEquals(tooShort, result5);
        assertEquals(tooShort, result6);
        assertEquals(tooShort, result7);
    }

    @Test
    @DisplayName("边界条件 - PCAP 数据太短")
    void testPcapDataTooShort() {
        byte[] tooShort = new byte[2];

        byte[] result1 = ConstraintFixer.restorePcapMagic(tooShort, true);
        byte[] result2 = ConstraintFixer.restorePcapMagic(tooShort);
        byte[] result3 = ConstraintFixer.fixPcapPacketLength(tooShort, 0, 10, 10, false);

        assertEquals(tooShort, result1);
        assertEquals(tooShort, result2);
        assertEquals(tooShort, result3);
    }

    @Test
    @DisplayName("边界条件 - PNG 相关方法数据太短")
    void testPngDataTooShort() {
        byte[] tooShort = new byte[10];

        byte[] result1 = ConstraintFixer.fixPngIhdrBitDepth(tooShort, 0);
        byte[] result2 = ConstraintFixer.fixPngIhdrDimensions(tooShort, 0);
        byte[] result3 = ConstraintFixer.ensurePngIend(tooShort);
        byte[] result4 = ConstraintFixer.syncPngChunkLength(tooShort, 100, 20);

        assertEquals(tooShort, result1);
        assertEquals(tooShort, result2);
        assertEquals(tooShort, result3);
        assertEquals(tooShort, result4);
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
