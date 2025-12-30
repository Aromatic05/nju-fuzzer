package edu.nju.fuzzing.mutate.binary;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
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
 * PcapScanner 单元测试
 * 
 * 验证点：
 * 1. Magic 识别 (Big/Little Endian)
 * 2. Global Header 解析
 * 3. Packet Record 解析
 * 4. 协议头部解析 (Ethernet/IP/TCP/UDP)
 */
class PcapScannerTest {

    private PcapScanner scanner;

    @BeforeEach
    void setUp() {
        scanner = new PcapScanner();
    }

    // ==========================================
    // Magic 识别测试
    // ==========================================

    @Test
    @DisplayName("matches() - Little Endian Magic (0xD4C3B2A1)")
    void testMatchesLittleEndianMagic() {
        byte[] pcap = createMinimalPcap(false);
        assertTrue(scanner.matches(pcap));
    }

    @Test
    @DisplayName("matches() - Big Endian Magic (0xA1B2C3D4)")
    void testMatchesBigEndianMagic() {
        byte[] pcap = createMinimalPcap(true);
        assertTrue(scanner.matches(pcap));
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

    // ==========================================
    // Global Header 解析测试
    // ==========================================

    @Test
    @DisplayName("scan() - 解析 Global Header")
    void testScanGlobalHeader() {
        byte[] pcap = createMinimalPcap(false);
        ScanResult result = scanner.scan(pcap);

        assertTrue(result.isValid());
        assertEquals("PCAP", result.getFormatType());

        List<BinaryChunk> chunks = result.getChunks();
        assertFalse(chunks.isEmpty());

        BinaryChunk header = chunks.get(0);
        assertEquals("GLOBAL_HEADER", header.getChunkType());
        assertTrue(header.isCritical());
    }

    @Test
    @DisplayName("scan() - 字节序正确检测")
    void testByteOrderDetection() {
        // Little Endian
        byte[] pcapLe = createMinimalPcap(false);
        ScanResult resultLe = scanner.scan(pcapLe);
        assertEquals(ByteOrder.LITTLE_ENDIAN, resultLe.getByteOrder());

        // Big Endian
        byte[] pcapBe = createMinimalPcap(true);
        ScanResult resultBe = scanner.scan(pcapBe);
        assertEquals(ByteOrder.BIG_ENDIAN, resultBe.getByteOrder());
    }

    @Test
    @DisplayName("scan() - Global Header 字段映射")
    void testGlobalHeaderFields() {
        byte[] pcap = createMinimalPcap(false);
        ScanResult result = scanner.scan(pcap);

        List<FieldMapping> globalFields = result.getGlobalFields();
        assertFalse(globalFields.isEmpty());

        // 验证必要字段
        boolean hasMagic = globalFields.stream()
            .anyMatch(f -> "magic".equals(f.getName()) && f.getType() == FieldType.MAGIC);
        assertTrue(hasMagic, "应该有 magic 字段");

        boolean hasSnaplen = globalFields.stream()
            .anyMatch(f -> "snaplen".equals(f.getName()) && f.getType() == FieldType.LENGTH);
        assertTrue(hasSnaplen, "应该有 snaplen 字段");
    }

    // ==========================================
    // Packet Record 解析测试
    // ==========================================

    @Test
    @DisplayName("scan() - 解析 Packet Records")
    void testScanPacketRecords() {
        byte[] pcap = createPcapWithPackets(false, 3);
        ScanResult result = scanner.scan(pcap);

        assertTrue(result.isValid());

        // 应该有 1 个 Global Header + 3 个 Packets
        long packetCount = result.getChunks().stream()
            .filter(c -> c.getChunkType().startsWith("PACKET_"))
            .count();
        assertEquals(3, packetCount);
    }

    @Test
    @DisplayName("scan() - Packet Header 字段映射")
    void testPacketHeaderFields() {
        byte[] pcap = createPcapWithPackets(false, 1);
        ScanResult result = scanner.scan(pcap);

        BinaryChunk packet = result.getChunks().stream()
            .filter(c -> c.getChunkType().startsWith("PACKET_"))
            .findFirst()
            .orElse(null);
        assertNotNull(packet);

        List<FieldMapping> fields = packet.getFields();

        // 验证 incl_len 字段
        boolean hasInclLen = fields.stream()
            .anyMatch(f -> "incl_len".equals(f.getName()) && f.getType() == FieldType.LENGTH);
        assertTrue(hasInclLen, "应该有 incl_len 字段");

        // 验证 orig_len 字段
        boolean hasOrigLen = fields.stream()
            .anyMatch(f -> "orig_len".equals(f.getName()) && f.getType() == FieldType.LENGTH);
        assertTrue(hasOrigLen, "应该有 orig_len 字段");
    }

    // ==========================================
    // 协议头部解析测试
    // ==========================================

    @Test
    @DisplayName("scan() - Ethernet Header 解析")
    void testEthernetParsing() {
        byte[] pcap = createPcapWithEthernetPacket(false);
        ScanResult result = scanner.scan(pcap);

        BinaryChunk packet = result.getChunks().stream()
            .filter(c -> c.getChunkType().startsWith("PACKET_"))
            .findFirst()
            .orElse(null);
        assertNotNull(packet);

        // 验证 ethertype 字段
        boolean hasEthertype = packet.getFields().stream()
            .anyMatch(f -> "ethertype".equals(f.getName()));
        assertTrue(hasEthertype, "应该有 ethertype 字段");
    }

    @Test
    @DisplayName("scan() - IPv4 Header 解析")
    void testIPv4Parsing() {
        byte[] pcap = createPcapWithIPv4Packet(false);
        ScanResult result = scanner.scan(pcap);

        BinaryChunk packet = result.getChunks().stream()
            .filter(c -> c.getChunkType().startsWith("PACKET_"))
            .findFirst()
            .orElse(null);
        assertNotNull(packet);

        // 验证 IP checksum 字段
        boolean hasIpChecksum = packet.getFields().stream()
            .anyMatch(f -> "ip_checksum".equals(f.getName()) && f.getType() == FieldType.CHECKSUM);
        assertTrue(hasIpChecksum, "应该有 ip_checksum 字段");
    }

    // ==========================================
    // 边界条件测试
    // ==========================================

    @Test
    @DisplayName("scan() - 无效数据返回无效结果")
    void testScanInvalidData() {
        byte[] invalid = {0x00, 0x01, 0x02, 0x03};
        ScanResult result = scanner.scan(invalid);
        assertFalse(result.isValid());
    }

    @Test
    @DisplayName("scan() - 仅 Global Header (无 Packets)")
    void testScanGlobalHeaderOnly() {
        byte[] pcap = createMinimalPcap(false);
        ScanResult result = scanner.scan(pcap);

        assertTrue(result.isValid());
        // 仅有 Global Header
        assertEquals(1, result.getChunks().size());
    }

    @Test
    @DisplayName("getFormatName() - 返回 PCAP")
    void testGetFormatName() {
        assertEquals("PCAP", scanner.getFormatName());
    }

    // ==========================================
    // 辅助方法
    // ==========================================

    private byte[] createMinimalPcap(boolean bigEndian) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteOrder order = bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;

        // Magic Number
        writeInt(baos, 0xA1B2C3D4, order);
        // Version Major/Minor
        writeShort(baos, (short) 2, order);
        writeShort(baos, (short) 4, order);
        // Reserved (thiszone, sigfigs)
        writeInt(baos, 0, order);
        writeInt(baos, 0, order);
        // Snaplen
        writeInt(baos, 65535, order);
        // Link Type (Ethernet)
        writeInt(baos, 1, order);

        return baos.toByteArray();
    }

    private byte[] createPcapWithPackets(boolean bigEndian, int packetCount) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteOrder order = bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;

        // Global Header
        writeBytes(baos, createMinimalPcap(bigEndian));

        // Packets
        for (int i = 0; i < packetCount; i++) {
            byte[] payload = new byte[64];
            
            // Packet Header
            writeInt(baos, (int) (System.currentTimeMillis() / 1000), order); // ts_sec
            writeInt(baos, 0, order);  // ts_usec
            writeInt(baos, payload.length, order);  // incl_len
            writeInt(baos, payload.length, order);  // orig_len
            
            // Packet Data
            writeBytes(baos, payload);
        }

        return baos.toByteArray();
    }

    private byte[] createPcapWithEthernetPacket(boolean bigEndian) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteOrder order = bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;

        // Global Header
        writeBytes(baos, createMinimalPcap(bigEndian));

        // Ethernet Frame (14 bytes header + padding)
        ByteArrayOutputStream packet = new ByteArrayOutputStream();
        writeBytes(packet, new byte[6]);  // Dst MAC
        writeBytes(packet, new byte[6]);  // Src MAC
        packet.write(0x08);         // EtherType high (IPv4)
        packet.write(0x00);         // EtherType low
        writeBytes(packet, new byte[46]); // Payload

        byte[] packetData = packet.toByteArray();

        // Packet Header
        writeInt(baos, (int) (System.currentTimeMillis() / 1000), order);
        writeInt(baos, 0, order);
        writeInt(baos, packetData.length, order);
        writeInt(baos, packetData.length, order);

        writeBytes(baos, packetData);

        return baos.toByteArray();
    }

    private byte[] createPcapWithIPv4Packet(boolean bigEndian) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteOrder order = bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;

        // Global Header
        writeBytes(baos, createMinimalPcap(bigEndian));

        // Ethernet + IPv4 Frame
        ByteArrayOutputStream packet = new ByteArrayOutputStream();
        // Ethernet Header
        writeBytes(packet, new byte[6]);  // Dst MAC
        writeBytes(packet, new byte[6]);  // Src MAC
        packet.write(0x08);         // EtherType high (IPv4)
        packet.write(0x00);         // EtherType low
        
        // IPv4 Header (20 bytes)
        packet.write(0x45);         // Version + IHL
        packet.write(0x00);         // TOS
        packet.write(0x00);         // Total Length high
        packet.write(0x28);         // Total Length low (40)
        writeBytes(packet, new byte[4]);  // ID, Flags, Fragment
        packet.write(0x40);         // TTL
        packet.write(0x06);         // Protocol (TCP)
        packet.write(0x00);         // Checksum high
        packet.write(0x00);         // Checksum low
        writeBytes(packet, new byte[8]);  // Src/Dst IP
        
        // Padding
        writeBytes(packet, new byte[20]);

        byte[] packetData = packet.toByteArray();

        // Packet Header
        writeInt(baos, (int) (System.currentTimeMillis() / 1000), order);
        writeInt(baos, 0, order);
        writeInt(baos, packetData.length, order);
        writeInt(baos, packetData.length, order);

        writeBytes(baos, packetData);

        return baos.toByteArray();
    }

    private void writeInt(ByteArrayOutputStream out, int value, ByteOrder order) {
        ByteBuffer bb = ByteBuffer.allocate(4).order(order);
        bb.putInt(value);
        out.write(bb.array(), 0, 4);
    }

    private void writeShort(ByteArrayOutputStream out, short value, ByteOrder order) {
        ByteBuffer bb = ByteBuffer.allocate(2).order(order);
        bb.putShort(value);
        out.write(bb.array(), 0, 2);
    }

    private void writeBytes(ByteArrayOutputStream out, byte[] data) {
        out.write(data, 0, data.length);
    }
}
