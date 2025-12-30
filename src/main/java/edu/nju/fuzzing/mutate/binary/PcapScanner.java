package edu.nju.fuzzing.mutate.binary;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * PCAP 格式扫描器
 * 
 * PCAP 结构：
 * - Global Header (24 bytes)
 * - Packet Records (Packet Header + Packet Data) ...
 * 
 * 每个 Packet Header (16 bytes):
 * - ts_sec (4 bytes)
 * - ts_usec (4 bytes)  
 * - incl_len (4 bytes) - 实际捕获的长度
 * - orig_len (4 bytes) - 原始包长度
 */
public class PcapScanner implements FormatScanner {
    
    // Magic Numbers
    public static final int MAGIC_USEC_BE = 0xA1B2C3D4;
    public static final int MAGIC_USEC_LE = 0xD4C3B2A1;
    public static final int MAGIC_NSEC_BE = 0xA1B23C4D;
    public static final int MAGIC_NSEC_LE = 0x4D3CB2A1;
    
    @Override
    public String getFormatName() {
        return "PCAP";
    }
    
    @Override
    public boolean matches(byte[] data) {
        if (data == null || data.length < 4) return false;
        
        int magic = ByteBuffer.wrap(data, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        return magic == MAGIC_USEC_BE || magic == MAGIC_USEC_LE ||
               magic == MAGIC_NSEC_BE || magic == MAGIC_NSEC_LE;
    }
    
    @Override
    public ScanResult scan(byte[] data) {
        List<BinaryChunk> chunks = new ArrayList<>();
        List<FieldMapping> globalFields = new ArrayList<>();
        
        if (!matches(data) || data.length < 24) {
            return new ScanResult(false, "PCAP", data, chunks, globalFields);
        }
        
        // 确定字节序
        int magicBe = ByteBuffer.wrap(data, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        ByteOrder order = (magicBe == MAGIC_USEC_BE || magicBe == MAGIC_NSEC_BE) 
                          ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        
        ByteBuffer bb = ByteBuffer.wrap(data).order(order);
        
        // 解析 Global Header
        int magic = bb.getInt(0);
        int versionMajor = bb.getShort(4) & 0xFFFF;
        int versionMinor = bb.getShort(6) & 0xFFFF;
        int snapLen = bb.getInt(16);
        int linkType = bb.getInt(20);
        
        // 添加全局字段
        globalFields.add(new FieldMapping(0, 4, FieldType.MAGIC, order, "magic", magic));
        globalFields.add(new FieldMapping(4, 2, FieldType.VERSION, order, "version_major", versionMajor));
        globalFields.add(new FieldMapping(6, 2, FieldType.VERSION, order, "version_minor", versionMinor));
        globalFields.add(new FieldMapping(8, 4, FieldType.OFFSET, order, "thiszone"));
        globalFields.add(new FieldMapping(12, 4, FieldType.FLAGS, order, "sigfigs"));
        globalFields.add(new FieldMapping(16, 4, FieldType.LENGTH, order, "snaplen", snapLen));
        globalFields.add(new FieldMapping(20, 4, FieldType.TYPE, order, "linktype", linkType));
        
        // 创建 Global Header 块
        byte[] headerData = new byte[24];
        System.arraycopy(data, 0, headerData, 0, 24);
        BinaryChunk headerChunk = new BinaryChunk(0, 24, "GLOBAL_HEADER", headerData);
        headerChunk.setCritical(true);
        headerChunk.setDataOffset(24);
        headerChunk.setDataLength(0);
        for (FieldMapping f : globalFields) {
            headerChunk.addField(f);
        }
        chunks.add(headerChunk);
        
        // 解析 Packet Records
        int offset = 24;
        int packetIndex = 0;
        
        while (offset + 16 <= data.length) {
            BinaryChunk packet = parsePacket(data, offset, order, packetIndex);
            if (packet == null) {
                break;
            }
            
            chunks.add(packet);
            offset = packet.getEndOffset();
            packetIndex++;
            
            // 安全限制
            if (packetIndex > 10000) break;
        }
        
        ScanResult result = new ScanResult(true, "PCAP", data, chunks, globalFields);
        result.setByteOrder(order);
        result.setHeaderSize(24);
        
        return result;
    }
    
    /**
     * 解析单个 Packet Record
     */
    private BinaryChunk parsePacket(byte[] data, int offset, ByteOrder order, int index) {
        if (offset + 16 > data.length) return null;
        
        ByteBuffer bb = ByteBuffer.wrap(data).order(order);
        
        int tsSec = bb.getInt(offset);
        int tsUsec = bb.getInt(offset + 4);
        int inclLen = bb.getInt(offset + 8);
        int origLen = bb.getInt(offset + 12);
        
        // 防御性检查
        if (inclLen < 0) inclLen = 0;
        if (inclLen > data.length - offset - 16) {
            inclLen = data.length - offset - 16;
        }
        
        int totalLength = 16 + inclLen;
        
        byte[] rawData = new byte[totalLength];
        System.arraycopy(data, offset, rawData, 0, Math.min(totalLength, data.length - offset));
        
        String chunkType = String.format("PACKET_%d", index);
        BinaryChunk chunk = new BinaryChunk(offset, totalLength, chunkType, rawData);
        chunk.setCritical(false);
        chunk.setDataOffset(16);
        chunk.setDataLength(inclLen);
        
        // 添加字段映射
        chunk.addField(new FieldMapping(0, 4, FieldType.FLAGS, order, "ts_sec", tsSec));
        chunk.addField(new FieldMapping(4, 4, FieldType.FLAGS, order, "ts_usec", tsUsec));
        chunk.addField(new FieldMapping(8, 4, FieldType.LENGTH, order, "incl_len", inclLen));
        chunk.addField(new FieldMapping(12, 4, FieldType.LENGTH, order, "orig_len", origLen));
        
        if (inclLen > 0) {
            chunk.addField(new FieldMapping(16, inclLen, FieldType.DATA, order, "packet_data"));
            
            // 尝试解析 Ethernet/IP 头部
            parsePacketInternals(chunk, rawData, 16, inclLen, order);
        }
        
        return chunk;
    }
    
    /**
     * 解析包内部结构（Ethernet -> IP -> TCP/UDP）
     */
    private void parsePacketInternals(BinaryChunk chunk, byte[] rawData, int dataOffset, int dataLen, ByteOrder order) {
        if (dataLen < 14) return;  // 最小 Ethernet 头
        
        // Ethernet Header (14 bytes)
        // 6 bytes dst MAC + 6 bytes src MAC + 2 bytes EtherType
        int etherType = ((rawData[dataOffset + 12] & 0xFF) << 8) | (rawData[dataOffset + 13] & 0xFF);
        
        chunk.addField(new FieldMapping(dataOffset, 6, FieldType.DATA, ByteOrder.BIG_ENDIAN, "dst_mac"));
        chunk.addField(new FieldMapping(dataOffset + 6, 6, FieldType.DATA, ByteOrder.BIG_ENDIAN, "src_mac"));
        chunk.addField(new FieldMapping(dataOffset + 12, 2, FieldType.TYPE, ByteOrder.BIG_ENDIAN, "ethertype", etherType));
        
        if (etherType == 0x0800 && dataLen >= 34) {
            // IPv4
            parseIPv4(chunk, rawData, dataOffset + 14, dataLen - 14);
        } else if (etherType == 0x86DD && dataLen >= 54) {
            // IPv6
            parseIPv6(chunk, rawData, dataOffset + 14, dataLen - 14);
        }
    }
    
    /**
     * 解析 IPv4 头部
     */
    private void parseIPv4(BinaryChunk chunk, byte[] data, int offset, int len) {
        if (len < 20) return;
        
        int ihl = (data[offset] & 0x0F) * 4;
        int totalLen = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        int protocol = data[offset + 9] & 0xFF;
        
        chunk.addField(new FieldMapping(offset, 1, FieldType.FLAGS, ByteOrder.BIG_ENDIAN, 
                       "ip_ver_ihl", data[offset] & 0xFF));
        chunk.addField(new FieldMapping(offset + 2, 2, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, 
                       "ip_total_length", totalLen));
        chunk.addField(new FieldMapping(offset + 9, 1, FieldType.TYPE, ByteOrder.BIG_ENDIAN, 
                       "ip_protocol", protocol));
        chunk.addField(new FieldMapping(offset + 10, 2, FieldType.CHECKSUM, ByteOrder.BIG_ENDIAN, 
                       "ip_checksum"));
        chunk.addField(new FieldMapping(offset + 12, 4, FieldType.DATA, ByteOrder.BIG_ENDIAN, 
                       "src_ip"));
        chunk.addField(new FieldMapping(offset + 16, 4, FieldType.DATA, ByteOrder.BIG_ENDIAN, 
                       "dst_ip"));
        
        if (len >= ihl + 4) {
            if (protocol == 6) {
                // TCP
                parseTCP(chunk, data, offset + ihl, len - ihl);
            } else if (protocol == 17) {
                // UDP
                parseUDP(chunk, data, offset + ihl, len - ihl);
            }
        }
    }
    
    /**
     * 解析 IPv6 头部
     */
    private void parseIPv6(BinaryChunk chunk, byte[] data, int offset, int len) {
        if (len < 40) return;
        
        int payloadLen = ((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF);
        int nextHeader = data[offset + 6] & 0xFF;
        
        chunk.addField(new FieldMapping(offset + 4, 2, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, 
                       "ipv6_payload_length", payloadLen));
        chunk.addField(new FieldMapping(offset + 6, 1, FieldType.TYPE, ByteOrder.BIG_ENDIAN, 
                       "ipv6_next_header", nextHeader));
    }
    
    /**
     * 解析 TCP 头部
     */
    private void parseTCP(BinaryChunk chunk, byte[] data, int offset, int len) {
        if (len < 20) return;
        
        int srcPort = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        int dstPort = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        
        chunk.addField(new FieldMapping(offset, 2, FieldType.DATA, ByteOrder.BIG_ENDIAN, 
                       "tcp_src_port", srcPort));
        chunk.addField(new FieldMapping(offset + 2, 2, FieldType.DATA, ByteOrder.BIG_ENDIAN, 
                       "tcp_dst_port", dstPort));
        chunk.addField(new FieldMapping(offset + 16, 2, FieldType.CHECKSUM, ByteOrder.BIG_ENDIAN, 
                       "tcp_checksum"));
    }
    
    /**
     * 解析 UDP 头部
     */
    private void parseUDP(BinaryChunk chunk, byte[] data, int offset, int len) {
        if (len < 8) return;
        
        int srcPort = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        int dstPort = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        int udpLen = ((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF);
        
        chunk.addField(new FieldMapping(offset, 2, FieldType.DATA, ByteOrder.BIG_ENDIAN, 
                       "udp_src_port", srcPort));
        chunk.addField(new FieldMapping(offset + 2, 2, FieldType.DATA, ByteOrder.BIG_ENDIAN, 
                       "udp_dst_port", dstPort));
        chunk.addField(new FieldMapping(offset + 4, 2, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, 
                       "udp_length", udpLen));
        chunk.addField(new FieldMapping(offset + 6, 2, FieldType.CHECKSUM, ByteOrder.BIG_ENDIAN, 
                       "udp_checksum"));
    }
}
