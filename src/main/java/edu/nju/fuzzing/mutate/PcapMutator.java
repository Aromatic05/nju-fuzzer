package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.binary.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 结构感知型 PCAP 变异器
 *
 * 使用 PcapScanner 解析 seed 数据，提取 packet record 结构，
 * 然后通过 StructureMutator 进行有针对性的变异：
 * 1. 包长度字段变异 (incl_len/orig_len 不一致)
 * 2. Packet 删除/复制/交换
 * 3. 协议头部字段变异 (IP/TCP/UDP)
 * 4. 时间戳攻击
 * 
 * 保留生成模式作为回退
 */
public class PcapMutator implements Mutator {

    private static final int MAGIC_USEC = 0xA1B2C3D4;
    private static final int MAGIC_NSEC = 0xA1B23C4D;

    // Link Types
    private static final int DLT_EN10MB = 1; // Ethernet (大多数解析器的重点)
    
    private final PcapScanner scanner = new PcapScanner();
    private final Random random = new Random();

    @Override
    public Iterator<Testcase> mutate(Seed seed, int energy) {
        int count = Math.max(1, energy);
        byte[] seedData = seed.getData();
        
        // 尝试解析 seed
        ScanResult scanResult = null;
        if (scanner.matches(seedData)) {
            scanResult = scanner.scan(seedData);
        }
        
        final ScanResult finalScanResult = scanResult;

        return new Iterator<Testcase>() {
            private int remaining = count;

            @Override
            public boolean hasNext() {
                return remaining > 0;
            }

            @Override
            public Testcase next() {
                if (remaining <= 0) throw new NoSuchElementException();
                remaining--;

                try {
                    byte[] pcapData;
                    
                    // 如果成功解析了 seed，使用结构感知变异
                    if (finalScanResult != null && finalScanResult.isValid()) {
                        pcapData = mutateFromSeed(finalScanResult);
                    } else {
                        // 回退到生成模式
                        pcapData = generatePcap();
                    }
                    
                    return new Testcase(pcapData, seed, "structure:PCAP");
                } catch (Exception e) {
                    try {
                        return new Testcase(generatePcap(), seed, "grammar:PCAP");
                    } catch (IOException ex) {
                        throw new RuntimeException(ex);
                    }
                }
            }
        };
    }
    
    /**
     * 基于解析的 seed 进行结构感知变异
     */
    private byte[] mutateFromSeed(ScanResult result) throws IOException {
        byte[] data = result.getOriginalData().clone();
        List<BinaryChunk> chunks = result.getChunks();
        ByteOrder order = result.getByteOrder();
        ThreadLocalRandom rand = ThreadLocalRandom.current();
        
        // 选择变异策略
        int strategy = rand.nextInt(10);
        
        if (strategy < 2 && chunks.size() > 2) {
            // 20%: Packet 操作 (删除、复制、交换)
            data = mutatePacketStructure(data, chunks, rand);
        } else if (strategy < 5) {
            // 30%: 长度字段变异
            data = mutateLengthFields(data, chunks, order, rand);
        } else if (strategy < 7) {
            // 20%: 协议头部变异 (IP checksum, flags)
            data = mutateProtocolFields(data, chunks, rand);
        } else if (strategy < 9) {
            // 20%: 时间戳攻击
            data = mutateTimestamps(data, chunks, order, rand);
        } else {
            // 10%: 数据区域位翻转
            data = mutateDataRegions(data, chunks, rand);
        }
        
        // 确保 Magic 正确
        if (rand.nextInt(10) > 1) {
            data = ConstraintFixer.restorePcapMagic(data);
        }
        
        return data;
    }
    
    /**
     * Packet 结构变异：删除/复制/交换
     */
    private byte[] mutatePacketStructure(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) throws IOException {
        // 找到 packet chunks (排除 GLOBAL_HEADER)
        List<BinaryChunk> packets = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (chunk.getChunkType().startsWith("PACKET_")) {
                packets.add(chunk);
            }
        }
        
        if (packets.isEmpty()) {
            return data;
        }
        
        int op = rand.nextInt(3);
        
        if (op == 0 && packets.size() > 1) {
            // 删除一个 packet
            BinaryChunk toDelete = packets.get(rand.nextInt(packets.size()));
            return StructureMutator.deleteChunk(data, toDelete);
            
        } else if (op == 1) {
            // 复制一个 packet
            BinaryChunk toDuplicate = packets.get(rand.nextInt(packets.size()));
            return StructureMutator.duplicateChunk(data, toDuplicate);
            
        } else if (op == 2 && packets.size() >= 2) {
            // 交换两个 packet
            int idx1 = rand.nextInt(packets.size());
            int idx2 = rand.nextInt(packets.size());
            while (idx2 == idx1) idx2 = rand.nextInt(packets.size());
            return StructureMutator.swapChunks(data, packets.get(idx1), packets.get(idx2));
        }
        
        return data;
    }
    
    /**
     * 长度字段变异 (incl_len / orig_len 不一致)
     */
    private byte[] mutateLengthFields(byte[] data, List<BinaryChunk> chunks, ByteOrder order, ThreadLocalRandom rand) {
        // 找有 incl_len 或 ip_total_length 字段的 chunk
        List<FieldMapping> lengthFields = new ArrayList<>();
        
        for (BinaryChunk chunk : chunks) {
            for (FieldMapping field : chunk.getFields()) {
                if (field.getType() == FieldType.LENGTH) {
                    // 转换为全局偏移
                    int globalOffset = chunk.getStartOffset() + field.getOffset();
                    lengthFields.add(new FieldMapping(globalOffset, field.getLength(), 
                            field.getType(), field.getByteOrder(), field.getName()));
                }
            }
        }
        
        if (lengthFields.isEmpty()) return data;
        
        FieldMapping target = lengthFields.get(rand.nextInt(lengthFields.size()));
        return StructureMutator.mutateLength(data, target, rand);
    }
    
    /**
     * 协议头部字段变异 (IP checksum, flags)
     */
    private byte[] mutateProtocolFields(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // 找到协议相关字段
        List<FieldMapping> protoFields = new ArrayList<>();
        
        for (BinaryChunk chunk : chunks) {
            for (FieldMapping field : chunk.getFields()) {
                String name = field.getName();
                if (name != null && (name.contains("checksum") || name.contains("flags") || 
                                     name.contains("protocol") || name.contains("port"))) {
                    int globalOffset = chunk.getStartOffset() + field.getOffset();
                    protoFields.add(new FieldMapping(globalOffset, field.getLength(), 
                            field.getType(), field.getByteOrder(), field.getName()));
                }
            }
        }
        
        if (protoFields.isEmpty()) return data;
        
        byte[] result = data.clone();
        FieldMapping target = protoFields.get(rand.nextInt(protoFields.size()));
        
        // 随机修改字段值
        for (int i = 0; i < target.getLength() && target.getOffset() + i < result.length; i++) {
            if (rand.nextBoolean()) {
                result[target.getOffset() + i] ^= (1 << rand.nextInt(8));
            }
        }
        
        return result;
    }
    
    /**
     * 时间戳攻击 (非单调/极端值)
     */
    private byte[] mutateTimestamps(byte[] data, List<BinaryChunk> chunks, ByteOrder order, ThreadLocalRandom rand) {
        byte[] result = data.clone();
        
        for (BinaryChunk chunk : chunks) {
            if (chunk.getChunkType().startsWith("PACKET_")) {
                // 找到 ts_sec 字段
                for (FieldMapping field : chunk.getFields()) {
                    if ("ts_sec".equals(field.getName()) && rand.nextBoolean()) {
                        int globalOffset = chunk.getStartOffset() + field.getOffset();
                        
                        // 写入极端时间戳
                        int evilTs = rand.nextBoolean() ? 0 : Integer.MAX_VALUE;
                        ByteBuffer bb = ByteBuffer.wrap(result);
                        bb.order(order);
                        if (globalOffset + 4 <= result.length) {
                            bb.putInt(globalOffset, evilTs);
                        }
                        break;
                    }
                }
            }
        }
        
        return result;
    }
    
    /**
     * 数据区域位翻转
     */
    private byte[] mutateDataRegions(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        List<BinaryChunk> withData = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (chunk.getDataLength() > 0 && chunk.getChunkType().startsWith("PACKET_")) {
                withData.add(chunk);
            }
        }
        
        if (withData.isEmpty()) return data;
        
        BinaryChunk target = withData.get(rand.nextInt(withData.size()));
        int dataStart = target.getStartOffset() + target.getDataOffset();
        int dataLen = target.getDataLength();
        
        if (dataStart + dataLen > data.length || dataLen <= 0) return data;
        
        return StructureMutator.bitFlipDataRegion(data, dataStart, dataLen, rand);
    }

    private byte[] generatePcap() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        // 1. Global Header Config
        boolean bigEndian = rand.nextBoolean(); // PCAP 容器的字节序
        int magic = rand.nextBoolean() ? MAGIC_USEC : MAGIC_NSEC;
        int snapLen = rand.nextInt(20) == 0 ? 65535 : (rand.nextInt(2000) + 64);

        // 我们主要专注于 Ethernet，因为它是绝大多数 DPI 测试的基础
        int linkType = DLT_EN10MB;

        // Write Global Header
        writeInt(baos, magic, bigEndian);
        writeShort(baos, (short) 2, bigEndian);
        writeShort(baos, (short) 4, bigEndian);
        writeInt(baos, 0, bigEndian);
        writeInt(baos, 0, bigEndian);
        writeInt(baos, snapLen, bigEndian);
        writeInt(baos, linkType, bigEndian);

        // 2. Packets Generation
        int pktCount = 1 + rand.nextInt(30);
        long currentTs = System.currentTimeMillis() / 1000;

        for (int i = 0; i < pktCount; i++) {
            // [Attack] Timestamp Fuzzing: 偶尔时间倒流，或跳跃极大
            if (rand.nextInt(10) == 0) currentTs -= rand.nextInt(10000);
            else currentTs += rand.nextInt(5);

            byte[] payload = generateEthernetPayload(rand);

            // 计算长度
            int realLen = payload.length;
            int inclLen = realLen;
            int origLen = realLen;

            // [Attack] PCAP Length Corruption
            int strategy = rand.nextInt(100);
            if (strategy < 10) {
                // Buffer truncation: incl_len < real_len
                // 告诉解析器有 100 字节，实际只写了 50 字节 -> 解析下一个包头时错位
                inclLen = Math.max(0, realLen - rand.nextInt(50));
            } else if (strategy < 20) {
                // Logical error: incl_len > snapLen
                inclLen = snapLen + rand.nextInt(100);
            } else if (strategy < 30) {
                // Logical error: incl_len > orig_len (impossible in reality)
                origLen = inclLen - 10;
            }

            // Write Packet Header
            writeInt(baos, (int) currentTs, bigEndian);
            writeInt(baos, rand.nextInt(1000000), bigEndian); // usec
            writeInt(baos, inclLen, bigEndian);
            writeInt(baos, origLen, bigEndian);

            // Write Payload
            // 注意：如果 inclLen < payload.length，我们只写 inclLen 这么多吗？
            // 实际上为了制造文件格式错误，我们可能写入 payload.length，但 Header 说只有 inclLen
            // 这会导致解析器读取下一个 Header 时读到 payload 的剩余部分（垃圾数据）
            // 这里我们模拟正常的截断行为，或者恶意的错位

            if (strategy < 10) {
                // 恶意错位：写入的数据量 != inclLen
                baos.write(payload);
            } else {
                // 正常写入：写入量 = inclLen (如果 payload 不够补0，多了截断)
                if (payload.length >= inclLen) {
                    baos.write(payload, 0, inclLen);
                } else {
                    baos.write(payload);
                    for(int k=0; k<inclLen-payload.length; k++) baos.write(0);
                }
            }
        }

        return baos.toByteArray();
    }

    /**
     * 构造伪造的 Ethernet -> IP -> TCP/UDP 协议栈
     * 网络协议字段必须使用 Big Endian (Network Byte Order)
     */
    private byte[] generateEthernetPayload(ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream pkt = new ByteArrayOutputStream();

        // --- Ethernet Header (14 bytes) ---
        byte[] destMac = new byte[6]; rand.nextBytes(destMac);
        byte[] srcMac = new byte[6]; rand.nextBytes(srcMac);
        pkt.write(destMac);
        pkt.write(srcMac);

        // EtherType
        int etherType;
        if (rand.nextInt(10) < 8) {
            etherType = 0x0800; // IPv4 (Most common)
        } else if (rand.nextInt(5) == 0) {
            etherType = 0x86DD; // IPv6
        } else {
            etherType = rand.nextInt(0xFFFF); // Fuzzing unknown protocols
        }
        writeNetworkShort(pkt, (short) etherType); // Big Endian!

        // --- IP Header ---
        if (etherType == 0x0800) {
            generateIPv4(pkt, rand);
        } else if (etherType == 0x86DD) {
            generateIPv6(pkt, rand);
        } else {
            // Random payload for unknown protocol
            byte[] garbage = new byte[rand.nextInt(100)];
            rand.nextBytes(garbage);
            pkt.write(garbage);
        }

        return pkt.toByteArray();
    }

    private void generateIPv4(ByteArrayOutputStream pkt, ThreadLocalRandom rand) throws IOException {
        // Version(4) + IHL(4)
        // [Attack] IHL < 5 (Header too short)
        int ihl = rand.nextInt(20) == 0 ? 4 : 5;
        pkt.write((4 << 4) | ihl);

        // TOS
        pkt.write(0);

        // Total Length
        // [Attack] Mismatch with PCAP length
        int totalLen = rand.nextInt(1500);
        writeNetworkShort(pkt, (short) totalLen);

        // ID, Flags, Frag Offset
        writeNetworkShort(pkt, (short) rand.nextInt(65535));
        // [Attack] Teardrop (overlapping fragments) simulation
        int fragOff = rand.nextInt(20) == 0 ? 0x2000 : 0; // MF flag
        writeNetworkShort(pkt, (short) fragOff);

        // TTL
        pkt.write(64);

        // Protocol
        int proto = rand.nextBoolean() ? 6 : 17;
        pkt.write(proto);

        // Checksum (Random is fine for fuzzing, parsers often ignore or error out gracefully)
        writeNetworkShort(pkt, (short) rand.nextInt(65535));

        // Src/Dst IP
        pkt.write(new byte[4]); // Src
        pkt.write(new byte[4]); // Dst

        // --- Transport Layer ---
        generateTransport(pkt, proto, rand);
    }

    private void generateIPv6(ByteArrayOutputStream pkt, ThreadLocalRandom rand) throws IOException {
        // Ver(4) + Traffic Class(8) + Flow Label(20)
        pkt.write(0x60);
        pkt.write(0);
        pkt.write(0);
        pkt.write(0);

        // Payload Len
        writeNetworkShort(pkt, (short) rand.nextInt(1500));

        // Next Header
        int nextHeader = rand.nextBoolean() ? 6 : 17;
        pkt.write(nextHeader);

        // Hop Limit
        pkt.write(64);

        // Src/Dst Address (16 bytes each)
        pkt.write(new byte[32]);

        generateTransport(pkt, nextHeader, rand);
    }

    private void generateTransport(ByteArrayOutputStream pkt, int proto, ThreadLocalRandom rand) throws IOException {
        // [Attack] Fuzzing TCP/UDP ports and flags
        int srcPort = rand.nextInt(65535);
        int dstPort = rand.nextInt(65535);

        writeNetworkShort(pkt, (short) srcPort);
        writeNetworkShort(pkt, (short) dstPort);

        if (proto == 17) { // UDP
            writeNetworkShort(pkt, (short) (8 + rand.nextInt(100))); // Len
            writeNetworkShort(pkt, (short) 0); // Checksum
            // UDP Data
            byte[] data = new byte[rand.nextInt(50)];
            rand.nextBytes(data);
            pkt.write(data);
        } else { // TCP
            // Seq, Ack
            writeInt(pkt, rand.nextInt(), false); // Endianness matters less here for structure
            writeInt(pkt, rand.nextInt(), false);

            // Data Offset (4) + Reserved (3) + Flags (9)
            // [Attack] Data Offset < 5 (Header too short)
            int dataOffset = rand.nextInt(10) == 0 ? 4 : 5;
            short flags = (short) rand.nextInt(0x1FF); // Syn, Fin, Rst, etc.
            writeNetworkShort(pkt, (short) ((dataOffset << 12) | flags));

            // Window, Checksum, Urg Ptr
            writeNetworkShort(pkt, (short) 8192);
            writeNetworkShort(pkt, (short) 0);
            writeNetworkShort(pkt, (short) 0);

            // TCP Options & Data
            if (dataOffset > 5) {
                // [Attack] Malformed Options
                pkt.write(0); // EOL
                pkt.write(0);
                pkt.write(0);
                pkt.write(0);
            }
        }
    }

    // --- Helpers ---

    private void writeInt(ByteArrayOutputStream out, int v, boolean bigEndian) {
        if (bigEndian) {
            out.write((v >>> 24) & 0xFF);
            out.write((v >>> 16) & 0xFF);
            out.write((v >>>  8) & 0xFF);
            out.write((v >>>  0) & 0xFF);
        } else {
            out.write((v >>>  0) & 0xFF);
            out.write((v >>>  8) & 0xFF);
            out.write((v >>> 16) & 0xFF);
            out.write((v >>> 24) & 0xFF);
        }
    }

    private void writeShort(ByteArrayOutputStream out, short v, boolean bigEndian) {
        if (bigEndian) {
            out.write((v >>> 8) & 0xFF);
            out.write((v >>> 0) & 0xFF);
        } else {
            out.write((v >>> 0) & 0xFF);
            out.write((v >>> 8) & 0xFF);
        }
    }

    // 网络协议必须使用 Big Endian
    private void writeNetworkShort(ByteArrayOutputStream out, short v) {
        out.write((v >>> 8) & 0xFF);
        out.write((v >>> 0) & 0xFF);
    }
}