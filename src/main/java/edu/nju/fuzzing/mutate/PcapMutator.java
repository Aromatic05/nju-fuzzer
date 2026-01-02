package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.binary.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
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
 * 
 * 攻击向量覆盖：
 * - PCAP 长度欺骗 (5种攻击策略)
 * - IP Total Length 不一致 (4种策略)
 * - IP 分片攻击 (Teardrop/Tiny Fragment/DF+MF)
 * - TCP Data Offset 畸形 (0-4非法值)
 * - TCP Options 攻击 (无限循环/畸形格式)
 * - IPv6 Extension Headers
 * - 时间戳攻击 (负数/非法微秒/极端值)
 * - 应用层协议 (DNS/HTTP/TLS)
 * - Checksum 系统性破坏
 */
public class PcapMutator implements Mutator {

    private static final int MAGIC_USEC = 0xA1B2C3D4;
    private static final int MAGIC_NSEC = 0xA1B23C4D;

    // Link Types
    private static final int DLT_EN10MB = 1; // Ethernet (大多数解析器的重点)

    // 常用端口
    private static final int[] WELL_KNOWN_PORTS = { 53, 80, 443, 22, 25, 110, 143, 8080, 8443 };

    // TLS Handshake 常量
    private static final byte TLS_CONTENT_HANDSHAKE = 0x16;
    @SuppressWarnings("unused")
    private static final byte TLS_VERSION_TLS10 = 0x01;
    @SuppressWarnings("unused")
    private static final byte TLS_VERSION_TLS11 = 0x02;
    private static final byte TLS_VERSION_TLS12 = 0x03;

    private final PcapScanner scanner = new PcapScanner();

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
                if (remaining <= 0)
                    throw new NoSuchElementException();
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
    private byte[] mutatePacketStructure(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand)
            throws IOException {
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
            while (idx2 == idx1)
                idx2 = rand.nextInt(packets.size());
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

        if (lengthFields.isEmpty())
            return data;

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

        if (protoFields.isEmpty())
            return data;

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
     * 时间戳攻击 (非单调/极端值/负数/非法微秒)
     */
    private byte[] mutateTimestamps(byte[] data, List<BinaryChunk> chunks, ByteOrder order, ThreadLocalRandom rand) {
        byte[] result = data.clone();

        for (BinaryChunk chunk : chunks) {
            if (chunk.getChunkType().startsWith("PACKET_")) {
                for (FieldMapping field : chunk.getFields()) {
                    int globalOffset = chunk.getStartOffset() + field.getOffset();
                    ByteBuffer bb = ByteBuffer.wrap(result);
                    bb.order(order);

                    // ts_sec 攻击
                    if ("ts_sec".equals(field.getName()) && rand.nextInt(5) == 0) {
                        int attackType = rand.nextInt(5);
                        int evilTs;

                        if (attackType == 0) {
                            evilTs = 0; // 1970-01-01
                        } else if (attackType == 1) {
                            evilTs = Integer.MAX_VALUE; // 2038 年问题
                        } else if (attackType == 2) {
                            evilTs = -rand.nextInt(100000); // 负数（1970 年之前）
                        } else if (attackType == 3) {
                            evilTs = Integer.MIN_VALUE; // 最小负数
                        } else {
                            evilTs = rand.nextInt(); // 随机值
                        }

                        if (globalOffset + 4 <= result.length) {
                            bb.putInt(globalOffset, evilTs);
                        }
                    }

                    // ts_usec 攻击（非法微秒值）
                    if ("ts_usec".equals(field.getName()) && rand.nextInt(5) == 0) {
                        int evilUsec;
                        if (rand.nextBoolean()) {
                            // > 1000000 (非法)
                            evilUsec = 1000000 + rand.nextInt(1000000);
                        } else {
                            // 负数
                            evilUsec = -rand.nextInt(1000000);
                        }
                        if (globalOffset + 4 <= result.length) {
                            bb.putInt(globalOffset, evilUsec);
                        }
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

        if (withData.isEmpty())
            return data;

        BinaryChunk target = withData.get(rand.nextInt(withData.size()));
        int dataStart = target.getStartOffset() + target.getDataOffset();
        int dataLen = target.getDataLength();

        if (dataStart + dataLen > data.length || dataLen <= 0)
            return data;

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
            // 问题7: 增强时间戳攻击
            int tsAttack = rand.nextInt(10);
            if (tsAttack == 0) {
                // 攻击1: 时间倒流
                currentTs -= rand.nextInt(10000);
            } else if (tsAttack == 1) {
                // 攻击2: 负数时间戳
                currentTs = -rand.nextInt(100000);
            } else if (tsAttack == 2) {
                // 攻击3: 巨大跳跃
                currentTs += rand.nextInt(1000000);
            } else {
                // 正常递增
                currentTs += rand.nextInt(5);
            }

            // 微秒/纳秒攻击
            int usec;
            if (rand.nextInt(10) == 0) {
                // 10%: 非法微秒值 (> 1000000)
                usec = 1000000 + rand.nextInt(1000000);
            } else if (rand.nextInt(20) == 0) {
                // 5%: 负数
                usec = -rand.nextInt(1000000);
            } else {
                usec = rand.nextInt(1000000);
            }

            byte[] payload = generateEthernetPayload(rand);
            int realLen = payload.length;

            // 问题1: 修复长度欺骗攻击
            int strategy = rand.nextInt(100);
            int inclLen, origLen;

            if (strategy < 10) {
                // 攻击1: incl_len < 实际数据（数据错位）
                // 解析器会将部分 payload 误解析为下一个包头
                inclLen = Math.max(10, realLen - rand.nextInt(50));
                origLen = realLen;

                writeInt(baos, (int) currentTs, bigEndian);
                writeInt(baos, usec, bigEndian);
                writeInt(baos, inclLen, bigEndian);
                writeInt(baos, origLen, bigEndian);

                // 写入全部 payload（制造错位）
                baos.write(payload);

            } else if (strategy < 20) {
                // 攻击2: incl_len > 实际数据（OOB 读取）
                inclLen = realLen + rand.nextInt(100) + 10;
                origLen = realLen;

                writeInt(baos, (int) currentTs, bigEndian);
                writeInt(baos, usec, bigEndian);
                writeInt(baos, inclLen, bigEndian);
                writeInt(baos, origLen, bigEndian);

                // 只写入实际数据，解析器会读到 EOF
                baos.write(payload);

            } else if (strategy < 30) {
                // 攻击3: incl_len > orig_len（逻辑错误）
                inclLen = realLen;
                origLen = Math.max(0, inclLen - rand.nextInt(50) - 1); // 修复：确保不为负

                writeInt(baos, (int) currentTs, bigEndian);
                writeInt(baos, usec, bigEndian);
                writeInt(baos, inclLen, bigEndian);
                writeInt(baos, origLen, bigEndian);

                baos.write(payload, 0, Math.min(payload.length, inclLen));

            } else if (strategy < 40) {
                // 攻击4: incl_len > snapLen（违反全局约束）
                inclLen = snapLen + rand.nextInt(100) + 1;
                origLen = inclLen;

                writeInt(baos, (int) currentTs, bigEndian);
                writeInt(baos, usec, bigEndian);
                writeInt(baos, inclLen, bigEndian);
                writeInt(baos, origLen, bigEndian);

                baos.write(payload, 0, Math.min(payload.length, inclLen));
                // 如果 payload 不够长，填充
                for (int k = payload.length; k < inclLen; k++) {
                    baos.write(rand.nextInt(256));
                }

            } else if (strategy < 45) {
                // 攻击5: incl_len = 0
                inclLen = 0;
                origLen = realLen;

                writeInt(baos, (int) currentTs, bigEndian);
                writeInt(baos, usec, bigEndian);
                writeInt(baos, inclLen, bigEndian);
                writeInt(baos, origLen, bigEndian);
                // 不写入任何 payload

            } else {
                // 55%: 正常写入
                inclLen = realLen;
                origLen = realLen;

                writeInt(baos, (int) currentTs, bigEndian);
                writeInt(baos, usec, bigEndian);
                writeInt(baos, inclLen, bigEndian);
                writeInt(baos, origLen, bigEndian);

                baos.write(payload);
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
        byte[] destMac = new byte[6];
        rand.nextBytes(destMac);
        byte[] srcMac = new byte[6];
        rand.nextBytes(srcMac);
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
        ByteArrayOutputStream ipPkt = new ByteArrayOutputStream();

        // Version(4) + IHL(4)
        // 问题4: IHL < 5 攻击
        int ihl;
        int ihlAttack = rand.nextInt(10);
        if (ihlAttack == 0) {
            ihl = rand.nextInt(5); // 0-4 (非法)
        } else {
            ihl = 5 + rand.nextInt(6); // 5-10 (正常或有 Options)
        }
        ipPkt.write((4 << 4) | ihl);

        // TOS
        ipPkt.write(rand.nextInt(256));

        // Total Length 占位（稍后回填）
        int totalLenOffset = ipPkt.size();
        writeNetworkShort(ipPkt, (short) 0);

        // ID
        int ipId = rand.nextInt(65535);
        writeNetworkShort(ipPkt, (short) ipId);

        // 问题4: IP 分片攻击
        int fragAttack = rand.nextInt(10);
        int fragFlags;

        if (fragAttack == 0) {
            // 攻击1: Teardrop (重叠分片)
            int fragOff = 100; // Offset = 800 字节
            fragFlags = 0x2000 | fragOff; // MF = 1
        } else if (fragAttack == 1) {
            // 攻击2: Tiny Fragment
            fragFlags = 0x2000; // MF = 1, Offset = 0, 但包很小
        } else if (fragAttack == 2) {
            // 攻击3: Invalid Offset (总长度溢出)
            int fragOff = 8191; // 最大值 (8191 * 8 = 65528)
            fragFlags = 0x2000 | fragOff;
        } else if (fragAttack == 3) {
            // 攻击4: DF + MF 同时设置（非法）
            fragFlags = 0x6000; // DF | MF
        } else {
            // 60% 正常（无分片）
            fragFlags = 0;
        }
        writeNetworkShort(ipPkt, (short) fragFlags);

        // TTL
        ipPkt.write(64);

        // Protocol
        int proto = rand.nextBoolean() ? 6 : 17;
        ipPkt.write(proto);

        // Checksum 占位
        int checksumOffset = ipPkt.size();
        writeNetworkShort(ipPkt, (short) 0);

        // Src/Dst IP
        byte[] srcIp = new byte[4];
        rand.nextBytes(srcIp);
        byte[] dstIp = new byte[4];
        rand.nextBytes(dstIp);
        ipPkt.write(srcIp);
        ipPkt.write(dstIp);

        // IP Options (如果 IHL > 5)
        int optionsLen = (ihl - 5) * 4;
        if (optionsLen > 0) {
            byte[] options = new byte[optionsLen];
            rand.nextBytes(options);
            ipPkt.write(options);
        }

        // Transport Layer
        generateTransport(ipPkt, proto, rand);

        // 问题2: 计算实际长度并回填
        byte[] ipData = ipPkt.toByteArray();
        int actualLen = ipData.length;

        int totalLenAttack = rand.nextInt(10);
        int declaredLen;

        if (totalLenAttack == 0) {
            // 攻击1: Total Length < 实际长度
            declaredLen = Math.max(20, actualLen / 2);
        } else if (totalLenAttack == 1) {
            // 攻击2: Total Length > 实际长度
            declaredLen = actualLen + rand.nextInt(500);
        } else if (totalLenAttack == 2) {
            // 攻击3: Total Length < IP Header 最小值
            declaredLen = rand.nextInt(20);
        } else if (totalLenAttack == 3) {
            // 攻击4: Total Length = 0
            declaredLen = 0;
        } else {
            // 60% 正常
            declaredLen = actualLen;
        }

        // 回填 Total Length
        ipData[totalLenOffset] = (byte) (declaredLen >>> 8);
        ipData[totalLenOffset + 1] = (byte) declaredLen;

        // 问题3: 计算 IP Checksum
        int checksumAttack = rand.nextInt(10);
        short checksum;

        if (checksumAttack < 3) {
            // 30%: 正确 Checksum（让包能通过验证）
            // 先清零 checksum 字段
            ipData[checksumOffset] = 0;
            ipData[checksumOffset + 1] = 0;
            checksum = calculateIPChecksum(ipData, 0, ihl * 4);
        } else if (checksumAttack < 6) {
            // 30%: 错误 Checksum
            checksum = (short) rand.nextInt(65535);
        } else {
            // 40%: 零值（测试"未计算"处理）
            checksum = 0;
        }

        // 回填 Checksum
        ipData[checksumOffset] = (byte) (checksum >>> 8);
        ipData[checksumOffset + 1] = (byte) checksum;

        pkt.write(ipData);
    }

    /**
     * 计算 IP Header Checksum
     */
    private short calculateIPChecksum(byte[] data, int offset, int len) {
        long sum = 0;
        for (int i = 0; i < len; i += 2) {
            if (offset + i + 1 < data.length) {
                int word = ((data[offset + i] & 0xFF) << 8) | (data[offset + i + 1] & 0xFF);
                sum += word;
            } else if (offset + i < data.length) {
                sum += (data[offset + i] & 0xFF) << 8;
            }
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (short) ~sum;
    }

    private void generateIPv6(ByteArrayOutputStream pkt, ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream ipv6Pkt = new ByteArrayOutputStream();

        // Ver(4) + Traffic Class(8) + Flow Label(20)
        ipv6Pkt.write(0x60 | (rand.nextInt(16))); // Version 6 + TC high bits
        ipv6Pkt.write(rand.nextInt(256)); // TC low + Flow Label high
        ipv6Pkt.write(rand.nextInt(256)); // Flow Label mid
        ipv6Pkt.write(rand.nextInt(256)); // Flow Label low

        // Payload Len 占位
        int payloadLenOffset = ipv6Pkt.size();
        writeNetworkShort(ipv6Pkt, (short) 0);

        // Next Header
        int nextHeader;
        int extAttack = rand.nextInt(10);

        if (extAttack < 2) {
            // 20%: Extension Headers (Fragment Header)
            nextHeader = 44;
        } else if (extAttack == 2) {
            // 10%: Hop-by-Hop Options
            nextHeader = 0;
        } else {
            nextHeader = rand.nextBoolean() ? 6 : 17;
        }
        ipv6Pkt.write(nextHeader);

        // Hop Limit
        ipv6Pkt.write(rand.nextInt(256));

        // Src/Dst Address (16 bytes each)
        byte[] srcAddr = new byte[16];
        byte[] dstAddr = new byte[16];
        rand.nextBytes(srcAddr);
        rand.nextBytes(dstAddr);
        ipv6Pkt.write(srcAddr);
        ipv6Pkt.write(dstAddr);

        // Extension Headers or Transport
        if (nextHeader == 44) {
            // Fragment Header (8 bytes)
            int finalProto = rand.nextBoolean() ? 6 : 17;
            ipv6Pkt.write(finalProto); // Next Header
            ipv6Pkt.write(0); // Reserved
            int fragOff = rand.nextInt(8192);
            int mFlag = rand.nextBoolean() ? 1 : 0;
            writeNetworkShort(ipv6Pkt, (short) ((fragOff << 3) | mFlag));
            // Identification (4 bytes)
            writeInt(ipv6Pkt, rand.nextInt(), false);

            generateTransport(ipv6Pkt, finalProto, rand);
        } else if (nextHeader == 0) {
            // Hop-by-Hop Options Header
            int finalProto = rand.nextBoolean() ? 6 : 17;
            ipv6Pkt.write(finalProto); // Next Header
            int hdrExtLen = rand.nextInt(4); // 以 8 字节为单位
            ipv6Pkt.write(hdrExtLen);
            // Options (填充到 8 字节的倍数)
            int optLen = (hdrExtLen + 1) * 8 - 2;
            byte[] opts = new byte[optLen];
            rand.nextBytes(opts);
            ipv6Pkt.write(opts);

            generateTransport(ipv6Pkt, finalProto, rand);
        } else {
            generateTransport(ipv6Pkt, nextHeader, rand);
        }

        // 计算并回填 Payload Length
        byte[] ipv6Data = ipv6Pkt.toByteArray();
        int actualPayloadLen = ipv6Data.length - 40; // 减去固定 Header

        int payloadAttack = rand.nextInt(10);
        int declaredLen;

        if (payloadAttack == 0) {
            // 攻击1: Payload Length < 实际
            declaredLen = actualPayloadLen / 2;
        } else if (payloadAttack == 1) {
            // 攻击2: Payload Length > 实际
            declaredLen = actualPayloadLen + rand.nextInt(500);
        } else if (payloadAttack == 2) {
            // 攻击3: Jumbogram (0 表示 > 65535)
            declaredLen = 0;
        } else {
            declaredLen = actualPayloadLen;
        }

        // 回填 Payload Length
        ipv6Data[payloadLenOffset] = (byte) (declaredLen >>> 8);
        ipv6Data[payloadLenOffset + 1] = (byte) declaredLen;

        pkt.write(ipv6Data);
    }

    private void generateTransport(ByteArrayOutputStream pkt, int proto, ThreadLocalRandom rand) throws IOException {
        // 问题10: 20% 概率选择特定协议端口
        int srcPort = rand.nextInt(65535);
        int dstPort = rand.nextInt(65535);

        if (rand.nextInt(5) == 0) {
            dstPort = WELL_KNOWN_PORTS[rand.nextInt(WELL_KNOWN_PORTS.length)];
        }

        if (proto == 17) { // UDP
            // 问题9: 修复 UDP 长度
            byte[] data;

            // 根据端口生成应用层数据
            if (dstPort == 53 || srcPort == 53) {
                data = generateDnsPayload(rand);
            } else {
                data = new byte[rand.nextInt(50)];
                rand.nextBytes(data);
            }

            int actualUdpLen = 8 + data.length;
            int declaredLen;

            int udpLenAttack = rand.nextInt(10);
            if (udpLenAttack == 0) {
                // 攻击1: UDP Len < 实际
                declaredLen = Math.max(8, actualUdpLen / 2);
            } else if (udpLenAttack == 1) {
                // 攻击2: UDP Len > 实际
                declaredLen = actualUdpLen + rand.nextInt(100);
            } else if (udpLenAttack == 2) {
                // 攻击3: UDP Len < 8（非法）
                declaredLen = rand.nextInt(8);
            } else {
                declaredLen = actualUdpLen;
            }

            writeNetworkShort(pkt, (short) srcPort);
            writeNetworkShort(pkt, (short) dstPort);
            writeNetworkShort(pkt, (short) declaredLen);
            writeNetworkShort(pkt, (short) 0); // Checksum
            pkt.write(data);

        } else { // TCP
            writeNetworkShort(pkt, (short) srcPort);
            writeNetworkShort(pkt, (short) dstPort);

            // Seq, Ack
            writeInt(pkt, rand.nextInt(), false);
            writeInt(pkt, rand.nextInt(), false);

            // 问题5: TCP Data Offset 攻击 (增强版)
            int dataOffset;
            int dataOffsetAttack = rand.nextInt(10);

            if (dataOffsetAttack == 0) {
                // 攻击1: Data Offset = 0 (严重非法)
                dataOffset = 0;
            } else if (dataOffsetAttack == 1) {
                // 攻击2: Data Offset = 1-3 (< 最小值 5)
                dataOffset = 1 + rand.nextInt(3);
            } else if (dataOffsetAttack == 2) {
                // 攻击3: Data Offset = 4 (恰好在边界)
                dataOffset = 4;
            } else if (dataOffsetAttack == 3) {
                // 攻击4: Data Offset > 15 (溢出 4 位字段)
                // 注意: 写入时只取低 4 位，但这会产生意外值
                dataOffset = 16 + rand.nextInt(16);
            } else {
                // 60% 正常 (5-10, 对应 20-40 字节 Header)
                dataOffset = 5 + rand.nextInt(6);
            }

            // TCP Flags 攻击: 测试非法标志组合
            short flags;
            int flagAttack = rand.nextInt(10);
            if (flagAttack == 0) {
                // SYN + FIN 同时设置 (非法)
                flags = 0x003; // FIN | SYN
            } else if (flagAttack == 1) {
                // SYN + RST 同时设置 (非法)
                flags = 0x006; // RST | SYN
            } else if (flagAttack == 2) {
                // 所有标志全部设置
                flags = 0x1FF;
            } else if (flagAttack == 3) {
                // 保留位被设置
                flags = (short) (rand.nextInt(0x1FF) | 0xE00);
            } else {
                flags = (short) rand.nextInt(0x1FF);
            }
            writeNetworkShort(pkt, (short) (((dataOffset & 0xF) << 12) | (flags & 0xFFF)));

            // Window
            writeNetworkShort(pkt, (short) (8192 + rand.nextInt(8192)));

            // 问题3: TCP Checksum 攻击 (增强版)
            int tcpChecksumAttack = rand.nextInt(10);
            short tcpChecksum;
            if (tcpChecksumAttack == 0) {
                // 攻击1: Checksum = 0 (可能被视为"未计算")
                tcpChecksum = 0;
            } else if (tcpChecksumAttack == 1) {
                // 攻击2: Checksum = 0xFFFF (常见错误值)
                tcpChecksum = (short) 0xFFFF;
            } else if (tcpChecksumAttack < 5) {
                // 30%: 随机错误 Checksum
                tcpChecksum = (short) rand.nextInt(65535);
            } else {
                // 50%: 保持 0 (让解析器处理)
                tcpChecksum = 0;
            }
            writeNetworkShort(pkt, tcpChecksum);

            // Urgent Pointer
            writeNetworkShort(pkt, (short) 0);

            // TCP Options (如果 Data Offset > 5 且 <= 15)
            if (dataOffset > 5 && dataOffset <= 15) {
                int optionsLen = (dataOffset - 5) * 4;
                int optAttack = rand.nextInt(10);

                if (optAttack == 0) {
                    // 攻击1: 全零 Options (填充)
                    for (int i = 0; i < optionsLen; i++) {
                        pkt.write(0);
                    }
                } else if (optAttack == 1) {
                    // 攻击2: 只有 EOL (End of Option List)
                    pkt.write(0); // EOL = 0
                    for (int i = 1; i < optionsLen; i++) {
                        pkt.write(rand.nextInt(256)); // 垃圾数据
                    }
                } else if (optAttack == 2) {
                    // 攻击3: 畸形 MSS Option (Kind 但 Length 不对)
                    pkt.write(2); // MSS Kind
                    pkt.write(3); // 应该是 4, 但我们写 3
                    pkt.write(rand.nextInt(256));
                    for (int i = 3; i < optionsLen; i++) {
                        pkt.write(rand.nextInt(256));
                    }
                } else if (optAttack == 3) {
                    // 攻击4: 无限循环 Options (Length = 0 导致解析器卡住)
                    pkt.write(2); // MSS Kind
                    pkt.write(0); // Length = 0 (严重错误!)
                    for (int i = 2; i < optionsLen; i++) {
                        pkt.write(rand.nextInt(256));
                    }
                } else if (optAttack == 4) {
                    // 攻击5: Window Scale > 14 (RFC 非法)
                    pkt.write(3); // Window Scale Kind
                    pkt.write(3); // Length
                    pkt.write(rand.nextInt(128) + 15); // shift_cnt > 14
                    for (int i = 3; i < optionsLen; i++) {
                        pkt.write(1); // NOP padding
                    }
                } else if (optAttack == 5) {
                    // 攻击6: SACK Permitted + SACK blocks 不匹配
                    pkt.write(4); // SACK Permitted Kind
                    pkt.write(2); // Length = 2
                    // 然后跟一个畸形的 SACK
                    if (optionsLen >= 10) {
                        pkt.write(5); // SACK Kind
                        pkt.write(255); // 非法长度
                        for (int i = 4; i < optionsLen; i++) {
                            pkt.write(rand.nextInt(256));
                        }
                    } else {
                        for (int i = 2; i < optionsLen; i++) {
                            pkt.write(rand.nextInt(256));
                        }
                    }
                } else if (optAttack == 6) {
                    // 攻击7: Timestamp 选项异常
                    if (optionsLen >= 12) {
                        pkt.write(1); // NOP
                        pkt.write(1); // NOP
                        pkt.write(8); // Timestamp Kind
                        pkt.write(10); // Length
                        // TSval 和 TSecr
                        for (int i = 0; i < 8; i++) {
                            pkt.write(0xFF); // 极端值
                        }
                        for (int i = 12; i < optionsLen; i++) {
                            pkt.write(1); // NOP padding
                        }
                    } else {
                        byte[] opts = new byte[optionsLen];
                        rand.nextBytes(opts);
                        pkt.write(opts);
                    }
                } else {
                    // 随机填充 Options
                    byte[] opts = new byte[optionsLen];
                    rand.nextBytes(opts);
                    pkt.write(opts);
                }
            }

            // TCP Payload (根据端口生成应用层协议)
            if (dstPort == 80 || srcPort == 80 || dstPort == 8080 || srcPort == 8080) {
                byte[] httpData = generateHttpPayload(rand);
                pkt.write(httpData);
            } else if (dstPort == 443 || srcPort == 443 || dstPort == 8443 || srcPort == 8443) {
                // TLS Handshake
                byte[] tlsData = generateTlsPayload(rand);
                pkt.write(tlsData);
            } else if (rand.nextInt(3) == 0) {
                // 33%: 随机数据
                byte[] data = new byte[rand.nextInt(100)];
                rand.nextBytes(data);
                pkt.write(data);
            }
        }
    }

    /**
     * 问题10: 生成 TLS Handshake Payload
     * 针对 TLS 解析器的攻击向量
     */
    private byte[] generateTlsPayload(ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream tls = new ByteArrayOutputStream();

        int attackType = rand.nextInt(10);

        if (attackType == 0) {
            // 攻击1: 非法 Content Type
            tls.write(rand.nextInt(256)); // 无效类型
            tls.write(0x03); // Version major
            tls.write(TLS_VERSION_TLS12);
            writeNetworkShort(tls, (short) rand.nextInt(100));
            byte[] garbage = new byte[rand.nextInt(100)];
            rand.nextBytes(garbage);
            tls.write(garbage);

        } else if (attackType == 1) {
            // 攻击2: 超长 Record Length
            tls.write(TLS_CONTENT_HANDSHAKE);
            tls.write(0x03);
            tls.write(TLS_VERSION_TLS12);
            writeNetworkShort(tls, (short) 0xFFFF); // 最大长度
            // 实际写入很少数据
            byte[] small = new byte[10];
            rand.nextBytes(small);
            tls.write(small);

        } else if (attackType == 2) {
            // 攻击3: 畸形 ClientHello
            tls.write(TLS_CONTENT_HANDSHAKE);
            tls.write(0x03);
            tls.write(TLS_VERSION_TLS12);
            writeNetworkShort(tls, (short) 50);
            // Handshake Header
            tls.write(0x01); // ClientHello
            // Length (3 bytes) - 故意错误
            tls.write(0);
            tls.write(0xFF);
            tls.write(0xFF);
            // 随机数据
            byte[] data = new byte[46];
            rand.nextBytes(data);
            tls.write(data);

        } else if (attackType == 3) {
            // 攻击4: SSL 2.0 ClientHello (老版本)
            tls.write(0x80); // SSL 2.0 record header
            tls.write(rand.nextInt(100) + 10); // Length
            tls.write(0x01); // ClientHello
            tls.write(0x00);
            tls.write(0x02); // SSL 2.0
            byte[] data = new byte[rand.nextInt(50) + 10];
            rand.nextBytes(data);
            tls.write(data);

        } else if (attackType == 4) {
            // 攻击5: Session ID 溢出
            tls.write(TLS_CONTENT_HANDSHAKE);
            tls.write(0x03);
            tls.write(TLS_VERSION_TLS12);
            writeNetworkShort(tls, (short) 100);
            // Handshake Header
            tls.write(0x01); // ClientHello
            tls.write(0);
            tls.write(0);
            tls.write(96);
            // Client Version
            tls.write(0x03);
            tls.write(0x03);
            // Random (32 bytes)
            byte[] random = new byte[32];
            rand.nextBytes(random);
            tls.write(random);
            // Session ID Length (非法值 > 32)
            tls.write(255);
            // 随机填充
            byte[] garbage = new byte[59];
            rand.nextBytes(garbage);
            tls.write(garbage);

        } else if (attackType == 5) {
            // 攻击6: 零长度 Extensions
            tls.write(TLS_CONTENT_HANDSHAKE);
            tls.write(0x03);
            tls.write(TLS_VERSION_TLS12);
            writeNetworkShort(tls, (short) 45);
            tls.write(0x01);
            tls.write(0);
            tls.write(0);
            tls.write(41);
            tls.write(0x03);
            tls.write(0x03);
            byte[] random = new byte[32];
            rand.nextBytes(random);
            tls.write(random);
            tls.write(0); // Session ID len = 0
            tls.write(0);
            tls.write(2); // Cipher suites len = 2
            tls.write(0);
            tls.write(0x2F); // TLS_RSA_WITH_AES_128_CBC_SHA
            tls.write(1); // Compression methods len
            tls.write(0); // null compression
            tls.write(0);
            tls.write(0); // Extensions length = 0

        } else {
            // 正常 TLS 记录 (便于深层解析)
            tls.write(TLS_CONTENT_HANDSHAKE);
            tls.write(0x03);
            tls.write(rand.nextBoolean() ? TLS_VERSION_TLS12 : TLS_VERSION_TLS10);
            int len = rand.nextInt(100) + 20;
            writeNetworkShort(tls, (short) len);
            byte[] data = new byte[len];
            rand.nextBytes(data);
            tls.write(data);
        }

        return tls.toByteArray();
    }

    /**
     * 问题10: 生成 DNS Payload
     * 针对 DNS 解析器的攻击向量
     */
    private byte[] generateDnsPayload(ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream dns = new ByteArrayOutputStream();

        // Transaction ID
        writeNetworkShort(dns, (short) rand.nextInt(65535));

        // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
        int flagsAttack = rand.nextInt(10);
        int flags;
        if (flagsAttack == 0) {
            // 攻击1: 保留位非零
            flags = rand.nextInt(0xFFFF) | 0x0070; // Z bits
        } else if (flagsAttack == 1) {
            // 攻击2: 非法 Opcode
            flags = 0x7800; // Opcode = 15 (reserved)
        } else if (flagsAttack == 2) {
            // 攻击3: 非法 RCODE
            flags = 0x000F; // RCODE = 15 (reserved)
        } else {
            flags = rand.nextInt(0xFFFF);
        }
        writeNetworkShort(dns, (short) flags);

        // Questions, Answers, Authority, Additional
        int countAttack = rand.nextInt(10);
        int qdcount, ancount, nscount, arcount;

        if (countAttack == 0) {
            // 攻击: 声称有大量记录但实际没有
            qdcount = rand.nextInt(1000) + 100;
            ancount = rand.nextInt(1000);
            nscount = rand.nextInt(100);
            arcount = rand.nextInt(100);
        } else if (countAttack == 1) {
            // 攻击: 极端值
            qdcount = 65535;
            ancount = 65535;
            nscount = 65535;
            arcount = 65535;
        } else {
            qdcount = rand.nextInt(10);
            ancount = rand.nextInt(10);
            nscount = rand.nextInt(5);
            arcount = rand.nextInt(5);
        }

        writeNetworkShort(dns, (short) qdcount);
        writeNetworkShort(dns, (short) ancount);
        writeNetworkShort(dns, (short) nscount);
        writeNetworkShort(dns, (short) arcount);

        // Query Section (实际只写入一个或少量)
        int actualQueries = Math.min(qdcount, 3);
        for (int q = 0; q < actualQueries; q++) {
            int queryAttack = rand.nextInt(10);

            if (queryAttack == 0) {
                // 攻击1: 压缩指针循环 (无限循环)
                dns.write(0xC0); // Pointer
                dns.write(0x0C); // 指向自己 (offset 12 = Questions start)
            } else if (queryAttack == 1) {
                // 攻击2: 超长 Label (> 63)
                dns.write(255); // Label 长度 > 63
                byte[] label = new byte[63]; // 实际写入 63 字节
                rand.nextBytes(label);
                dns.write(label);
                dns.write(0);
            } else if (queryAttack == 2) {
                // 攻击3: 总长度 > 255
                for (int i = 0; i < 5; i++) {
                    String label = "a".repeat(63);
                    dns.write(63);
                    dns.write(label.getBytes(StandardCharsets.US_ASCII));
                }
                dns.write(0);
            } else if (queryAttack == 3) {
                // 攻击4: 无效压缩指针 (指向包外)
                dns.write(0xC0);
                dns.write(0xFF); // offset 255 可能超出包
            } else if (queryAttack == 4) {
                // 攻击5: 空 Query Name
                dns.write(0); // 只有 root
            } else {
                // 正常 Query
                String[] labels = { "www", "example", "com" };
                for (String label : labels) {
                    dns.write(label.length());
                    dns.write(label.getBytes(StandardCharsets.US_ASCII));
                }
                dns.write(0); // End
            }

            // Query Type 攻击
            int typeAttack = rand.nextInt(5);
            int qtype;
            if (typeAttack == 0) {
                qtype = 255; // ANY (放大攻击)
            } else if (typeAttack == 1) {
                qtype = 65535; // 极端值
            } else {
                qtype = new int[] { 1, 2, 5, 6, 15, 16, 28 }[rand.nextInt(7)]; // A, NS, CNAME, SOA, MX, TXT, AAAA
            }
            writeNetworkShort(dns, (short) qtype);
            writeNetworkShort(dns, (short) 1); // Class IN
        }

        return dns.toByteArray();
    }

    /**
     * 问题10: 生成 HTTP Payload
     * 针对 HTTP 解析器的攻击向量
     */
    private byte[] generateHttpPayload(ThreadLocalRandom rand) {
        int attackType = rand.nextInt(15);
        StringBuilder http = new StringBuilder();

        if (attackType == 0) {
            // 攻击1: 路径穿越
            http.append("GET /../../../etc/passwd HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("\r\n");

        } else if (attackType == 1) {
            // 攻击2: 超长路径
            http.append("GET /").append("A".repeat(10000)).append(" HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("\r\n");

        } else if (attackType == 2) {
            // 攻击3: 空字节注入
            http.append("GET /%00/admin HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("\r\n");

        } else if (attackType == 3) {
            // 攻击4: 超长 Header
            http.append("GET / HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("X-Evil: ").append("A".repeat(8000)).append("\r\n");
            http.append("\r\n");

        } else if (attackType == 4) {
            // 攻击5: Content-Length 不匹配
            http.append("POST / HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("Content-Length: 99999\r\n");
            http.append("\r\n");
            http.append("small body");

        } else if (attackType == 5) {
            // 攻击6: HTTP Request Smuggling (CL-TE)
            http.append("POST / HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("Content-Length: 0\r\n");
            http.append("Transfer-Encoding: chunked\r\n");
            http.append("\r\n");

        } else if (attackType == 6) {
            // 攻击7: HTTP Request Smuggling (TE-CL)
            http.append("POST / HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("Transfer-Encoding: chunked\r\n");
            http.append("Content-Length: 100\r\n");
            http.append("\r\n");
            http.append("0\r\n\r\n");

        } else if (attackType == 7) {
            // 攻击8: 畸形 HTTP 版本
            http.append("GET / HTTP/9.9\r\n");
            http.append("Host: example.com\r\n");
            http.append("\r\n");

        } else if (attackType == 8) {
            // 攻击9: 畸形 Method
            http.append("NOTAMETHOD / HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("\r\n");

        } else if (attackType == 9) {
            // 攻击10: 多个 Host Header
            http.append("GET / HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("Host: evil.com\r\n");
            http.append("\r\n");

        } else if (attackType == 10) {
            // 攻击11: 畸形 Chunked 编码
            http.append("POST / HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("Transfer-Encoding: chunked\r\n");
            http.append("\r\n");
            http.append("FFFFFFFFFF\r\n"); // 非法 chunk 大小
            http.append("data\r\n");
            http.append("0\r\n\r\n");

        } else if (attackType == 11) {
            // 攻击12: CRLF 注入
            http.append("GET /page HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("X-Inject: value\r\nX-Evil: injected\r\n");
            http.append("\r\n");

        } else if (attackType == 12) {
            // 攻击13: 负数 Content-Length
            http.append("POST / HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("Content-Length: -1\r\n");
            http.append("\r\n");

        } else if (attackType == 13) {
            // 攻击14: 只有 CR 或 LF
            http.append("GET / HTTP/1.1\r");
            http.append("Host: example.com\r");
            http.append("\r");

        } else {
            // 正常 HTTP 请求
            String[] methods = { "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS" };
            String method = methods[rand.nextInt(methods.length)];
            String[] paths = { "/", "/index.html", "/api/users", "/search?q=test" };
            String path = paths[rand.nextInt(paths.length)];

            http.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
            http.append("Host: example.com\r\n");
            http.append("User-Agent: Fuzzer/1.0\r\n");
            http.append("Accept: */*\r\n");
            http.append("\r\n");
        }

        return http.toString().getBytes(StandardCharsets.US_ASCII);
    }

    // --- Helpers ---

    private void writeInt(ByteArrayOutputStream out, int v, boolean bigEndian) {
        if (bigEndian) {
            out.write((v >>> 24) & 0xFF);
            out.write((v >>> 16) & 0xFF);
            out.write((v >>> 8) & 0xFF);
            out.write((v >>> 0) & 0xFF);
        } else {
            out.write((v >>> 0) & 0xFF);
            out.write((v >>> 8) & 0xFF);
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