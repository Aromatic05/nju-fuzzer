package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 增强型 PCAP 变异器
 *
 * 改进点：
 * 1. 协议栈感知 (Protocol-Aware): 构造真实的 Ethernet/IP/TCP 头部，深入测试 DPI 引擎。
 * 2. 混合字节序处理: PCAP 头遵循 Global Header 字节序，但 Payload 强制使用网络字节序 (Big Endian)。
 * 3. 深度逻辑漏洞: 构造 IP Total Length 与 PCAP incl_len 不一致的情况。
 * 4. 时间戳回溯攻击: 生成非单调的时间戳。
 */
public class PcapMutator implements Mutator {

    private static final int MAGIC_USEC = 0xA1B2C3D4;
    private static final int MAGIC_NSEC = 0xA1B23C4D;

    // Link Types
    private static final int DLT_EN10MB = 1; // Ethernet (大多数解析器的重点)

    @Override
    public Iterator<Testcase> mutate(Seed seed, int energy) {
        int count = Math.max(1, energy);

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
                    byte[] pcapData = generatePcap();
                    return new Testcase(pcapData, seed, "grammar:AdvancedPCAP");
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
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