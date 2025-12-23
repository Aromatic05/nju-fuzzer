package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * PcapMutator 单元测试
 *
 * 验证点：
 * 1. 容器格式完整性 (Global Header Magic/Endianness)
 * 2. 协议栈感知能力 (Ethernet/IPv4/IPv6/TCP/UDP 识别)
 * 3. 攻击向量覆盖 (长度冲突、IHL 畸形、时间戳回溯、TCP 标志模糊)
 * 4. 统计报告 (可视化展示 DPI Fuzzing 能力)
 */
class PcapMutatorTest {

    private Seed dummySeed;
    private PcapMutator mutator;

    @BeforeEach
    void setUp() {
        dummySeed = Seed.loadWithMetadata(new File("dummy_pcap"), new byte[0]);
        mutator = new PcapMutator();
    }

    // ==========================================
    // 基础功能测试
    // ==========================================

    @Test
    @DisplayName("Test 1: Global Header - 验证 Magic Number 与 字节序")
    void testGlobalHeader() {
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 100);
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            assertTrue(data.length >= 24, "PCAP 文件过短");

            // 检查 Magic (A1B2C3D4 或 D4C3B2A1)
            ByteBuffer bb = ByteBuffer.wrap(data);
            int magic = bb.getInt();
            assertTrue(magic == 0xA1B2C3D4 || magic == 0xD4C3B2A1 ||
                            magic == 0xA1B23C4D || magic == 0x4D3CB2A1,
                    "非法 PCAP Magic: " + Integer.toHexString(magic));
        }
    }

    @Test
    @DisplayName("Test 2: Diversity - 变异结果多样性检查")
    void testDiversity() {
        Set<Integer> hashes = new HashSet<>();
        int count = 100;
        Iterator<Testcase> iter = mutator.mutate(dummySeed, count);
        while (iter.hasNext()) {
            hashes.add(Arrays.hashCode(iter.next().getData()));
        }
        assertTrue(hashes.size() > 95, "PCAP 生成重复率过高: " + hashes.size());
    }

    // ==========================================
    // 覆盖率报告
    // ==========================================

    @Test
    @DisplayName("Test 3-10: Coverage Report - 解析 1000 个样本并统计协议特征")
    void testCoverage() {
        int totalFiles = 1000;
        Map<String, Integer> stats = new HashMap<>();
        String[] keys = {
                "Total Files", "Total Packets", "IPv4 Packets", "IPv6 Packets",
                "TCP Packets", "UDP Packets", "Length Confusion (incl_len)",
                "IHL Attack (IHL < 5)", "TCP Offset Attack (< 5)", "Timestamp Anomaly (Backwards)"
        };
        for (String k : keys) stats.put(k, 0);

        Iterator<Testcase> iter = mutator.mutate(dummySeed, totalFiles);

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            stats.put("Total Files", stats.get("Total Files") + 1);
            analyzePcap(data, stats);
        }

        printReport(stats);

        // 断言核心协议特征均被生成
        assertCovered(stats, "IPv4 Packets");
        assertCovered(stats, "TCP Packets");
        assertCovered(stats, "Length Confusion (incl_len)");
        assertCovered(stats, "IHL Attack (IHL < 5)");
        assertCovered(stats, "Timestamp Anomaly (Backwards)");
    }

    private void analyzePcap(byte[] data, Map<String, Integer> stats) {
        if (data.length < 24) return;

        ByteBuffer bb = ByteBuffer.wrap(data);
        int magic = bb.getInt();
        ByteOrder order = (magic == 0xA1B2C3D4 || magic == 0xA1B23C4D) ?
                ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        bb.order(order);

        int pos = 24; // Skip Global Header
        long lastTs = 0;

        while (pos + 16 <= data.length) {
            stats.put("Total Packets", stats.get("Total Packets") + 1);

            // Packet Header (16 bytes)
            long tsSec = bb.getInt(pos) & 0xFFFFFFFFL;
            int inclLen = bb.getInt(pos + 8);
            int origLen = bb.getInt(pos + 12);

            // 1. Timestamp Anomaly
            if (lastTs != 0 && tsSec < lastTs) inc(stats, "Timestamp Anomaly (Backwards)");
            lastTs = tsSec;

            // 2. Length Confusion
            if (inclLen != origLen || inclLen > 65535) inc(stats, "Length Confusion (incl_len)");

            // 3. Payload Protocol Analysis
            int payloadStart = pos + 16;
            if (payloadStart + 14 <= data.length) {
                analyzeEthernet(data, payloadStart, Math.min(inclLen, data.length - payloadStart), stats);
            }

            pos += 16 + inclLen; // 按照 inclLen 跳转
            if (pos < 0) break; // 防止溢出
        }
    }

    private void analyzeEthernet(byte[] data, int start, int len, Map<String, Integer> stats) {
        if (len < 14) return;
        // EtherType at offset 12
        int etherType = ((data[start + 12] & 0xFF) << 8) | (data[start + 13] & 0xFF);

        if (etherType == 0x0800) {
            inc(stats, "IPv4 Packets");
            analyzeIPv4(data, start + 14, len - 14, stats);
        } else if (etherType == 0x86DD) {
            inc(stats, "IPv6 Packets");
        }
    }

    private void analyzeIPv4(byte[] data, int start, int len, Map<String, Integer> stats) {
        if (len < 20) return;
        int ihl = data[start] & 0x0F;
        int proto = data[start + 9] & 0xFF;

        if (ihl < 5) inc(stats, "IHL Attack (IHL < 5)");

        if (proto == 6) {
            inc(stats, "TCP Packets");
            int tcpStart = start + (ihl * 4);
            if (tcpStart + 13 < data.length) {
                int dataOffset = (data[tcpStart + 12] >> 4) & 0x0F;
                if (dataOffset < 5) inc(stats, "TCP Offset Attack (< 5)");
            }
        } else if (proto == 17) {
            inc(stats, "UDP Packets");
        }
    }

    private void inc(Map<String, Integer> stats, String key) {
        stats.put(key, stats.get(key) + 1);
    }

    private void assertCovered(Map<String, Integer> stats, String key) {
        assertTrue(stats.get(key) > 0, "算法未生成核心特征: " + key);
    }

    private void printReport(Map<String, Integer> stats) {
        int totalFiles = stats.get("Total Files");
        int totalPkts = stats.get("Total Packets");
        System.out.println("====== PcapMutator Functional Coverage Report ======");
        System.out.println("Real Files Generated: " + totalFiles);
        System.out.println("Total Packets Parsed: " + totalPkts);
        System.out.println("---------------------------------------------------");
        System.out.printf("%-30s | %-10s | %-10s%n", "Feature / Attack", "Count", "Rate/Packet");
        System.out.println("---------------------------------------------------");

        String[] order = {
                "IPv4 Packets", "IPv6 Packets", "TCP Packets", "UDP Packets",
                "Length Confusion (incl_len)", "IHL Attack (IHL < 5)",
                "TCP Offset Attack (< 5)", "Timestamp Anomaly (Backwards)"
        };

        for (String k : order) {
            int v = stats.get(k);
            double rate = (totalPkts > 0) ? (v * 100.0) / totalPkts : 0.0;
            System.out.printf("%-30s | %-10d | %6.2f%%%n", k, v, rate);
        }
        System.out.println("===================================================");
    }

    @Test
    @DisplayName("Test 11: Empty/Small Pcap - 健壮性检查")
    void testRobustness() {
        // 即使 Energy 只有 1，也应生成合法的 PCAP Header
        Iterator<Testcase> iter = mutator.mutate(dummySeed, 1);
        assertTrue(iter.hasNext());
        byte[] data = iter.next().getData();
        assertTrue(data.length >= 24);
    }
}