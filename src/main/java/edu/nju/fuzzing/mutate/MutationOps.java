package edu.nju.fuzzing.mutate;

import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 高性能底层变异算子集合 (Stateless Utility Class)
 *
 * 包含 AFL 标准算子 + 增强算子 (Token, Clone, Swap)。
 * 优化点：无 ByteBuffer 开销、无锁随机数、In-Place 优先策略。
 */
public class MutationOps {

    // === Interesting Values (AFL 经典“魔术数字”) ===
    // 用于触发整数溢出、符号错误、缓冲区边界等
    private static final byte[] INTERESTING_8 = {-128, -1, 0, 1, 16, 32, 64, 100, 127};
    private static final short[] INTERESTING_16 = {-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767};
    private static final int[] INTERESTING_32 = {-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647};

    // 获取当前线程的随机数生成器 (无锁，极快)
    private static ThreadLocalRandom rand() {
        return ThreadLocalRandom.current();
    }

    // ==========================================
    // 第一类：原地变异 (In-Place Mutation)
    // 特点：直接修改传入数组，返回 void。不产生新对象，GC 压力为 0。
    // ==========================================

    /** 1. 随机位翻转 */
    public static void flipBit(byte[] data) {
        if (data.length == 0) return;
        int byteIdx = rand().nextInt(data.length);
        int bitIdx = rand().nextInt(8);
        data[byteIdx] ^= (1 << bitIdx);
    }

    /** 2. 随机字节翻转 (XOR 0xFF) */
    public static void flipByte(byte[] data) {
        if (data.length == 0) return;
        int idx = rand().nextInt(data.length);
        data[idx] ^= 0xFF;
    }

    /** 3. 随机字节加减 (1-35) */
    public static void arithByte(byte[] data) {
        if (data.length == 0) return;
        int idx = rand().nextInt(data.length);
        byte val = (byte) (1 + rand().nextInt(35));
        if (rand().nextBoolean()) data[idx] += val;
        else data[idx] -= val;
    }

    /** 4. 随机 2字节(Short) 加减 (随机大小端) */
    public static void arithShort(byte[] data) {
        if (data.length < 2) {
            arithByte(data); // 降级处理
            return;
        }
        int idx = rand().nextInt(data.length - 1);
        boolean bigEndian = rand().nextBoolean();
        short val = (short) (1 + rand().nextInt(35));

        // 手动读写 Short，避免创建对象
        short current = getShort(data, idx, bigEndian);
        if (rand().nextBoolean()) current += val;
        else current -= val;
        putShort(data, idx, current, bigEndian);
    }

    /** 5. 随机 4字节(Int) 加减 (随机大小端) */
    public static void arithInt(byte[] data) {
        if (data.length < 4) {
            arithShort(data); // 降级处理
            return;
        }
        int idx = rand().nextInt(data.length - 3);
        boolean bigEndian = rand().nextBoolean();
        int val = 1 + rand().nextInt(35);

        int current = getInt(data, idx, bigEndian);
        if (rand().nextBoolean()) current += val;
        else current -= val;
        putInt(data, idx, current, bigEndian);
    }

    /** 6. 特殊值替换 (8/16/32 bit) */
    public static void setInteresting(byte[] data) {
        if (data.length == 0) return;
        int width = rand().nextInt(3); // 0=8bit, 1=16bit, 2=32bit

        // 长度不足时自动降级
        if (width == 2 && data.length < 4) width = 1;
        if (width == 1 && data.length < 2) width = 0;

        int idx = rand().nextInt(data.length - (width == 0 ? 0 : (width == 1 ? 1 : 3)));
        boolean bigEndian = rand().nextBoolean();

        if (width == 0) {
            data[idx] = INTERESTING_8[rand().nextInt(INTERESTING_8.length)];
        } else if (width == 1) {
            short val = INTERESTING_16[rand().nextInt(INTERESTING_16.length)];
            putShort(data, idx, val, bigEndian);
        } else {
            int val = INTERESTING_32[rand().nextInt(INTERESTING_32.length)];
            putInt(data, idx, val, bigEndian);
        }
    }

    /** 7. 随机交换两个字节 (破坏顺序) */
    public static void swapBytes(byte[] data) {
        if (data.length < 2) return;
        int idx1 = rand().nextInt(data.length);
        int idx2 = rand().nextInt(data.length);
        if (idx1 != idx2) {
            byte tmp = data[idx1];
            data[idx1] = data[idx2];
            data[idx2] = tmp;
        }
    }

    /** 8. 块覆写 (用随机数覆盖一段区域) */
    public static void overwriteBlock(byte[] data) {
        if (data.length == 0) return;
        int len = 1 + rand().nextInt(Math.min(data.length, 32));
        int start = rand().nextInt(data.length - len + 1);
        // 直接填充，避免分配临时数组
        for (int i = 0; i < len; i++) {
            data[start + i] = (byte) rand().nextInt(256);
        }
    }

    /** 9. 字典/Token 替换 (将关键字写入数据) */
    public static void overwriteToken(byte[] data, byte[] token) {
        if (data.length < token.length) return; // 空间不足，跳过
        int idx = rand().nextInt(data.length - token.length + 1);
        System.arraycopy(token, 0, data, idx, token.length);
    }

    // ==========================================
    // 第二类：结构变异 (Structural Mutation)
    // 特点：改变数组长度，必须分配新内存并返回 byte[]。
    // ==========================================

    /** 10. 块删除 */
    public static byte[] deleteBlock(byte[] data) {
        if (data.length < 2) return data.clone(); // 保持语义一致，返回新副本
        int len = 1 + rand().nextInt(data.length / 2);
        int start = rand().nextInt(data.length - len);

        byte[] res = new byte[data.length - len];
        // Copy Head
        System.arraycopy(data, 0, res, 0, start);
        // Copy Tail
        System.arraycopy(data, start + len, res, start, data.length - start - len);
        return res;
    }

    /** 11. 块插入 (插入随机数或重复字节) */
    public static byte[] insertBlock(byte[] data) {
        int len = 1 + rand().nextInt(32);
        byte[] res = new byte[data.length + len];

        int pos = (data.length == 0) ? 0 : rand().nextInt(data.length + 1);

        // Copy Head
        if (pos > 0) System.arraycopy(data, 0, res, 0, pos);

        // Fill New Block
        if (rand().nextBoolean()) {
            // Fill with random bytes
            for (int i = 0; i < len; i++) res[pos + i] = (byte) rand().nextInt(256);
        } else {
            // Fill with fixed byte (e.g. 0x00 or 0x41)
            byte val = (byte) rand().nextInt(256);
            Arrays.fill(res, pos, pos + len, val);
        }

        // Copy Tail
        if (pos < data.length) System.arraycopy(data, pos, res, pos + len, data.length - pos);
        return res;
    }

    /** 12. 块克隆 (复制自身一段数据插入到另一处) - 很有效！ */
    public static byte[] cloneBlock(byte[] data) {
        if (data.length < 2) return data.clone();

        int len = 1 + rand().nextInt(data.length / 2);
        int srcPos = rand().nextInt(data.length - len); // 复制源
        int dstPos = rand().nextInt(data.length + 1);   // 插入点

        byte[] res = new byte[data.length + len];

        // 1. Copy Head (0..dst)
        if (dstPos > 0) System.arraycopy(data, 0, res, 0, dstPos);

        // 2. Copy Clone (src..src+len)
        System.arraycopy(data, srcPos, res, dstPos, len);

        // 3. Copy Tail (dst..end)
        if (dstPos < data.length) System.arraycopy(data, dstPos, res, dstPos + len, data.length - dstPos);

        return res;
    }

    /** 13. 字典/Token 插入 (将关键字插入数据) */
    public static byte[] insertToken(byte[] data, byte[] token) {
        byte[] res = new byte[data.length + token.length];
        int idx = (data.length == 0) ? 0 : rand().nextInt(data.length + 1);

        if (idx > 0) System.arraycopy(data, 0, res, 0, idx);
        System.arraycopy(token, 0, res, idx, token.length);
        if (idx < data.length) System.arraycopy(data, idx, res, idx + token.length, data.length - idx);

        return res;
    }

    // ==========================================
    // 辅助方法：手动位运算处理大小端 (避免 ByteBuffer 对象开销)
    // ==========================================

    private static short getShort(byte[] b, int off, boolean bigEndian) {
        int b1 = b[off] & 0xFF;
        int b2 = b[off + 1] & 0xFF;
        return bigEndian ? (short) ((b1 << 8) | b2) : (short) (b1 | (b2 << 8));
    }

    private static void putShort(byte[] b, int off, short val, boolean bigEndian) {
        if (bigEndian) {
            b[off] = (byte) (val >> 8);
            b[off + 1] = (byte) val;
        } else {
            b[off] = (byte) val;
            b[off + 1] = (byte) (val >> 8);
        }
    }

    private static int getInt(byte[] b, int off, boolean bigEndian) {
        int b1 = b[off] & 0xFF;
        int b2 = b[off + 1] & 0xFF;
        int b3 = b[off + 2] & 0xFF;
        int b4 = b[off + 3] & 0xFF;
        if (bigEndian) {
            return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
        } else {
            return b1 | (b2 << 8) | (b3 << 16) | (b4 << 24);
        }
    }

    private static void putInt(byte[] b, int off, int val, boolean bigEndian) {
        if (bigEndian) {
            b[off] = (byte) (val >> 24);
            b[off + 1] = (byte) (val >> 16);
            b[off + 2] = (byte) (val >> 8);
            b[off + 3] = (byte) val;
        } else {
            b[off] = (byte) val;
            b[off + 1] = (byte) (val >> 8);
            b[off + 2] = (byte) (val >> 16);
            b[off + 3] = (byte) (val >> 24);
        }
    }
}