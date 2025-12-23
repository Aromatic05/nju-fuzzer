package edu.nju.fuzzing.mutate;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Random;

/**
 * 底层变异算子集合 (Stateless Utility Class)
 * 对应 AFL 文档中的原子操作，已增强为工业级实现。
 */
public class MutationOps {

    private static final Random random = new Random();

    // === Interesting Values (保持不变) ===
    private static final byte[] INTERESTING_8 = {-128, -1, 0, 1, 16, 32, 64, 100, 127};
    private static final short[] INTERESTING_16 = {-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767};
    private static final int[] INTERESTING_32 = {-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647};

    // --- 1. Bitflip (位翻转) ---
    public static byte[] flipBit(byte[] data) {
        if (data.length == 0) return data;
        byte[] res = data.clone();
        int byteIdx = random.nextInt(res.length);
        res[byteIdx] ^= (1 << random.nextInt(8));
        return res;
    }

    // --- 2. Byteflip (字节翻转) ---
    public static byte[] flipByte(byte[] data) {
        if (data.length == 0) return data;
        byte[] res = data.clone();
        res[random.nextInt(res.length)] ^= 0xFF;
        return res;
    }

    // --- 3. Arith (算术加减 - 增强版) ---

    // 8-bit 加减
    public static byte[] arithByte(byte[] data) {
        if (data.length == 0) return data;
        byte[] res = data.clone();
        int idx = random.nextInt(res.length);
        int val = 1 + random.nextInt(35);
        if (random.nextBoolean()) res[idx] += (byte) val;
        else res[idx] -= (byte) val;
        return res;
    }

    // [新增] 16-bit 加减 (针对长度字段、偏移量)
    public static byte[] arithShort(byte[] data) {
        if (data.length < 2) return arithByte(data);
        byte[] res = data.clone();
        int idx = random.nextInt(res.length - 1);
        ByteOrder order = random.nextBoolean() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;

        short val = (short) (1 + random.nextInt(35));
        ByteBuffer bb = ByteBuffer.wrap(res).order(order);
        short current = bb.getShort(idx);

        if (random.nextBoolean()) current += val;
        else current -= val;

        bb.putShort(idx, current);
        return res;
    }

    // [新增] 32-bit 加减 (针对大整数)
    public static byte[] arithInt(byte[] data) {
        if (data.length < 4) return arithShort(data);
        byte[] res = data.clone();
        int idx = random.nextInt(res.length - 3);
        ByteOrder order = random.nextBoolean() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;

        int val = 1 + random.nextInt(35);
        ByteBuffer bb = ByteBuffer.wrap(res).order(order);
        int current = bb.getInt(idx);

        if (random.nextBoolean()) current += val;
        else current -= val;

        bb.putInt(idx, current);
        return res;
    }

    // --- 4. Interest (特殊值替换) ---
    public static byte[] setInteresting(byte[] data) {
        if (data.length == 0) return data;
        byte[] res = data.clone();
        int width = random.nextInt(3);

        if (width == 2 && res.length < 4) width = 1;
        if (width == 1 && res.length < 2) width = 0;

        int idx = random.nextInt(res.length - (width == 0 ? 0 : (width == 1 ? 1 : 3)));
        ByteOrder order = random.nextBoolean() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;

        if (width == 0) {
            res[idx] = INTERESTING_8[random.nextInt(INTERESTING_8.length)];
        } else if (width == 1) {
            short val = INTERESTING_16[random.nextInt(INTERESTING_16.length)];
            ByteBuffer.wrap(res).order(order).putShort(idx, val);
        } else {
            int val = INTERESTING_32[random.nextInt(INTERESTING_32.length)];
            ByteBuffer.wrap(res).order(order).putInt(idx, val);
        }
        return res;
    }

    // --- 5. Block Operations (块操作) ---

    public static byte[] deleteBlock(byte[] data) {
        if (data.length < 2) return data;
        int len = 1 + random.nextInt(data.length / 2);
        int start = random.nextInt(data.length - len);
        byte[] res = new byte[data.length - len];
        System.arraycopy(data, 0, res, 0, start);
        System.arraycopy(data, start + len, res, start, data.length - start - len);
        return res;
    }

    public static byte[] insertBlock(byte[] data) {
        int len = 1 + random.nextInt(32);
        byte[] block = new byte[len];
        if (random.nextBoolean()) random.nextBytes(block);
        else Arrays.fill(block, (byte) random.nextInt(256)); // 重复字节填充

        byte[] res = new byte[data.length + len];
        int pos = (data.length == 0) ? 0 : random.nextInt(data.length + 1);
        if (pos > 0) System.arraycopy(data, 0, res, 0, pos);
        System.arraycopy(block, 0, res, pos, len);
        if (pos < data.length) System.arraycopy(data, pos, res, pos + len, data.length - pos);
        return res;
    }

    public static byte[] overwriteBlock(byte[] data) {
        if (data.length == 0) return data;
        byte[] res = data.clone();
        int len = 1 + random.nextInt(Math.min(data.length, 32));
        int start = random.nextInt(data.length - len + 1);
        byte[] block = new byte[len];
        random.nextBytes(block);
        System.arraycopy(block, 0, res, start, len);
        return res;
    }

    // [新增] 块克隆 (Block Clone): 复制自身的一段数据插到另一处
    // 这比随机插入更有效，因为复制的是“合法”的数据片段
    public static byte[] cloneBlock(byte[] data) {
        if (data.length < 2) return data;

        // 1. 随机选一段源数据
        int len = 1 + random.nextInt(data.length / 2);
        int srcPos = random.nextInt(data.length - len);

        // 2. 随机选一个插入点
        int dstPos = random.nextInt(data.length + 1);

        byte[] res = new byte[data.length + len];

        // 3. 拼装: [0..dst] + [src..src+len] + [dst..end]
        if (dstPos > 0) System.arraycopy(data, 0, res, 0, dstPos);
        System.arraycopy(data, srcPos, res, dstPos, len);
        if (dstPos < data.length) System.arraycopy(data, dstPos, res, dstPos + len, data.length - dstPos);

        return res;
    }

    // --- 6. Special Operations (杂项) ---

    // [新增] 字节交换 (Bytes Swap): 随机交换两个字节
    public static byte[] swapBytes(byte[] data) {
        if (data.length < 2) return data;
        byte[] res = data.clone();
        int idx1 = random.nextInt(res.length);
        int idx2 = random.nextInt(res.length);
        byte tmp = res[idx1];
        res[idx1] = res[idx2];
        res[idx2] = tmp;
        return res;
    }

    public static byte[] overwriteToken(byte[] data, byte[] token) {
        if (data.length < token.length) return data;
        byte[] res = data.clone();
        int idx = random.nextInt(res.length - token.length + 1);
        System.arraycopy(token, 0, res, idx, token.length);
        return res;
    }

    public static byte[] insertToken(byte[] data, byte[] token) {
        byte[] res = new byte[data.length + token.length];
        int idx = (data.length == 0) ? 0 : random.nextInt(data.length + 1);
        if (idx > 0) System.arraycopy(data, 0, res, 0, idx);
        System.arraycopy(token, 0, res, idx, token.length);
        if (idx < data.length) System.arraycopy(data, idx, res, idx + token.length, data.length - idx);
        return res;
    }
}