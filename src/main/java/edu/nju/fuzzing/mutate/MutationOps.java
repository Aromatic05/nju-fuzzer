package edu.nju.fuzzing.mutate;

import java.util.Random;

/**
 * 静态工具类：包含具体的变异算子算法
 * 所有的操作都应该返回一个新的 byte[]，不修改原数组
 */
public class MutationOps {

    private static final Random random = new Random();

    // AFL 标准的一些“有趣数字”，容易触发整数溢出或边界条件
    private static final byte[] INTERESTING_8 = {
            -128, -1, 0, 1, 16, 32, 64, 100, 127
    };

    /**
     * 1. 随机比特翻转 (Bit Flip)
     * 选一个字节，翻转其中的 1 个 bit
     */
    public static byte[] flipBit(byte[] data) {
        if (data.length == 0) return data;
        byte[] mutated = data.clone();

        int byteIdx = random.nextInt(mutated.length);
        int bitIdx = random.nextInt(8);

        mutated[byteIdx] ^= (1 << bitIdx); // XOR 操作翻转指定位
        return mutated;
    }

    /**
     * 2. 随机字节翻转 (Byte Flip)
     * 选一个字节，与 0xFF 进行异或（全翻转）
     */
    public static byte[] flipByte(byte[] data) {
        if (data.length == 0) return data;
        byte[] mutated = data.clone();

        int idx = random.nextInt(mutated.length);
        mutated[idx] ^= 0xFF;
        return mutated;
    }

    /**
     * 3. 随机算术加减 (Arithmetic)
     * 选一个字节，加或减一个小整数 (1-35)
     */
    public static byte[] arithByte(byte[] data) {
        if (data.length == 0) return data;
        byte[] mutated = data.clone();

        int idx = random.nextInt(mutated.length);
        int val = 1 + random.nextInt(35);

        if (random.nextBoolean()) {
            mutated[idx] += (byte) val;
        } else {
            mutated[idx] -= (byte) val;
        }
        return mutated;
    }

    /**
     * 4. 替换为特殊值 (Interesting Value)
     * 将某个字节替换为边界值 (如 0, -1, MAX_INT)
     */
    public static byte[] setInteresting8(byte[] data) {
        if (data.length == 0) return data;
        byte[] mutated = data.clone();

        int idx = random.nextInt(mutated.length);
        byte val = INTERESTING_8[random.nextInt(INTERESTING_8.length)];
        mutated[idx] = val;
        return mutated;
    }

    /**
     * 5. 块删除 (Block Deletion)
     * 随机删除一段字节，改变文件长度
     */
    public static byte[] deleteBlock(byte[] data) {
        if (data.length < 2) return data; // 太短不删

        // 随机删除长度，最大不超过总长度的一半
        int delLen = 1 + random.nextInt(data.length / 2);
        // 随机起始位置
        int startOffset = random.nextInt(data.length - delLen);

        byte[] mutated = new byte[data.length - delLen];

        // 拼凑：前半段 + 后半段
        System.arraycopy(data, 0, mutated, 0, startOffset);
        System.arraycopy(data, startOffset + delLen, mutated, startOffset, data.length - startOffset - delLen);

        return mutated;
    }

    /**
     * 6. 块插入 (Block Insertion)
     * 随机插入一段杂乱数据，改变文件长度
     */
    public static byte[] insertBlock(byte[] data) {
        // 限制插入块的最大长度，防止文件膨胀过快
        int insertLen = 1 + random.nextInt(64);
        byte[] block = new byte[insertLen];
        random.nextBytes(block); // 生成随机填充数据

        byte[] mutated = new byte[data.length + insertLen];
        int insertAt = (data.length == 0) ? 0 : random.nextInt(data.length + 1);

        // 拼凑：前半段 + 新块 + 后半段
        if (insertAt > 0) {
            System.arraycopy(data, 0, mutated, 0, insertAt);
        }
        System.arraycopy(block, 0, mutated, insertAt, insertLen);
        if (insertAt < data.length) {
            System.arraycopy(data, insertAt, mutated, insertAt + insertLen, data.length - insertAt);
        }

        return mutated;
    }

    /**
     * 7. 块覆写 (Block Overwrite)
     * 随机用一段杂乱数据覆盖原有数据，不改变长度
     */
    public static byte[] overwriteBlock(byte[] data) {
        if (data.length == 0) return data;
        byte[] mutated = data.clone();

        int len = 1 + random.nextInt(Math.min(data.length, 64));
        int start = random.nextInt(data.length - len + 1);

        byte[] block = new byte[len];
        random.nextBytes(block);

        System.arraycopy(block, 0, mutated, start, len);
        return mutated;
    }
}