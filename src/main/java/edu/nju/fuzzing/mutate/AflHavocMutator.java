package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class AflHavocMutator implements Mutator {

    private final List<Seed> corpus;
    private final List<byte[]> dictionary = new ArrayList<>();

    // 定义操作码常量，方便管理
    private static final int OP_FLIP_BIT = 0;
    private static final int OP_FLIP_BYTE = 1;
    private static final int OP_SWAP_BYTES = 2;
    private static final int OP_ARITH_BYTE = 3;
    private static final int OP_ARITH_SHORT = 4;
    private static final int OP_ARITH_INT = 5;
    private static final int OP_INTERESTING = 6;
    private static final int OP_DELETE_BLOCK = 7;
    private static final int OP_INSERT_BLOCK = 8;
    private static final int OP_OVERWRITE_BLOCK = 9;
    private static final int OP_CLONE_BLOCK = 10;
    private static final int OP_OVERWRITE_TOKEN = 11;
    private static final int OP_INSERT_TOKEN = 12;

    // 权重表：让轻量级、保持结构的变异出现概率更高
    // 数组大小 100，存储操作码
    private final int[] weightedOps = new int[100];

    public AflHavocMutator(List<Seed> corpus) {
        this.corpus = corpus;
        initDictionary(); // 加载默认字典
        initWeights();    // 初始化概率表
    }

    /**
     * 初始化变异算子的权重
     * 策略：
     * - Bit/Byte Flip & Arith (In-Place): ~60%
     * - Token/Interesting: ~20%
     * - Block Ops (Structural): ~20% (减少内存分配频率)
     */
    private void initWeights() {
        int idx = 0;
        // 1. In-Place Ops (High Freq)
        idx = fillWeight(idx, 10, OP_FLIP_BIT);
        idx = fillWeight(idx, 10, OP_FLIP_BYTE);
        idx = fillWeight(idx, 10, OP_ARITH_BYTE);
        idx = fillWeight(idx, 10, OP_ARITH_SHORT);
        idx = fillWeight(idx, 5,  OP_ARITH_INT);
        idx = fillWeight(idx, 5,  OP_SWAP_BYTES);

        // 2. Token & Interesting (High Value)
        idx = fillWeight(idx, 10, OP_INTERESTING);
        idx = fillWeight(idx, 10, OP_OVERWRITE_TOKEN); // 字典替换非常有价值

        // 3. Structural Ops (Expensive)
        idx = fillWeight(idx, 5, OP_INSERT_TOKEN);
        idx = fillWeight(idx, 5, OP_DELETE_BLOCK);
        idx = fillWeight(idx, 5, OP_INSERT_BLOCK);
        idx = fillWeight(idx, 5, OP_OVERWRITE_BLOCK);
        idx = fillWeight(idx, 5, OP_CLONE_BLOCK);

        // 填满剩余部分（防止数组越界）
        while (idx < 100) weightedOps[idx++] = OP_FLIP_BIT;
    }

    private int fillWeight(int start, int count, int op) {
        for (int i = 0; i < count && start < 100; i++) {
            weightedOps[start++] = op;
        }
        return start;
    }

    // 支持外部添加字典，不再局限于硬编码
    public void addDictionaryEntry(byte[] token) {
        if (token != null && token.length > 0) {
            dictionary.add(token);
        }
    }

    // 支持加载字符串列表作为字典
    public void loadDictionary(List<String> tokens) {
        for (String t : tokens) {
            addDictionaryEntry(t.getBytes(StandardCharsets.ISO_8859_1));
        }
    }

    private void initDictionary() {
        // 默认保留一些通用 Magic Bytes
        addToken(new byte[]{0x7F, 'E', 'L', 'F'}); // ELF
        addToken(new byte[]{'P', 'K', 0x03, 0x04}); // ZIP
        addToken(new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF}); // JPEG
        addToken(new byte[]{'H', 'T', 'T', 'P'});
    }

    private void addToken(byte[] b) { dictionary.add(b); }
    private ThreadLocalRandom random() { return ThreadLocalRandom.current(); }

    @Override
    public Iterator<Testcase> mutate(Seed seed, int energy) {
        final byte[] originalData = seed.getDataCopy();

        return new Iterator<Testcase>() {
            private int remaining = energy;

            @Override
            public boolean hasNext() {
                return remaining > 0;
            }

            @Override
            public Testcase next() {
                if (remaining <= 0) throw new NoSuchElementException();
                remaining--;

                byte[] data = originalData.clone();
                String desc = "havoc";

                // === 优化1: Splicing 策略增强 ===
                // 增加 Splicing 的概率到 30%，因为这是发现新路径的重要手段
                if (corpus.size() > 1 && random().nextInt(100) < 30) {
                    data = splice(data);
                    desc = "splice+havoc";
                }

                // === 优化2: Adaptive Stacking 动态调整 ===
                // 如果数据量很大，减少堆叠层数以节省时间
                int perfScore = (data.length > 1024 * 128) ? 8 : 32;
                int stackCount = 2 + random().nextInt(perfScore);

                // 极小文件不适合多次破坏性变异
                if (data.length < 4) stackCount = Math.min(stackCount, 2);

                for (int j = 0; j < stackCount; j++) {
                    // 使用加权随机选择算子
                    int op = weightedOps[random().nextInt(weightedOps.length)];

                    // 如果没有字典，跳过字典相关操作，回退到 bitflip
                    if (dictionary.isEmpty() && (op == OP_OVERWRITE_TOKEN || op == OP_INSERT_TOKEN)) {
                        op = OP_FLIP_BIT;
                    }

                    switch (op) {
                        // In-Place Ops
                        case OP_FLIP_BIT:      MutationOps.flipBit(data); break;
                        case OP_FLIP_BYTE:     MutationOps.flipByte(data); break;
                        case OP_SWAP_BYTES:    MutationOps.swapBytes(data); break;
                        case OP_ARITH_BYTE:    MutationOps.arithByte(data); break;
                        case OP_ARITH_SHORT:   MutationOps.arithShort(data); break;
                        case OP_ARITH_INT:     MutationOps.arithInt(data); break;
                        case OP_INTERESTING:   MutationOps.setInteresting(data); break;
                        case OP_OVERWRITE_BLOCK: MutationOps.overwriteBlock(data); break;
                        case OP_OVERWRITE_TOKEN:
                            MutationOps.overwriteToken(data, dictionary.get(random().nextInt(dictionary.size())));
                            break;

                        // Structural Ops (涉及 Array 扩容/缩容)
                        case OP_DELETE_BLOCK:  data = MutationOps.deleteBlock(data); break;
                        case OP_INSERT_BLOCK:  data = MutationOps.insertBlock(data); break;
                        case OP_CLONE_BLOCK:   data = MutationOps.cloneBlock(data); break;
                        case OP_INSERT_TOKEN:
                            data = MutationOps.insertToken(data, dictionary.get(random().nextInt(dictionary.size())));
                            break;
                    }
                }
                return new Testcase(data, seed, desc);
            }
        };
    }

    /**
     * 增强版 Splicing
     * 随机选择 "拼接 (Concat)" 或 "插入 (Insert)" 模式
     */
    private byte[] splice(byte[] targetA) {
        if (corpus.isEmpty()) return targetA;

        // 随机选择另一个种子
        Seed seedB = corpus.get(random().nextInt(corpus.size()));
        byte[] targetB = seedB.getData();

        if (targetA.length < 4 || targetB.length < 4) return targetA;

        // 模式 1: 标准尾部拼接 (A 的头 + B 的尾)
        // 模式 2: 中间插入 (A 的头 + B 的一段 + A 的尾) -> 类似于 Overwrite 但可能改变长度

        // 这里演示更稳健的标准拼接，并增加长度保护
        int splitAtA = random().nextInt(targetA.length);
        int splitAtB = random().nextInt(targetB.length);

        // 计算新长度，避免生成过大文件导致 OOM 或超时
        long newLenLong = (long) splitAtA + (long) (targetB.length - splitAtB);
        if (newLenLong > 1024 * 1024) { // 限制 1MB
            return targetA;
        }
        int newLen = (int) newLenLong;

        byte[] res = new byte[newLen];
        System.arraycopy(targetA, 0, res, 0, splitAtA);
        System.arraycopy(targetB, splitAtB, res, splitAtA, targetB.length - splitAtB);
        return res;
    }
}