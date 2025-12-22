package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * AFL 风格的 Havoc (大破坏) 变异器
 * 包含了 Splice (拼接) 逻辑。
 * 适用于通用二进制目标 (readelf, objdump, tcpdump, jpeg 等)。
 */
public class AflHavocMutator implements Mutator {

    private final Random random = new Random();
    private final List<Seed> corpus; // 引用全局种子队列，用于 Splice

    public AflHavocMutator(List<Seed> corpus) {
        this.corpus = corpus;
    }

    @Override
    public List<Testcase> mutate(Seed seed, int energy) {
        List<Testcase> testcases = new ArrayList<>(energy);
        byte[] originalData = seed.getData(); // 获取副本

        for (int i = 0; i < energy; i++) {
            byte[] data = originalData.clone();
            String desc = "havoc";

            // === 1. SPLICE 阶段 ===
            // 20% 概率触发，且必须有其他种子可用
            // Splice 对 binutils 和 tcpdump 等分包结构程序非常有效
            if (corpus.size() > 1 && random.nextInt(100) < 20) {
                data = splice(data);
                desc = "splice+havoc";
            }

            // === 2. HAVOC 阶段 (变异堆叠) ===
            // 对数据进行 2 到 8 次连续破坏
            int stackCount = 2 + random.nextInt(7);
            if (data.length < 4) stackCount = 1;

            for (int j = 0; j < stackCount; j++) {
                int op = random.nextInt(7); // 7 种原子操作
                switch (op) {
                    case 0: data = MutationOps.flipBit(data); break;
                    case 1: data = MutationOps.flipByte(data); break;
                    case 2: data = MutationOps.arithByte(data); break;
                    case 3: data = MutationOps.setInteresting(data); break;
                    case 4: data = MutationOps.deleteBlock(data); break;
                    case 5: data = MutationOps.insertBlock(data); break;
                    case 6: data = MutationOps.overwriteBlock(data); break;
                }
            }

            testcases.add(new Testcase(data, seed, desc));
        }

        return testcases;
    }

    /**
     * Splice (拼接) 算子
     * 随机找另一个种子，切开并拼接到当前种子后面
     */
    private byte[] splice(byte[] targetA) {
        // 尝试 3 次寻找合适的配对种子
        Seed seedB = targetA.length > 0 ? corpus.get(random.nextInt(corpus.size())) : null;
        if (seedB == null || seedB.getData().length < 2) return targetA;

        byte[] targetB = seedB.getData(); // 这里可以直接读 raw data，只读不写
        if (targetA.length < 2) return targetA;

        // 随机切分点
        int splitAtA = random.nextInt(targetA.length);
        int splitAtB = random.nextInt(targetB.length);

        // 拼接: A[0..splitA] + B[splitB..end]
        int newLen = splitAtA + (targetB.length - splitAtB);
        byte[] res = new byte[newLen];

        System.arraycopy(targetA, 0, res, 0, splitAtA);
        System.arraycopy(targetB, splitAtB, res, splitAtA, targetB.length - splitAtB);

        return res;
    }
}