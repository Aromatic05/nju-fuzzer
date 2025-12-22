package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Havoc (大破坏) 变异器实现
 * 核心逻辑：对每一个生成的 Testcase，随机堆叠多个变异算子
 */
public class HavocMutator implements Mutator {

    private final Random random = new Random();

    // 堆叠参数：对每个 Testcase，最少执行 2 个算子，最多执行 8 个算子
    private static final int MIN_STACK = 2;
    private static final int MAX_STACK = 8;

    @Override
    public List<Testcase> mutate(Seed seed, int energy) {
        // 预分配列表大小，避免扩容开销
        List<Testcase> testcases = new ArrayList<>(energy);
        byte[] originalData = seed.getData();

        for (int i = 0; i < energy; i++) {
            // 1. 获取一份原始数据的拷贝 (绝对不能修改 originalData)
            byte[] mutatedData = originalData.clone();

            // 2. 决定本次堆叠多少个算子 (如果是极小文件，就只变异一次)
            int stackCount = (mutatedData.length < 4)
                    ? 1
                    : MIN_STACK + random.nextInt(MAX_STACK - MIN_STACK + 1);

            // 3. 循环应用算子 (Stacking)
            for (int j = 0; j < stackCount; j++) {
                mutatedData = applyRandomOp(mutatedData);
            }

            // 4. 生成 Testcase 对象并加入结果列表
            // 假设 Testcase 有一个构造函数接收 byte[] 数据
            // 在 HavocMutator.mutate 方法中:
            testcases.add(new Testcase(mutatedData, seed, "havoc_stack"));
        }

        return testcases;
    }

    /**
     * 随机选择并应用一个算子
     */
    private byte[] applyRandomOp(byte[] data) {
        // 随机选择 0 到 6 号算子
        int op = random.nextInt(7);

        switch (op) {
            case 0: return MutationOps.flipBit(data);
            case 1: return MutationOps.flipByte(data);
            case 2: return MutationOps.arithByte(data);
            case 3: return MutationOps.setInteresting8(data);
            case 4: return MutationOps.deleteBlock(data);
            case 5: return MutationOps.insertBlock(data);
            case 6: return MutationOps.overwriteBlock(data);
            default: return data;
        }
    }
}