package edu.nju.fuzzing.schedule;

import edu.nju.fuzzing.model.Seed;

import java.util.List;

/**
 * 种子选择器：决定下一个对哪个种子进行变异。
 * 策略：优先选择未测试过的新种子；若都测试过，则轮询。
 */
public class SeedPrioritizer {

    private int currentIndex = 0;

    /**
     * 从种子列表中选出一个种子
     *
     * @param seeds 当前的种子队列 (来自 SeedQueue.getSeeds())
     * @return 选中的 Seed，如果队列为空则返回 null
     */
    public Seed pick(List<Seed> seeds) {
        if (seeds == null || seeds.isEmpty()) {
            return null;
        }

        // 1. 【优先策略】寻找未被 Fuzz 过的“处女”种子
        for (Seed seed : seeds) {
            if (!seed.isWasFuzzed()) {
                return seed;
            }
        }

        // 2. 【兜底策略】Round Robin
        int size = seeds.size();
        
        // --- 修改开始 ---
        // 使用取模运算计算实际下标，这样 currentIndex 可以一直增加
        // 即使 size 变了，它也会尝试指向下一个逻辑位置
        int actualIndex = currentIndex % size;
        
        Seed selected = seeds.get(actualIndex);

        // 指针简单自增，不立即取模
        // 这样当 size=1 时，index 会变成 1。
        // 下次 size=2 时，1 % 2 = 1，就会取到第 2 个元素 (s2)，符合测试预期。
        currentIndex++; 
        // --- 修改结束 ---

        return selected;
    }
}