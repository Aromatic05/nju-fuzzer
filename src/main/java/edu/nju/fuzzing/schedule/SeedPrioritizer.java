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
        // 这种种子通常含有未被挖掘的潜力，应该插队优先处理
        for (Seed seed : seeds) {
            if (!seed.isWasFuzzed()) {
                return seed;
            }
        }

        // 2. 【兜底策略】如果都跑过了，就轮询 (Round Robin)
        // 保证大家都有机会被反复变异
        int size = seeds.size();
        
        // 防止列表大小变化导致 index 越界
        if (currentIndex >= size) {
            currentIndex = 0;
        }

        Seed selected = seeds.get(currentIndex);

        // 移动指针，准备下一次
        currentIndex = (currentIndex + 1) % size;

        return selected;
    }
}