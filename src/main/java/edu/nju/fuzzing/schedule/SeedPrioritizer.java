package edu.nju.fuzzing.schedule;

import edu.nju.fuzzing.model.Seed;

import java.util.List;

/**
 * 种子选择器：决定下一个对哪个种子进行变异。
 * 策略：优先选择未测试过的新种子；若都测试过，则轮询。
 */
public class SeedPrioritizer {

    private int currentIndex = 0;

    private static double scoreForSelection(Seed seed) {
        // Higher score = more likely to be fuzzed next.
        // Keep this deterministic and monotonic w.r.t. useful metadata.
        double score = 0.0;

        // Prefer seeds that likely cover more (once metadata exists).
        score += Math.max(0, seed.getBitmapSize());

        // CoverageDB hints: favored/rarity/redundancy.
        if (seed.isFavored()) {
            score += 10_000.0;
        }
        if (seed.isRedundant()) {
            score -= 2_000.0;
        }

        // Prefer seeds that cover rare edges.
        // rarityScore is already a sum of 1/freq, so a larger value is better.
        double rarityScore = seed.getRarityScore();
        if (rarityScore > 0) {
            score += 500.0 * rarityScore;
        }
        int minFreq = seed.getMinEdgeFrequency();
        if (minFreq > 0 && minFreq <= 2) {
            score += 250.0;
        }

        // Penalize unstable traces slightly.
        if (seed.getStability() == edu.nju.fuzzing.model.CoverageEx.Stability.UNSTABLE) {
            score -= 500.0;
        }

        // Prefer faster seeds (execTimeNanos): use a soft penalty.
        long execTimeNanos = seed.getExecutionTime();
        if (execTimeNanos > 0) {
            // Convert to microseconds to avoid overflow and reduce sensitivity.
            long execUs = Math.max(1, execTimeNanos / 1000L);
            score += 1_000_000.0 / execUs;
        }

        // Prefer shallower seeds a bit (reduce getting stuck deep).
        score += Math.max(0, 16 - seed.getDepth());

        // Give a small boost to seeds with higher handicap (new seeds).
        score += Math.max(0, seed.getHandicap());

        return score;
    }

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

        // 1) Prefer unfuzzed seeds, but choose the best one deterministically.
        Seed bestUnfuzzed = null;
        double bestScore = Double.NEGATIVE_INFINITY;
        for (Seed seed : seeds) {
            if (!seed.isWasFuzzed()) {
                double s = scoreForSelection(seed);
                if (bestUnfuzzed == null || s > bestScore) {
                    bestUnfuzzed = seed;
                    bestScore = s;
                }
            }
        }
        if (bestUnfuzzed != null) {
            return bestUnfuzzed;
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