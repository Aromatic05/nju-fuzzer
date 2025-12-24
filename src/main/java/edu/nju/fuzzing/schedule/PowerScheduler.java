package edu.nju.fuzzing.schedule;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.SeedType;

public class PowerScheduler {

    private static final int BASE_ENERGY = 100;
    private static final int MAX_ENERGY = 5000;

    public int assignEnergy(Seed seed) {
        if (seed == null) return 0;

        double score = BASE_ENERGY;

        // 1. 执行时间因子
        long execTime = seed.getExecutionTime();
        if (execTime > 0) {
            long execUs = execTime / 1000;
            if (execUs < 20000) {
                score *= 3.0;
            } else if (execUs < 50000) {
                score *= 2.0;
            } else if (execUs > 1000000) {
                score *= 0.25;
            } else if (execUs > 200000) {
                score *= 0.5;
            }
        }

        // 2. 覆盖率因子
        int bitmapSize = seed.getBitmapSize();
        if (bitmapSize > 1000) {
            score *= 2.0;
        } else if (bitmapSize > 500) {
            score *= 1.5;
        } else if (bitmapSize < 50) {
            score *= 0.5;
        }

        // 3. 新手保护 (Handicap)
        // 【修改点】：这里改成 > 1，因为 Seed 的 handicap 最低是 1
        if (seed.getHandicap() >= 4) {
            score *= 2.0; 
        } else if (seed.getHandicap() > 1) { // <--- 关键修改：从 0 改成 1
            score *= 1.5;
        }

        // 4. 深度因子
        if (seed.getDepth() > 5) {
            score *= 1.2;
        }

        // 5. 输入大小因子（额外增强）：小输入更便宜，能多跑；超大输入适当降能量。
        // 注意：测试里 seed data 可能是空数组，这里保持中性。
        int inputSize = 0;
        byte[] data = seed.getData();
        if (data != null) inputSize = data.length;
        if (inputSize > 0) {
            if (inputSize <= 128) {
                score *= 1.2;
            } else if (inputSize >= 256 * 1024) {
                score *= 0.7;
            } else if (inputSize >= 1024 * 1024) {
                score *= 0.4;
            }
        }

        // 6. 类型因子（额外增强）：如果类型可识别，轻微加成。
        // 测试默认 UNKNOWN，保持中性。
        SeedType type = seed.getType();
        if (type != null && type != SeedType.UNKNOWN) {
            score *= 1.1;
        }

        // 7. CoverageDB 信号：favored/rarity/redundant/unstable
        // Favored seeds deserve more energy; redundant and unstable seeds get less.
        if (seed.isFavored()) {
            score *= 1.5;
        }
        if (seed.isRedundant()) {
            score *= 0.5;
        }
        if (seed.getStability() == edu.nju.fuzzing.model.CoverageEx.Stability.UNSTABLE) {
            score *= 0.7;
        }

        // Rare edges: boost proportionally but keep it bounded.
        // rarityScore is sum(1/freq), usually small; cap multiplier to avoid explosions.
        double rarity = seed.getRarityScore();
        if (rarity > 0) {
            double rarityMul = 1.0 + Math.min(1.0, rarity); // cap at x2.0
            score *= rarityMul;
        }
        int minFreq = seed.getMinEdgeFrequency();
        if (minFreq > 0 && minFreq <= 2) {
            score *= 1.2;
        }

        int finalEnergy = (int) score;
        return Math.max(1, Math.min(finalEnergy, MAX_ENERGY));
    }
}