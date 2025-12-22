package edu.nju.fuzzing.schedule;

import edu.nju.fuzzing.model.Seed;

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

        int finalEnergy = (int) score;
        return Math.max(1, Math.min(finalEnergy, MAX_ENERGY));
    }
}