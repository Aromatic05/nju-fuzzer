package edu.nju.fuzzing.schedule;

import edu.nju.fuzzing.model.Seed;

/**
 * 能量调度器：决定一个种子在这一轮中应该进行多少次变异尝试。
 * 核心逻辑：基于种子的性能指标（执行时间、覆盖率、新鲜度）动态计算能量。
 */
public class PowerScheduler {

    // 基础变异次数
    private static final int BASE_ENERGY = 100;
    // 最大能量限制 (防止死循环太久)
    private static final int MAX_ENERGY = 5000;

    /**
     * 计算能量
     * @param seed 目标种子
     * @return 变异次数 (energy)
     */
    public int assignEnergy(Seed seed) {
        if (seed == null) return 0;

        // 初始能量
        double score = BASE_ENERGY;

        // --- 1. 执行时间因子 (Time Factor) ---
        // 目标：奖励跑得快的种子
        long execTime = seed.getExecutionTime(); // 纳秒
        if (execTime > 0) {
            long execUs = execTime / 1000; // 微秒
            
            // 阈值参考 AFL 的配置
            if (execUs < 20000) {        // < 20ms: 极快
                score *= 3.0;
            } else if (execUs < 50000) { // < 50ms: 快
                score *= 2.0;
            } else if (execUs > 200000) { // > 200ms: 慢
                score *= 0.5;
            } else if (execUs > 1000000) { // > 1s: 极慢
                score *= 0.25;
            }
        }

        // --- 2. 覆盖率因子 (Bitmap Size Factor) ---
        // 目标：奖励覆盖率高的种子 (更可能触达深层逻辑)
        int bitmapSize = seed.getBitmapSize();
        if (bitmapSize > 1000) {
            score *= 2.0;
        } else if (bitmapSize > 500) {
            score *= 1.5;
        } else if (bitmapSize < 50) {
            // 覆盖率太低可能价值不大
            score *= 0.5;
        }

        // --- 3. 新手保护 (Handicap) ---
        // 目标：刚加入的种子 (Handicap=8) 会获得巨大的能量加成
        // 随着被调度次数增加，Handicap 降低，能量回归正常
        if (seed.getHandicap() >= 4) {
            score *= 2.0; // 新手光环
        } else if (seed.getHandicap() > 0) {
            score *= 1.5;
        }

        // --- 4. 深度因子 (Depth) ---
        // 目标：深层变异出来的种子通常比较难得
        if (seed.getDepth() > 5) {
            score *= 1.2;
        }

        // --- 5. 归一化 ---
        int finalEnergy = (int) score;

        // 兜底：至少跑 1 次，至多跑 MAX_ENERGY 次
        return Math.max(1, Math.min(finalEnergy, MAX_ENERGY));
    }
}