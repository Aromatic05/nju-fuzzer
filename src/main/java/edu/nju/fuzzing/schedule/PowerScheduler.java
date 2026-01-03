package edu.nju.fuzzing.schedule;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.SeedType;
import edu.nju.fuzzing.stats.FuzzStats;

import java.util.HashMap;
import java.util.Map;

public class PowerScheduler {

    private static final int BASE_ENERGY = 100;
    private static final int MAX_ENERGY = 5000;

    // Optional: provides global avg exec time for adaptive thresholds.
    private FuzzStats fuzzStats;

    // In-memory scheduling state (not persisted).
    private final Map<String, SeedRunStats> seedStats = new HashMap<>();
    private long totalChosen = 0;

    private static final class SeedRunStats {
        long chosenCount;
        int consecutiveNoNewPathRounds;
        boolean newPathSeenThisRound;
    }

    public PowerScheduler() {
        this(null);
    }

    public PowerScheduler(FuzzStats fuzzStats) {
        this.fuzzStats = fuzzStats;
    }

    /**
     * Late binding for legacy constructors / tests.
     * FuzzingEngine 会在构造完成后注入自身的 fuzzStats。
     */
    public void setFuzzStats(FuzzStats fuzzStats) {
        this.fuzzStats = fuzzStats;
    }

    /**
     * Called by FuzzingEngine to report whether this parent seed produced a new path in the last round.
     */
    public void recordRoundResult(Seed seed, boolean producedNewPath) {
        if (seed == null) return;
        SeedRunStats st = seedStats.get(seed.getId());
        if (st == null) return;
        if (producedNewPath) {
            st.consecutiveNoNewPathRounds = 0;
        } else {
            st.consecutiveNoNewPathRounds = Math.min(1_000_000, st.consecutiveNoNewPathRounds + 1);
        }
        st.newPathSeenThisRound = false;
    }

    /**
     * Called by FuzzingEngine when a new path is observed while fuzzing the given parent seed.
     */
    public void recordNewPathDuringRound(Seed parentSeed) {
        if (parentSeed == null) return;
        SeedRunStats st = seedStats.get(parentSeed.getId());
        if (st != null) {
            st.newPathSeenThisRound = true;
        }
    }

    private long resolveAvgExecUsFallback() {
        // Default baseline: 100ms. This matches many unit-test assumptions and gives a sane midpoint.
        return 100_000L;
    }

    private long resolveAvgExecUs() {
        if (fuzzStats != null) {
            long avg = fuzzStats.getAvgExecTimeUs();
            if (avg > 0) return avg;
        }
        return resolveAvgExecUsFallback();
    }

    public int assignEnergy(Seed seed) {
        if (seed == null) return 0;

        double score = BASE_ENERGY;

        // 0) Update in-memory scheduling state
        SeedRunStats st = seedStats.computeIfAbsent(seed.getId(), k -> new SeedRunStats());
        st.chosenCount++;
        totalChosen++;
        double avgChosen = seedStats.isEmpty() ? 0.0 : (double) totalChosen / (double) seedStats.size();

        // 1) 执行时间因子（自适应：相对于全局平均）
        long avgExecUs = resolveAvgExecUs();
        long execUs = 0L;
        long execTime = seed.getExecutionTime();
        if (execTime > 0) {
            execUs = Math.max(1L, execTime / 1000L);
        }
        if (execUs > 0 && avgExecUs > 0) {
            if (execUs < (long) (avgExecUs * 0.25)) {          // 极快：快于平均 4 倍
                score *= 3.0;
            } else if (execUs < (long) (avgExecUs * 0.50)) {   // 较快：快于平均 2 倍
                score *= 2.0;
            } else if (execUs > (long) (avgExecUs * 5.0)) {    // 极慢：慢于平均 5 倍
                score *= 0.25;
            } else if (execUs > (long) (avgExecUs * 2.0)) {    // 较慢：慢于平均 2 倍
                score *= 0.5;
            }
            // 中间区间保持 x1.0
        }

        // 2) 覆盖率/bitmapSize：不再直接奖励或惩罚（避免“路径长/循环展开”造成虚高误导）

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
            } else if (inputSize >= 1024 * 1024) {
                score *= 0.4;
            } else if (inputSize >= 256 * 1024) {
                score *= 0.7;
            }
        }

        // 6. 类型因子（额外增强）：如果类型可识别，轻微加成。
        // 测试默认 UNKNOWN，保持中性。
        SeedType type = seed.getType();
        if (type != null && type != SeedType.UNKNOWN) {
            score *= 1.1;
        }

        // 7. CoverageDB 信号：favored/rarity/redundant/unstable
        // Favored seeds are the core signal in AFL-style scheduling.
        if (seed.isFavored()) {
            score *= 3.0;
        }
        if (seed.isRedundant()) {
            score *= 0.5;
        }
        if (seed.getStability() == edu.nju.fuzzing.model.CoverageEx.Stability.UNSTABLE) {
            score *= 0.4;
        }

        // Rare edges: smooth boost to avoid multiplication explosion.
        double rarity = seed.getRarityScore();
        if (rarity > 0) {
            score *= (1.0 + Math.log10(1.0 + rarity));
        }
        int minFreq = seed.getMinEdgeFrequency();
        if (minFreq > 0 && minFreq <= 2) {
            score *= 1.2;
        }

        // 8) 能量衰减：避免“老种子长期霸占 CPU”
        // 8.1 chosenCount 相对衰减：被选中次数越多，能量越低（逼迫队列流转）
        if (avgChosen > 0) {
            double relativeChosen = (st.chosenCount + 1.0) / (avgChosen + 1.0);
            if (relativeChosen > 1.0) {
                // Soft decay: relative^(-0.7)
                score *= Math.pow(relativeChosen, -0.7);
            }
        }

        // 8.2 stagnation 衰减：连续多轮没有新路径，快速降能量
        // 如果本轮已经产生新路径（由 engine 回传），则不施加该惩罚
        if (!st.newPathSeenThisRound && st.consecutiveNoNewPathRounds > 0) {
            score *= Math.pow(0.7, Math.min(10, st.consecutiveNoNewPathRounds));
        }

        int finalEnergy = (int) score;
        return Math.max(1, Math.min(finalEnergy, MAX_ENERGY));
    }
}