package edu.nju.fuzzing.schedule;

import edu.nju.fuzzing.model.Seed;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class SeedPrioritizerTest {

    private SeedPrioritizer prioritizer;
    private List<Seed> seeds;

    @BeforeEach
    public void setup() {
        prioritizer = new SeedPrioritizer();
        seeds = new ArrayList<>();
    }

    // 辅助方法：快速创建种子 (修正版)
    private Seed createSeed(String name, boolean fuzzed) {
        // 【修正】使用静态工厂方法创建，而不是 new
        Seed s = Seed.loadWithMetadata(new File(name), new byte[0]);
        if (fuzzed) {
            s.markAsFuzzed();
        }
        return s;
    }

    /** Case 1: 测试空列表输入，应返回 null */
    @Test
    public void testEmptyList() {
        Seed result = prioritizer.pick(new ArrayList<>());
        Assertions.assertNull(result, "Should return null for empty list");
    }

    /** Case 2: 测试 null 输入，应返回 null */
    @Test
    public void testNullList() {
        Seed result = prioritizer.pick(null);
        Assertions.assertNull(result, "Should return null for null list");
    }

    /** Case 3: 只有新种子 (!wasFuzzed)，应该选中它 */
    @Test
    public void testSingleNewSeed() {
        Seed s1 = createSeed("new", false);
        seeds.add(s1);
        Assertions.assertEquals(s1, prioritizer.pick(seeds));
    }

    /** Case 4: 混合状态，应该优先选新种子，忽略老种子 */
    @Test
    public void testPrioritizeUnfuzzed() {
        Seed oldS = createSeed("old", true);
        Seed newS = createSeed("new", false);
        
        seeds.add(oldS);
        seeds.add(newS); // 新种子在后面

        // 应该跳过 old，直接选 new
        Assertions.assertEquals(newS, prioritizer.pick(seeds));
    }

    /** Case 5: 多个新种子，应该返回第一个遇到的 */
    @Test
    public void testMultipleUnfuzzed() {
        Seed new1 = createSeed("new1", false);
        Seed new2 = createSeed("new2", false);
        seeds.add(new1);
        seeds.add(new2);

        Assertions.assertEquals(new1, prioritizer.pick(seeds));
    }

    /** Case 5b: 多个新种子时，favored 应优先 */
    @Test
    public void testFavoredUnfuzzedBeatsNonFavored() {
        Seed s1 = createSeed("s1", false);
        Seed s2 = createSeed("s2", false);
        s2.setFavored(true);

        seeds.add(s1);
        seeds.add(s2);

        Assertions.assertEquals(s2, prioritizer.pick(seeds));
    }

    /** Case 6: 全部都是老种子，进入 Round Robin 模式 (第一次选第0个) */
    @Test
    public void testAllFuzzedStartsRoundRobin() {
        Seed s1 = createSeed("s1", true);
        Seed s2 = createSeed("s2", true);
        seeds.add(s1);
        seeds.add(s2);

        // 第一次轮询应该选 s1
        Assertions.assertEquals(s1, prioritizer.pick(seeds));
    }

    /** Case 7: Round Robin 的序列测试 (0 -> 1 -> 0) */
    @Test
    public void testRoundRobinSequence() {
        Seed s1 = createSeed("s1", true);
        Seed s2 = createSeed("s2", true);
        seeds.add(s1);
        seeds.add(s2);

        // 第1次 -> s1
        Assertions.assertEquals(s1, prioritizer.pick(seeds));
        // 第2次 -> s2
        Assertions.assertEquals(s2, prioritizer.pick(seeds));
        // 第3次 -> 回到 s1
        Assertions.assertEquals(s1, prioritizer.pick(seeds));
    }

    /** Case 8: 状态动态转换 (新种子被测完后，逻辑自动切换到 RR) */
    @Test
    public void testTransitionFromPriorityToRR() {
        Seed s1 = createSeed("s1", false); // 新
        Seed s2 = createSeed("s2", true);  // 老
        seeds.add(s1);
        seeds.add(s2);

        // 1. 优先选 s1
        Seed picked = prioritizer.pick(seeds);
        Assertions.assertEquals(s1, picked);

        // 2. 模拟 s1 跑完了，变老了
        s1.markAsFuzzed();

        // 3. 再次选择，现在都是老种子了，开始轮询
        Seed next = prioritizer.pick(seeds);
        Assertions.assertEquals(s1, next, "Should start RR from index 0");
    }

    /** Case 9: 列表扩容后的轮询稳定性 */
    @Test
    public void testListExpansion() {
        Seed s1 = createSeed("s1", true);
        seeds.add(s1);

        prioritizer.pick(seeds); // pick s1

        // 突然加入 s2
        Seed s2 = createSeed("s2", true);
        seeds.add(s2);

        // 下一次 pick，index=1，应该选中 s2
        Assertions.assertEquals(s2, prioritizer.pick(seeds));
    }

    /** Case 10: 索引越界保护 (当队列缩小时) */
    @Test
    public void testIndexOutOfBoundsProtection() {
        Seed s1 = createSeed("s1", true);
        Seed s2 = createSeed("s2", true);
        seeds.add(s1);
        seeds.add(s2);

        prioritizer.pick(seeds); // pick s1
        prioritizer.pick(seeds); // pick s2

        // 移除 s2
        seeds.remove(s2);

        // 下一次 pick，index=2，size=1，取模后应回到 s1
        Assertions.assertEquals(s1, prioritizer.pick(seeds));
    }
}