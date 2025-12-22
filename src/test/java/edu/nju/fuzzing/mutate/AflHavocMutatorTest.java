package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 验证 Havoc 和 Splice 变异器的逻辑
 */
class AflHavocMutatorTest {

    private List<Seed> corpus;
    private Seed seedA;
    private Seed seedB;
    private AflHavocMutator mutator;

    @BeforeEach
    void setUp() {
        // 准备语料库
        corpus = new ArrayList<>();

        // --- 修复点：使用 loadWithMetadata 创建初始种子 ---

        // 模拟 Seed A (全 A)
        byte[] dataA = "AAAA".repeat(20).getBytes(StandardCharsets.UTF_8);
        seedA = Seed.loadWithMetadata(new File("seedA"), dataA);

        // 模拟 Seed B (全 B)
        byte[] dataB = "BBBB".repeat(20).getBytes(StandardCharsets.UTF_8);
        seedB = Seed.loadWithMetadata(new File("seedB"), dataB);

        corpus.add(seedA);
        corpus.add(seedB);

        mutator = new AflHavocMutator(corpus);
    }

    @Test
    void testMutate_ShouldRespectEnergy() {
        int energy = 50;
        List<Testcase> results = mutator.mutate(seedA, energy);
        Assertions.assertEquals(energy, results.size(), "生成的 Testcase 数量应等于 energy");
    }

    @Test
    void testMutate_ShouldProduceVariety() {
        // Havoc 应该产生变化
        List<Testcase> results = mutator.mutate(seedA, 10);
        for (Testcase tc : results) {
            // 注意：Testcase 是 record，访问数据使用 tc.data() 或 tc.getDataCopy()
            Assertions.assertFalse(Arrays.equals(seedA.getDataCopy(), tc.data()), "Testcase 不应与原种子完全相同");
            Assertions.assertEquals(seedA, tc.parent(), "Testcase 的父节点引用应正确");
        }
    }

    @Test
    void testMutate_DescriptionCheck() {
        List<Testcase> results = mutator.mutate(seedA, 5);
        for (Testcase tc : results) {
            String desc = tc.description();
            Assertions.assertTrue(desc.contains("havoc"), "描述信息应包含 havoc");
        }
    }

    @Test
    void testSplice_ShouldOccurIdeally() {
        // Splice 概率较低 (20%)，我们通过大量运行来捕捉一次
        boolean spliceFound = false;

        // 尝试生成 1000 个，理论上会有 Splice
        List<Testcase> results = mutator.mutate(seedA, 1000);

        for (Testcase tc : results) {
            // 如果发生了 Splice，描述信息里会有 "splice"
            if (tc.description().contains("splice")) {
                spliceFound = true;
                break;
            }
        }

        Assertions.assertTrue(spliceFound, "在大样本下应该触发 Splice 变异");
    }

    @Test
    void testSplice_LogicCheck() {
        // 手动检查 Splice 效果：如果产生了 Splice，它应该包含 'B'
        List<Testcase> results = mutator.mutate(seedA, 500);
        boolean containsB = false;
        for (Testcase tc : results) {
            String s = new String(tc.data());
            if (s.contains("BB")) {
                containsB = true;
                break;
            }
        }
        Assertions.assertTrue(containsB, "种子A变异后应包含种子B的片段 (Splice效果)");
    }

    @Test
    void testSmallSeed_ShouldNotCrash() {
        // --- 修复点 ---
        Seed small = Seed.loadWithMetadata(new File("small"), new byte[]{1});
        List<Testcase> res = mutator.mutate(small, 5);
        Assertions.assertEquals(5, res.size());
    }

    @Test
    void testZeroEnergy_ShouldReturnEmpty() {
        List<Testcase> res = mutator.mutate(seedA, 0);
        Assertions.assertTrue(res.isEmpty());
    }

    @Test
    void testEmptyCorpus_HavocShouldStillWork() {
        // 如果语料库只有一个种子，Splice 不应触发，但 Havoc 应正常工作
        List<Seed> singleCorpus = new ArrayList<>();
        singleCorpus.add(seedA);
        AflHavocMutator singleMutator = new AflHavocMutator(singleCorpus);

        List<Testcase> res = singleMutator.mutate(seedA, 10);
        Assertions.assertEquals(10, res.size());
        for(Testcase tc : res) {
            Assertions.assertFalse(tc.description().contains("splice"), "只有一个种子时不应触发 Splice");
        }
    }

    @Test
    void testDeepCopyCheck() {
        // 确保变异没有修改原 Seed 的数据
        byte[] original = seedA.getDataCopy();
        mutator.mutate(seedA, 10);
        Assertions.assertArrayEquals(original, seedA.getDataCopy(), "变异操作不应污染原 Seed 数据");
    }
}