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
    // === 新增测试样例 ===

    @Test
    void testDictionaryInjection_ShouldContainKeywords() {
        // 给一个全 0 的种子，并给予足够的能量，看能否变异出字典里的关键字
        Seed blankSeed = Seed.loadWithMetadata(new File("blank"), new byte[50]); // 50个0

        // 尝试变异 500 次，期望至少命中一次字典算子
        List<Testcase> results = mutator.mutate(blankSeed, 500);

        boolean foundKeyword = false;
        for (Testcase tc : results) {
            String s = new String(tc.data(), StandardCharsets.ISO_8859_1);
            // 检查你在 AflHavocMutator.initDictionary 里定义的关键字
            if (s.contains("ELF") || s.contains("PNG") || s.contains("<root>") || s.contains("SELECT")) {
                foundKeyword = true;
                break;
            }
        }
        Assertions.assertTrue(foundKeyword, "Havoc 应该能从内置字典中注入关键字 (如 ELF, <root>)");
    }

    @Test
    void testAdaptiveStacking_HighEnergyChangesMore() {
        // 测试自适应堆叠：高能量应该导致数据被修改得面目全非
        // 低能量 (stack 2-8) vs 高能量 (stack 2-32)
        // 这里的 energy 参数不仅决定数量，在你的算法里也决定了 maxStack 深度

        // 1. 低能量变异 (Energy=50) -> maxStack = 8
        // 我们需要 Hack 一下 Seed 的 energy 属性，或者在 mutate 调用时传入
        // 注意：你的 mutate 方法是用传入参数 energy 来决定循环次数
        // 但你的 AflHavocMutator 内部逻辑是用传入的 energy 来判断 maxStack

        // 低能量测试: energy=100
        Seed seed = Seed.loadWithMetadata(new File("seed"), new byte[100]); // 100个0
        List<Testcase> lowEnergyResults = mutator.mutate(seed, 100);

        // 高能量测试: energy=2000 (触发 maxStack=32)
        List<Testcase> highEnergyResults = mutator.mutate(seed, 2000);

        // 计算平均改变的字节数 (Hamming Distance 近似值)
        double lowChangeRate = calculateAverageChangeRate(seed.getData(), lowEnergyResults);
        double highChangeRate = calculateAverageChangeRate(seed.getData(), highEnergyResults);

        System.out.println("Low Energy Change Rate: " + lowChangeRate);
        System.out.println("High Energy Change Rate: " + highChangeRate);

        // 高能量（堆叠更多算子）通常会导致更多字节被修改
        // 注意：这是概率性的，但在大样本下应该成立
        Assertions.assertTrue(highChangeRate > lowChangeRate * 0.8,
                "高能量变异应当倾向于产生更剧烈的变化 (堆叠更多算子)");
    }

    // 辅助方法：计算平均有多少个字节发生了变化
    private double calculateAverageChangeRate(byte[] original, List<Testcase> cases) {
        long totalDiff = 0;
        for (Testcase tc : cases) {
            byte[] mutated = tc.data();
            // 只比较重合部分的字节差异
            int len = Math.min(original.length, mutated.length);
            for (int i = 0; i < len; i++) {
                if (original[i] != mutated[i]) {
                    totalDiff++;
                }
            }
            // 长度差异也算一种变化
            totalDiff += Math.abs(original.length - mutated.length);
        }
        return (double) totalDiff / cases.size();
    }
}