package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AflHavocMutator 的单元测试 (修正版)
 * 适配具体的 Seed 类定义
 */
class AflHavocMutatorTest {

    private List<Seed> corpus;
    private Seed basicSeed;

    @BeforeEach
    void setUp() {
        corpus = new ArrayList<>();
        // [修正] 使用 Seed.loadWithMetadata 创建对象
        // 传入一个虚拟的文件路径和字节数据即可
        byte[] data = "AAAA".getBytes(StandardCharsets.ISO_8859_1);
        basicSeed = Seed.loadWithMetadata(new File("dummy_seed_A"), data);
        corpus.add(basicSeed);
    }

    // ==========================================
    // 基础功能测试
    // ==========================================

    @Test
    @DisplayName("Test 1: Iterator Protocol - 迭代器基本行为测试")
    void testIteratorProtocol() {
        int energy = 5;
        AflHavocMutator mutator = new AflHavocMutator(corpus);
        Iterator<Testcase> iter = mutator.mutate(basicSeed, energy);

        int count = 0;
        while (iter.hasNext()) {
            Testcase tc = iter.next();
            assertNotNull(tc);
            assertNotNull(tc.getData());
            count++;
        }

        assertEquals(energy, count, "迭代器生成的数量应严格等于 Energy");
        assertThrows(NoSuchElementException.class, iter::next, "耗尽后调用 next() 应抛出异常");
    }

    @Test
    @DisplayName("Test 2: Mutation Effectiveness - 变异应产生不同的数据")
    void testMutationEffectiveness() {
        AflHavocMutator mutator = new AflHavocMutator(corpus);
        Iterator<Testcase> iter = mutator.mutate(basicSeed, 50);

        boolean anyChanged = false;
        byte[] original = basicSeed.getData();

        while (iter.hasNext()) {
            byte[] mutated = iter.next().getData();
            if (!Arrays.equals(original, mutated)) {
                anyChanged = true;
                break;
            }
        }
        assertTrue(anyChanged, "经过多次 Havoc，生成的数据应该与原始数据不同");
    }

    // ==========================================
    // 结构与拼接测试 (Structural & Splicing)
    // ==========================================

    @Test
    @DisplayName("Test 3: Structural Change - 长度应发生变化 (插入/删除)")
    void testStructuralChange() {
        AflHavocMutator mutator = new AflHavocMutator(corpus);
        Iterator<Testcase> iter = mutator.mutate(basicSeed, 100);

        boolean lengthChanged = false;
        int origLen = basicSeed.getData().length;

        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            if (data.length != origLen) {
                lengthChanged = true;
                break;
            }
        }
        assertTrue(lengthChanged, "Havoc 应包含结构性变异导致长度变化");
    }

    @Test
    @DisplayName("Test 4: Splicing - 应该融合语料库中其他种子的内容")
    void testSplicing() {
        // [修正] 创建真实的 Seed 对象
        byte[] dataA = "AAAA".repeat(10).getBytes();
        byte[] dataB = "BBBB".repeat(10).getBytes();

        Seed seedA = Seed.loadWithMetadata(new File("seed_A"), dataA);
        Seed seedB = Seed.loadWithMetadata(new File("seed_B"), dataB);

        List<Seed> multiCorpus = Arrays.asList(seedA, seedB);

        AflHavocMutator mutator = new AflHavocMutator(multiCorpus);

        // 对 SeedA 进行变异
        Iterator<Testcase> iter = mutator.mutate(seedA, 200);

        boolean spliced = false;
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            String content = new String(data);
            // 检查内容是否混合
            if (content.contains("AAAA") && content.contains("BBBB")) {
                spliced = true;
                break;
            }
        }
        assertTrue(spliced, "当语料库 > 1 时，Splicing 应该触发并混合内容");
    }

    // ==========================================
    // 字典功能测试
    // ==========================================

    @Test
    @DisplayName("Test 5: Dictionary Insertion - 应该插入自定义 Token")
    void testDictionary() {
        AflHavocMutator mutator = new AflHavocMutator(corpus);
        String magicToken = "MAGIC_TOKEN";
        mutator.addDictionaryEntry(magicToken.getBytes());

        Iterator<Testcase> iter = mutator.mutate(basicSeed, 200);

        boolean foundToken = false;
        while (iter.hasNext()) {
            byte[] data = iter.next().getData();
            if (indexOf(data, magicToken.getBytes()) != -1) {
                foundToken = true;
                break;
            }
        }
        assertTrue(foundToken, "变异结果应包含注入的字典 Token");
    }

    @Test
    @DisplayName("Test 6: Load Dictionary - 批量加载字典")
    void testLoadDictionary() {
        AflHavocMutator mutator = new AflHavocMutator(corpus);
        List<String> dicts = Arrays.asList("FUNC", "VAR", "LET");
        mutator.loadDictionary(dicts);

        // 创建一个空内容的 Seed 方便观察插入
        Seed emptySeed = Seed.loadWithMetadata(new File("empty"), new byte[20]);
        Iterator<Testcase> iter = mutator.mutate(emptySeed, 200);

        boolean foundAny = false;
        while(iter.hasNext()) {
            byte[] data = iter.next().getData();
            if (indexOf(data, "FUNC".getBytes()) != -1 ||
                    indexOf(data, "VAR".getBytes()) != -1) {
                foundAny = true;
                break;
            }
        }
        assertTrue(foundAny, "批量加载的字典应被用于变异");
    }

    // ==========================================
    // 边界与健壮性测试
    // ==========================================

    @Test
    @DisplayName("Test 7: Empty Seed - 空数据种子变异不应报错")
    void testEmptySeed() {
        // [修正] 创建真实的空 Seed
        Seed emptySeed = Seed.loadWithMetadata(new File("empty"), new byte[0]);
        AflHavocMutator mutator = new AflHavocMutator(corpus);

        assertDoesNotThrow(() -> {
            Iterator<Testcase> iter = mutator.mutate(emptySeed, 10);
            while (iter.hasNext()) {
                byte[] data = iter.next().getData();
                assertNotNull(data);
            }
        }, "变异空种子不应抛出异常");
    }

    @Test
    @DisplayName("Test 8: Large Seed - 大文件处理性能/逻辑检查")
    void testLargeSeed() {
        byte[] largeData = new byte[1024 * 200];
        Arrays.fill(largeData, (byte) 'A');
        // [修正] 创建真实的大 Seed
        Seed largeSeed = Seed.loadWithMetadata(new File("large"), largeData);

        AflHavocMutator mutator = new AflHavocMutator(corpus);

        long startTime = System.currentTimeMillis();
        Iterator<Testcase> iter = mutator.mutate(largeSeed, 10);
        while (iter.hasNext()) {
            Testcase tc = iter.next();
            assertNotNull(tc.getData());
        }
        long duration = System.currentTimeMillis() - startTime;

        assertTrue(duration < 2000, "大文件变异不应耗时过长");
    }

    @Test
    @DisplayName("Test 9: Invalid Inputs - 错误的字典输入")
    void testInvalidInputs() {
        AflHavocMutator mutator = new AflHavocMutator(corpus);
        mutator.addDictionaryEntry(null);
        mutator.addDictionaryEntry(new byte[0]);

        Iterator<Testcase> iter = mutator.mutate(basicSeed, 5);
        while(iter.hasNext()) {
            assertNotNull(iter.next().getData());
        }
    }

    @Test
    @DisplayName("Test 10: Data Isolation - 变异不应修改原始种子对象")
    void testDataIsolation() {
        byte[] originalData = basicSeed.getData();
        // 留一个副本用于对比
        byte[] copyOriginal = Arrays.copyOf(originalData, originalData.length);

        AflHavocMutator mutator = new AflHavocMutator(corpus);
        Iterator<Testcase> iter = mutator.mutate(basicSeed, 10);

        if (iter.hasNext()) {
            byte[] mutated = iter.next().getData();
            // 尝试污染变异后的数据
            if (mutated.length > 0) mutated[0] = (byte) 0xFF;
        }

        // 验证原始 Seed 内的数据没有被上面那行修改影响
        assertArrayEquals(copyOriginal, basicSeed.getData(), "变异操作产生的副作用不应污染原始 Seed 对象");
    }

    // ==========================================
    // 辅助方法
    // ==========================================

    private int indexOf(byte[] data, byte[] pattern) {
        if (pattern.length == 0) return 0;
        outer:
        for (int i = 0; i < data.length - pattern.length + 1; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}