package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.SeedType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * MutatorFactory 单元测试
 *
 * 测试覆盖：
 * 1. 构造函数正确性
 * 2. 各类型种子对应的 Mutator 创建
 * 3. 未知类型和 null 类型的兜底策略
 * 4. Havoc 混合策略（概率统计）
 * 5. 边界情况和异常处理
 */
class MutatorFactoryTest {

    private MutatorFactory factory;
    private List<Seed> corpus;

    @BeforeEach
    void setUp() {
        corpus = new ArrayList<>();
        // 添加一些种子到 corpus 供 AflHavocMutator 使用
        corpus.add(createSeedWithType("seed1", SeedType.XML, "<root/>".getBytes()));
        corpus.add(createSeedWithType("seed2", SeedType.LUA, "print('hello')".getBytes()));
        factory = new MutatorFactory(corpus);
    }

    /**
     * 创建指定类型的 Seed（用于测试）
     */
    private Seed createSeedWithType(String name, SeedType type, byte[] data) {
        Seed seed = Seed.loadWithMetadata(new File(name), data);
        // 使用反射设置类型（因为 Seed 可能没有 public setter）
        try {
            Field typeField = Seed.class.getDeclaredField("type");
            typeField.setAccessible(true);
            typeField.set(seed, type);
        } catch (Exception e) {
            // 如果反射失败，跳过类型设置
        }
        return seed;
    }

    // ==========================================
    // 构造函数测试
    // ==========================================

    @Nested
    @DisplayName("构造函数测试")
    class ConstructorTests {

        @Test
        @DisplayName("Test 1: 正常构造 - 非空 corpus")
        void testConstructorWithNonEmptyCorpus() {
            assertNotNull(factory);
            // 验证 factory 可以正常工作
            Seed seed = createSeedWithType("test", SeedType.UNKNOWN, new byte[0]);
            Mutator mutator = factory.createMutator(seed);
            assertNotNull(mutator);
        }

        @Test
        @DisplayName("Test 2: 空 corpus 构造")
        void testConstructorWithEmptyCorpus() {
            List<Seed> emptyCorpus = new ArrayList<>();
            MutatorFactory emptyFactory = new MutatorFactory(emptyCorpus);
            assertNotNull(emptyFactory);

            Seed seed = createSeedWithType("test", SeedType.UNKNOWN, new byte[0]);
            Mutator mutator = emptyFactory.createMutator(seed);
            assertNotNull(mutator);
            assertInstanceOf(AflHavocMutator.class, mutator);
        }

        @Test
        @DisplayName("Test 3: null corpus 构造（应优雅处理或抛出异常）")
        void testConstructorWithNullCorpus() {
            // 根据实现，可能抛出异常或接受 null
            // 这里测试实际行为
            try {
                MutatorFactory nullFactory = new MutatorFactory(null);
                // 如果没抛异常，验证可以正常创建 mutator
                Seed seed = createSeedWithType("test", SeedType.UNKNOWN, new byte[0]);
                assertNotNull(nullFactory.createMutator(seed));
            } catch (NullPointerException e) {
                // 也是合理的行为
                assertTrue(true);
            }
        }
    }

    // ==========================================
    // 类型映射测试
    // ==========================================

    @Nested
    @DisplayName("类型映射测试")
    class TypeMappingTests {

        @Test
        @DisplayName("Test 4: XML 类型 -> XmlMutator")
        void testXmlType() {
            Seed seed = createSeedWithType("test.xml", SeedType.XML, "<root/>".getBytes());
            // 多次尝试，跳过 Havoc 概率
            for (int i = 0; i < 20; i++) {
                Mutator mutator = factory.createMutator(seed);
                if (mutator instanceof XmlMutator) {
                    assertTrue(true);
                    return;
                }
            }
            fail("多次尝试后仍未返回 XmlMutator");
        }

        @Test
        @DisplayName("Test 5: MJS 类型 -> MjsMutator")
        void testMjsType() {
            Seed seed = createSeedWithType("test.mjs", SeedType.MJS, "{}".getBytes());
            for (int i = 0; i < 20; i++) {
                Mutator mutator = factory.createMutator(seed);
                if (mutator instanceof MjsMutator) {
                    assertTrue(true);
                    return;
                }
            }
            fail("多次尝试后仍未返回 MjsMutator");
        }

        @Test
        @DisplayName("Test 6: LUA 类型 -> LuaMutator")
        void testLuaType() {
            Seed seed = createSeedWithType("test.lua", SeedType.LUA, "print('hello')".getBytes());
            for (int i = 0; i < 20; i++) {
                Mutator mutator = factory.createMutator(seed);
                if (mutator instanceof LuaMutator) {
                    assertTrue(true);
                    return;
                }
            }
            fail("多次尝试后仍未返回 LuaMutator");
        }

        @Test
        @DisplayName("Test 7: CXX 类型 -> CxxMutator")
        void testCxxType() {
            Seed seed = createSeedWithType("test.cxx", SeedType.CXX, "_Z3foov".getBytes());
            for (int i = 0; i < 20; i++) {
                Mutator mutator = factory.createMutator(seed);
                if (mutator instanceof CxxMutator) {
                    assertTrue(true);
                    return;
                }
            }
            fail("多次尝试后仍未返回 CxxMutator");
        }

        @Test
        @DisplayName("Test 8: PNG 类型 -> PngMutator")
        void testPngType() {
            byte[] pngHeader = { (byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };
            Seed seed = createSeedWithType("test.png", SeedType.PNG, pngHeader);
            for (int i = 0; i < 20; i++) {
                Mutator mutator = factory.createMutator(seed);
                if (mutator instanceof PngMutator) {
                    assertTrue(true);
                    return;
                }
            }
            fail("多次尝试后仍未返回 PngMutator");
        }

        @Test
        @DisplayName("Test 9: ELF 类型 -> ElfMutator")
        void testElfType() {
            byte[] elfHeader = { 0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00 };
            Seed seed = createSeedWithType("test.elf", SeedType.ELF, elfHeader);
            for (int i = 0; i < 20; i++) {
                Mutator mutator = factory.createMutator(seed);
                if (mutator instanceof ElfMutator) {
                    assertTrue(true);
                    return;
                }
            }
            fail("多次尝试后仍未返回 ElfMutator");
        }

        @Test
        @DisplayName("Test 10: JPEG 类型 -> JpegMutator")
        void testJpegType() {
            byte[] jpegHeader = { (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0 };
            Seed seed = createSeedWithType("test.jpg", SeedType.JPEG, jpegHeader);
            for (int i = 0; i < 20; i++) {
                Mutator mutator = factory.createMutator(seed);
                if (mutator instanceof JpegMutator) {
                    assertTrue(true);
                    return;
                }
            }
            fail("多次尝试后仍未返回 JpegMutator");
        }

        @Test
        @DisplayName("Test 11: PCAP 类型 -> PcapMutator")
        void testPcapType() {
            byte[] pcapHeader = { (byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1 };
            Seed seed = createSeedWithType("test.pcap", SeedType.PCAP, pcapHeader);
            for (int i = 0; i < 20; i++) {
                Mutator mutator = factory.createMutator(seed);
                if (mutator instanceof PcapMutator) {
                    assertTrue(true);
                    return;
                }
            }
            fail("多次尝试后仍未返回 PcapMutator");
        }
    }

    // ==========================================
    // 兜底策略测试
    // ==========================================

    @Nested
    @DisplayName("兜底策略测试")
    class FallbackTests {

        @Test
        @DisplayName("Test 12: UNKNOWN 类型 -> AflHavocMutator")
        void testUnknownType() {
            Seed seed = createSeedWithType("test.bin", SeedType.UNKNOWN, new byte[] { 1, 2, 3 });
            Mutator mutator = factory.createMutator(seed);
            assertInstanceOf(AflHavocMutator.class, mutator, "UNKNOWN 类型应返回 AflHavocMutator");
        }

        @Test
        @DisplayName("Test 13: null 类型 -> AflHavocMutator")
        void testNullType() {
            Seed seed = createSeedWithType("test.bin", null, new byte[] { 1, 2, 3 });
            Mutator mutator = factory.createMutator(seed);
            assertInstanceOf(AflHavocMutator.class, mutator, "null 类型应返回 AflHavocMutator");
        }

        @Test
        @DisplayName("Test 14: 验证 defaultMutator 是单例")
        void testDefaultMutatorIsSingleton() {
            Seed seed1 = createSeedWithType("test1.bin", SeedType.UNKNOWN, new byte[] { 1 });
            Seed seed2 = createSeedWithType("test2.bin", SeedType.UNKNOWN, new byte[] { 2 });

            Mutator mutator1 = factory.createMutator(seed1);
            Mutator mutator2 = factory.createMutator(seed2);

            assertSame(mutator1, mutator2, "UNKNOWN 类型应返回相同的 defaultMutator 单例");
        }
    }

    // ==========================================
    // Havoc 混合策略测试
    // ==========================================

    @Nested
    @DisplayName("Havoc 混合策略测试")
    class HavocStrategyTests {

        @Test
        @DisplayName("Test 15: Havoc 概率统计验证（期望 ~10%）")
        void testHavocProbability() {
            Seed seed = createSeedWithType("test.xml", SeedType.XML, "<root/>".getBytes());

            int totalTrials = 1000;
            int havocCount = 0;
            int specificCount = 0;

            for (int i = 0; i < totalTrials; i++) {
                Mutator mutator = factory.createMutator(seed);
                if (mutator instanceof AflHavocMutator) {
                    havocCount++;
                } else if (mutator instanceof XmlMutator) {
                    specificCount++;
                }
            }

            double havocRate = (havocCount * 100.0) / totalTrials;
            double specificRate = (specificCount * 100.0) / totalTrials;

            System.out.printf("Havoc 选择率: %.1f%% (期望 ~10%%)%n", havocRate);
            System.out.printf("特定 Mutator 选择率: %.1f%% (期望 ~90%%)%n", specificRate);

            // 允许一定的统计误差（±5%）
            assertTrue(havocRate >= 5.0 && havocRate <= 20.0,
                    String.format("Havoc 概率 %.1f%% 应在 5-20%% 范围内", havocRate));
            assertTrue(specificRate >= 75.0 && specificRate <= 95.0,
                    String.format("特定 Mutator 概率 %.1f%% 应在 75-95%% 范围内", specificRate));

            // 验证两者之和为 100%
            assertEquals(totalTrials, havocCount + specificCount,
                    "Havoc + Specific 应覆盖所有情况");
        }

        @Test
        @DisplayName("Test 16: 所有已知类型都有 Havoc 回退可能")
        void testAllTypesCanFallbackToHavoc() {
            SeedType[] knownTypes = { SeedType.XML, SeedType.MJS, SeedType.LUA, SeedType.CXX,
                    SeedType.PNG, SeedType.ELF, SeedType.JPEG, SeedType.PCAP };

            for (SeedType type : knownTypes) {
                Seed seed = createSeedWithType("test", type, new byte[] { 1, 2, 3 });

                boolean foundHavoc = false;
                // 尝试足够多次以期望覆盖 10% 概率
                for (int i = 0; i < 100; i++) {
                    if (factory.createMutator(seed) instanceof AflHavocMutator) {
                        foundHavoc = true;
                        break;
                    }
                }
                assertTrue(foundHavoc,
                        String.format("类型 %s 应该有机会回退到 AflHavocMutator", type));
            }
        }
    }

    // ==========================================
    // 参数化测试 - 覆盖所有类型
    // ==========================================

    @Nested
    @DisplayName("参数化类型测试")
    class ParameterizedTypeTests {

        @ParameterizedTest(name = "Test 17-{index}: 类型 {0} 创建 Mutator 不为 null")
        @EnumSource(SeedType.class)
        @DisplayName("Test 17: 所有 SeedType 都能创建 Mutator")
        void testAllSeedTypesCreateMutator(SeedType type) {
            Seed seed = createSeedWithType("test", type, new byte[] { 1, 2, 3, 4 });
            Mutator mutator = factory.createMutator(seed);
            assertNotNull(mutator, "类型 " + type + " 应该能创建 Mutator");
        }
    }

    // ==========================================
    // Mutator 正确性验证
    // ==========================================

    @Nested
    @DisplayName("Mutator 功能验证")
    class MutatorFunctionalityTests {

        @Test
        @DisplayName("Test 18: 创建的 Mutator 能正常进行变异")
        void testCreatedMutatorCanMutate() {
            // 测试各种类型的 Mutator 都能正常工作
            Map<SeedType, byte[]> testData = new HashMap<>();
            testData.put(SeedType.XML, "<root><item/></root>".getBytes(StandardCharsets.UTF_8));
            testData.put(SeedType.LUA, "local x = 1\nprint(x)".getBytes(StandardCharsets.UTF_8));
            testData.put(SeedType.CXX, "_Z3foov".getBytes(StandardCharsets.UTF_8));
            testData.put(SeedType.UNKNOWN, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });

            for (Map.Entry<SeedType, byte[]> entry : testData.entrySet()) {
                Seed seed = createSeedWithType("test", entry.getKey(), entry.getValue());
                Mutator mutator = factory.createMutator(seed);

                // 验证 mutator 可以正常工作
                var iterator = mutator.mutate(seed, 5);
                assertNotNull(iterator, "Mutator 应返回非空迭代器");

                int count = 0;
                while (iterator.hasNext() && count < 5) {
                    var testcase = iterator.next();
                    assertNotNull(testcase, "Testcase 不应为 null");
                    assertNotNull(testcase.getData(), "Testcase 数据不应为 null");
                    count++;
                }
                assertTrue(count > 0,
                        String.format("类型 %s 的 Mutator 应生成至少一个 Testcase", entry.getKey()));
            }
        }

        @Test
        @DisplayName("Test 19: 二进制类型 Mutator 保持格式头部")
        void testBinaryMutatorsPreserveHeaders() {
            // PNG header
            byte[] pngData = new byte[100];
            pngData[0] = (byte) 0x89;
            pngData[1] = 'P';
            pngData[2] = 'N';
            pngData[3] = 'G';
            pngData[4] = 0x0D;
            pngData[5] = 0x0A;
            pngData[6] = 0x1A;
            pngData[7] = 0x0A;

            Seed pngSeed = createSeedWithType("test.png", SeedType.PNG, pngData);

            // 获取 PngMutator（跳过 Havoc 概率）
            Mutator mutator = null;
            for (int i = 0; i < 20; i++) {
                Mutator m = factory.createMutator(pngSeed);
                if (m instanceof PngMutator) {
                    mutator = m;
                    break;
                }
            }

            if (mutator != null) {
                var iterator = mutator.mutate(pngSeed, 10);
                int validHeaderCount = 0;
                while (iterator.hasNext()) {
                    byte[] mutatedData = iterator.next().getData();
                    // 检查 PNG 头部是否保持
                    if (mutatedData.length >= 8 &&
                            (mutatedData[0] & 0xFF) == 0x89 &&
                            mutatedData[1] == 'P' &&
                            mutatedData[2] == 'N' &&
                            mutatedData[3] == 'G') {
                        validHeaderCount++;
                    }
                }
                assertTrue(validHeaderCount > 0, "PngMutator 应该保持 PNG 头部完整性");
            }
        }
    }

    // ==========================================
    // 边界情况测试
    // ==========================================

    @Nested
    @DisplayName("边界情况测试")
    class EdgeCaseTests {

        @Test
        @DisplayName("Test 20: 空数据种子")
        void testEmptyDataSeed() {
            Seed seed = createSeedWithType("empty", SeedType.UNKNOWN, new byte[0]);
            Mutator mutator = factory.createMutator(seed);
            assertNotNull(mutator);

            // 验证可以正常变异
            var iterator = mutator.mutate(seed, 3);
            assertNotNull(iterator);
        }

        @Test
        @DisplayName("Test 21: 大数据种子")
        void testLargeDataSeed() {
            byte[] largeData = new byte[1024 * 1024]; // 1MB
            for (int i = 0; i < largeData.length; i++) {
                largeData[i] = (byte) (i % 256);
            }

            Seed seed = createSeedWithType("large", SeedType.UNKNOWN, largeData);
            Mutator mutator = factory.createMutator(seed);
            assertNotNull(mutator);
            assertInstanceOf(AflHavocMutator.class, mutator);
        }

        @Test
        @DisplayName("Test 22: 连续创建多个 Mutator")
        void testContinuousCreation() {
            // 验证 factory 可以连续创建多个 mutator 而不会出问题
            SeedType[] types = SeedType.values();
            for (int i = 0; i < 100; i++) {
                SeedType type = types[i % types.length];
                Seed seed = createSeedWithType("test" + i, type, new byte[] { (byte) i });
                Mutator mutator = factory.createMutator(seed);
                assertNotNull(mutator, "第 " + i + " 次创建应成功");
            }
        }

        @Test
        @DisplayName("Test 23: 同一种子多次获取 Mutator（类型一致性）")
        void testSameSeedMultipleTimes() {
            Seed seed = createSeedWithType("test", SeedType.LUA, "local x = 1".getBytes());

            // 统计返回的类型
            int luaMutatorCount = 0;
            int havocMutatorCount = 0;

            for (int i = 0; i < 50; i++) {
                Mutator mutator = factory.createMutator(seed);
                if (mutator instanceof LuaMutator) {
                    luaMutatorCount++;
                } else if (mutator instanceof AflHavocMutator) {
                    havocMutatorCount++;
                }
            }

            // 应该只有这两种可能
            assertEquals(50, luaMutatorCount + havocMutatorCount,
                    "LUA 类型只应返回 LuaMutator 或 AflHavocMutator");
            assertTrue(luaMutatorCount > havocMutatorCount,
                    "LuaMutator 应该比 AflHavocMutator 出现更频繁");
        }
    }

    // ==========================================
    // 多线程安全测试
    // ==========================================

    @Nested
    @DisplayName("线程安全测试")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Test 24: 多线程并发创建 Mutator")
        void testConcurrentMutatorCreation() throws InterruptedException {
            int threadCount = 10;
            int iterationsPerThread = 100;
            Thread[] threads = new Thread[threadCount];
            boolean[] success = { true };

            for (int t = 0; t < threadCount; t++) {
                final int threadId = t;
                threads[t] = new Thread(() -> {
                    try {
                        SeedType[] types = SeedType.values();
                        for (int i = 0; i < iterationsPerThread; i++) {
                            SeedType type = types[(threadId * iterationsPerThread + i) % types.length];
                            Seed seed = createSeedWithType("thread" + threadId + "_" + i, type,
                                    new byte[] { (byte) i });
                            Mutator mutator = factory.createMutator(seed);
                            if (mutator == null) {
                                success[0] = false;
                            }
                        }
                    } catch (Exception e) {
                        success[0] = false;
                        e.printStackTrace();
                    }
                });
            }

            // 启动所有线程
            for (Thread thread : threads) {
                thread.start();
            }

            // 等待所有线程完成
            for (Thread thread : threads) {
                thread.join();
            }

            assertTrue(success[0], "多线程并发创建 Mutator 应该成功");
        }
    }

    // ==========================================
    // 覆盖率报告
    // ==========================================

    @Test
    @DisplayName("Test 25: 综合覆盖率报告")
    void testCoverageReport() {
        Map<String, Integer> stats = new HashMap<>();
        stats.put("Total", 0);
        stats.put("XML", 0);
        stats.put("MJS", 0);
        stats.put("LUA", 0);
        stats.put("CXX", 0);
        stats.put("PNG", 0);
        stats.put("ELF", 0);
        stats.put("JPEG", 0);
        stats.put("PCAP", 0);
        stats.put("UNKNOWN", 0);
        stats.put("Havoc Fallback", 0);

        SeedType[] knownTypes = { SeedType.XML, SeedType.MJS, SeedType.LUA, SeedType.CXX,
                SeedType.PNG, SeedType.ELF, SeedType.JPEG, SeedType.PCAP };

        int samplesPerType = 100;

        for (SeedType type : knownTypes) {
            Seed seed = createSeedWithType("test", type, new byte[] { 1, 2, 3, 4 });

            for (int i = 0; i < samplesPerType; i++) {
                Mutator mutator = factory.createMutator(seed);
                stats.put("Total", stats.get("Total") + 1);

                if (mutator instanceof AflHavocMutator) {
                    stats.put("Havoc Fallback", stats.get("Havoc Fallback") + 1);
                } else {
                    stats.put(type.name(), stats.get(type.name()) + 1);
                }
            }
        }

        // 打印报告
        System.out.println("\n====== MutatorFactory Coverage Report ======");
        System.out.printf("%-20s | %-10s | %-10s%n", "Category", "Count", "Rate");
        System.out.println("----------------------------------------------");

        int total = stats.get("Total");
        for (String key : new String[] { "XML", "MJS", "LUA", "CXX", "PNG", "ELF", "JPEG", "PCAP", "Havoc Fallback" }) {
            int count = stats.get(key);
            double rate = (count * 100.0) / total;
            System.out.printf("%-20s | %-10d | %6.2f%%%n", key, count, rate);
        }
        System.out.println("==============================================\n");

        // 验证所有特定类型都被覆盖
        for (SeedType type : knownTypes) {
            assertTrue(stats.get(type.name()) > 0,
                    "类型 " + type + " 应该被覆盖");
        }

        // 验证 Havoc 回退发生
        assertTrue(stats.get("Havoc Fallback") > 0, "Havoc 回退应该发生");

        // 验证 Havoc 比例在预期范围内 (~10%)
        double havocRate = (stats.get("Havoc Fallback") * 100.0) / total;
        assertTrue(havocRate >= 5.0 && havocRate <= 20.0,
                String.format("Havoc 回退率 %.1f%% 应在 5-20%% 范围内", havocRate));
    }
}
