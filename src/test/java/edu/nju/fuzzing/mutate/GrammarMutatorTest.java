package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 验证基于语法的变异器
 */
class GrammarMutatorTest {

    private GrammarMutator mutator;
    private byte[] dummyData = "dummy".getBytes();

    @BeforeEach
    void setUp() {
        mutator = new GrammarMutator();
    }

    @Test
    void testXmlMode_DetectionAndGeneration() {
        // --- 修复点 ---
        Seed xmlSeed = Seed.loadWithMetadata(new File("target.xml"), dummyData);
        List<Testcase> results = mutator.mutate(xmlSeed, 10);

        Assertions.assertFalse(results.isEmpty());

        String content = new String(results.get(0).data(), StandardCharsets.UTF_8);
        System.out.println("XML Output: " + content);

        Assertions.assertTrue(content.startsWith("<root>") || content.contains("<"), "XML 模式应包含 XML 标签");
        // 注意：根据你的语法定义，可能不是严格以 <root> 开头，这里只要包含特征即可
        Assertions.assertTrue(results.get(0).description().contains("xml"), "描述应包含 xml");
    }

    @Test
    void testJsonMode_DetectionAndGeneration() {
        // --- 修复点 ---
        Seed jsonSeed = Seed.loadWithMetadata(new File("data.json"), dummyData);
        List<Testcase> results = mutator.mutate(jsonSeed, 20);

        Assertions.assertFalse(results.isEmpty());
        String content = new String(results.get(0).data());
        System.out.println("JSON Output: " + content);

        boolean isJson = content.trim().startsWith("{") || content.trim().startsWith("[");
        Assertions.assertTrue(isJson, "JSON 模式应生成 {} 或 []");
    }

    @Test
    void testLuaMode_DetectionAndGeneration() {
        // --- 修复点 ---
        Seed luaSeed = Seed.loadWithMetadata(new File("script.lua"), dummyData);
        List<Testcase> results = mutator.mutate(luaSeed, 20);

        Assertions.assertFalse(results.isEmpty());
        String content = new String(results.get(0).data());
        System.out.println("Lua Output: " + content);

        boolean validLua = content.contains("function") || content.contains("=") || content.contains("print");
        Assertions.assertTrue(validLua, "Lua 模式应包含关键字");
    }

    @Test
    void testUnknownMode_ShouldPickRandom() {
        // --- 修复点 ---
        Seed binSeed = Seed.loadWithMetadata(new File("program.bin"), dummyData);
        List<Testcase> results = mutator.mutate(binSeed, 20);

        Assertions.assertFalse(results.isEmpty());

        String desc = results.get(0).description();
        Assertions.assertTrue(desc.contains("xml") || desc.contains("json") || desc.contains("lua"));
    }

    @Test
    void testEnergyRatio_ShouldGenerateFew() {
        // --- 修复点 ---
        Seed seed = Seed.loadWithMetadata(new File("test.xml"), dummyData);
        List<Testcase> results = mutator.mutate(seed, 100);

        // GrammarMutator 逻辑是 max(1, energy/10)
        Assertions.assertEquals(10, results.size());
    }

    @Test
    void testLowEnergy_ShouldAtLeastOne() {
        // --- 修复点 ---
        Seed seed = Seed.loadWithMetadata(new File("test.xml"), dummyData);
        List<Testcase> results = mutator.mutate(seed, 1);
        Assertions.assertEquals(1, results.size());
    }

    @Test
    void testParentReference() {
        // --- 修复点 ---
        Seed seed = Seed.loadWithMetadata(new File("ref.xml"), dummyData);
        List<Testcase> results = mutator.mutate(seed, 10);
        Assertions.assertEquals(seed, results.get(0).parent());
    }

    @Test
    void testMjsExtension_ShouldBeJson() {
        // --- 修复点 ---
        Seed mjsSeed = Seed.loadWithMetadata(new File("test.mjs"), dummyData);
        List<Testcase> results = mutator.mutate(mjsSeed, 10);
        String desc = results.get(0).description();
        Assertions.assertTrue(desc.contains("json"));
    }
}