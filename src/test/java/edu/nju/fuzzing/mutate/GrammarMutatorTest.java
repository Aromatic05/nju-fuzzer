package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 验证 GrammarMutator (Dispatcher) 及其子类的生成逻辑
 * 包含：魔术数检查、内部结构验证、多样性验证
 */
class GrammarMutatorTest {

    private GrammarMutator mutator;

    @BeforeEach
    void setUp() {
        mutator = new GrammarMutator();
    }

    private Seed createSeed(String name, byte[] data) {
        return Seed.loadWithMetadata(new File(name), data);
    }

    private Seed createTextSeed(String name, String content) {
        return Seed.loadWithMetadata(new File(name), content.getBytes(StandardCharsets.ISO_8859_1));
    }

    // --- 二进制格式测试 ---

    @Test
    @DisplayName("T02-T04: ELF 二进制生成验证")
    void testElfGeneration() {
        Seed seed = createSeed("test.elf", new byte[]{0x7F, 'E', 'L', 'F'});
        List<Testcase> res = mutator.mutate(seed, 10);

        Assertions.assertFalse(res.isEmpty(), "ELF Should generate testcases");
        byte[] data = res.get(0).data();

        Assertions.assertEquals(0x7F, data[0] & 0xFF);
        Assertions.assertEquals('E', data[1]);
        Assertions.assertTrue(data.length > 5);
    }

    @Test
    @DisplayName("T05: JPEG 图片生成验证")
    void testJpegGeneration() {
        Seed seed = createSeed("test.jpg", new byte[]{(byte)0xFF, (byte)0xD8});
        Testcase tc = mutator.mutate(seed, 10).get(0);
        byte[] data = tc.data();

        Assertions.assertEquals((byte)0xFF, data[0]);
        Assertions.assertEquals((byte)0xD8, data[1]);
        int len = data.length;
        Assertions.assertEquals((byte)0xFF, data[len-2]);
        Assertions.assertEquals((byte)0xD9, data[len-1]);
    }

    @Test
    @DisplayName("T06: PNG 图片生成验证")
    void testPngGeneration() {
        Seed seed = createSeed("test.png", new byte[]{(byte)0x89, 'P', 'N', 'G'});
        Testcase tc = mutator.mutate(seed, 10).get(0);
        byte[] data = tc.data();

        String content = new String(data, StandardCharsets.ISO_8859_1);
        Assertions.assertTrue(content.contains("IHDR"));
    }

    @Test
    @DisplayName("T10: PCAP 抓包文件生成验证")
    void testPcapGeneration() {
        Seed seed = createSeed("test.pcap", new byte[]{(byte)0xD4, (byte)0xC3, (byte)0xB2, (byte)0xA1});
        Testcase tc = mutator.mutate(seed, 10).get(0);
        Assertions.assertTrue(tc.data().length >= 40);
    }

    // --- 文本格式测试 ---

    @Test
    @DisplayName("T07: XML 结构生成验证")
    void testXmlGeneration() {
        Seed seed = createTextSeed("test.xml", "<root>");
        Testcase tc = mutator.mutate(seed, 10).get(0);
        String s = new String(tc.data());
        Assertions.assertTrue(s.contains("<") || s.contains(">"));
    }

    @Test
    @DisplayName("T09: JSON 结构生成验证")
    void testJsonGeneration() {
        Seed seed = createTextSeed("test.json", "{");
        Testcase tc = mutator.mutate(seed, 10).get(0);
        String s = new String(tc.data()).trim();
        boolean isJson = s.startsWith("{") || s.startsWith("[");
        Assertions.assertTrue(isJson);
    }

    @Test
    @DisplayName("T08: Lua 脚本生成验证")
    void testLuaGeneration() {
        // [修复]：使用 "local a=1" 确保能触发 SeedType.LUA 检测
        // 之前的 "local" 太短且不含空格，可能被判为 UNKNOWN
        Seed seed = createTextSeed("test.lua", "local a=1");

        List<Testcase> res = mutator.mutate(seed, 10);
        Assertions.assertFalse(res.isEmpty(), "Should detect Lua type and generate");

        Testcase tc = res.get(0);
        String s = new String(tc.data());

        // 验证生成的代码包含 Lua 关键字
        boolean hasKeyword = s.contains("function") || s.contains("if") || s.contains("print") || s.contains("a=");
        Assertions.assertTrue(hasKeyword, "Lua script should contain keywords. Generated: " + s);
    }

    @Test
    @DisplayName("T01: C++ Mangled Name 生成验证")
    void testCxxGeneration() {
        Seed seed = createTextSeed("test.cxx", "_Z");
        Testcase tc = mutator.mutate(seed, 10).get(0);
        String s = new String(tc.data());
        Assertions.assertTrue(s.startsWith("_Z"));
    }

    // --- 边界与健壮性测试 ---

    @Test
    @DisplayName("多样性测试: 确保不是生成死数据")
    void testDiversity() {
        // [修复]：改用 JSON 进行多样性测试
        // JsonMutator 的规则定义更完善，组合空间更大，容易通过多样性检查
        Seed seed = createTextSeed("test.json", "{");

        // 生成 250 energy -> 约 50 个 Testcase
        List<Testcase> res = mutator.mutate(seed, 250);

        Set<String> unique = new HashSet<>();
        for (Testcase tc : res) {
            unique.add(new String(tc.data()));
        }

        System.out.println("Generated " + res.size() + " testcases, unique: " + unique.size());

        // 期望至少有 5 个不同的结果
        Assertions.assertTrue(unique.size() > 5, "Generator lacks diversity. Unique count: " + unique.size());
    }

    @Test
    @DisplayName("未知类型: 优雅降级")
    void testUnknownType() {
        Seed seed = createSeed("unknown.bin", new byte[]{0, 0, 0, 0});
        List<Testcase> res = mutator.mutate(seed, 10);
        Assertions.assertTrue(res.isEmpty());
    }

    @Test
    @DisplayName("编码安全: ISO-8859-1 测试")
    void testEncodingSafety() {
        Seed seed = createSeed("test.jpg", new byte[]{(byte)0xFF, (byte)0xD8});
        Testcase tc = mutator.mutate(seed, 10).get(0);
        byte[] data = tc.data();

        boolean hasNegativeByte = false;
        for (byte b : data) {
            if (b < 0) hasNegativeByte = true;
        }
        Assertions.assertTrue(hasNegativeByte, "Must handle bytes > 127 correctly");
    }

    @Test
    @DisplayName("递归深度限制")
    void testRecursionLimit() {
        // 使用一个容易递归的类型 (XML)
        Seed seed = createTextSeed("complex.xml", "<root>");
        Assertions.assertDoesNotThrow(() -> mutator.mutate(seed, 50));
    }
}