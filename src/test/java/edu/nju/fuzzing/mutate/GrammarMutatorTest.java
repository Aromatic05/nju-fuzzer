package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * 验证 GrammarMutator 对 T01-T10 所有目标的生成逻辑是否正确
 * 重点验证：二进制魔术数、关键文本结构、编码完整性
 */
class GrammarMutatorTest {

    private GrammarMutator mutator;
    private final byte[] dummy = new byte[]{0};

    @BeforeEach
    void setUp() {
        mutator = new GrammarMutator();
    }

    // --- 1. 二进制格式测试 (T02-T06, T10) ---

    @Test
    @DisplayName("T02-T04: ELF 头验证 (7F 45 4C 46)")
    void testElfBinaryStructure() {
        Seed seed = Seed.loadWithMetadata(new File("target.elf"), dummy);
        Testcase tc = mutator.mutate(seed, 10).get(0);
        byte[] data = tc.data();

        Assertions.assertTrue(data.length > 4, "ELF 长度应大于 4");
        Assertions.assertEquals(0x7F, data[0] & 0xFF);
        Assertions.assertEquals('E', data[1]);
        Assertions.assertEquals('L', data[2]);
        Assertions.assertEquals('F', data[3]);
        // 验证 Class (64bit=2)
        Assertions.assertEquals(0x02, data[4] & 0xFF);
    }

    @Test
    @DisplayName("T05: JPEG 头尾验证 (FF D8 ... FF D9)")
    void testJpegBinaryStructure() {
        Seed seed = Seed.loadWithMetadata(new File("target.jpg"), dummy);
        Testcase tc = mutator.mutate(seed, 10).get(0);
        byte[] data = tc.data();

        Assertions.assertEquals(0xFF, data[0] & 0xFF, "SOI Marker Byte 1");
        Assertions.assertEquals(0xD8, data[1] & 0xFF, "SOI Marker Byte 2");

        // 验证结尾
        int len = data.length;
        Assertions.assertEquals(0xFF, data[len-2] & 0xFF, "EOI Marker Byte 1");
        Assertions.assertEquals(0xD9, data[len-1] & 0xFF, "EOI Marker Byte 2");
    }

    @Test
    @DisplayName("T06: PNG 8字节 Magic 验证")
    void testPngBinaryStructure() {
        Seed seed = Seed.loadWithMetadata(new File("target.png"), dummy);
        Testcase tc = mutator.mutate(seed, 10).get(0);
        byte[] data = tc.data();

        // 89 50 4E 47 0D 0A 1A 0A
        int[] expected = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

        for (int i = 0; i < expected.length; i++) {
            Assertions.assertEquals(expected[i], data[i] & 0xFF, "PNG Byte " + i + " mismatch");
        }
    }

    @Test
    @DisplayName("T10: PCAP Global Header 验证")
    void testPcapBinaryStructure() {
        Seed seed = Seed.loadWithMetadata(new File("capture.pcap"), dummy);
        Testcase tc = mutator.mutate(seed, 10).get(0);
        byte[] data = tc.data();

        // D4 C3 B2 A1
        Assertions.assertEquals(0xD4, data[0] & 0xFF);
        Assertions.assertEquals(0xC3, data[1] & 0xFF);
        Assertions.assertEquals(0xB2, data[2] & 0xFF);
        Assertions.assertEquals(0xA1, data[3] & 0xFF);
        // Version Major 2 (offset 4+2-2 = 4)
        Assertions.assertEquals(0x02, data[4] & 0xFF);
    }

    // --- 2. 文本/混合格式测试 (T01, T07-T09) ---

    @Test
    @DisplayName("T01: Cxxfilt Mangled Name (_Z开头)")
    void testCxxFiltStructure() {
        Seed seed = Seed.loadWithMetadata(new File("cxxfilt"), dummy);
        Testcase tc = mutator.mutate(seed, 10).get(0);
        String s = new String(tc.data(), StandardCharsets.ISO_8859_1);

        Assertions.assertTrue(s.startsWith("_Z"), "必须以 _Z 开头");
        Assertions.assertTrue(s.length() > 3, "生成的名称太短");
        // 验证后续字符是否是预定义的函数名片段
        boolean hasFunc = s.contains("3bar") || s.contains("4func") || s.contains("3foo") || s.contains("4main");
        Assertions.assertTrue(hasFunc, "必须包含预定义的函数名");
    }

    @Test
    @DisplayName("T07: XML 标签闭合验证")
    void testXmlStructure() {
        Seed seed = Seed.loadWithMetadata(new File("data.xml"), dummy);
        Testcase tc = mutator.mutate(seed, 10).get(0);
        String s = new String(tc.data());

        Assertions.assertTrue(s.contains("<") && s.contains(">"));
        // 简单验证闭合性 (非严格)
        if (s.startsWith("<root>")) {
            Assertions.assertTrue(s.endsWith("</root>"), "Root tag must be closed");
        }
    }

    @Test
    @DisplayName("T09: JSON 结构验证")
    void testJsonStructure() {
        Seed seed = Seed.loadWithMetadata(new File("test.mjs"), dummy); // mjs 也用 json 语法
        Testcase tc = mutator.mutate(seed, 10).get(0);
        String s = new String(tc.data());

        s = s.trim();
        boolean validWrap = (s.startsWith("{") && s.endsWith("}")) || (s.startsWith("[") && s.endsWith("]"));
        Assertions.assertTrue(validWrap, "JSON must be object {} or array []");
    }

    @Test
    @DisplayName("T08: Lua 关键字验证")
    void testLuaStructure() {
        Seed seed = Seed.loadWithMetadata(new File("script.lua"), dummy);
        Testcase tc = mutator.mutate(seed, 10).get(0);
        String s = new String(tc.data());

        boolean hasKeyword = s.contains("function") || s.contains("if") || s.contains("print") || s.contains("a=");
        Assertions.assertTrue(hasKeyword, "生成的 Lua 代码必须包含关键字");
    }

    // --- 3. 边界与健壮性测试 ---

    @Test
    @DisplayName("编码完整性: 验证 0x80-0xFF 字节不被破坏")
    void testIso88591Encoding() {
        // 使用 JPEG 模式，因为它包含很多 FF (255)
        Seed seed = Seed.loadWithMetadata(new File("test.jpg"), dummy);
        Testcase tc = mutator.mutate(seed, 10).get(0);
        byte[] data = tc.data();

        // 如果错误地使用了 UTF-8，0xFF 会变成 0x3F (?) 或者 0xC3 0xBF (双字节)
        // 我们验证是否存在负字节 (在Java中 byte 是有符号的，0xFF = -1)
        boolean hasHighByte = false;
        for (byte b : data) {
            if (b < 0) { // 即 > 127
                hasHighByte = true;
                break;
            }
        }
        Assertions.assertTrue(hasHighByte, "必须能够生成 >127 的字节 (如 0xFF)");
    }

    @Test
    @DisplayName("递归深度限制: 防止 StackOverflow")
    void testRecursionDepth() {
        // 即使生成 1000 次，也不应该抛出异常
        Seed seed = Seed.loadWithMetadata(new File("complex.xml"), dummy);
        for (int i = 0; i < 100; i++) {
            Assertions.assertDoesNotThrow(() -> mutator.mutate(seed, 10));
        }
        // 验证长度没有失控
        Testcase tc = mutator.mutate(seed, 10).get(0);
        Assertions.assertTrue(tc.data().length < 1024 * 1024, "单个用例不应过大");
    }

    @Test
    @DisplayName("未知扩展名: 随机回退机制")
    void testUnknownExtension() {
        Seed seed = Seed.loadWithMetadata(new File("unknown.xyz"), dummy);
        Testcase tc = mutator.mutate(seed, 10).get(0);

        Assertions.assertNotNull(tc.data());
        Assertions.assertTrue(tc.data().length > 0);
        // 描述中应包含某种模式
        Assertions.assertTrue(tc.description().startsWith("grammar:"));
    }

    @Test
    @DisplayName("空能量处理")
    void testZeroEnergy() {
        Seed seed = Seed.loadWithMetadata(new File("test.xml"), dummy);
        // GrammarMutator 逻辑是 max(1, energy/5)，所以 energy=0 时应该生成 1 个
        List<Testcase> res = mutator.mutate(seed, 0);
        Assertions.assertEquals(1, res.size());
    }
}