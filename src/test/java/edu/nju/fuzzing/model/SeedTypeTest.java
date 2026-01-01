package edu.nju.fuzzing.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

/**
 * SeedTypeTest
 * 全面验证种子类型自动识别逻辑的正确性与健壮性。
 */
class SeedTypeTest {

    // ==========================================
    // 1. 二进制格式测试 (Binary Formats)
    // ==========================================

    @Test
    @DisplayName("ELF: Linux 可执行文件 (7F 45 4C 46)")
    void testElf() {
        // 标准 ELF 头
        byte[] elf = {0x7F, 'E', 'L', 'F', 0x02, 0x01};
        Assertions.assertEquals(SeedType.ELF, SeedType.detect(elf));
    }

    @Test
    @DisplayName("JPEG: 图片格式 (FF D8)")
    void testJpeg() {
        // 标准 JPEG 头
        byte[] jpeg = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0};
        Assertions.assertEquals(SeedType.JPEG, SeedType.detect(jpeg));
    }

    @Test
    @DisplayName("PNG: 图片格式 (89 50 4E 47)")
    void testPng() {
        // 标准 PNG 头
        byte[] png = {(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A};
        Assertions.assertEquals(SeedType.PNG, SeedType.detect(png));
    }

    @Test
    @DisplayName("PCAP: 网络抓包 (大小端兼容)")
    void testPcap() {
        // Case 1: Big Endian (D4 C3 B2 A1)
        byte[] big = {(byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1};
        Assertions.assertEquals(SeedType.PCAP, SeedType.detect(big));

        // Case 2: Little Endian (A1 B2 C3 D4) - Tcpdump 常见
        byte[] little = {(byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4};
        Assertions.assertEquals(SeedType.PCAP, SeedType.detect(little));
    }

    // ==========================================
    // 2. 文本格式测试 (Text Formats)
    // ==========================================

    @Test
    @DisplayName("XML: 标签检测")
    void testXml() {
        // 标准开头
        Assertions.assertEquals(SeedType.XML, SeedType.detect("<root>".getBytes()));
        // 声明开头
        Assertions.assertEquals(SeedType.XML, SeedType.detect("<?xml version='1.0'>".getBytes()));
    }

    @Test
    @DisplayName("JSON: 对象与数组")
    void testJson() {
        // 对象
        Assertions.assertEquals(SeedType.MJS, SeedType.detect("{\"key\": \"val\"}".getBytes()));
        // 数组
        Assertions.assertEquals(SeedType.MJS, SeedType.detect("[1, 2, 3]".getBytes()));
    }

    @Test
    @DisplayName("CXX: C++ Mangled Name (_Z)")
    void testCxx() {
        // 标准 Mangled Name
        Assertions.assertEquals(SeedType.CXX, SeedType.detect("_Z3barv".getBytes()));
        Assertions.assertEquals(SeedType.CXX, SeedType.detect("_Z4mainPi".getBytes()));
    }

    @Test
    @DisplayName("LUA: 关键字扫描")
    void testLua() {
        // 开头不是特定字符，需要扫描内容
        Assertions.assertEquals(SeedType.LUA, SeedType.detect("function f() end".getBytes()));
        Assertions.assertEquals(SeedType.LUA, SeedType.detect("print('hello')".getBytes()));
        Assertions.assertEquals(SeedType.LUA, SeedType.detect("local x = 1".getBytes()));
        // 关键字在后面
        String code = "x=1; y=2; if x==y then return end";
        Assertions.assertEquals(SeedType.LUA, SeedType.detect(code.getBytes()));
    }

    // ==========================================
    // 3. 极短种子测试 (验证 Short-Circuit 逻辑)
    // ==========================================

    @Test
    @DisplayName("Short: 极短 JSON (2字节)")
    void testShortJson() {
        // 之前如果有 length < 4 的检查，这里会失败
        Assertions.assertEquals(SeedType.MJS, SeedType.detect("{}".getBytes()));
        Assertions.assertEquals(SeedType.MJS, SeedType.detect("[]".getBytes()));
    }

    @Test
    @DisplayName("Short: 极短 JPEG (2字节)")
    void testShortJpeg() {
        // 仅包含 SOI
        byte[] shortestJpeg = {(byte) 0xFF, (byte) 0xD8};
        Assertions.assertEquals(SeedType.JPEG, SeedType.detect(shortestJpeg));
    }

    @Test
    @DisplayName("Short: 极短 CXX (2字节)")
    void testShortCxx() {
        Assertions.assertEquals(SeedType.CXX, SeedType.detect("_Z".getBytes()));
    }

    @Test
    @DisplayName("Short: 极短 XML (3字节)")
    void testShortXml() {
        Assertions.assertEquals(SeedType.XML, SeedType.detect("<a>".getBytes()));
    }

    // ==========================================
    // 4. 容错性测试 (Trimming & Encoding)
    // ==========================================

    @Test
    @DisplayName("Trim: 忽略前导空格和换行")
    void testWhitespaceHandling() {
        // XML 带空格
        Assertions.assertEquals(SeedType.XML, SeedType.detect("  <doc>".getBytes()));
        // JSON 带换行
        Assertions.assertEquals(SeedType.MJS, SeedType.detect("\n\t{\"a\":1}".getBytes()));
    }

    // ==========================================
    // 5. 异常与边界测试 (Negative Cases)
    // ==========================================

    @Test
    @DisplayName("Null 或 Empty")
    void testNullOrEmpty() {
        Assertions.assertEquals(SeedType.UNKNOWN, SeedType.detect(null));
        Assertions.assertEquals(SeedType.UNKNOWN, SeedType.detect(new byte[0]));
    }

    @Test
    @DisplayName("Unknown: 纯文本但无特征")
    void testUnknownText() {
        Assertions.assertEquals(SeedType.UNKNOWN, SeedType.detect("Hello World".getBytes()));
        Assertions.assertEquals(SeedType.UNKNOWN, SeedType.detect("123456".getBytes()));
    }

    @Test
    @DisplayName("Unknown: 随机二进制")
    void testUnknownBinary() {
        byte[] junk = {0x00, 0x01, 0x02, 0x03, 0x04};
        Assertions.assertEquals(SeedType.UNKNOWN, SeedType.detect(junk));
    }

    @Test
    @DisplayName("Unknown: 极短且无特征")
    void testShortUnknown() {
        // 长度为 3，且不是 XML
        Assertions.assertEquals(SeedType.UNKNOWN, SeedType.detect(new byte[]{'A', 'B', 'C'}));
    }
}