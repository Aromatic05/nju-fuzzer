package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 全能型语法变异器
 * 覆盖 T01-T10 所有目标（包括二进制格式的伪造）
 */
public class GrammarMutator implements Mutator {

    private final Random random = new Random();
    private final Map<String, Map<String, List<String>>> grammars = new HashMap<>();
    private static final int MAX_DEPTH = 25;

    public GrammarMutator() {
        // T07
        initXmlGrammar();
        // T09
        initJsonGrammar();
        // T08
        initLuaGrammar();
        // T01
        initCxxGrammar();
        // T02, T03, T04 (ELF Binaries)
        initElfGrammar();
        // T05 (JPEG)
        initJpegGrammar();
        // T06 (PNG)
        initPngGrammar();
        // T10 (PCAP)
        initPcapGrammar();
    }

    // --- 文本类语法 ---

    private void initXmlGrammar() {
        Map<String, List<String>> xml = new HashMap<>();
        xml.put("<start>", Arrays.asList("<root><elem/></root>", "<root><elem><elem/></elem></root>"));
        xml.put("<elem>", Arrays.asList("<tag prop='val'/>", "<tag>text</tag>"));
        xml.put("<tag>", Arrays.asList("foo", "bar", "div"));
        grammars.put("xml", xml);
    }

    private void initJsonGrammar() {
        Map<String, List<String>> json = new HashMap<>();
        json.put("<start>", Arrays.asList("{ <kv> }", "[ <val>, <val> ]"));
        json.put("<kv>", Arrays.asList("\"id\": <val>", "\"key\": \"str\""));
        json.put("<val>", Arrays.asList("123", "true", "null", "[]", "{}"));
        grammars.put("json", json);
    }

    private void initLuaGrammar() {
        Map<String, List<String>> lua = new HashMap<>();
        lua.put("<start>", Arrays.asList("function f() <stmt> end", "a=1; <stmt>"));
        lua.put("<stmt>", Arrays.asList("print('ok')", "if 1==1 then return end"));
        grammars.put("lua", lua);
    }

    // T01: cxxfilt (C++ Mangled Names)
    // 规则：_Z + <func_name_len> + <func_name> + <args>...
    private void initCxxGrammar() {
        Map<String, List<String>> cxx = new HashMap<>();
        cxx.put("<start>", Arrays.asList("_Z<func><args>", "_Z3foo<type>", "_Z4mainv"));
        cxx.put("<func>", Arrays.asList("3bar", "4func", "1f")); // len + name
        cxx.put("<args>", Arrays.asList("i", "if", "v", "Pi")); // int, int float, void, pointer int
        cxx.put("<type>", Arrays.asList("i", "c", "d"));
        grammars.put("cxx", cxx);
    }

    // --- 二进制类语法 (使用 ISO-8859-1 映射) ---
    // \\u00XX 代表十六进制字节

    // T02, T03, T04: ELF Format
    // Magic: 0x7F 'E' 'L' 'F'
    private void initElfGrammar() {
        Map<String, List<String>> elf = new HashMap<>();
        // Magic + Class(64bit) + Endian(LSB) + Version + ABI
        String header = "\u007FELF\u0002\u0001\u0001\u0000";
        elf.put("<start>", Arrays.asList(header + "<padding><type><machine>"));
        elf.put("<padding>", Arrays.asList("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"));
        elf.put("<type>", Arrays.asList("\u0002\u0000", "\u0003\u0000")); // Executable or Shared
        elf.put("<machine>", Arrays.asList("\u003E\u0000", "\u0003\u0000")); // x86-64 or x86
        grammars.put("elf", elf);
    }

    // T05: JPEG Format
    // SOI (FF D8) ... EOI (FF D9)
    private void initJpegGrammar() {
        Map<String, List<String>> jpeg = new HashMap<>();
        jpeg.put("<start>", Arrays.asList("\u00FF\u00D8<segments>\u00FF\u00D9"));
        jpeg.put("<segments>", Arrays.asList("<dqt><sof>", "<app0><dqt>"));
        // APP0 Marker: FF E0 + len + 'JFIF'
        jpeg.put("<app0>", Arrays.asList("\u00FF\u00E0\u0000\u0010JFIF\u0000\u0001"));
        // DQT Marker: FF DB
        jpeg.put("<dqt>", Arrays.asList("\u00FF\u00DB\u0000\u0043\u0000<data64>"));
        // SOF Marker: FF C0
        jpeg.put("<sof>", Arrays.asList("\u00FF\u00C0\u0000\u0011\u0008<dim>"));
        jpeg.put("<dim>", Arrays.asList("\u0000\u0064\u0000\u0064")); // 100x100
        jpeg.put("<data64>", Arrays.asList("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        grammars.put("jpeg", jpeg);
    }

    // T06: PNG Format
    // Magic: 89 50 4E 47 0D 0A 1A 0A
    private void initPngGrammar() {
        Map<String, List<String>> png = new HashMap<>();
        // 这里使用了 \r 和 \n，这是安全的
        String magic = "\u0089PNG\r\n\u001A\n";
        png.put("<start>", Arrays.asList(magic + "<ihdr><iend>"));

        // 【修复点】：将原来的 \\u000D 改为 \r
        // IHDR Chunk: len(13) + "IHDR" + W + H + Depth + Color + Comp + Filter + Interlace + CRC
        png.put("<ihdr>", Arrays.asList("\u0000\u0000\u0000\rIHDR\u0000\u0000\u0000\u0010\u0000\u0000\u0000\u0010\u0008\u0002\u0000\u0000\u0000\u0000"));

        // IEND Chunk
        png.put("<iend>", Arrays.asList("\u0000\u0000\u0000\u0000IEND\u00AE\u0042\u0060\u0082"));
        grammars.put("png", png);
    }

    // T10: PCAP Format (tcpdump)
    // Magic: D4 C3 B2 A1
    private void initPcapGrammar() {
        Map<String, List<String>> pcap = new HashMap<>();
        // Global Header: Magic + Ver(2.4) + Zone + SigFigs + SnapLen + Net
        String global = "\u00D4\u00C3\u00B2\u00A1\u0002\u0000\u0004\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0004\u0000\u0001\u0000\u0000\u0000";
        pcap.put("<start>", Arrays.asList(global + "<packet>"));
        // Packet Header + Data
        pcap.put("<packet>", Arrays.asList("<p_hdr><p_data>", "<p_hdr><p_data><packet>"));
        pcap.put("<p_hdr>", Arrays.asList("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000\u0010\u0000\u0000\u0000")); // len=16
        pcap.put("<p_data>", Arrays.asList("0123456789ABCDEF"));
        grammars.put("pcap", pcap);
    }

    @Override
    public List<Testcase> mutate(Seed seed, int energy) {
        List<Testcase> res = new ArrayList<>();
        String mode = detectMode(seed);
        // 基于语法的生成是高效的，产生少量高质量种子即可
        int genCount = Math.max(1, energy / 5);

        for (int i = 0; i < genCount; i++) {
            String gen = generate(mode, "<start>", 0);
            // 关键：使用 ISO_8859_1 以支持二进制数据的 1:1 映射
            res.add(new Testcase(
                    gen.getBytes(StandardCharsets.ISO_8859_1),
                    seed,
                    "grammar:" + mode
            ));
        }
        return res;
    }

    private String detectMode(Seed seed) {
        String name = seed.getFile().getName().toLowerCase();
        // 扩展检测逻辑以覆盖所有 Target
        if (name.contains("xml")) return "xml";
        if (name.contains("json") || name.contains("mjs")) return "json";
        if (name.contains("lua")) return "lua";

        if (name.contains("cxx") || name.startsWith("_z")) return "cxx"; // T01
        if (name.contains("elf") || name.contains("readelf") || name.contains("nm") || name.contains("objdump")) return "elf"; // T02-T04
        if (name.endsWith(".jpg") || name.endsWith(".jpeg") || name.contains("djpeg")) return "jpeg"; // T05
        if (name.endsWith(".png") || name.contains("readpng")) return "png"; // T06
        if (name.endsWith(".pcap") || name.contains("tcpdump")) return "pcap"; // T10

        // 如果无法识别，随机选一种，试图撞大运
        List<String> keys = new ArrayList<>(grammars.keySet());
        return keys.get(random.nextInt(keys.size()));
    }

    private String generate(String mode, String token, int depth) {
        if (depth > MAX_DEPTH) return "";

        // 1. 如果不是以 < 开头，直接返回
        if (!token.startsWith("<")) return token;

        Map<String, List<String>> rules = grammars.get(mode);
        // 如果 mode 不存在或 token 不在规则中，当作普通文本处理
        if (rules == null) return token;
        List<String> expansions = rules.get(token);
        if (expansions == null || expansions.isEmpty()) return token;

        String rule = expansions.get(random.nextInt(expansions.size()));
        StringBuilder sb = new StringBuilder();
        // 修正后的正则：正确处理 <tag>
        Pattern p = Pattern.compile("(<[^>]+>)|([^<]+)");
        Matcher m = p.matcher(rule);

        while (m.find()) {
            if (m.group(1) != null) {
                sb.append(generate(mode, m.group(1), depth + 1));
            } else {
                sb.append(m.group(2));
            }
        }
        return sb.toString();
    }
}