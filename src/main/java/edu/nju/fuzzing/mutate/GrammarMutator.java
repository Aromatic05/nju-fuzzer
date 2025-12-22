package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 基于语法的变异器 (Generative)
 * 包含了 XML, JSON, Lua 三种语法规则，覆盖 T07, T08, T09 目标。
 */
public class GrammarMutator implements Mutator {

    private final Random random = new Random();

    // 语法仓库：Map<ModeName, Map<Token, Rules>>
    private final Map<String, Map<String, List<String>>> grammars = new HashMap<>();
    private static final int MAX_DEPTH = 20;

    public GrammarMutator() {
        initXmlGrammar();
        initJsonGrammar();
        initLuaGrammar();
    }

    // --- 语法定义区 ---

    private void initXmlGrammar() {
        Map<String, List<String>> xml = new HashMap<>();
        xml.put("<start>", Arrays.asList("<root><elem/></root>", "<root><elem><elem/></elem></root>"));
        xml.put("<elem>", Arrays.asList("<tag prop='val'/>", "<tag><elem/></tag>", "text"));
        xml.put("<tag>", Arrays.asList("foo", "bar", "a", "div", "span"));
        grammars.put("xml", xml);
    }

    private void initJsonGrammar() {
        Map<String, List<String>> json = new HashMap<>();
        json.put("<start>", Arrays.asList("{ <kv_list> }", "[ <val_list> ]"));
        json.put("<kv_list>", Arrays.asList("<kv>", "<kv>, <kv_list>"));
        json.put("<kv>", Arrays.asList("\"key\": <val>"));
        json.put("<val_list>", Arrays.asList("<val>", "<val>, <val_list>"));
        json.put("<val>", Arrays.asList("123", "\"str\"", "true", "null", "{ <kv> }", "[ <val> ]"));
        grammars.put("json", json);
    }

    private void initLuaGrammar() {
        Map<String, List<String>> lua = new HashMap<>();
        lua.put("<start>", Arrays.asList("function f() <stmt> end f()", "<stmt>"));
        lua.put("<stmt>", Arrays.asList("a = 1;", "print('test');", "if 1==1 then <stmt> end", "<stmt> <stmt>"));
        grammars.put("lua", lua);
    }

    @Override
    public List<Testcase> mutate(Seed seed, int energy) {
        List<Testcase> res = new ArrayList<>();
        // 自动探测语法模式：根据文件名后缀或随机
        String mode = detectMode(seed);

        // 语法变异通常产生结构完全不同的样本，数量不宜过多，取 energy 的 10% 或至少 1 个
        int genCount = Math.max(1, energy / 10);

        for (int i = 0; i < genCount; i++) {
            String gen = generate(mode, "<start>", 0);
            res.add(new Testcase(
                    gen.getBytes(StandardCharsets.UTF_8),
                    seed,
                    "grammar:" + mode
            ));
        }
        return res;
    }

    // 简单的模式匹配
    private String detectMode(Seed seed) {
        String name = seed.getFile().getName().toLowerCase();
        if (name.contains("xml")) return "xml";
        if (name.contains("json") || name.contains("mjs")) return "json";
        if (name.contains("lua")) return "lua";

        // 默认随机混淆
        List<String> keys = new ArrayList<>(grammars.keySet());
        return keys.get(random.nextInt(keys.size()));
    }

    // 递归生成核心逻辑
    private String generate(String mode, String token, int depth) {
        if (depth > MAX_DEPTH) return ""; // 深度熔断

        if (!token.startsWith("<")) return token; // 终结符

        Map<String, List<String>> rules = grammars.get(mode);
        List<String> expansions = rules.get(token);

        // 如果没找到规则或规则为空，返回空串防止报错
        if (expansions == null || expansions.isEmpty()) return "";

        String rule = expansions.get(random.nextInt(expansions.size()));

        StringBuilder sb = new StringBuilder();
        // 正则匹配 <tag> 或 普通文本
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