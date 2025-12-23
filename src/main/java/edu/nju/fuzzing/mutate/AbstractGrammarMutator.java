package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 语法变异器的抽象父类
 * 负责通用的生成逻辑，子类只需实现 defineGrammar() 来填充规则。
 */
public abstract class AbstractGrammarMutator implements Mutator {

    protected final Map<String, List<String>> rules = new HashMap<>();
    protected final Random random = new Random();
    private static final int MAX_DEPTH = 25;

    public AbstractGrammarMutator() {
        defineGrammar();
    }

    /**
     * 子类必须实现此方法，在其中调用 addRule() 定义语法
     */
    protected abstract void defineGrammar();

    /**
     * 辅助方法：添加一条规则
     */
    protected void addRule(String key, List<String> expansions) {
        rules.put(key, expansions);
    }

    @Override
    public List<Testcase> mutate(Seed seed, int energy) {
        List<Testcase> res = new ArrayList<>();
        // 语法生成通常产生 20% 左右的样本即可，或者至少 1 个
        int genCount = Math.max(1, energy / 5);

        for (int i = 0; i < genCount; i++) {
            // 从 <start> 开始生成
            String gen = generate("<start>", 0);

            // 统一使用 ISO_8859_1 编码，兼容二进制和文本
            res.add(new Testcase(
                    gen.getBytes(StandardCharsets.ISO_8859_1),
                    seed,
                    "grammar:" + this.getClass().getSimpleName()
            ));
        }
        return res;
    }

    private String generate(String token, int depth) {
        if (depth > MAX_DEPTH) return "";

        // 1. 如果不是变量（非 <...>），直接返回文本
        if (!token.startsWith("<")) return token;

        // 2. 查找规则
        List<String> expansions = rules.get(token);

        // 3. 如果没找到规则（可能是 XML 的字面量标签 <root>），原样返回
        if (expansions == null || expansions.isEmpty()) return token;

        // 4. 随机展开
        String rule = expansions.get(random.nextInt(expansions.size()));

        StringBuilder sb = new StringBuilder();
        Pattern p = Pattern.compile("(<[^>]+>)|([^<]+)");
        Matcher m = p.matcher(rule);

        while (m.find()) {
            if (m.group(1) != null) {
                sb.append(generate(m.group(1), depth + 1));
            } else {
                sb.append(m.group(2));
            }
        }
        return sb.toString();
    }
}