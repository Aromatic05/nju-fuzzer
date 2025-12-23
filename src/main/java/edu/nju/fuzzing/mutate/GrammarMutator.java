package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.SeedType;
import edu.nju.fuzzing.model.Testcase;
// 导入你刚才建立的子类
import edu.nju.fuzzing.mutate.grammars.*;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * 语法变异调度器 (Dispatcher)
 * 职责：根据 Seed 的类型，将变异任务分发给对应的具体变异器实现。
 */
public class GrammarMutator implements Mutator {

    // 核心注册表：类型 -> 策略
    private final Map<SeedType, AbstractGrammarMutator> strategies = new EnumMap<>(SeedType.class);

    public GrammarMutator() {
        // 在这里注册所有的语法策略
        // 确保你的 grammars 包下有这些类
        strategies.put(SeedType.XML, new XmlMutator());
        strategies.put(SeedType.JSON, new JsonMutator());
        strategies.put(SeedType.LUA, new LuaMutator());
        strategies.put(SeedType.CXX, new CxxMutator());

        strategies.put(SeedType.ELF, new ElfMutator());
        strategies.put(SeedType.JPEG, new JpegMutator());
        strategies.put(SeedType.PNG, new PngMutator());
        strategies.put(SeedType.PCAP, new PcapMutator());

        // UNKNOWN 类型不注册，意味着未知类型不使用语法变异
    }

    @Override
    public List<Testcase> mutate(Seed seed, int energy) {
        // 1. 获取种子类型 (这是从 Seed.java 获取的)
        SeedType type = seed.getType();

        // 2. 查找对应的变异策略
        AbstractGrammarMutator mutator = strategies.get(type);

        if (mutator != null) {
            // 3. 如果找到了（比如是 XML），就委托给 XmlMutator 去干活
            return mutator.mutate(seed, energy);
        } else {
            // 4. 如果没找到（比如是 UNKNOWN），返回空列表
            // FuzzingEngine 收到空列表后，会自然地回退到 Havoc 变异
            return new ArrayList<>();
        }
    }
}