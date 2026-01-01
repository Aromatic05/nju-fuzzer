package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.SeedType;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

public class MutatorFactory {

    private final List<Seed> corpus;

    // 通用变异器作为单例存在（兜底 + 混合策略）
    // 注意：确保 AflHavocMutator 内部是线程安全的（使用 ThreadLocalRandom 即可）
    private final Mutator defaultMutator;

    // 混合策略：有多少概率强制使用 Havoc 变异，而不是语法变异
    // 经验值：10% - 20% 的概率用“乱拳打死老师傅”的位变异效果很好
    private static final int HAVOC_PROBABILITY = 10;

    public MutatorFactory(List<Seed> corpus) {
        this.corpus = corpus;
        this.defaultMutator = new AflHavocMutator(corpus);
    }

    /**
     * 根据 Seed 的类型动态创建对应的 Mutator
     */
    public Mutator createMutator(Seed seed) {
        SeedType type = seed.getType();

        // 1. [兜底策略] 类型未知，只能用通用变异
        if (type == null || type == SeedType.UNKNOWN) {
            return defaultMutator;
        }

        // 2. [混合策略] 即使是已知类型，也偶尔用一下 Havoc
        // 目的：语法变异器生成的结构太完整，有时无法触发底层的位解析错误。
        // 通过这一步，我们让特定格式的种子也能享受到 BitFlip/Splicing 的变异。
        if (shouldUseHavoc()) {
            return defaultMutator;
        }

        // 3. [多态创建] 根据类型创建特定的语法变异器
        // 保持了你希望的“即时创建”模式
        switch (type) {
            // --- 文本类 ---
            case XML:   return new XmlMutator();
            case MJS:   return new MjsMutator();
            case LUA:   return new LuaMutator();
            case CXX:   return new CxxMutator();

            // --- 二进制类 ---
            case PNG:   return new PngMutator();
            case ELF:   return new ElfMutator();
            case JPEG:  return new JpegMutator();
            case PCAP:  return new PcapMutator();

            // --- 未实现的类型 ---
            // 如果未来加了新类型但忘了加 case，默认回退到通用变异
            default:    return defaultMutator;
        }
    }

    /**
     * 辅助方法：决定是否使用 Havoc 变异
     */
    private boolean shouldUseHavoc() {
        return ThreadLocalRandom.current().nextInt(100) < HAVOC_PROBABILITY;
    }
}