package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * 增强版 AflHavocMutator
 * 特性：
 * 1. 支持 Splice (拼接)
 * 2. 支持 Dictionary (字典/Token) 注入
 * 3. 支持 Adaptive Stacking (自适应堆叠力度)
 */
public class AflHavocMutator implements Mutator {

    private final Random random = new Random();
    private final List<Seed> corpus;

    // === 内置通用字典 (Common Tokens) ===
    // 包含二进制魔术数和常见文本关键字，增强针对性
    private final List<byte[]> dictionary = new ArrayList<>();

    public AflHavocMutator(List<Seed> corpus) {
        this.corpus = corpus;
        initDictionary();
    }

    private void initDictionary() {
        // XML / HTML
        addToken("<root>"); addToken("</root>"); addToken("<a>"); addToken("href=");
        // JSON / Script
        addToken("function"); addToken("var"); addToken("return"); addToken("true"); addToken("false");
        // Binary Headers (ELF, PNG, JPEG, GIF, PDF)
        addToken(new byte[]{0x7F, 'E', 'L', 'F'});
        addToken(new byte[]{(byte)0x89, 'P', 'N', 'G'});
        addToken(new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF});
        addToken(new byte[]{'%', 'P', 'D', 'F', '-'});
        // SQL
        addToken("SELECT"); addToken(" WHERE "); addToken("' OR '1'='1");
    }

    private void addToken(String s) {
        dictionary.add(s.getBytes(StandardCharsets.ISO_8859_1)); // 使用单字节编码防止破坏二进制
    }

    private void addToken(byte[] b) {
        dictionary.add(b);
    }

    @Override
    public List<Testcase> mutate(Seed seed, int energy) {
        List<Testcase> testcases = new ArrayList<>(energy);
        byte[] originalData = seed.getDataCopy();

        for (int i = 0; i < energy; i++) {
            byte[] data = originalData.clone();
            String desc = "havoc";

            // === 1. SPLICE 阶段 (20% 概率) ===
            if (corpus.size() > 1 && random.nextInt(100) < 20) {
                data = splice(data);
                desc = "splice+havoc";
            }

            // === 2. 自适应 HAVOC 阶段 ===
            // 改进点：不再固定 2-8 次。如果 energy 很高，说明这个种子很重要，
            // 我们允许它进行更剧烈的破坏（堆叠更多算子），最高可达 32 次。
            // 这是一个简单的启发式逻辑。
            int maxStack = (energy > 1000) ? 32 : (energy > 200 ? 16 : 8);
            int stackCount = 2 + random.nextInt(maxStack);

            // 小文件保护
            if (data.length < 4) stackCount = Math.min(stackCount, 2);

            for (int j = 0; j < stackCount; j++) {
                // 现在有 9 种算子 (0-8)
                int op = random.nextInt(9);

                switch (op) {
                    case 0: data = MutationOps.flipBit(data); break;
                    case 1: data = MutationOps.flipByte(data); break;
                    case 2: data = MutationOps.arithByte(data); break;
                    case 3: data = MutationOps.setInteresting(data); break;
                    case 4: data = MutationOps.deleteBlock(data); break;
                    case 5: data = MutationOps.insertBlock(data); break;
                    case 6: data = MutationOps.overwriteBlock(data); break;
                    // === 新增字典算子 ===
                    case 7:
                        if (!dictionary.isEmpty()) {
                            byte[] token = dictionary.get(random.nextInt(dictionary.size()));
                            data = MutationOps.overwriteToken(data, token);
                        }
                        break;
                    case 8:
                        if (!dictionary.isEmpty()) {
                            byte[] token = dictionary.get(random.nextInt(dictionary.size()));
                            data = MutationOps.insertToken(data, token);
                        }
                        break;
                }
            }

            testcases.add(new Testcase(data, seed, desc));
        }

        return testcases;
    }

    private byte[] splice(byte[] targetA) {
        if (corpus.isEmpty()) return targetA;

        Seed seedB = corpus.get(random.nextInt(corpus.size()));
        byte[] targetB = seedB.getData(); // 只读，无需 Copy

        if (targetA.length < 2 || targetB.length < 2) return targetA;

        int splitAtA = random.nextInt(targetA.length);
        int splitAtB = random.nextInt(targetB.length);

        int newLen = splitAtA + (targetB.length - splitAtB);
        // 限制一下拼接后的最大长度，防止无限膨胀
        if (newLen > 1024 * 1024) return targetA;

        byte[] res = new byte[newLen];
        System.arraycopy(targetA, 0, res, 0, splitAtA);
        System.arraycopy(targetB, splitAtB, res, splitAtA, targetB.length - splitAtB);

        return res;
    }
}