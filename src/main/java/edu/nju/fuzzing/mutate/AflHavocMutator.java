package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * 增强版 AflHavocMutator
 * 集成了 13 种变异算子，支持自适应堆叠和字典操作。
 */
public class AflHavocMutator implements Mutator {

    private final Random random = new Random();
    private final List<Seed> corpus;
    private final List<byte[]> dictionary = new ArrayList<>();

    public AflHavocMutator(List<Seed> corpus) {
        this.corpus = corpus;
        initDictionary();
    }

    private void initDictionary() {
        addToken("<root>"); addToken("</root>"); addToken("<a>"); addToken("href=");
        addToken("function"); addToken("var"); addToken("return"); addToken("true"); addToken("false");
        addToken(new byte[]{0x7F, 'E', 'L', 'F'});
        addToken(new byte[]{(byte)0x89, 'P', 'N', 'G'});
        addToken(new byte[]{(byte)0xFF, (byte)0xD8, (byte)0xFF});
        addToken(new byte[]{'%', 'P', 'D', 'F', '-'});
        addToken("SELECT"); addToken(" WHERE "); addToken("' OR '1'='1");
    }

    private void addToken(String s) { dictionary.add(s.getBytes(StandardCharsets.ISO_8859_1)); }
    private void addToken(byte[] b) { dictionary.add(b); }

    @Override
    public List<Testcase> mutate(Seed seed, int energy) {
        List<Testcase> testcases = new ArrayList<>(energy);
        byte[] originalData = seed.getDataCopy();

        for (int i = 0; i < energy; i++) {
            byte[] data = originalData.clone();
            String desc = "havoc";

            // 1. Splice
            if (corpus.size() > 1 && random.nextInt(100) < 20) {
                data = splice(data);
                desc = "splice+havoc";
            }

            // 2. Adaptive Stacking
            int maxStack = (energy > 1000) ? 32 : (energy > 200 ? 16 : 8);
            int stackCount = 2 + random.nextInt(maxStack);
            if (data.length < 4) stackCount = Math.min(stackCount, 2);

            for (int j = 0; j < stackCount; j++) {
                // 现在有 13 种算子 (0-12)
                int op = random.nextInt(13);

                switch (op) {
                    // === Bit Level ===
                    case 0: data = MutationOps.flipBit(data); break;
                    case 1: data = MutationOps.flipByte(data); break;
                    case 2: data = MutationOps.swapBytes(data); break; // 新增

                    // === Arithmetic ===
                    case 3: data = MutationOps.arithByte(data); break;
                    case 4: data = MutationOps.arithShort(data); break; // 新增
                    case 5: data = MutationOps.arithInt(data); break;   // 新增

                    // === Special Values ===
                    case 6: data = MutationOps.setInteresting(data); break;

                    // === Block Operations ===
                    case 7: data = MutationOps.deleteBlock(data); break;
                    case 8: data = MutationOps.insertBlock(data); break;
                    case 9: data = MutationOps.overwriteBlock(data); break;
                    case 10: data = MutationOps.cloneBlock(data); break; // 新增

                    // === Dictionary ===
                    case 11:
                        if (!dictionary.isEmpty())
                            data = MutationOps.overwriteToken(data, dictionary.get(random.nextInt(dictionary.size())));
                        break;
                    case 12:
                        if (!dictionary.isEmpty())
                            data = MutationOps.insertToken(data, dictionary.get(random.nextInt(dictionary.size())));
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
        byte[] targetB = seedB.getData();

        if (targetA.length < 2 || targetB.length < 2) return targetA;

        int splitAtA = random.nextInt(targetA.length);
        int splitAtB = random.nextInt(targetB.length);

        int newLen = splitAtA + (targetB.length - splitAtB);
        if (newLen > 1024 * 1024) return targetA;

        byte[] res = new byte[newLen];
        System.arraycopy(targetA, 0, res, 0, splitAtA);
        System.arraycopy(targetB, splitAtB, res, splitAtA, targetB.length - splitAtB);
        return res;
    }
}