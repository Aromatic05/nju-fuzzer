package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.grammar.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 语法感知 C++ Mangled Name 变异器
 *
 * 核心改进：
 * 1. 使用种子内容进行变异
 * 2. 容错分词 -> 语法感知变异 -> 序列化
 * 3. 针对 Itanium C++ ABI 特有结构进行变异
 */
public class CxxMutator implements Mutator {

    private static final String[] BASE_TYPES = {
            "v", "w", "b", "c", "a", "h", "s", "t",
            "i", "j", "l", "m", "x", "y", "n", "o",
            "f", "d", "e", "g", "z",
            "Da", "Dc", "Dn", "Di", "Ds"
    };

    private static final String[] MODIFIERS = {"P", "R", "O", "K", "V", "r"};

    private static final String[] OPERATORS = {
            "nw", "na", "dl", "da",
            "ps", "ng", "ad", "de",
            "co", "nt",
            "pl", "mi", "ml", "dv", "rm", "an", "or", "eo",
            "aS", "pL", "mI",
            "eq", "ne", "lt", "gt",
            "cl", "ix", "qu"
    };

    private static final String[] STD_SUBS = {"St", "Sa", "Sb", "Ss", "Si", "So", "Sd"};

    private final CxxTokenizer tokenizer = new CxxTokenizer();

    @Override
    public Iterator<Testcase> mutate(Seed seed, int energy) {
        int count = Math.max(1, energy);
        return new Iterator<Testcase>() {
            private int remaining = count;

            @Override
            public boolean hasNext() {
                return remaining > 0;
            }

            @Override
            public Testcase next() {
                if (remaining <= 0) throw new NoSuchElementException();
                remaining--;

                ThreadLocalRandom rand = ThreadLocalRandom.current();
                byte[] seedData = seed.getData();
                byte[] mutatedBytes;
                String desc;

                int strategy = rand.nextInt(100);

                if (strategy < 10) {
                    mutatedBytes = generateAttackPayload(rand);
                    desc = "CXX:Attack";
                } else if (strategy < 20) {
                    mutatedBytes = createDeepNesting(seedData, rand);
                    desc = "CXX:DeepNest";
                } else if (seedData == null || seedData.length == 0 || !isValidMangledName(seedData)) {
                    mutatedBytes = generateMangledName(rand).getBytes(StandardCharsets.ISO_8859_1);
                    desc = "CXX:Gen";
                } else {
                    mutatedBytes = mutateWithGrammar(seedData, rand);
                    desc = "CXX:GrammarMut";
                }

                return new Testcase(mutatedBytes, seed, "grammar:" + desc);
            }
        };
    }

    private boolean isValidMangledName(byte[] data) {
        if (data.length < 2) return false;
        return data[0] == '_' && data[1] == 'Z';
    }

    private byte[] mutateWithGrammar(byte[] seedData, ThreadLocalRandom rand) {
        List<Token> tokens = tokenizer.tokenize(seedData);
        if (tokens.isEmpty()) {
            return generateMangledName(rand).getBytes(StandardCharsets.ISO_8859_1);
        }

        int mutationCount = 1 + rand.nextInt(3);
        List<Token> mutatedTokens = new ArrayList<>(tokens);

        for (int i = 0; i < mutationCount; i++) {
            int mutationType = rand.nextInt(10);

            switch (mutationType) {
                case 0: mutatedTokens = mutateTypes(mutatedTokens, rand); break;
                case 1: mutatedTokens = mutateModifiers(mutatedTokens, rand); break;
                case 2: mutatedTokens = mutateSubstitutions(mutatedTokens, rand); break;
                case 3: mutatedTokens = mutateLengths(mutatedTokens, rand); break;
                case 4: mutatedTokens = mutateNames(mutatedTokens, rand); break;
                case 5: mutatedTokens = insertTemplates(mutatedTokens, rand); break;
                case 6: mutatedTokens = duplicateTokens(mutatedTokens, rand); break;
                case 7: mutatedTokens = deleteTokens(mutatedTokens, rand); break;
                case 8: mutatedTokens = swapTokens(mutatedTokens, rand); break;
                default: mutatedTokens = corruptNestedStructure(mutatedTokens, rand); break;
            }
        }

        StringBuilder result = new StringBuilder();
        for (Token token : mutatedTokens) {
            if (token.getValue() != null) {
                result.append(token.getValue());
            }
        }

        return result.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private List<Token> mutateTypes(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        for (Token token : tokens) {
            if (token.getType() == Token.Type.CXX_TYPE && rand.nextInt(4) == 0) {
                String newType = BASE_TYPES[rand.nextInt(BASE_TYPES.length)];
                result.add(token.withValue(newType));
            } else {
                result.add(token);
            }
        }
        return result;
    }

    private List<Token> mutateModifiers(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        for (Token token : tokens) {
            if (token.getType() == Token.Type.CXX_MODIFIER && rand.nextInt(3) == 0) {
                String newMod = MODIFIERS[rand.nextInt(MODIFIERS.length)];
                result.add(token.withValue(newMod));
            } else {
                result.add(token);
            }
            if (token.getType() == Token.Type.CXX_TYPE && rand.nextInt(5) == 0) {
                String extra = MODIFIERS[rand.nextInt(MODIFIERS.length)];
                result.add(new Token(Token.Type.CXX_MODIFIER, extra));
            }
        }
        return result;
    }

    private List<Token> mutateSubstitutions(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        for (Token token : tokens) {
            if (token.getType() == Token.Type.CXX_SUBST && rand.nextInt(3) == 0) {
                int subChoice = rand.nextInt(4);
                String newSub;
                switch (subChoice) {
                    case 0: newSub = "S_"; break;
                    case 1: newSub = "S" + rand.nextInt(100) + "_"; break;
                    case 2: newSub = "S" + (rand.nextInt(10000) + 1000) + "_"; break;
                    default: newSub = STD_SUBS[rand.nextInt(STD_SUBS.length)]; break;
                }
                result.add(token.withValue(newSub));
            } else {
                result.add(token);
            }
        }
        return result;
    }

    private List<Token> mutateLengths(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        for (Token token : tokens) {
            if (token.getType() == Token.Type.CXX_LENGTH && rand.nextInt(3) == 0) {
                int lengthChoice = rand.nextInt(5);
                String newLength;
                switch (lengthChoice) {
                    case 0: newLength = "0"; break;
                    case 1: newLength = String.valueOf(rand.nextInt(100)); break;
                    case 2: newLength = "2147483647"; break;
                    case 3: newLength = "99999999999"; break;
                    default: newLength = "-1"; break;
                }
                result.add(token.withValue(newLength));
            } else {
                result.add(token);
            }
        }
        return result;
    }

    private List<Token> mutateNames(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        for (Token token : tokens) {
            if (token.getType() == Token.Type.CXX_NAME && rand.nextInt(4) == 0) {
                String original = token.getValue();
                int mutOp = rand.nextInt(4);
                String newName;
                switch (mutOp) {
                    case 0: newName = original + "AAAA"; break;
                    case 1: newName = original.isEmpty() ? "x" : original.substring(0, Math.min(1, original.length())); break;
                    case 2: newName = "A".repeat(100 + rand.nextInt(200)); break;
                    default: newName = original + "\0\0"; break;
                }
                result.add(token.withValue(newName));
            } else {
                result.add(token);
            }
        }
        return result;
    }

    private List<Token> insertTemplates(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens);
        int count = 1 + rand.nextInt(5);
        for (int i = 0; i < count; i++) {
            int pos = rand.nextInt(Math.max(1, result.size()));
            result.add(pos, new Token(Token.Type.CXX_TEMPLATE, "I"));
            result.add(pos + 1, new Token(Token.Type.CXX_TYPE, BASE_TYPES[rand.nextInt(BASE_TYPES.length)]));
            if (rand.nextBoolean()) {
                result.add(pos + 2, new Token(Token.Type.CXX_NESTED, "E"));
            }
        }
        return result;
    }

    private List<Token> duplicateTokens(List<Token> tokens, ThreadLocalRandom rand) {
        if (tokens.size() < 2) return tokens;
        List<Token> result = new ArrayList<>(tokens);
        int start = rand.nextInt(tokens.size());
        int end = Math.min(start + 2 + rand.nextInt(5), tokens.size());
        List<Token> segment = new ArrayList<>(tokens.subList(start, end));
        int repeat = 2 + rand.nextInt(10);
        for (int i = 0; i < repeat; i++) {
            result.addAll(start, segment);
        }
        return result;
    }

    private List<Token> deleteTokens(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>();
        boolean keepPrefix = true;
        for (Token token : tokens) {
            if (keepPrefix && token.getType() == Token.Type.CXX_PREFIX) {
                result.add(token);
                keepPrefix = false;
            } else if (rand.nextInt(8) != 0) {
                result.add(token);
            }
        }
        return result.isEmpty() ? tokens : result;
    }

    private List<Token> swapTokens(List<Token> tokens, ThreadLocalRandom rand) {
        if (tokens.size() < 3) return tokens;
        List<Token> result = new ArrayList<>(tokens);
        int i = 1 + rand.nextInt(result.size() - 1);
        int j = 1 + rand.nextInt(result.size() - 1);
        if (i != j) {
            Token temp = result.get(i);
            result.set(i, result.get(j));
            result.set(j, temp);
        }
        return result;
    }

    private List<Token> corruptNestedStructure(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        int openCount = 0;
        for (Token token : tokens) {
            if (token.getType() == Token.Type.CXX_NESTED || token.getType() == Token.Type.CXX_TEMPLATE) {
                if ("N".equals(token.getValue()) || "I".equals(token.getValue())) {
                    openCount++;
                    result.add(token);
                    if (rand.nextInt(3) == 0) {
                        result.add(token);
                        openCount++;
                    }
                } else if ("E".equals(token.getValue())) {
                    if (rand.nextInt(4) == 0) {
                        continue;
                    }
                    openCount--;
                    result.add(token);
                }
            } else {
                result.add(token);
            }
        }
        return result;
    }

    private byte[] generateAttackPayload(ThreadLocalRandom rand) {
        StringBuilder sb = new StringBuilder("_Z");
        int attack = rand.nextInt(5);

        switch (attack) {
            case 0:
                sb.append(rand.nextBoolean() ? "2147483647" : "99999999999999999");
                sb.append("func");
                break;
            case 1:
                sb.append("4main");
                int depth = 1000 + rand.nextInt(4000);
                for (int i = 0; i < depth; i++) {
                    if (rand.nextBoolean()) sb.append("P");
                    else sb.append("A").append(rand.nextInt(10)).append("_");
                }
                sb.append("i");
                break;
            case 2:
                sb.append("3foo");
                sb.append("S");
                if (rand.nextBoolean()) sb.append("_");
                else sb.append(rand.nextInt(2048)).append("_");
                break;
            case 3:
                sb.append("4func");
                int templateDepth = 50 + rand.nextInt(100);
                for (int i = 0; i < templateDepth; i++) {
                    sb.append("I");
                    if (i % 5 == 0) sb.append("UlT_E_");
                    else sb.append(BASE_TYPES[rand.nextInt(BASE_TYPES.length)]);
                }
                int closeCount = templateDepth + (rand.nextInt(10) - 5);
                for (int i = 0; i < Math.max(0, closeCount); i++) sb.append("E");
                break;
            default:
                sb.append("N");
                for (int i = 0; i < 100; i++) {
                    sb.append("3ns").append(i);
                }
                break;
        }

        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private byte[] createDeepNesting(byte[] seedData, ThreadLocalRandom rand) {
        StringBuilder sb = new StringBuilder();
        
        if (seedData != null && seedData.length >= 2 && seedData[0] == '_' && seedData[1] == 'Z') {
            sb.append(new String(seedData, StandardCharsets.ISO_8859_1));
            int depth = 100 + rand.nextInt(200);
            for (int i = 0; i < depth; i++) {
                sb.append("P");
            }
            sb.append("i");
        } else {
            sb.append("_Z");
            int depth = 500 + rand.nextInt(1000);
            for (int i = 0; i < depth; i++) {
                if (rand.nextBoolean()) sb.append("P");
                else sb.append("A1_");
            }
            sb.append("i");
        }

        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private String generateMangledName(ThreadLocalRandom rand) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("_Z");

        int strategy = rand.nextInt(100);

        if (strategy < 5) {
            sb.append(rand.nextBoolean() ? "2147483647" : "99999999999999999");
            sb.append("function");
        } else if (strategy < 10) {
            sb.append("4main");
            int depth = 50 + rand.nextInt(200);
            for (int i = 0; i < depth; i++) {
                if (rand.nextBoolean()) sb.append("P");
                else sb.append("A").append(rand.nextInt(10)).append("_");
            }
            sb.append("i");
        } else if (strategy < 20) {
            sb.append("3foo");
            sb.append("S");
            if (rand.nextBoolean()) sb.append("_");
            else sb.append(rand.nextInt(100)).append("_");
        } else if (strategy < 35) {
            sb.append("4func");
            int depth = 10 + rand.nextInt(30);
            for (int i = 0; i < depth; i++) {
                sb.append("I");
                if (i % 5 == 0) sb.append("UlT_E_");
                else sb.append(randomType(rand, 0));
            }
            int closeCount = depth + (rand.nextInt(10) - 5);
            for (int i = 0; i < Math.max(0, closeCount); i++) sb.append("E");
        } else {
            generateComplexSignature(sb, rand);
        }

        return sb.toString();
    }

    private void generateComplexSignature(StringBuilder sb, ThreadLocalRandom rand) {
        if (rand.nextBoolean()) {
            sb.append("N");
            if (rand.nextInt(10) < 3) sb.append(MODIFIERS[rand.nextInt(MODIFIERS.length)]);
            if (rand.nextInt(10) < 2) sb.append(STD_SUBS[rand.nextInt(STD_SUBS.length)]);

            int parts = 1 + rand.nextInt(4);
            for (int i = 0; i < parts; i++) {
                if (rand.nextInt(10) < 2) {
                    sb.append(OPERATORS[rand.nextInt(OPERATORS.length)]);
                } else if (rand.nextInt(10) < 2) {
                    String ctor = (rand.nextBoolean() ? "C" : "D") + rand.nextInt(4);
                    sb.append(ctor);
                } else {
                    String part = "ns" + rand.nextInt(100);
                    sb.append(part.length()).append(part);
                }
                if (rand.nextBoolean()) {
                    sb.append("I");
                    sb.append(randomType(rand, 0));
                    sb.append("E");
                }
            }
            sb.append("E");
        } else {
            String name = "func";
            sb.append(name.length()).append(name);
        }

        int args = rand.nextInt(6);
        if (args == 0) sb.append("v");
        for (int i = 0; i < args; i++) {
            sb.append(randomType(rand, 0));
        }
    }

    private String randomType(ThreadLocalRandom rand, int depth) {
        if (depth > 8) {
            return BASE_TYPES[rand.nextInt(BASE_TYPES.length)];
        }

        int choice = rand.nextInt(100);

        if (choice < 30) {
            return BASE_TYPES[rand.nextInt(BASE_TYPES.length)];
        } else if (choice < 50) {
            return MODIFIERS[rand.nextInt(MODIFIERS.length)] + randomType(rand, depth + 1);
        } else if (choice < 65) {
            String dim = rand.nextBoolean() ? String.valueOf(rand.nextInt(100)) : "";
            return "A" + dim + "_" + randomType(rand, depth + 1);
        } else if (choice < 75) {
            StringBuilder fp = new StringBuilder();
            fp.append("PF");
            fp.append(randomType(rand, depth + 1));
            fp.append(randomType(rand, depth + 1));
            if (rand.nextBoolean()) fp.append(randomType(rand, depth + 1));
            fp.append("E");
            return fp.toString();
        } else if (choice < 90) {
            StringBuilder t = new StringBuilder();
            t.append("I");
            int count = 1 + rand.nextInt(3);
            for (int i = 0; i < count; i++) t.append(randomType(rand, depth + 1));
            t.append("E");
            return t.toString();
        } else {
            if (rand.nextBoolean()) return "Dt" + randomType(rand, depth + 1) + "E";
            return "S" + (rand.nextBoolean() ? "_" : "0_");
        }
    }
}
