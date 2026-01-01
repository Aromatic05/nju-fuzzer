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
 * 4. 长度-名称同步机制，保证结构合法性
 * 5. 可选的语法检查与自动修复
 */
public class CxxMutator implements Mutator {

    private static final int MAX_SYNTAX_FIX_ATTEMPTS = 3;

    private static final String[] BASE_TYPES = {
            "v", "w", "b", "c", "a", "h", "s", "t",
            "i", "j", "l", "m", "x", "y", "n", "o",
            "f", "d", "e", "g", "z",
            "Da", "Dc", "Dn", "Di", "Ds"
    };

    private static final String[] MODIFIERS = { "P", "R", "O", "K", "V", "r" };

    private static final String[] OPERATORS = {
            "nw", "na", "dl", "da",
            "ps", "ng", "ad", "de",
            "co", "nt",
            "pl", "mi", "ml", "dv", "rm", "an", "or", "eo",
            "aS", "pL", "mI",
            "eq", "ne", "lt", "gt",
            "cl", "ix", "qu"
    };

    private static final String[] STD_SUBS = { "St", "Sa", "Sb", "Ss", "Si", "So", "Sd" };

    // 预定义的 mangled name 语料库（问题 3.2）
    private static final String[] CORPUS = {
            // 简单函数
            "_Z4funcv", // void func()
            "_Z4funci", // func(int)
            "_Z4funcid", // func(int, double)
            "_Z4funcPi", // func(int*)
            "_Z4funcRi", // func(int&)
            "_Z4funcKi", // func(const int)

            // 命名空间
            "_ZN3foo3barEv", // foo::bar()
            "_ZN3foo3baz4quxEi", // foo::baz::qux(int)
            "_ZN3std6vectorIiE4sizeEv", // std::vector<int>::size()

            // 模板
            "_Z4funcIiEvT_", // template<class T> void func(T)
            "_Z4funcIiET_S0_", // 带替换的模板
            "_Z4funcIidEvT_T0_", // template<class T, class U> void func(T, U)
            "_ZN3FooIiE3getEv", // Foo<int>::get()

            // 复杂类型
            "_Z4funcPFviE", // func(void (*)(int))
            "_Z4funcA10_i", // func(int[10])
            "_Z4funcRKi", // func(const int&)
            "_Z4funcPPi", // func(int**)

            // 操作符
            "_ZNK3FooplERKS_", // Foo::operator+(const Foo&) const
            "_ZN3FooclEi", // Foo::operator()(int)
            "_ZN3FooixEi", // Foo::operator[](int)

            // 构造/析构
            "_ZN3FooC1Ev", // Foo::Foo()
            "_ZN3FooC2Ei", // Foo::Foo(int)
            "_ZN3FooD1Ev", // Foo::~Foo()

            // 标准库
            "_ZSt4cout", // std::cout
            "_ZNSt6vectorIiE9push_backERKi", // std::vector<int>::push_back
            "_ZNSs6appendEPKc", // std::string::append
    };

    private final CxxTokenizer tokenizer = new CxxTokenizer();

    // 语法检查器和修复器
    private final CxxSyntaxChecker syntaxChecker = new CxxSyntaxChecker();
    private final CxxSyntaxFixer syntaxFixer = new CxxSyntaxFixer(syntaxChecker);

    // 是否强制语法正确（默认false以允许生成语法错误的输入用于测试解析器容错）
    private boolean enforceSyntaxCorrectness = false;

    /**
     * 设置是否强制语法正确
     * 
     * @param enforce true则变异后自动修复语法错误，false则允许生成语法错误的输入
     */
    public void setEnforceSyntaxCorrectness(boolean enforce) {
        this.enforceSyntaxCorrectness = enforce;
    }

    /**
     * 检查 mangled name 语法是否正确
     */
    public CxxSyntaxChecker.CheckResult checkSyntax(String mangledName) {
        return syntaxChecker.check(mangledName);
    }

    /**
     * 修复 mangled name 语法错误
     */
    public String fixSyntax(String mangledName) {
        return syntaxFixer.fix(mangledName);
    }

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
                if (remaining <= 0)
                    throw new NoSuchElementException();
                remaining--;

                ThreadLocalRandom rand = ThreadLocalRandom.current();
                byte[] seedData = seed.getData();
                byte[] mutatedBytes;
                String desc;

                int strategy = rand.nextInt(100);

                if (strategy < 5) {
                    // [5%] 使用语料库种子进行变异
                    String corpus = CORPUS[rand.nextInt(CORPUS.length)];
                    mutatedBytes = mutateWithGrammar(corpus.getBytes(StandardCharsets.ISO_8859_1), rand);
                    desc = "CXX:CorpusMut";
                } else if (strategy < 10) {
                    // [5%] 攻击 Payload
                    mutatedBytes = generateAttackPayload(rand);
                    // 对攻击负载也应用语法修复（如果启用）
                    if (enforceSyntaxCorrectness) {
                        String fixed = applySyntaxFixIfNeeded(
                                new String(mutatedBytes, StandardCharsets.ISO_8859_1), rand);
                        mutatedBytes = fixed.getBytes(StandardCharsets.ISO_8859_1);
                    }
                    desc = "CXX:Attack";
                } else if (strategy < 15) {
                    // [5%] 深层嵌套攻击
                    mutatedBytes = createDeepNesting(seedData, rand);
                    // 对深层嵌套也应用语法修复（如果启用）
                    if (enforceSyntaxCorrectness) {
                        String fixed = applySyntaxFixIfNeeded(
                                new String(mutatedBytes, StandardCharsets.ISO_8859_1), rand);
                        mutatedBytes = fixed.getBytes(StandardCharsets.ISO_8859_1);
                    }
                    desc = "CXX:DeepNest";
                } else if (seedData == null || seedData.length == 0 || !isValidMangledName(seedData)) {
                    // 种子无效，使用语料库生成
                    String corpus = CORPUS[rand.nextInt(CORPUS.length)];
                    mutatedBytes = mutateWithGrammar(corpus.getBytes(StandardCharsets.ISO_8859_1), rand);
                    desc = "CXX:Gen";
                } else {
                    // [80%] 基于种子的语法感知变异
                    mutatedBytes = mutateWithGrammar(seedData, rand);
                    desc = "CXX:GrammarMut";
                }

                return new Testcase(mutatedBytes, seed, "grammar:" + desc);
            }
        };
    }

    private boolean isValidMangledName(byte[] data) {
        if (data.length < 2)
            return false;
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
                case 0:
                    mutatedTokens = mutateTypes(mutatedTokens, rand);
                    break;
                case 1:
                    mutatedTokens = mutateModifiers(mutatedTokens, rand);
                    break;
                case 2:
                    mutatedTokens = mutateSubstitutions(mutatedTokens, rand);
                    break;
                case 3:
                    mutatedTokens = mutateLengths(mutatedTokens, rand);
                    break;
                case 4:
                    mutatedTokens = mutateNames(mutatedTokens, rand);
                    break;
                case 5:
                    mutatedTokens = insertTemplates(mutatedTokens, rand);
                    break;
                case 6:
                    mutatedTokens = duplicateTokens(mutatedTokens, rand);
                    break;
                case 7:
                    mutatedTokens = deleteTokens(mutatedTokens, rand);
                    break;
                case 8:
                    mutatedTokens = swapTokens(mutatedTokens, rand);
                    break;
                default:
                    mutatedTokens = corruptNestedStructure(mutatedTokens, rand);
                    break;
            }
        }

        StringBuilder result = new StringBuilder();
        for (Token token : mutatedTokens) {
            if (token.getValue() != null) {
                result.append(token.getValue());
            }
        }

        String mangledResult = result.toString();

        // 可选的语法检查与修复
        if (enforceSyntaxCorrectness) {
            mangledResult = applySyntaxFixIfNeeded(mangledResult, rand);
        }

        return mangledResult.getBytes(StandardCharsets.ISO_8859_1);
    }

    /**
     * 检查语法并在需要时修复
     */
    private String applySyntaxFixIfNeeded(String mangledName, ThreadLocalRandom rand) {
        CxxSyntaxChecker.CheckResult checkResult = syntaxChecker.check(mangledName);

        if (checkResult.isValid) {
            return mangledName;
        }

        // 尝试修复
        for (int attempt = 0; attempt < MAX_SYNTAX_FIX_ATTEMPTS; attempt++) {
            String fixed = syntaxFixer.fix(mangledName);
            CxxSyntaxChecker.CheckResult fixedResult = syntaxChecker.check(fixed);

            if (fixedResult.isValid) {
                return fixed;
            }

            mangledName = fixed;
        }

        return mangledName;
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
        // 问题4修复：统计实际替换候选数量，生成合法范围内的替换序号
        int maxSubst = countSubstitutions(tokens);

        List<Token> result = new ArrayList<>(tokens.size());
        for (Token token : tokens) {
            if (token.getType() == Token.Type.CXX_SUBST && rand.nextInt(3) == 0) {
                int subChoice = rand.nextInt(10);
                String newSub;
                switch (subChoice) {
                    case 0:
                    case 1:
                        newSub = "S_"; // S0 的简写
                        break;
                    case 2:
                    case 3:
                    case 4:
                        // 生成合法范围内的替换序号
                        int validSeq = rand.nextInt(Math.max(1, maxSubst));
                        newSub = "S" + (validSeq == 0 ? "" : toBase36(validSeq)) + "_";
                        break;
                    case 5:
                        // [10%] 故意超出范围（用于测试解析器健壮性）
                        newSub = "S" + (maxSubst + rand.nextInt(10) + 1) + "_";
                        break;
                    default:
                        newSub = STD_SUBS[rand.nextInt(STD_SUBS.length)];
                        break;
                }
                result.add(token.withValue(newSub));
            } else {
                result.add(token);
            }
        }
        return result;
    }

    /**
     * 统计当前符号中的替换候选数量
     */
    private int countSubstitutions(List<Token> tokens) {
        int count = 0;
        for (Token t : tokens) {
            // 名称、类型等会自动成为替换候选
            if (t.getType() == Token.Type.CXX_NAME ||
                    t.getType() == Token.Type.CXX_TYPE ||
                    t.getType() == Token.Type.CXX_TEMPLATE) {
                count++;
            }
        }
        return Math.max(1, count);
    }

    /**
     * 转换为 base-36 字符串
     */
    private String toBase36(int n) {
        if (n <= 0)
            return "";
        StringBuilder sb = new StringBuilder();
        while (n > 0) {
            int digit = n % 36;
            if (digit < 10) {
                sb.insert(0, (char) ('0' + digit));
            } else {
                sb.insert(0, (char) ('A' + digit - 10));
            }
            n /= 36;
        }
        return sb.toString();
    }

    private List<Token> mutateLengths(List<Token> tokens, ThreadLocalRandom rand) {
        // 问题1修复：同步更新长度和名称
        List<Token> result = new ArrayList<>(tokens.size());

        for (int i = 0; i < tokens.size(); i++) {
            Token token = tokens.get(i);

            if (token.getType() == Token.Type.CXX_LENGTH && rand.nextInt(3) == 0) {
                // 查找对应的名称 token
                if (i + 1 < tokens.size() && tokens.get(i + 1).getType() == Token.Type.CXX_NAME) {
                    Token nameToken = tokens.get(i + 1);
                    String name = nameToken.getValue();

                    if (name != null && !name.isEmpty()) {
                        int op = rand.nextInt(10);
                        String newName;

                        switch (op) {
                            case 0:
                                // 截断名称
                                int newLen = Math.max(1, name.length() / 2);
                                newName = name.substring(0, newLen);
                                break;
                            case 1:
                                // 扩展名称
                                newName = name + "_ext";
                                break;
                            case 2:
                                // 复制名称
                                newName = name + name;
                                break;
                            case 3:
                                // 添加数字后缀
                                newName = name + rand.nextInt(1000);
                                break;
                            case 4:
                                // [10%] 故意不匹配（测试解析器）：声明长度大于实际
                                result.add(token.withValue(String.valueOf(name.length() + 5)));
                                result.add(nameToken);
                                i++; // 跳过名称 token
                                continue;
                            default:
                                // 保持同步的随机名称
                                String[] nameParts = { "foo", "bar", "baz", "qux", "test", "func", "method" };
                                newName = nameParts[rand.nextInt(nameParts.length)] + rand.nextInt(100);
                                break;
                        }

                        // 同步更新长度和名称
                        result.add(token.withValue(String.valueOf(newName.length())));
                        result.add(nameToken.withValue(newName));
                        i++; // 跳过名称 token
                        continue;
                    }
                }

                // 没有对应名称，保持原样
                result.add(token);
            } else {
                result.add(token);
            }
        }
        return result;
    }

    private List<Token> mutateNames(List<Token> tokens, ThreadLocalRandom rand) {
        // 问题2和6修复：名称变异后更新长度前缀，减少 NUL 字符使用
        List<Token> result = new ArrayList<>(tokens.size());

        for (int i = 0; i < tokens.size(); i++) {
            Token token = tokens.get(i);

            if (token.getType() == Token.Type.CXX_NAME && rand.nextInt(4) == 0) {
                String original = token.getValue() != null ? token.getValue() : "x";
                int mutOp = rand.nextInt(20);
                String newName;

                switch (mutOp) {
                    case 0:
                    case 1:
                        // 扩展名称
                        newName = original + "_ext";
                        break;
                    case 2:
                    case 3:
                        // 截断名称
                        newName = original.isEmpty() ? "x" : original.substring(0, Math.max(1, original.length() / 2));
                        break;
                    case 4:
                        // 长名称（但不过长）
                        newName = "A".repeat(50 + rand.nextInt(50));
                        break;
                    case 5:
                        // 数字后缀
                        newName = original + rand.nextInt(10000);
                        break;
                    case 6:
                        // 下划线前缀
                        newName = "_" + original;
                        break;
                    case 7:
                    case 8:
                        // 常见名称
                        String[] commonNames = { "get", "set", "init", "run", "exec", "call", "new", "del" };
                        newName = commonNames[rand.nextInt(commonNames.length)] + original;
                        break;
                    case 19:
                        // [5%] NUL 字符注入（问题6：降低比例用于攻击测试）
                        newName = original + "\0";
                        break;
                    default:
                        // 简单变换
                        newName = original + "_" + rand.nextInt(100);
                        break;
                }

                // 查找并更新前面的长度 token（如果存在）
                if (i > 0 && result.size() > 0) {
                    Token prevToken = result.get(result.size() - 1);
                    if (prevToken.getType() == Token.Type.CXX_LENGTH) {
                        // 更新长度以匹配新名称
                        result.set(result.size() - 1, prevToken.withValue(String.valueOf(newName.length())));
                    }
                }

                result.add(token.withValue(newName));
            } else {
                result.add(token);
            }
        }
        return result;
    }

    private List<Token> insertTemplates(List<Token> tokens, ThreadLocalRandom rand) {
        // 问题3修复：将未闭合模板的比例从 50% 降低到 10%
        List<Token> result = new ArrayList<>(tokens);
        int count = 1 + rand.nextInt(3); // 减少模板数量

        for (int i = 0; i < count; i++) {
            int pos = rand.nextInt(Math.max(1, result.size()));

            // 确保不会插入到 _Z 前缀之前
            if (pos == 0 && !result.isEmpty() &&
                    result.get(0).getType() == Token.Type.CXX_PREFIX) {
                pos = 1;
            }

            result.add(pos, new Token(Token.Type.CXX_TEMPLATE, "I"));

            // 添加模板参数
            int paramCount = 1 + rand.nextInt(2);
            for (int j = 0; j < paramCount; j++) {
                result.add(pos + 1 + j, new Token(Token.Type.CXX_TYPE, BASE_TYPES[rand.nextInt(BASE_TYPES.length)]));
            }

            // 90% 概率添加闭合 E（问题3修复）
            if (rand.nextInt(10) != 0) {
                result.add(pos + 1 + paramCount, new Token(Token.Type.CXX_NESTED, "E"));
            }
        }
        return result;
    }

    private List<Token> duplicateTokens(List<Token> tokens, ThreadLocalRandom rand) {
        if (tokens.size() < 2)
            return tokens;
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
        if (tokens.size() < 3)
            return tokens;
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
        // 问题5修复：将破坏比例从 33%/25% 降低到 10%
        List<Token> result = new ArrayList<>(tokens.size());
        int openCount = 0;

        for (Token token : tokens) {
            if (token.getType() == Token.Type.CXX_NESTED || token.getType() == Token.Type.CXX_TEMPLATE) {
                if ("N".equals(token.getValue()) || "I".equals(token.getValue())) {
                    openCount++;
                    result.add(token);
                    // 10% 概率重复开始符（问题5修复：从 33% 降低）
                    if (rand.nextInt(10) == 0) {
                        result.add(token);
                        openCount++;
                    }
                } else if ("E".equals(token.getValue())) {
                    // 10% 概率删除结束符（问题5修复：从 25% 降低）
                    if (rand.nextInt(10) == 0 && openCount > 1) {
                        // 只在有多余开放结构时才考虑删除
                        openCount--;
                        continue;
                    }
                    if (openCount > 0) {
                        openCount--;
                    }
                    result.add(token);
                }
            } else {
                result.add(token);
            }
        }

        // 补充缺失的 E
        while (openCount > 0) {
            result.add(new Token(Token.Type.CXX_NESTED, "E"));
            openCount--;
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
                    if (rand.nextBoolean())
                        sb.append("P");
                    else
                        sb.append("A").append(rand.nextInt(10)).append("_");
                }
                sb.append("i");
                break;
            case 2:
                sb.append("3foo");
                sb.append("S");
                if (rand.nextBoolean())
                    sb.append("_");
                else
                    sb.append(rand.nextInt(2048)).append("_");
                break;
            case 3:
                sb.append("4func");
                int templateDepth = 50 + rand.nextInt(100);
                for (int i = 0; i < templateDepth; i++) {
                    sb.append("I");
                    if (i % 5 == 0)
                        sb.append("UlT_E_");
                    else
                        sb.append(BASE_TYPES[rand.nextInt(BASE_TYPES.length)]);
                }
                // 问题7修复：90% 保持平衡
                int closeCount;
                if (rand.nextInt(10) == 0) {
                    closeCount = templateDepth + (rand.nextInt(10) - 5);
                } else {
                    closeCount = templateDepth;
                }
                for (int i = 0; i < Math.max(0, closeCount); i++)
                    sb.append("E");
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
                if (rand.nextBoolean())
                    sb.append("P");
                else
                    sb.append("A1_");
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
                if (rand.nextBoolean())
                    sb.append("P");
                else
                    sb.append("A").append(rand.nextInt(10)).append("_");
            }
            sb.append("i");
        } else if (strategy < 20) {
            sb.append("3foo");
            sb.append("S");
            if (rand.nextBoolean())
                sb.append("_");
            else
                sb.append(rand.nextInt(100)).append("_");
        } else if (strategy < 35) {
            sb.append("4func");
            int depth = 10 + rand.nextInt(30);
            for (int i = 0; i < depth; i++) {
                sb.append("I");
                if (i % 5 == 0)
                    sb.append("UlT_E_");
                else
                    sb.append(randomType(rand, 0));
            }
            // 问题7修复：90% 保持平衡，10% 不平衡用于测试
            int closeCount;
            if (rand.nextInt(10) == 0) {
                // 10% 不平衡
                closeCount = depth + (rand.nextInt(10) - 5);
            } else {
                // 90% 平衡
                closeCount = depth;
            }
            for (int i = 0; i < Math.max(0, closeCount); i++)
                sb.append("E");
        } else {
            generateComplexSignature(sb, rand);
        }

        return sb.toString();
    }

    private void generateComplexSignature(StringBuilder sb, ThreadLocalRandom rand) {
        if (rand.nextBoolean()) {
            sb.append("N");
            if (rand.nextInt(10) < 3)
                sb.append(MODIFIERS[rand.nextInt(MODIFIERS.length)]);
            if (rand.nextInt(10) < 2)
                sb.append(STD_SUBS[rand.nextInt(STD_SUBS.length)]);

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
        if (args == 0)
            sb.append("v");
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
            if (rand.nextBoolean())
                fp.append(randomType(rand, depth + 1));
            fp.append("E");
            return fp.toString();
        } else if (choice < 90) {
            StringBuilder t = new StringBuilder();
            t.append("I");
            int count = 1 + rand.nextInt(3);
            for (int i = 0; i < count; i++)
                t.append(randomType(rand, depth + 1));
            t.append("E");
            return t.toString();
        } else {
            if (rand.nextBoolean())
                return "Dt" + randomType(rand, depth + 1) + "E";
            return "S" + (rand.nextBoolean() ? "_" : "0_");
        }
    }
}
