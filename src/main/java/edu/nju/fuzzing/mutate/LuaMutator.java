package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.grammar.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 语法感知 Lua 脚本变异器
 *
 * 核心改进：
 * 1. 使用种子内容进行变异
 * 2. 容错分词 -> 树构建 -> 语法感知变异 -> 序列化
 * 3. 针对 Lua 特有结构进行变异（关键字、运算符、字符串等）
 */
public class LuaMutator implements Mutator {

    private static final int MAX_DEPTH = 15;
    private static final String[] VARS = {"a", "b", "c", "t", "u", "f", "co", "m"};

    private static final String[] ATTACK_PAYLOADS = {
            "string.find(string.rep('a', 10000), string.rep('a?', 10000) .. 'a')",
            "local a = function() return 1 end; local b = function() return 2 end; debug.upvaluejoin(a, 1, b, 1)",
            "local t = {}; setmetatable(t, {__gc = function(o) setmetatable(o, getmetatable(o)) end}); t = nil; collectgarbage()",
            "local t = {}; for i=1,100 do t[#t+1]=1 end; t[2147483647] = 1; print(#t)",
            "load(string.dump(function() print('test') end))()"
    };

    private static final String[] INJECTION_PAYLOADS = {
            "\\0",
            "%s%s%s%s",
            "../../../etc/passwd",
            "$(id)",
            "`id`",
            "'; DROP TABLE users; --",
            "\\x00\\x01\\x02",
    };

    private static final String[][] KEYWORD_REPLACEMENTS = {
            {"local", ""},
            {"local", "global"},
            {"function", "func"},
            {"end", ""},
            {"then", ""},
            {"do", ""},
            {"==", "="},
            {"~=", "!="},
            {"and", "&"},
            {"or", "|"},
            {"not", "!"},
    };

    private final LuaTokenizer tokenizer = new LuaTokenizer();

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

                if (strategy < 5) {
                    mutatedBytes = ATTACK_PAYLOADS[rand.nextInt(ATTACK_PAYLOADS.length)]
                            .getBytes(StandardCharsets.UTF_8);
                    desc = "Lua:Payload";
                } else if (strategy < 10) {
                    mutatedBytes = createDeepNesting(seedData, rand);
                    desc = "Lua:DeepNest";
                } else if (seedData == null || seedData.length == 0) {
                    mutatedBytes = generateChunk(rand).getBytes(StandardCharsets.UTF_8);
                    desc = "Lua:Gen";
                } else {
                    mutatedBytes = mutateWithGrammar(seedData, rand);
                    desc = "Lua:GrammarMut";
                }

                return new Testcase(mutatedBytes, seed, "grammar:" + desc);
            }
        };
    }

    private byte[] mutateWithGrammar(byte[] seedData, ThreadLocalRandom rand) {
        List<Token> tokens = tokenizer.tokenize(seedData);
        if (tokens.isEmpty()) {
            return generateChunk(rand).getBytes(StandardCharsets.UTF_8);
        }

        TokenNode tree = tokenizer.buildTree(tokens);

        int mutationCount = 1 + rand.nextInt(3);
        for (int i = 0; i < mutationCount; i++) {
            int mutationType = rand.nextInt(10);
            
            switch (mutationType) {
                case 0:
                    replaceKeywords(tree, rand);
                    break;
                case 1:
                    mutateOperators(tree, rand);
                    break;
                case 2:
                    mutateStrings(tree, rand);
                    break;
                case 3:
                    MutationStrategy.mutateNumbers(tree, rand);
                    break;
                case 4:
                    MutationStrategy.deleteNodes(tree, 0.1, rand);
                    break;
                case 5:
                    MutationStrategy.swapNodes(tree, rand);
                    break;
                case 6:
                    MutationStrategy.duplicateSubtree(tree, 1 + rand.nextInt(3), rand);
                    break;
                case 7:
                    insertRandomStatement(tree, rand);
                    break;
                case 8:
                    mutateIdentifiers(tree, rand);
                    break;
                default:
                    injectGarbageCollection(tree, rand);
                    break;
            }
        }

        String result;
        if (rand.nextInt(20) == 0) {
            result = tree.serializeWithMissingClose(rand, 0.2);
        } else {
            result = tree.serialize();
        }

        return result.getBytes(StandardCharsets.UTF_8);
    }

    private void replaceKeywords(TokenNode tree, ThreadLocalRandom rand) {
        List<TokenNode> leaves = tree.collectLeaves();
        for (TokenNode leaf : leaves) {
            if (leaf.getToken() == null) continue;
            Token token = leaf.getToken();
            
            if (token.getType() == Token.Type.KEYWORD || token.getType() == Token.Type.OPERATOR) {
                for (String[] pair : KEYWORD_REPLACEMENTS) {
                    if (pair[0].equals(token.getValue()) && rand.nextInt(4) == 0) {
                        replaceTokenValue(leaf, pair[1]);
                        break;
                    }
                }
            }
        }
    }

    private void mutateOperators(TokenNode tree, ThreadLocalRandom rand) {
        String[] operators = {"+", "-", "*", "/", "%", "^", "..", "==", "~=", "<", ">", "<=", ">=", "and", "or", "not", "//", "&", "|", "~", "<<", ">>"};
        
        List<TokenNode> leaves = tree.collectLeaves();
        for (TokenNode leaf : leaves) {
            if (leaf.getToken() != null && leaf.getToken().getType() == Token.Type.OPERATOR) {
                if (rand.nextInt(5) == 0) {
                    String newOp = operators[rand.nextInt(operators.length)];
                    replaceTokenValue(leaf, newOp);
                }
            }
        }
    }

    private void mutateStrings(TokenNode tree, ThreadLocalRandom rand) {
        List<TokenNode> leaves = tree.collectLeaves();
        for (TokenNode leaf : leaves) {
            if (leaf.getToken() != null && leaf.getToken().getType() == Token.Type.STRING) {
                if (rand.nextInt(4) == 0) {
                    String original = leaf.getToken().getValue();
                    String mutated = mutateStringValue(original, rand);
                    replaceTokenValue(leaf, mutated);
                }
            }
        }
    }

    private String mutateStringValue(String original, ThreadLocalRandom rand) {
        if (original.length() < 2) return original;
        
        int op = rand.nextInt(6);
        char quote = original.charAt(0);
        String inner = original.length() > 2 ? original.substring(1, original.length() - 1) : "";
        
        switch (op) {
            case 0:
                return original.substring(1, original.length() - 1);
            case 1:
                String payload = INJECTION_PAYLOADS[rand.nextInt(INJECTION_PAYLOADS.length)];
                return quote + inner + payload + quote;
            case 2:
                return quote + inner.repeat(10 + rand.nextInt(100)) + quote;
            case 3:
                return quote + "%" + "b()[a-z]*" + quote;
            case 4:
                return "[[" + inner + "]]";
            default:
                return quote + "\\0\\1\\2\\3" + inner + quote;
        }
    }

    private void mutateIdentifiers(TokenNode tree, ThreadLocalRandom rand) {
        List<TokenNode> leaves = tree.collectLeaves();
        for (TokenNode leaf : leaves) {
            if (leaf.getToken() != null && leaf.getToken().getType() == Token.Type.IDENTIFIER) {
                if (rand.nextInt(5) == 0) {
                    String newVar = VARS[rand.nextInt(VARS.length)];
                    replaceTokenValue(leaf, newVar);
                }
            }
        }
    }

    private void insertRandomStatement(TokenNode tree, ThreadLocalRandom rand) {
        String[] statements = {
                "collectgarbage()",
                "debug.getregistry()",
                "pcall(error, 'fuzz')",
                "coroutine.yield()",
                "setmetatable({}, {__gc = function() end})",
                "rawset(_G, 'fuzz', nil)",
                "goto fuzz_label ::fuzz_label::",
        };
        
        Token newToken = new Token(Token.Type.IDENTIFIER, statements[rand.nextInt(statements.length)] + "; ");
        List<TokenNode> children = tree.getChildren();
        if (!children.isEmpty()) {
            int pos = rand.nextInt(children.size());
            tree.insertChild(pos, TokenNode.createLeaf(newToken));
        }
    }

    private void injectGarbageCollection(TokenNode tree, ThreadLocalRandom rand) {
        Token gcToken = new Token(Token.Type.IDENTIFIER, "; collectgarbage(); ");
        List<TokenNode> children = tree.getChildren();
        if (!children.isEmpty()) {
            int count = 1 + rand.nextInt(3);
            for (int i = 0; i < count && !children.isEmpty(); i++) {
                int pos = rand.nextInt(children.size());
                tree.insertChild(pos, TokenNode.createLeaf(gcToken));
            }
        }
    }

    private void replaceTokenValue(TokenNode leaf, String newValue) {
        Token newToken = leaf.getToken().withValue(newValue);
        TokenNode parent = leaf.getParent();
        if (parent != null) {
            int idx = parent.getChildren().indexOf(leaf);
            if (idx >= 0) {
                parent.replaceChild(idx, TokenNode.createLeaf(newToken));
            }
        }
    }

    private byte[] createDeepNesting(byte[] seedData, ThreadLocalRandom rand) {
        StringBuilder sb = new StringBuilder();
        int depth = 50 + rand.nextInt(100);
        
        for (int i = 0; i < depth; i++) {
            sb.append("do ");
        }
        
        if (seedData != null && seedData.length > 0) {
            sb.append(new String(seedData, StandardCharsets.UTF_8));
        } else {
            sb.append("local x = 1");
        }
        
        for (int i = 0; i < depth; i++) {
            sb.append(" end");
        }
        
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private String generateChunk(ThreadLocalRandom rand) {
        StringBuilder sb = new StringBuilder();
        sb.append("do\n");
        int lines = 5 + rand.nextInt(15);
        for (int i = 0; i < lines; i++) {
            sb.append(generateStat(0, rand)).append("\n");
            if (rand.nextInt(20) == 0) sb.append("collectgarbage();\n");
        }
        sb.append("end");
        return sb.toString();
    }

    private String generateStat(int depth, ThreadLocalRandom rand) {
        if (depth > MAX_DEPTH) return "do return end";

        int type = rand.nextInt(100);

        if (type < 25) {
            return "local " + pickVar(rand) + " = " + generateExpr(depth, rand);
        } else if (type < 45) {
            return pickVar(rand) + " = " + generateExpr(depth, rand);
        } else if (type < 55) {
            return generateFuncCall(depth, rand);
        } else if (type < 65) {
            return "if " + generateExpr(depth, rand) + " then " + generateStat(depth + 1, rand) + " end";
        } else if (type < 75) {
            return "for i = 1, " + (rand.nextInt(100)+1) + " do " + generateStat(depth + 1, rand) + " end";
        } else if (type < 85) {
            return "function " + pickVar(rand) + "() " + generateStat(depth + 1, rand) + " end";
        } else {
            return generateComplexStat(rand);
        }
    }

    private String generateExpr(int depth, ThreadLocalRandom rand) {
        if (depth > MAX_DEPTH) return "nil";

        int type = rand.nextInt(100);
        if (type < 30) return generatePrimitive(rand);
        if (type < 55) return pickVar(rand);
        if (type < 70) return generateTable(depth + 1, rand);
        if (type < 90) {
            String op = pickOp(rand);
            return "(" + generateExpr(depth + 1, rand) + " " + op + " " + generateExpr(depth + 1, rand) + ")";
        }
        return "function() return " + generateExpr(depth + 1, rand) + " end";
    }

    private String generateTable(int depth, ThreadLocalRandom rand) {
        StringBuilder sb = new StringBuilder("{");
        int size = rand.nextInt(6);
        for (int i = 0; i < size; i++) {
            if (i > 0) sb.append(", ");
            if (rand.nextBoolean()) {
                sb.append(generateExpr(depth + 1, rand));
            } else {
                sb.append("[").append(generateExpr(depth + 1, rand)).append("]=").append(generateExpr(depth + 1, rand));
            }
        }
        sb.append("}");
        return sb.toString();
    }

    private String generateComplexStat(ThreadLocalRandom rand) {
        int r = rand.nextInt(5);
        String v = pickVar(rand);

        if (r == 0) {
            return "setmetatable(" + v + ", { __index = " + pickVar(rand) + ", __gc = function(o) collectgarbage() end, __mode = 'kv' })";
        } else if (r == 1) {
            return "pcall(debug.setuservalue, " + v + ", " + pickVar(rand) + ")";
        } else if (r == 2) {
            return "coroutine.resume(coroutine.create(function(x) " + pickVar(rand) + "(x) end), " + pickVar(rand) + ")";
        } else if (r == 3) {
            return "::lbl::; if " + pickVar(rand) + " then goto lbl end";
        } else {
            return "pcall(load, string.dump(" + v + "))";
        }
    }

    private String generateFuncCall(int depth, ThreadLocalRandom rand) {
        String[] funcs = {
                "print", "tostring", "tonumber", "type", "assert",
                "table.insert", "table.remove", "table.concat", "table.sort",
                "string.rep", "string.reverse", "string.lower", "string.format",
                "math.sin", "math.random", "math.tointeger",
                "coroutine.create", "coroutine.status",
                "debug.getregistry", "collectgarbage"
        };
        String func = funcs[rand.nextInt(funcs.length)];
        if (func.equals("string.format")) {
            return "string.format('%s %d %f', " + pickVar(rand) + ", " + pickVar(rand) + ", " + pickVar(rand) + ")";
        }
        return func + "(" + generateExpr(depth + 1, rand) + ")";
    }

    private String pickVar(ThreadLocalRandom rand) {
        return VARS[rand.nextInt(VARS.length)];
    }

    private String pickOp(ThreadLocalRandom rand) {
        String[] ops = {"+", "-", "*", "/", "%", "^", "..", "==", "~=", "<", "<=", ">", ">=", "and", "or", "//", "&", "|", "~", "<<", ">>"};
        return ops[rand.nextInt(ops.length)];
    }

    private String generatePrimitive(ThreadLocalRandom rand) {
        int r = rand.nextInt(7);
        switch (r) {
            case 0: return String.valueOf(rand.nextInt(100));
            case 1: return String.valueOf(rand.nextInt());
            case 2: return String.valueOf(rand.nextDouble());
            case 3: return "0x" + Integer.toHexString(rand.nextInt());
            case 4: return rand.nextBoolean() ? "true" : "false";
            case 5: return "nil";
            case 6:
                if (rand.nextBoolean()) return "'" + "A".repeat(rand.nextInt(50)) + "'";
                return "'%" + (rand.nextBoolean() ? "b" : "f") + "[a-z]'";
            default: return "0";
        }
    }
}
