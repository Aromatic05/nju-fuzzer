package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 增强型 Lua 脚本变异器
 *
 * 改进点：
 * 1. 作用域模拟：优先定义变量再使用，减少无效的 nil error。
 * 2. 危险库覆盖：引入 debug.*, package.*, io.* 测试 VM 边界。
 * 3. 现代 Lua 特性：支持位运算 (5.3+), goto, label。
 * 4. GC 攻击：在元方法和循环中强制 GC，诱发 Use-After-Free。
 * 5. 模式匹配 Fuzzing：针对 Lua 特有的正则引擎生成复杂 Pattern。
 */
public class LuaMutator implements Mutator {

    private static final int MAX_DEPTH = 15; // 稍微降低深度，避免 Stack Overflow 被过早捕获

    // 常用变量名
    private static final String[] VARS = {"a", "b", "c", "t", "u", "f", "co", "m"};

    // 危险的攻击载荷
    private static final String[] ATTACK_PAYLOADS = {
            // [Attack] String Pattern ReDoS / Crash
            "string.find(string.rep('a', 10000), string.rep('a?', 10000) .. 'a')",

            // [Attack] Debug Library Upvalue Join (VM State Corruption)
            "local a = function() return 1 end; local b = function() return 2 end; debug.upvaluejoin(a, 1, b, 1)",

            // [Attack] Recursive __gc (Finalizer Loop)
            "local t = {}; setmetatable(t, {__gc = function(o) setmetatable(o, getmetatable(o)) end}); t = nil; collectgarbage()",

            // [Attack] Table length integer overflow
            "local t = {}; for i=1,100 do t[#t+1]=1 end; t[2147483647] = 1; print(#t)",

            // [Attack] Bytecode loading (if enabled)
            "load(string.dump(function() print('test') end))()"
    };

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
                String luaCode;

                if (rand.nextInt(100) < 5) { // 5% Payload
                    luaCode = ATTACK_PAYLOADS[rand.nextInt(ATTACK_PAYLOADS.length)];
                } else {
                    luaCode = generateChunk(rand);
                }

                return new Testcase(
                        luaCode.getBytes(StandardCharsets.ISO_8859_1),
                        seed,
                        "grammar:AdvancedLua"
                );
            }
        };
    }

    // ==========================================
    // 核心生成逻辑
    // ==========================================

    private String generateChunk(ThreadLocalRandom rand) {
        StringBuilder sb = new StringBuilder();
        // 增加 do...end 块，限制局部变量作用域
        sb.append("do\n");
        int lines = 5 + rand.nextInt(15);
        for (int i = 0; i < lines; i++) {
            sb.append(generateStat(0, rand)).append("\n");
            // 偶尔插入 GC 调用，测试 UAF
            if (rand.nextInt(20) == 0) sb.append("collectgarbage();\n");
        }
        sb.append("end");
        return sb.toString();
    }

    private String generateStat(int depth, ThreadLocalRandom rand) {
        if (depth > MAX_DEPTH) return "do return end";

        int type = rand.nextInt(100);

        if (type < 25) {
            // 定义局部变量 (提高生成概率，确保后续有变量可用)
            return "local " + pickVar(rand) + " = " + generateExpr(depth, rand);
        } else if (type < 45) {
            // 赋值
            return pickVar(rand) + " = " + generateExpr(depth, rand);
        } else if (type < 55) {
            // 函数调用
            return generateFuncCall(depth, rand);
        } else if (type < 65) {
            // 控制流
            return "if " + generateExpr(depth, rand) + " then " + generateStat(depth + 1, rand) + " end";
        } else if (type < 75) {
            // 循环 (Numeric For Loop 更容易触发 JIT 优化)
            return "for i = 1, " + (rand.nextInt(100)+1) + " do " + generateStat(depth + 1, rand) + " end";
        } else if (type < 85) {
            // 函数定义
            return "function " + pickVar(rand) + "() " + generateStat(depth + 1, rand) + " end";
        } else {
            // 高级特性 (Metatable, Debug, Coroutine)
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
            // 运算符
            String op = pickOp(rand);
            return "(" + generateExpr(depth + 1, rand) + " " + op + " " + generateExpr(depth + 1, rand) + ")";
        }
        // 匿名函数
        return "function() return " + generateExpr(depth + 1, rand) + " end";
    }

    // ==========================================
    // 复杂特性生成 (攻击重点)
    // ==========================================

    private String generateTable(int depth, ThreadLocalRandom rand) {
        StringBuilder sb = new StringBuilder("{");
        int size = rand.nextInt(6);
        for (int i = 0; i < size; i++) {
            if (i > 0) sb.append(", ");
            // 混合 Key 类型 (Int, String, Object)
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
            // [Metatable] 包含危险的元方法 (__gc, __mode)
            return "setmetatable(" + v + ", { " +
                    "__index = " + pickVar(rand) + ", " +
                    "__gc = function(o) collectgarbage() end, " + // GC in GC
                    "__mode = 'kv' " + // Weak table
                    "})";
        } else if (r == 1) {
            // [Debug Library] 操纵 Upvalue 或 Userdata
            // 这通常是沙箱逃逸或崩溃的源头
            return "pcall(debug.setuservalue, " + v + ", " + pickVar(rand) + ")";
        } else if (r == 2) {
            // [Coroutine] 恢复并传参
            return "coroutine.resume(coroutine.create(function(x) " + pickVar(rand) + "(x) end), " + pickVar(rand) + ")";
        } else if (r == 3) {
            // [Goto] 随机跳转 (Lua 5.2+)
            return "::lbl::; if " + pickVar(rand) + " then goto lbl end";
        } else {
            // [String Dump] 尝试加载
            return "pcall(load, string.dump(" + v + "))";
        }
    }

    private String generateFuncCall(int depth, ThreadLocalRandom rand) {
        // 扩展了危险函数列表
        String[] funcs = {
                "print", "tostring", "tonumber", "type", "assert",
                "table.insert", "table.remove", "table.concat", "table.sort",
                "string.rep", "string.reverse", "string.lower", "string.format",
                "math.sin", "math.random", "math.tointeger",
                "coroutine.create", "coroutine.status",
                "debug.getregistry", "collectgarbage"
        };

        String func = funcs[rand.nextInt(funcs.length)];

        // string.format 也是一个很好的 fuzz 点
        if (func.equals("string.format")) {
            return "string.format('%s %d %f', " + pickVar(rand) + ", " + pickVar(rand) + ", " + pickVar(rand) + ")";
        }

        return func + "(" + generateExpr(depth + 1, rand) + ")";
    }

    // ==========================================
    // 基础组件
    // ==========================================

    private String pickVar(ThreadLocalRandom rand) {
        return VARS[rand.nextInt(VARS.length)];
    }

    private String pickOp(ThreadLocalRandom rand) {
        // 包含 Lua 5.3 的位运算符和整除
        String[] ops = {
                "+", "-", "*", "/", "%", "^", "..", // Arith
                "==", "~=", "<", "<=", ">", ">=",   // Cmp
                "and", "or",                        // Logic
                "//", "&", "|", "~", "<<", ">>"     // Bitwise (5.3+)
        };
        return ops[rand.nextInt(ops.length)];
    }

    private String generatePrimitive(ThreadLocalRandom rand) {
        int r = rand.nextInt(7);
        switch (r) {
            case 0: return String.valueOf(rand.nextInt(100)); // Small Int
            case 1: return String.valueOf(rand.nextInt()); // Large Int
            case 2: return String.valueOf(rand.nextDouble()); // Float
            case 3: return "0x" + Integer.toHexString(rand.nextInt()); // Hex
            case 4: return rand.nextBoolean() ? "true" : "false";
            case 5: return "nil";
            case 6: // String with patterns
                if (rand.nextBoolean()) return "'" + "A".repeat(rand.nextInt(50)) + "'";
                // 生成可能引发 Pattern 引擎崩溃的特殊字符
                return "'%" + (rand.nextBoolean() ? "b" : "f") + "[a-z]'";
            default: return "0";
        }
    }
}