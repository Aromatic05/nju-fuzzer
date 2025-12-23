package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 增强型 C++ Mangled Name 变异器
 * 覆盖更多 Itanium C++ ABI 特性 (Operators, Ctors, Arrays, Lambdas)
 * 并增强了针对性的 Crash 模式。
 */
public class CxxMutator implements Mutator {

    // 扩展基础类型
    private static final String[] BASE_TYPES = {
            "v", "w", "b", "c", "a", "h", "s", "t", // void, wchar, bool, char, s-char, u-char, short, u-short
            "i", "j", "l", "m", "x", "y", "n", "o", // int, u-int, long, u-long, long long, u-long long, __int128...
            "f", "d", "e", "g", "z",                // float, double, long double, float128...
            "Da", "Dc", "Dn", "Di", "Ds"            // auto, decltype(auto), std::nullptr_t, char32_t, char16_t
    };

    // 扩展修饰符
    private static final String[] MODIFIERS = {"P", "R", "O", "K", "V", "r"}; // Pointer, Ref, R-Ref, Const, Volatile, Restrict

    // 操作符编码 (部分)
    private static final String[] OPERATORS = {
            "nw", "na", "dl", "da", // new, new[], delete, delete[]
            "ps", "ng", "ad", "de", // +, -, &, * (unary)
            "co", "nt", "l_n",      // ~, !, ! (logic)
            "pl", "mi", "ml", "dv", "rm", "an", "or", "eo", // +, -, *, /, %, &, |, ^
            "aS", "pL", "mI",       // =, +=, -=
            "eq", "ne", "lt", "gt", // ==, !=, <, >
            "cl", "ix", "qu"        // (), [], ?
    };

    // 特殊替换简写 (Standard Substitutions)
    private static final String[] STD_SUBS = {"St", "Sa", "Sb", "Ss", "Si", "So", "Sd"};

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

                // 可以在这里决定是 "Generate" 还是 "Mutate Existing Seed"
                // 目前保持 Generate 模式
                String mangle = generateMangledName();
                return new Testcase(
                        mangle.getBytes(StandardCharsets.ISO_8859_1),
                        seed,
                        "grammar:AdvancedCXX"
                );
            }
        };
    }

    private String generateMangledName() {
        StringBuilder sb = new StringBuilder(256);
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        sb.append("_Z");

        int strategy = rand.nextInt(100);

        if (strategy < 5) {
            // [5%] Integer Overflow / Big Allocation
            sb.append(rand.nextBoolean() ? "2147483647" : "99999999999999999");
            sb.append("function");
        }
        else if (strategy < 10) {
            // [5%] Deep Recursion (Stack Overflow)
            sb.append("4main");
            int depth = 1000 + rand.nextInt(4000);
            // 混合使用指针和数组，增加解析难度
            for (int i = 0; i < depth; i++) {
                if (rand.nextBoolean()) sb.append("P");
                else sb.append("A").append(rand.nextInt(10)).append("_");
            }
            sb.append("i");
        }
        else if (strategy < 20) {
            // [10%] Circular/Invalid Substitution (Logic Bomb/OOB)
            sb.append("3foo");
            // 尝试引用自身或尚未定义的替换
            // S_ 是第一个组件, S0_ 是第二个...
            sb.append("S");
            if (rand.nextBoolean()) {
                sb.append("_"); // 引用第一个组件（即 3foo），形成递归类型？
            } else {
                sb.append(rand.nextInt(2048)).append("_"); // 尝试越界
            }
        }
        else if (strategy < 35) {
            // [15%] Template Bomb (DoS)
            sb.append("4func");
            int depth = 20 + rand.nextInt(50);
            for (int i = 0; i < depth; i++) {
                sb.append("I");
                // 可以在模板参数中插入 lambda 或更复杂的类型
                if (i % 5 == 0) sb.append("UlT_E_"); // Lambda syntax
                else sb.append(randomType(rand, 0));
            }
            // 随机闭合，测试错误处理
            int closeCount = depth + (rand.nextInt(10) - 5);
            for (int i = 0; i < Math.max(0, closeCount); i++) sb.append("E");
        }
        else {
            // [65%] Valid/Semi-Valid Complex Structure
            generateComplexSignature(sb, rand);
        }

        return sb.toString();
    }

    private void generateComplexSignature(StringBuilder sb, ThreadLocalRandom rand) {
        // 1. Name Scope (Namespace / Class / Special)
        if (rand.nextBoolean()) {
            // Nested Name: N...E
            sb.append("N");

            // 随机插入 CV-qualifiers 在名字前 (member function const/volatile)
            if (rand.nextInt(10) < 3) sb.append(MODIFIERS[rand.nextInt(MODIFIERS.length)]);

            // 可能是标准库前缀
            if (rand.nextInt(10) < 2) sb.append(STD_SUBS[rand.nextInt(STD_SUBS.length)]);

            int parts = 1 + rand.nextInt(4);
            for (int i = 0; i < parts; i++) {
                if (rand.nextInt(10) < 2) {
                    // Operator Name
                    sb.append(OPERATORS[rand.nextInt(OPERATORS.length)]);
                } else if (rand.nextInt(10) < 2) {
                    // Ctor/Dtor
                    String ctor = (rand.nextBoolean() ? "C" : "D") + rand.nextInt(4); // C1, C2... D0...
                    sb.append(ctor);
                } else {
                    // Normal identifier
                    String part = "ns" + rand.nextInt(100);
                    sb.append(part.length()).append(part);
                }

                // 偶尔插入模板参数到名字中 (Class Template)
                if (rand.nextBoolean()) {
                    sb.append("I");
                    sb.append(randomType(rand, 0));
                    sb.append("E");
                }
            }
            sb.append("E");
        } else {
            // Simple Function or Data
            String name = "func";
            sb.append(name.length()).append(name);
        }

        // 2. Function Arguments
        // 多数解析器在解析完名字后，期待类型列表
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
            // Basic Type
            return BASE_TYPES[rand.nextInt(BASE_TYPES.length)];
        }
        else if (choice < 50) {
            // Modifier (Pointer, Ref, etc.)
            return MODIFIERS[rand.nextInt(MODIFIERS.length)] + randomType(rand, depth + 1);
        }
        else if (choice < 65) {
            // Array Type: A<num>_<type>
            String dim = rand.nextBoolean() ? String.valueOf(rand.nextInt(100)) : ""; // 空维度也是合法的 A_i
            return "A" + dim + "_" + randomType(rand, depth + 1);
        }
        else if (choice < 75) {
            // Function Pointer: P F <return> <args...> E
            StringBuilder fp = new StringBuilder();
            fp.append("PF");
            fp.append(randomType(rand, depth + 1)); // return type
            fp.append(randomType(rand, depth + 1)); // arg1
            if (rand.nextBoolean()) fp.append(randomType(rand, depth + 1)); // arg2
            fp.append("E");
            return fp.toString();
        }
        else if (choice < 90) {
            // Template: I <types...> E
            StringBuilder t = new StringBuilder();
            t.append("I");
            int count = 1 + rand.nextInt(3);
            for(int i=0; i<count; i++) t.append(randomType(rand, depth + 1));
            t.append("E");
            return t.toString();
        }
        else {
            // Decltype / Substitution / Vendor Extended
            if (rand.nextBoolean()) return "Dt" + randomType(rand, depth + 1) + "E"; // decltype
            return "S" + (rand.nextBoolean() ? "_" : "0_"); // Simple substitution
        }
    }
}