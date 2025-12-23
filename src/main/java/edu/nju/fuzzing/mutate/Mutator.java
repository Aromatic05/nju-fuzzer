package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import java.util.Iterator;

public interface Mutator {
    /**
     * 返回一个变异迭代器，支持惰性生成测试用例
     */
    Iterator<Testcase> mutate(Seed seed, int energy);
}