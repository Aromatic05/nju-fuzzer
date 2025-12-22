package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import java.util.List;

public interface Mutator {
    /**
     * 根据能量预算对种子进行变异
     * @param seed 原始种子
     * @param energy 预算生成的测试用例数量
     * @return 变异后的测试用例列表
     */
    List<Testcase> mutate(Seed seed, int energy);
}