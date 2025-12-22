package edu.nju.fuzzing.model;


import java.util.Arrays;

/**
 * 变异产生的临时测试用例。
 * 如果它触发了新路径，会被“晋升”为 Seed；否则会被 GC 回收。
 */
public record Testcase(
    // 1. 具体的样例内容 (Payload)
    // 这是 Executor 需要执行的数据
    byte[] data,

    // 2. 引用父 Seed
    // 必须引用，因为我们需要读取 Parent 的 depth 来计算 Child 的 depth
    Seed parent,

    // 3. 样例类型/变异描述 (Mutation Description)
    // 用于调试或分析，例如 "bitflip 2", "havoc", "splice"
    String description
) {
    /**
     * 获取数据的副本 (防御性拷贝)
     * 防止外部修改 Testcase 内部的数据，保证安全性
     */
    public byte[] getDataCopy() {
        return Arrays.copyOf(data, data.length);
    }
    
    // 原始数据访问 (如果不担心修改，为了性能可以直接用这个)
    public byte[] data() {
        return data;
    }
}
