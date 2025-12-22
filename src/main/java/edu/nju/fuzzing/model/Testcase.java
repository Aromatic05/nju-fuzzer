package edu.nju.fuzzing.model;

import java.util.Arrays;

/**
 * Testcase (DTO)
 * 纯粹的数据载体，不包含 IO 逻辑。
 */
public record Testcase(
        byte[] data,        // 核心数据
        Seed parent,        // 父节点引用
        String description  // 变异描述
) {
    // 唯一的逻辑只是为了保护数据的安全性
    public byte[] getDataCopy() {
        return Arrays.copyOf(data, data.length);
    }

    // 如果你很在意性能，且能保证外部不修改，可以直接用 record 自带的 data()
}