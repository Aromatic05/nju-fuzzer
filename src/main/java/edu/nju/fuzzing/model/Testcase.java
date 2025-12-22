package edu.nju.fuzzing.model;

import java.io.*;
import java.util.Arrays;

public record Testcase(
        byte[] data,
        Seed parent,
        String description
) {
    public byte[] getDataCopy() {
        return Arrays.copyOf(data, data.length);
    }

    // 必须有这个！否则 C 程序读不到数据
    public void saveToFile(File targetFile) throws IOException {
        // 使用 BufferedOutputStream 减少 IO 系统调用开销
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(targetFile))) {
            bos.write(data);
        } // try-with-resources 会自动 flush 和 close
    }
}