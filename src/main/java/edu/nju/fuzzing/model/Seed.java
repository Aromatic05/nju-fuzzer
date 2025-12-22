package edu.nju.fuzzing.model;

import java.io.File;

public class Seed {
    private final File file;
    private final byte[] data;
    private long executionTime; // 执行时间（纳秒）
    private int bitmapSize;     // 覆盖率大小

    public Seed(File file, byte[] data) {
        this.file = file;
        this.data = data;
        this.executionTime = 0;
        this.bitmapSize = 0;
    }

    // 用来更新meta信息
    public void setExecutionTime(long executionTime) { this.executionTime = executionTime; }
    public void setBitmapSize(int bitmapSize) { this.bitmapSize = bitmapSize; }

    // 获取信息的方法
    public File getFile() { return file; } // 返回文件对象
    public byte[] getData() { return data; } // 返回数据内容
    public long getExecutionTime() { return executionTime; }  // 返回执行时间
    public int getBitmapSize() { return bitmapSize; } // 返回覆盖率大小
    public int size() { // 返回数据长度
        return data.length;
    }
    public int getUnsignedByte(int index) { // 返回指定索引处的无符号字节值
        if (index < 0 || index >= data.length) return 0;
        return Byte.toUnsignedInt(data[index]);
    }
    
    // toString 便于调试
    @Override
    public String toString() {
        return "Seed{file=" + file.getName() + ", score=" + bitmapSize + "}";
    }
}