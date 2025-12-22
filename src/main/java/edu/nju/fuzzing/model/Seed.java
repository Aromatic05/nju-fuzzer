package edu.nju.fuzzing.model;

import java.io.File;
import java.util.Arrays;

/**
 * 种子：存储在队列中、有价值的输入。
 */
public class Seed {

    // --- 1. 基础信息 ---
    private final File file;       // 磁盘上的物理文件
    private final byte[] data;     // 内存中的数据缓存
    private final String id;       // 唯一标识 (通常是文件名)

    // --- 2. 血缘信息 (Lineage) ---
    private final String parentId; // 父种子的 ID (用于追溯)
    private final int depth;       // 变异深度 (初始=0, 每一代+1)
    private final String birthType;// 出生方式 (例如 "INITIAL" 或 "havoc")

    // --- 3. 动态调度指标 (Mutable) ---
    private long executionTime;    // 执行耗时 (ns)
    private int bitmapSize;        // 覆盖率大小
    private boolean wasFuzzed;     // 是否已被调度过
    private int handicap;          // 调度权重 (新手保护)

    /**
     * 构造函数 A: 用于加载初始种子 (从文件夹加载)
     * 此时没有 Parent，没有 Testcase
     */
    public Seed(File file, byte[] data) {
        this.file = file;
        this.data = data; // 初始加载通常不需要 copy，因为读取出来就是新的
        this.id = file.getName();
        
        // 初始属性
        this.parentId = null;
        this.depth = 0;
        this.birthType = "INITIAL";
        
        // 调度属性初始化
        this.wasFuzzed = false;
        this.handicap = 8;
    }

    /**
     * 构造函数 B: 用于从 Testcase 晋升 (Promotion)
     * 这是你最需要的：根据 Testcase 构造完整 Seed
     * 
     * @param file     已经保存到磁盘的文件对象 (由 CorpusManager 生成)
     * @param testcase 触发新路径的测试用例
     */
    public Seed(File file, Testcase testcase) {
        this.file = file;
        this.id = file.getName();
        
        // 1. 数据拷贝
        // 必须深拷贝，因为 Testcase 里的 byte[] 可能会被 Mutator 复用
        this.data = testcase.getDataCopy();

        // 2. 继承血缘 (关键逻辑)
        Seed parent = testcase.parent();
        if (parent != null) {
            this.parentId = parent.getId();
            this.depth = parent.getDepth() + 1; // 深度 +1
        } else {
            // 理论上 Testcase 都有 parent，防止空指针做个保底
            this.parentId = null;
            this.depth = 0;
        }

        // 3. 记录出生信息
        this.birthType = testcase.description();

        // 4. 调度属性初始化
        this.wasFuzzed = false;
        this.handicap = 8; // 新种子给予高权重
        this.executionTime = 0; // 等待外部 update
        this.bitmapSize = 0;    // 等待外部 update
    }

    // --- 业务方法 ---

    // 降低 handicap (每次 Fuzz 完调用)
    public void decreaseHandicap() {
        if (this.handicap > 1) this.handicap--;
    }

    // 标记已测试
    public void markAsFuzzed() {
        this.wasFuzzed = true;
    }

    // 封装无符号字节读取 (工具方法)
    public int getUnsignedByte(int index) {
        if (index < 0 || index >= data.length) return 0;
        return Byte.toUnsignedInt(data[index]);
    }

    // --- Getters & Setters ---
    public File getFile() { return file; }
    public byte[] getData() { return data; }
    public String getId() { return id; }
    public int getDepth() { return depth; }
    public String getParentId() { return parentId; }
    public boolean isWasFuzzed() { return wasFuzzed; }
    public int getHandicap() { return handicap; }
    public long getExecutionTime() { return executionTime; }
    public void setExecutionTime(long t) { this.executionTime = t; }
    public int getBitmapSize() { return bitmapSize; }
    public void setBitmapSize(int s) { this.bitmapSize = s; }
    
    @Override
    public String toString() {
        return String.format("Seed[id=%s, depth=%d, score=%d]", id, depth, bitmapSize);
    }
}