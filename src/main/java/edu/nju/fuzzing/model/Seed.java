package edu.nju.fuzzing.model;

import java.util.Arrays;
import java.io.*;
import java.nio.file.Path;
import java.util.Properties;

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


    public void saveMetadata() {
        // 元数据文件名：原文件名 + ".meta"
        File parentDir = file.getParentFile();
        File metaFile = (parentDir != null)
            ? new File(parentDir, file.getName() + ".meta")
            : new File(file.getName() + ".meta");
        
        Properties props = new Properties();
        
        // 1. 存血缘信息
        if (parentId != null) props.setProperty("parent_id", parentId);
        props.setProperty("depth", String.valueOf(depth));
        if (birthType != null) props.setProperty("birth_type", birthType);
        
        // 2. 存调度信息
        props.setProperty("handicap", String.valueOf(handicap));
        props.setProperty("was_fuzzed", String.valueOf(wasFuzzed));
        
        // 3. 存性能指标
        props.setProperty("exec_time", String.valueOf(executionTime));
        props.setProperty("bitmap_size", String.valueOf(bitmapSize));

        // 写入硬盘
        try (FileOutputStream out = new FileOutputStream(metaFile)) {
            props.store(out, "Seed Metadata");
        } catch (IOException e) {
            System.err.println("Failed to save metadata for seed: " + id);
            e.printStackTrace();
        }
    }

    /**
     * 静态工厂方法：尝试加载元数据并创建 Seed
     * 如果 .meta 文件不存在（比如用户提供的初始种子），则使用默认值
     */
    public static Seed loadWithMetadata(File seedFile, byte[] data) {
        // 1. 先创建一个默认状态的 Seed (depth=0, etc.)
        // 这里我们可以复用之前的构造函数逻辑，或者直接 new 一个对象再填值
        // 为了方便，我们假设这是一个新的 Seed，然后尝试覆盖它的字段
        // 注意：因为 Seed 的字段是 final 的，最好的方式是在构造前读取
        
        File parentDir = seedFile.getParentFile();
        File metaFile = (parentDir != null)
            ? new File(parentDir, seedFile.getName() + ".meta")
            : new File(seedFile.getName() + ".meta");
        
        String parentId = null;
        int depth = 0;
        String birthType = "INITIAL";
        int handicap = 8;
        boolean wasFuzzed = false;
        long execTime = 0;
        int bitmapSize = 0;

        // 2. 如果 .meta 存在，读取并覆盖
        if (metaFile.exists()) {
            try (FileInputStream in = new FileInputStream(metaFile)) {
                Properties props = new Properties();
                props.load(in);
                
                parentId = props.getProperty("parent_id", null);
                depth = Integer.parseInt(props.getProperty("depth", "0"));
                birthType = props.getProperty("birth_type", "INITIAL");
                handicap = Integer.parseInt(props.getProperty("handicap", "8"));
                wasFuzzed = Boolean.parseBoolean(props.getProperty("was_fuzzed", "false"));
                execTime = Long.parseLong(props.getProperty("exec_time", "0"));
                bitmapSize = Integer.parseInt(props.getProperty("bitmap_size", "0"));
                
            } catch (Exception e) {
                System.err.println("Warning: Corrupted metadata for " + seedFile.getName());
            }
        }

        // 3. 调用全参构造函数 (你需要添加这个构造函数)
        return new Seed(seedFile, data, parentId, depth, birthType, handicap, wasFuzzed, execTime, bitmapSize);
    }
    /**
     * 构造函数 A: 用于加载初始种子 (从文件夹加载)
     * 此时没有 Parent，没有 Testcase
     */

    // 你需要添加一个全参构造函数来支持 loadWithMetadata
    private Seed(File file, byte[] data, String parentId, int depth, String birthType, 
                 int handicap, boolean wasFuzzed, long execTime, int bitmapSize) {
        this.file = file;
        this.data = Arrays.copyOf(data, data.length);
        this.id = file.getName();
        this.parentId = parentId;
        this.depth = depth;
        this.birthType = birthType;
        this.handicap = handicap;
        this.wasFuzzed = wasFuzzed;
        this.executionTime = execTime;
        this.bitmapSize = bitmapSize;
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
    public byte[] getDataCopy() {
        return Arrays.copyOf(data, data.length);
    }
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