package edu.nju.fuzzing.model;

import edu.nju.fuzzing.cov.EdgeSet;

import java.io.*;
import java.util.Arrays;
import java.util.Properties;

/**
 * 种子：存储在队列中、有价值的输入。
 * [更新] 集成了 SeedType 以支持基于类型的变异调度
 */
public class Seed {

    // --- 1. 基础信息 ---
    private final File file;
    private final byte[] data;
    private final String id;

    // [新增] 种子类型：核心改动
    private final SeedType type;

    // --- 2. 血缘信息 ---
    private final String parentId;
    private final int depth;
    private final String birthType;

    // --- 3. 动态调度指标 ---
    private long executionTime;
    private int bitmapSize;
    private boolean wasFuzzed;
    private int handicap;
    private int energy; // 能量缓存

    // --- 4. CoverageDB/调度扩展指标 ---
    // These fields are hints for scheduling; they may change over time.
    private boolean favored;
    private boolean redundant;
    private int minEdgeFrequency;
    private double rarityScore;
    private CoverageEx.Stability stability;

    // Edge set is kept in-memory only (not persisted) to avoid huge .meta files.
    private transient EdgeSet edges;

    // === 元数据持久化 ===
    public void saveMetadata() {
        File parentDir = file.getParentFile();
        File metaFile = (parentDir != null)
                ? new File(parentDir, file.getName() + ".meta")
                : new File(file.getName() + ".meta");

        Properties props = new Properties();

        if (parentId != null) props.setProperty("parent_id", parentId);
        props.setProperty("depth", String.valueOf(depth));
        if (birthType != null) props.setProperty("birth_type", birthType);
        props.setProperty("handicap", String.valueOf(handicap));
        props.setProperty("was_fuzzed", String.valueOf(wasFuzzed));
        props.setProperty("exec_time", String.valueOf(executionTime));
        props.setProperty("bitmap_size", String.valueOf(bitmapSize));
        props.setProperty("energy", String.valueOf(energy));

        // Scheduling hints
        props.setProperty("favored", String.valueOf(favored));
        props.setProperty("redundant", String.valueOf(redundant));
        props.setProperty("min_edge_freq", String.valueOf(minEdgeFrequency));
        props.setProperty("rarity_score", String.valueOf(rarityScore));
        props.setProperty("stability", stability == null ? CoverageEx.Stability.UNKNOWN.name() : stability.name());

        // [新增] 保存类型名称 (如 "XML", "JPEG")
        props.setProperty("seed_type", type.name());

        try (FileOutputStream out = new FileOutputStream(metaFile)) {
            props.store(out, "Seed Metadata");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // === 静态工厂：加载种子 ===
    public static Seed loadWithMetadata(File seedFile, byte[] data) {
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
        int energy = 0;

        boolean favored = false;
        boolean redundant = false;
        int minEdgeFreq = 0;
        double rarityScore = 0.0;
        CoverageEx.Stability stability = CoverageEx.Stability.UNKNOWN;

        // [新增] 默认尝试自动检测类型 (解决初始种子没有meta的情况)
        SeedType type = SeedType.detect(data);

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
                energy = Integer.parseInt(props.getProperty("energy", "0"));

                favored = Boolean.parseBoolean(props.getProperty("favored", "false"));
                redundant = Boolean.parseBoolean(props.getProperty("redundant", "false"));
                minEdgeFreq = Integer.parseInt(props.getProperty("min_edge_freq", "0"));
                try {
                    rarityScore = Double.parseDouble(props.getProperty("rarity_score", "0.0"));
                } catch (NumberFormatException ignored) {
                    rarityScore = 0.0;
                }
                String stabilityStr = props.getProperty("stability", CoverageEx.Stability.UNKNOWN.name());
                try {
                    stability = CoverageEx.Stability.valueOf(stabilityStr);
                } catch (IllegalArgumentException ignored) {
                    stability = CoverageEx.Stability.UNKNOWN;
                }

                // [新增] 如果 meta 里有记录，优先使用记录的类型
                String typeStr = props.getProperty("seed_type");
                if (typeStr != null) {
                    try {
                        type = SeedType.valueOf(typeStr);
                    } catch (IllegalArgumentException e) {
                        // 如果类型名称不对，保持自动检测的结果
                    }
                }

            } catch (Exception e) {
                System.err.println("Warning: Corrupted metadata for " + seedFile.getName());
            }
        }

        return new Seed(seedFile, data, parentId, depth, birthType, handicap, wasFuzzed, execTime, bitmapSize,
            energy, type, favored, redundant, minEdgeFreq, rarityScore, stability);
    }

    // [更新] 全参构造函数
    private Seed(File file, byte[] data, String parentId, int depth, String birthType,
                 int handicap, boolean wasFuzzed, long execTime, int bitmapSize, int energy, SeedType type,
                 boolean favored, boolean redundant, int minEdgeFrequency, double rarityScore, CoverageEx.Stability stability) {
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
        this.energy = energy;
        this.type = type; // [新增]

        this.favored = favored;
        this.redundant = redundant;
        this.minEdgeFrequency = Math.max(0, minEdgeFrequency);
        this.rarityScore = Math.max(0.0, rarityScore);
        this.stability = stability == null ? CoverageEx.Stability.UNKNOWN : stability;
        this.edges = EdgeSet.empty();
    }

    // [更新] 晋升构造函数 (从 Testcase)
    public Seed(File file, Testcase testcase) {
        this.file = file;
        this.id = file.getName();
        this.data = testcase.getDataCopy();

        Seed parent = testcase.parent();
        if (parent != null) {
            this.parentId = parent.getId();
            this.depth = parent.getDepth() + 1;
            // [新增] 关键逻辑：继承父种子的类型
            // 比如父种子是 XML，变异后的子种子依然认为是 XML
            this.type = parent.getType();
        } else {
            this.parentId = null;
            this.depth = 0;
            // 兜底：如果没有父节点，重新检测
            this.type = SeedType.detect(this.data);
        }

        this.birthType = testcase.description();
        this.wasFuzzed = false;
        this.handicap = 8;
        this.executionTime = 0;
        this.bitmapSize = 0;
        this.energy = 0;

        this.favored = false;
        this.redundant = false;
        this.minEdgeFrequency = 0;
        this.rarityScore = 0.0;
        this.stability = CoverageEx.Stability.UNKNOWN;
        this.edges = EdgeSet.empty();
    }

    // --- Getters ---
    public SeedType getType() { return type; } // [新增]

    public File getFile() { return file; }
    public String getId() { return id; }
    public byte[] getData() { return data; }
    public byte[] getDataCopy() { return Arrays.copyOf(data, data.length); }
    public String getParentId() { return parentId; }
    public int getDepth() { return depth; }
    public boolean isWasFuzzed() { return wasFuzzed; }
    public int getHandicap() { return handicap; }
    public long getExecutionTime() { return executionTime; }
    public int getBitmapSize() { return bitmapSize; }
    public int getEnergy() { return energy; }

    public boolean isFavored() { return favored; }
    public boolean isRedundant() { return redundant; }
    public int getMinEdgeFrequency() { return minEdgeFrequency; }
    public double getRarityScore() { return rarityScore; }
    public CoverageEx.Stability getStability() { return stability; }
    public EdgeSet getEdges() { return edges == null ? EdgeSet.empty() : edges; }

    // --- Setters ---
    public void decreaseHandicap() { if (this.handicap > 1) this.handicap--; }
    public void markAsFuzzed() { this.wasFuzzed = true; }
    public void setExecutionTime(long t) { this.executionTime = t; }
    public void setBitmapSize(int s) { this.bitmapSize = s; }
    public void setEnergy(int e) { this.energy = e; }

    public void setFavored(boolean favored) { this.favored = favored; }
    public void setRedundant(boolean redundant) { this.redundant = redundant; }
    public void setMinEdgeFrequency(int minEdgeFrequency) { this.minEdgeFrequency = Math.max(0, minEdgeFrequency); }
    public void setRarityScore(double rarityScore) { this.rarityScore = Math.max(0.0, rarityScore); }
    public void setStability(CoverageEx.Stability stability) {
        this.stability = stability == null ? CoverageEx.Stability.UNKNOWN : stability;
    }
    public void setEdges(EdgeSet edges) { this.edges = edges == null ? EdgeSet.empty() : edges; }

    @Override
    public String toString() {
        return String.format("Seed[id=%s, type=%s, cov=%d, favored=%s, redundant=%s, stability=%s]",
                id, type, bitmapSize, favored, redundant, stability);
    }
}