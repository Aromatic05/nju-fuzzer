package edu.nju.fuzzing.queue;

import edu.nju.fuzzing.model.Seed;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

/**
 * 管理内存中的种子队列。
 * 负责加载初始种子，并接收模糊测试过程中产生的新种子。
 */
public class SeedQueue {

    // 核心数据结构：存种子的列表
    // 使用 ArrayList 是因为它支持 O(1) 的随机访问，方便 Prioritizer 随机选取
    private final List<Seed> seeds = new ArrayList<>();

    /**
     * 从指定目录加载初始种子
     *
     * @param seedDir 种子所在的文件夹路径
     * @return 加载成功的种子数量
     */
    public int loadInitialSeeds(Path seedDir) throws IOException {
        if (!Files.exists(seedDir) || !Files.isDirectory(seedDir)) {
            throw new IOException("Seed directory does not exist or is not a directory: " + seedDir);
        }

        // 支持递归加载种子文件
        try (Stream<Path> walk = Files.walk(seedDir)) {
            walk.filter(Files::isRegularFile) // 过滤掉目录本身，只保留文件
                .filter(p -> !p.getFileName().toString().startsWith(".")) // 过滤隐藏文件
                .forEach(path -> {
                    try {
                        byte[] data = Files.readAllBytes(path);
                        // 初始种子没有元数据，暂设为0
                        Seed seed = new Seed(path.toFile(), data); // 封装成 Seed 对象
                        seeds.add(seed);
                    } catch (IOException e) {
                        System.err.println("Failed to read seed: " + path + ", " + e.getMessage());
                    }
                });
        }
        
        return seeds.size();
    }

    /**
     * 添加一个新种子到队列中
     * 通常由 FuzzingEngine 在发现新覆盖路径时调用
     */
    public void addSeed(Seed seed) {
        if (seed != null) {
            seeds.add(seed);
        }
    }

    /**
     * 获取所有种子列表（供 Prioritizer 使用）
     * 返回不可修改的视图，防止外部意外清空队列
     */
    public List<Seed> getSeeds() {
        return Collections.unmodifiableList(seeds);
    }
    
    /**
     * 获取种子总数
     */
    public int size() {
        return seeds.size();
    }

    /**
     * 判断队列是否为空
     */
    public boolean isEmpty() {
        return seeds.isEmpty();
    }
    
    // 方便调试打印
    @Override
    public String toString() {
        return "SeedQueue{size=" + seeds.size() + "}";
    }
}