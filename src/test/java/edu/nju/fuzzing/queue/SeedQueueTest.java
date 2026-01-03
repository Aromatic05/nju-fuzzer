package edu.nju.fuzzing.queue;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;

public class SeedQueueTest {

    @TempDir
    Path tempDir;

    /**
     * 测试 1: 复杂目录结构的初始化加载
     * 验证：递归加载、忽略隐藏文件、忽略孤立的 .meta 文件
     */
    @Test
    public void testComplexInitialization() throws IOException {
        // --- 1. 准备文件环境 ---
        // 根目录种子
        Files.writeString(tempDir.resolve("root.txt"), "root_data");

        // 子目录种子 (递归测试)
        Path subDir = tempDir.resolve("subdir");
        Files.createDirectory(subDir);
        Files.writeString(subDir.resolve("nested.bin"), "nested_data");

        // 隐藏文件 (应忽略)
        Files.writeString(tempDir.resolve(".DS_Store"), "junk");

        // 孤立的 .meta 文件 (应忽略，不能被当成种子读入)
        Files.writeString(tempDir.resolve("orphan.meta"), "fake_meta");

        // --- 2. 执行加载 ---
        SeedQueue queue = new SeedQueue();
        int count = queue.loadInitialSeeds(tempDir);

        // --- 3. 验证结果 ---
        Assertions.assertEquals(2, count, "Should load exactly 2 valid seeds");
        
        List<String> filenames = queue.getSeeds().stream()
                .map(s -> s.getFile().getName())
                .collect(Collectors.toList());

        Assertions.assertTrue(filenames.contains("root.txt"));
        Assertions.assertTrue(filenames.contains("nested.bin"));
        Assertions.assertFalse(filenames.contains(".DS_Store"));
        Assertions.assertFalse(filenames.contains("orphan.meta"));
    }

    /**
     * 测试 2: 完整生命周期 (变异 -> 晋升 -> 持久化 -> 恢复)
     * 这是最核心的测试，验证你的 SeedQueue 是否正确集成了元数据保存与加载
     */
    @Test
    public void testLifecycleAndPersistence() throws IOException {
        SeedQueue queue = new SeedQueue();

        // --- 阶段 A: 创建父种子 (模拟加载) ---
        File parentFile = tempDir.resolve("parent_seed").toFile();
        Files.write(parentFile.toPath(), "parent".getBytes());
        // 模拟初始加载的种子
        Seed parentSeed = Seed.loadWithMetadata(parentFile, "parent".getBytes());
        
        // --- 阶段 B: 模拟变异产生 Testcase ---
        byte[] childData = "child".getBytes();
        // 创建 Testcase，父节点指向 parentSeed
        Testcase testcase = new Testcase(childData, parentSeed, "havoc_bitflip");

        // --- 阶段 C: 晋升为子种子 (Promotion) ---
        File childFile = tempDir.resolve("child_seed").toFile();
        Files.write(childFile.toPath(), childData); // 物理文件必须存在
        
        // 使用 (File, Testcase) 构造函数
        Seed childSeed = new Seed(childFile, testcase);

        // 验证内存中的继承逻辑
        Assertions.assertEquals(1, childSeed.getDepth(), "Depth should be parent.depth + 1");
        Assertions.assertEquals(parentSeed.getId(), childSeed.getParentId(), "Parent ID should match");

        // --- 阶段 D: 加入队列 (触发 addSeed -> saveMetadata) ---
        queue.addSeed(childSeed);

        // 验证 .meta 文件是否真的生成了
        File metaFile = new File(tempDir.toFile(), "child_seed.meta");
        Assertions.assertTrue(metaFile.exists(), ".meta file should be created automatically on addSeed");

        // --- 阶段 E: 模拟重启 Fuzzer (重新加载) ---
        SeedQueue newQueue = new SeedQueue();
        newQueue.loadInitialSeeds(tempDir);

        // 找到恢复后的子种子
        Seed restoredSeed = newQueue.getSeeds().stream()
                .filter(s -> s.getFile().getName().equals("child_seed"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Child seed not found after reload"));

        // 验证元数据是否从 .meta 文件中恢复
        Assertions.assertEquals(1, restoredSeed.getDepth(), "Restored seed should maintain depth 1");
        Assertions.assertEquals(parentSeed.getId(), restoredSeed.getParentId(), "Restored seed should maintain parent ID");
        // 验证数据内容
        Assertions.assertArrayEquals(childData, restoredSeed.getData());
    }

    /**
     * 测试 3: 手动元数据加载
     * 验证 loadWithMetadata 工厂方法能否正确解析 .meta 文件
     */
    @Test
    public void testManualMetadataLoading() throws IOException {
        // 1. 创建种子文件
        File seedFile = tempDir.resolve("manual_seed").toFile();
        Files.write(seedFile.toPath(), "data".getBytes());

        // 2. 手动写入一个 .meta 文件
        File metaFile = tempDir.resolve("manual_seed.meta").toFile();
        Properties props = new Properties();
        props.setProperty("depth", "99");
        props.setProperty("parent_id", "god_seed");
        props.setProperty("handicap", "5");
        props.setProperty("exec_time", "123456");
        
        try (FileOutputStream out = new FileOutputStream(metaFile)) {
            props.store(out, null);
        }

        // 3. 通过 Queue 加载
        SeedQueue queue = new SeedQueue();
        queue.loadInitialSeeds(tempDir);
        Seed seed = queue.getSeeds().get(0);

        // 4. 验证是否读取了 meta 文件中的值
        Assertions.assertEquals(99, seed.getDepth());
        Assertions.assertEquals("god_seed", seed.getParentId());
        Assertions.assertEquals(5, seed.getHandicap());
        Assertions.assertEquals(123456L, seed.getExecutionTime());
    }

    /**
     * 测试 4: 动态属性操作
     * 验证业务逻辑是否符合预期
     */
    @Test
    public void testDynamicProperties() {
        // 创建一个 dummy 种子
        Seed seed = Seed.loadWithMetadata(new File("dummy"), new byte[0]);

        // 1. 验证初始 Handicap
        Assertions.assertEquals(8, seed.getHandicap(), "Initial handicap should be 8");

        // 2. 验证 Handicap 递减
        seed.decreaseHandicap();
        Assertions.assertEquals(7, seed.getHandicap());

        // 3. 验证 Handicap 下限
        for (int i = 0; i < 100; i++) seed.decreaseHandicap();
        Assertions.assertEquals(1, seed.getHandicap(), "Handicap should not go below 1");

        // 4. 验证状态标记
        Assertions.assertFalse(seed.isWasFuzzed());
        seed.markAsFuzzed();
        Assertions.assertTrue(seed.isWasFuzzed());
        
        // 5. 验证 Setter/Getter
        seed.setBitmapSize(500);
        Assertions.assertEquals(500, seed.getBitmapSize());
    }

    /**
     * 测试 5: 调度提示字段持久化
     * 验证：favored/redundant/min_edge_freq/rarity_score/stability 会写入 .meta 并在 reload 后恢复。
     */
    @Test
    public void testSchedulingHintsArePersistedAndRestored() throws IOException {
        // 1) 创建一个种子，并显式指定 run-wide SeedType
        byte[] data = "local a=1\nprint(a)".getBytes();
        File seedFile = tempDir.resolve("hint_seed").toFile();
        Files.write(seedFile.toPath(), data);

        Seed seed = Seed.loadWithMetadata(seedFile, data, edu.nju.fuzzing.model.SeedType.LUA);
        seed.setFavored(true);
        seed.setRedundant(true);
        seed.setMinEdgeFrequency(2);
        seed.setRarityScore(0.75);
        seed.setStability(edu.nju.fuzzing.model.CoverageEx.Stability.UNSTABLE);

        SeedQueue queue = new SeedQueue();
        queue.addSeed(seed);

        // 2) 模拟重启，重新加载
        SeedQueue reloaded = new SeedQueue();
        reloaded.loadInitialSeeds(tempDir, edu.nju.fuzzing.model.SeedType.LUA);

        Seed restored = reloaded.getSeeds().stream()
                .filter(s -> s.getFile().getName().equals("hint_seed"))
                .findFirst()
                .orElseThrow();

        Assertions.assertTrue(restored.isFavored());
        Assertions.assertTrue(restored.isRedundant());
        Assertions.assertEquals(2, restored.getMinEdgeFrequency());
        Assertions.assertEquals(0.75, restored.getRarityScore(), 1e-9);
        Assertions.assertEquals(edu.nju.fuzzing.model.CoverageEx.Stability.UNSTABLE, restored.getStability());

        // 同一次 run 必须保持同一种类型
        Assertions.assertEquals(edu.nju.fuzzing.model.SeedType.LUA, restored.getType());
    }
}
