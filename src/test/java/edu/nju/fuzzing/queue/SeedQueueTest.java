package edu.nju.fuzzing.queue;

import edu.nju.fuzzing.model.Seed;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class SeedQueueTest {

    // JUnit 5 会为每个测试方法创建一个全新的临时目录
    @TempDir
    Path tempDir;

    /**
     * 测试 1: 能否实现添加种子
     * 验证 addSeed 方法是否能正确将对象加入内存列表
     */
    @Test
    public void testAddSeed() {
        SeedQueue queue = new SeedQueue();
        
        // 初始状态应该为空
        Assertions.assertTrue(queue.isEmpty(), "Queue should be empty initially");

        // 构造一个虚拟种子
        byte[] data = "test_payload".getBytes();
        Seed seed = new Seed(new File("manual_seed.txt"), data);

        // 执行添加
        queue.addSeed(seed);

        // 验证
        Assertions.assertEquals(1, queue.size(), "Queue size should be 1");
        Assertions.assertFalse(queue.isEmpty());
        
        // 验证取出的数据是否一致
        Seed retrieved = queue.getSeeds().get(0);
        Assertions.assertEquals("manual_seed.txt", retrieved.getFile().getName());
        Assertions.assertArrayEquals(data, retrieved.getData());
    }

    /**
     * 测试 2: 能否正确初始化种子（扁平目录）
     * 验证 loadInitialSeeds 能读取当前目录下的文件，且忽略隐藏文件
     */
    @Test
    public void testLoadFlatDirectory() throws IOException {
        // --- 准备数据 ---
        // 1. 创建正常种子 A
        Path seedA = tempDir.resolve("seed_a.txt");
        Files.writeString(seedA, "AAAA");

        // 2. 创建正常种子 B
        Path seedB = tempDir.resolve("seed_b.bin");
        Files.write(seedB, new byte[]{0x01, 0x02});

        // 3. 创建隐藏文件 (应该被忽略)
        Path hidden = tempDir.resolve(".DS_Store");
        Files.writeString(hidden, "junk");

        // --- 执行 ---
        SeedQueue queue = new SeedQueue();
        int count = queue.loadInitialSeeds(tempDir);

        // --- 验证 ---
        // 期望只加载 A 和 B，共 2 个
        Assertions.assertEquals(2, count, "Should load exactly 2 visible files");
        Assertions.assertEquals(2, queue.size());

        List<Seed> seeds = queue.getSeeds();
        // 检查文件名是否存在
        boolean hasSeedA = seeds.stream().anyMatch(s -> s.getFile().getName().equals("seed_a.txt"));
        boolean hasSeedB = seeds.stream().anyMatch(s -> s.getFile().getName().equals("seed_b.bin"));
        boolean hasHidden = seeds.stream().anyMatch(s -> s.getFile().getName().equals(".DS_Store"));

        Assertions.assertTrue(hasSeedA, "Queue should contain seed_a.txt");
        Assertions.assertTrue(hasSeedB, "Queue should contain seed_b.bin");
        Assertions.assertFalse(hasHidden, "Queue should NOT contain hidden files");
    }
}