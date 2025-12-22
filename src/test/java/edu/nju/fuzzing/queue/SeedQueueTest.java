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
}