package edu.nju.fuzzing.stats;

import edu.nju.fuzzing.model.StatsTick;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class StatsWriterTest {

    @TempDir
    Path tempDir;
    
    private Path csvPath;
    private StatsWriter writer;
    private String prevStatsFlushEvery;

    @BeforeEach
    void setUp() throws IOException {
        csvPath = tempDir.resolve("stats.csv");
        prevStatsFlushEvery = System.getProperty("nju.fuzzer.statsFlushEvery");
        System.setProperty("nju.fuzzer.statsFlushEvery", "1");
        writer = new StatsWriter(csvPath);
    }

    @AfterEach
    void tearDown() throws IOException {
        if (writer != null) {
            writer.close();
        }

        if (prevStatsFlushEvery == null) System.clearProperty("nju.fuzzer.statsFlushEvery");
        else System.setProperty("nju.fuzzer.statsFlushEvery", prevStatsFlushEvery);
    }

    // --- CSV 格式合规性测试 ---

    @Test
    void shouldWriteHeaderOnCreation() throws IOException {
        writer.close(); // Flush to disk
        List<String> lines = Files.readAllLines(csvPath);
        
        assertFalse(lines.isEmpty());
        // [修改] 验证包含新的列名
        assertEquals("timestamp,target_name,exec_count,covered_edges,execs_per_sec,queue_size,total_paths,crash_count,hang_count", lines.get(0));
    }

    @Test
    void shouldAppendDataRowCorrectly() throws IOException {
        // 使用兼容构造函数，totalPaths 默认为 0
        StatsTick tick = new StatsTick("target_1", 10, 500, 100, 50.5, 5, 0, 0, 0);
        writer.tick(tick);
        writer.close();

        List<String> lines = Files.readAllLines(csvPath);
        assertEquals(2, lines.size()); // Header + 1 Row
        
        // [修改] 验证数据行包含 total_paths(0) 和 hang_count(0)
        // 格式: 10,target_1,500,100,50.50,5,0,0,0
        String row = lines.get(1);
        assertEquals("10,target_1,500,100,50.50,5,0,0,0", row);
    }

    @Test
    void shouldNotOverwriteExistingHeader() throws IOException {
        // Close first writer
        writer.close();
        
        // Open second writer in append mode
        try (StatsWriter writer2 = new StatsWriter(csvPath)) {
            writer2.tick(new StatsTick("target_1", 20, 1000, 200, 50.0, 10, 0, 0, 0));
        }

        List<String> lines = Files.readAllLines(csvPath);
        assertEquals(1, lines.stream().filter(l -> l.startsWith("timestamp")).count(), "Header should appear only once");
        assertEquals(1, lines.size() - 1, "Should have 1 row (from second write)");
    }

    // --- 协同工作测试 ---

    @Test
    void shouldWorkWithFuzzStatsOutput() throws IOException {
        FuzzStats stats = new FuzzStats("integration_test");
        stats.recordExec();
        stats.updateCoveredEdges(50);
        
        writer.tick(stats.toStatsTick(0));
        writer.close();
        
        String content = Files.readString(csvPath);
        assertTrue(content.contains("integration_test"), "Target name missing");
        assertTrue(content.contains(",50,"), "Covered edges missing");
    }

    @Test
    void shouldHandleMultipleTicks() throws IOException {
        for (int i = 0; i < 5; i++) {
            // 注意：这里使用了兼容构造函数
            writer.tick(new StatsTick("t", i, i*10, i*2, 1.0, 0, 0, 0, 0));
        }
        writer.close();
        
        long lineCount = Files.lines(csvPath).count();
        assertEquals(6, lineCount); // 1 Header + 5 Rows
    }

    // --- 边界情况测试 ---

    @Test
    void shouldAutoCreateParentDirectories() throws IOException {
        Path deepPath = tempDir.resolve("nested/dir/stats.csv");
        try (StatsWriter deepWriter = new StatsWriter(deepPath)) {
            deepWriter.tick(new StatsTick("t", 0,0,0,0,0,0,0,0));
        }
        assertTrue(Files.exists(deepPath));
    }

    @Test
    void shouldHandleCommaInTargetName() throws IOException {
        StatsTick tick = new StatsTick("bad,name", 0,0,0,0,0,0,0,0);
        writer.tick(tick);
        writer.close();
        
        String row = Files.readAllLines(csvPath).get(1);
        assertTrue(row.contains("bad,name"));
    }
    
    @Test
    void shouldFlushDataImmediately() throws IOException {
        writer.tick(new StatsTick("t", 1,1,1,1,1,1,1,1));
        
        List<String> lines = Files.readAllLines(csvPath);
        assertEquals(2, lines.size(), "Should have flushed data to disk");
    }

    @Test
    void shouldHandleFloatingPointPrecision() throws IOException {
        StatsTick tick = new StatsTick("t", 0,0,0, 1.23456789, 0,0,0,0);
        writer.tick(tick);
        writer.close();
        
        String row = Files.readAllLines(csvPath).get(1);
        assertTrue(row.contains("1.23"), "Should be formatted to 2 decimal places");
        assertFalse(row.contains("1.23456"), "Should truncate precision");
    }
}