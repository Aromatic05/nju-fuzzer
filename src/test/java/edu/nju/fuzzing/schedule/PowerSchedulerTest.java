package edu.nju.fuzzing.schedule;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.SeedType;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.stats.FuzzStats;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;

public class PowerSchedulerTest {

    private PowerScheduler scheduler;
    private FuzzStats stats;

    @BeforeEach
    public void setup() {
        // Provide a stable baseline for adaptive thresholds: avg exec time ~= 100ms.
        stats = new FuzzStats("test");
        stats.recordExec(100_000L * 1000L);
        scheduler = new PowerScheduler(stats);
    }

    // 辅助方法：创建一个没有任何加成的普通老种子
    private Seed createPlainSeed() {
        // 【修正】使用静态工厂方法
        Seed s = Seed.loadWithMetadata(new File("dummy"), new byte[0]);
        
        // 去掉新手保护 (Handicap 8 -> 0)
        for(int i=0; i<10; i++) s.decreaseHandicap();
        
        // 设置普通参数
        s.setExecutionTime(100_000 * 1000); // 100ms
        s.setBitmapSize(100);               // 100 bytes
        s.markAsFuzzed();
        return s;
    }

    private Seed createPlainSeedWithData(byte[] data) {
        return createPlainSeedWithData(data, SeedType.UNKNOWN);
    }

    private Seed createPlainSeedWithData(byte[] data, SeedType type) {
        Seed s = Seed.loadWithMetadata(new File("dummy"), data, type);

        // 去掉新手保护 (Handicap 8 -> 1)
        for (int i = 0; i < 10; i++) s.decreaseHandicap();

        // 设置普通参数（保持其他因子中性）
        s.setExecutionTime(100_000 * 1000); // 100ms
        s.setBitmapSize(100);
        s.markAsFuzzed();
        return s;
    }

    /** Case 1: null 输入 */
    @Test
    public void testNullSeed() {
        Assertions.assertEquals(0, scheduler.assignEnergy(null));
    }

    /** Case 2: 验证基准能量 */
    @Test
    public void testBaseEnergy() {
        Seed s = createPlainSeed();
        Assertions.assertEquals(100, scheduler.assignEnergy(s));
    }

    /** Case 2b: CoverageDB 信号 - favored 增加能量 */
    @Test
    public void testFavoredBoostsEnergy() {
        Seed s = createPlainSeed();
        s.setFavored(true);
        Assertions.assertEquals(300, scheduler.assignEnergy(s));
    }

    /** Case 2c: CoverageDB 信号 - redundant 降低能量 */
    @Test
    public void testRedundantReducesEnergy() {
        Seed s = createPlainSeed();
        s.setRedundant(true);
        Assertions.assertEquals(50, scheduler.assignEnergy(s));
    }

    /** Case 2d: CoverageDB 信号 - rarity 增加能量（封顶前） */
    @Test
    public void testRarityBoostsEnergy() {
        Seed s = createPlainSeed();
        s.setRarityScore(1.0);
        // 100 * (1 + log10(1+1)) ~= 130
        Assertions.assertEquals(130, scheduler.assignEnergy(s));
    }

    /** Case 2e: 输入大小因子 - 小输入 (<=128) 略增能量 */
    @Test
    public void testSmallInputBoostsEnergy() {
        Seed s = createPlainSeedWithData(new byte[64]);
        // 100 * 1.2 = 120
        Assertions.assertEquals(120, scheduler.assignEnergy(s));
    }

    /** Case 2f: 输入大小因子 - 大输入 (>=256KiB) 降低能量 */
    @Test
    public void testLargeInputReducesEnergy() {
        Seed s = createPlainSeedWithData(new byte[300 * 1024]);
        // 100 * 0.7 = 70
        Assertions.assertEquals(70, scheduler.assignEnergy(s));
    }

    /** Case 2g: 类型因子 - 可识别类型（非 UNKNOWN）略增能量 */
    @Test
    public void testKnownTypeBoostsEnergy() {
        byte[] data = new byte[200];

        Seed s = createPlainSeedWithData(data, SeedType.LUA);
        // inputSize=200 -> size 因子中性；type!=UNKNOWN -> x1.1
        Assertions.assertEquals(110, scheduler.assignEnergy(s));
    }

    /** Case 3: 时间因子 - 极快 (<20ms) */
    @Test
    public void testFastExecution() {
        Seed s = createPlainSeed();
        s.setExecutionTime(10_000 * 1000); // 10ms
        // 100 * 3.0 = 300
        Assertions.assertEquals(300, scheduler.assignEnergy(s));
    }

    /** Case 4: 时间因子 - 快 (<50ms) */
    @Test
    public void testMediumExecution() {
        Seed s = createPlainSeed();
        s.setExecutionTime(40_000 * 1000); // 40ms
        // 100 * 2.0 = 200
        Assertions.assertEquals(200, scheduler.assignEnergy(s));
    }

    /** Case 5: 时间因子 - 慢 (>200ms) */
    @Test
    public void testSlowExecution() {
        Seed s = createPlainSeed();
        s.setExecutionTime(300_000 * 1000); // 300ms
        // 100 * 0.5 = 50
        Assertions.assertEquals(50, scheduler.assignEnergy(s));
    }

    /** Case 6: 时间因子 - 极慢 (>1s) */
    @Test
    public void testVerySlowExecution() {
        Seed s = createPlainSeed();
        s.setExecutionTime(2_000_000 * 1000L); // 2s
        // 100 * 0.25 = 25
        Assertions.assertEquals(25, scheduler.assignEnergy(s));
    }

    /** Case 7: 覆盖率因子 - 大覆盖 (>1000) */
    @Test
    public void testHighCoverage() {
        Seed s = createPlainSeed();
        s.setBitmapSize(1200);
        // bitmapSize 不再直接参与能量分配
        Assertions.assertEquals(100, scheduler.assignEnergy(s));
    }

    /** Case 8: 覆盖率因子 - 极小覆盖 (<50) */
    @Test
    public void testLowCoverage() {
        Seed s = createPlainSeed();
        s.setBitmapSize(10);
        // bitmapSize 不再直接参与能量分配
        Assertions.assertEquals(100, scheduler.assignEnergy(s));
    }

    /** Case 9: 新手保护 (Handicap >= 4) */
    @Test
    public void testHighHandicap() {
        // 【修正】使用静态工厂方法，默认 handicap=8
        Seed s = Seed.loadWithMetadata(new File("fresh"), new byte[0]);
        // 设为普通时间/大小以排除干扰
        s.setExecutionTime(100_000 * 1000); 
        s.setBitmapSize(100);

        // 100 * 2.0 (Handicap) = 200
        Assertions.assertEquals(200, scheduler.assignEnergy(s));
    }

    /** Case 10: 深度因子 (Depth > 5) */
    @Test
    public void testDeepSeed() {
        // 模拟深层种子：通过 Testcase 晋升链构造
        // 1. 创建初始种子
        Seed current = Seed.loadWithMetadata(new File("root"), new byte[0]);
        
        // 2. 模拟 6 代变异
        for (int i = 0; i < 6; i++) {
            // new Testcase(data, parent, desc)
            Testcase tc = new Testcase(new byte[0], current, "mut");
            // new Seed(file, testcase) <- 这个构造函数是存在的
            current = new Seed(new File("gen" + i), tc);
        }
        
        // 此时 current.depth = 6
        current.setExecutionTime(100_000 * 1000);
        current.setBitmapSize(100);
        // 去掉新手保护
        for(int k=0; k<10; k++) current.decreaseHandicap();

        // 100 * 1.2 = 120
        Assertions.assertEquals(120, scheduler.assignEnergy(current));
    }

    /** Case 11: 综合测试 - "极品种子" (快 + 大 + 新) */
    @Test
    public void testSuperSeed() {
        Seed s = Seed.loadWithMetadata(new File("god"), new byte[0]); // Handicap=8 (x2)
        s.setExecutionTime(1000);      // 1us (x3)
        s.setBitmapSize(2000);         // Big (x2)

        // bitmapSize 不再直接奖励，Total = 100 * 2 * 3 = 600
        Assertions.assertEquals(600, scheduler.assignEnergy(s));
    }

/** Case 12: 能量封顶测试 */
    @Test
    public void testEnergyCap() {
        // 创建一个新种子 (Handicap=8)
        Seed s = Seed.loadWithMetadata(new File("god"), new byte[0]); 
        
        // 【修正点】：必须手动设置让它变强的属性！
        s.setExecutionTime(1000); // 极快 (x3)
        s.setBitmapSize(2000);    // 极大 (x2)
        // Handicap 默认是 8 (x2)
        
        // 理论计算（bitmap 不奖励）：100 * 3 * 2 = 600

        int energy = scheduler.assignEnergy(s);
        
        // 验证
        Assertions.assertTrue(energy <= 5000, "Energy should not exceed MAX_ENERGY");
        Assertions.assertTrue(energy >= 600, "Energy should be high for super seed, actual: " + energy);
    }
}
