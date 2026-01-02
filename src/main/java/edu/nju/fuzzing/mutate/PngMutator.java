package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.binary.*;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

/**
 * 结构感知型 PNG 变异器
 *
 * 使用 PngScanner 解析 seed 数据，提取 chunk 结构，
 * 然后通过 StructureMutator 进行有针对性的变异：
 * 1. 长度字段变异 (整数溢出)
 * 2. Chunk 删除/复制/交换
 * 3. 数据区域位翻转
 * 4. CRC 破坏
 * 5. Chunk Type 变异 (Critical/Ancillary 翻转)
 * 
 * 使用 ConstraintFixer 可选择性地修复 CRC 保持结构合法性
 * 
 * 已修复问题:
 * - 问题1: 长度字段变异同步更新实际数据大小
 * - 问题2: Chunk 顺序约束检查
 * - 问题3: CRC 修复策略精细控制
 * - 问题4: IHDR/IEND 数据保护
 * - 问题5: ColorType/BitDepth 非法组合测试
 * - 问题6: Scanline 溢出保护
 * - 问题7: PLTE 攻击向量增强
 * - 问题8: 删除未使用字段
 * - 问题9: EVIL_INTS 充分利用
 * - 问题10: Chunk Type 变异
 */
public class PngMutator implements Mutator {

    private static final byte[] PNG_SIGNATURE = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    
    private final PngScanner scanner = new PngScanner();
    
    // [问题8 修复] 删除了未使用的 private final Random random = new Random();

    // 容易引发溢出的整数
    private static final int[] EVIL_INTS = {
            0, 1, -1, 10000, 65535, 65536,
            Integer.MAX_VALUE, Integer.MIN_VALUE,
            0x7fffffff, 0x80000000,
            0x7ffffffe, 0x7ffffffd,  // 接近 MAX_VALUE
            0xffffffff, 0xfffffffe   // 接近 -1
    };
    
    // [问题4 修复] 关键 chunk 保护集合
    private static final Set<String> CRITICAL_CHUNKS = new HashSet<>(Arrays.asList(
        "IHDR", "IEND"
    ));
    
    // [问题2 修复] Chunk 顺序约束映射
    private static final Map<String, Integer> CHUNK_ORDER = new HashMap<>();
    static {
        CHUNK_ORDER.put("IHDR", 0);
        CHUNK_ORDER.put("cHRM", 5);
        CHUNK_ORDER.put("gAMA", 5);
        CHUNK_ORDER.put("iCCP", 10);   // 必须在 PLTE/IDAT 前
        CHUNK_ORDER.put("sRGB", 10);
        CHUNK_ORDER.put("sBIT", 15);
        CHUNK_ORDER.put("PLTE", 30);   // 必须在 IDAT 前
        CHUNK_ORDER.put("bKGD", 35);
        CHUNK_ORDER.put("hIST", 35);
        CHUNK_ORDER.put("tRNS", 35);   // 必须在 IDAT 前
        CHUNK_ORDER.put("pHYs", 40);
        CHUNK_ORDER.put("sPLT", 40);
        CHUNK_ORDER.put("IDAT", 50);
        CHUNK_ORDER.put("tEXt", 60);
        CHUNK_ORDER.put("zTXt", 60);
        CHUNK_ORDER.put("iTXt", 60);
        CHUNK_ORDER.put("tIME", 70);
        CHUNK_ORDER.put("IEND", 100);
    }
    
    // [问题5 修复] ColorType 与 BitDepth 的合法组合
    private static final Map<Integer, int[]> VALID_BIT_DEPTHS = new HashMap<>();
    static {
        VALID_BIT_DEPTHS.put(0, new int[]{1, 2, 4, 8, 16});   // Grayscale
        VALID_BIT_DEPTHS.put(2, new int[]{8, 16});            // TrueColor
        VALID_BIT_DEPTHS.put(3, new int[]{1, 2, 4, 8});       // Indexed
        VALID_BIT_DEPTHS.put(4, new int[]{8, 16});            // Grayscale + Alpha
        VALID_BIT_DEPTHS.put(6, new int[]{8, 16});            // TrueColor + Alpha
    }

    @Override
    public Iterator<Testcase> mutate(Seed seed, int energy) {
        int count = Math.max(1, energy);
        byte[] seedData = seed.getData();
        
        // 尝试解析 seed
        ScanResult scanResult = null;
        if (scanner.matches(seedData)) {
            scanResult = scanner.scan(seedData);
        }
        
        final ScanResult finalScanResult = scanResult;

        return new Iterator<Testcase>() {
            private int remaining = count;

            @Override
            public boolean hasNext() {
                return remaining > 0;
            }

            @Override
            public Testcase next() {
                if (remaining <= 0) throw new NoSuchElementException();
                remaining--;

                try {
                    byte[] pngData;
                    
                    // 如果成功解析了 seed，使用结构感知变异
                    if (finalScanResult != null && finalScanResult.isValid()) {
                        pngData = mutateFromSeed(finalScanResult);
                    } else {
                        // 回退到生成模式
                        pngData = generatePng();
                    }
                    
                    return new Testcase(pngData, seed, "structure:PNG");
                } catch (Exception e) {
                    // 出错时回退到生成模式
                    try {
                        return new Testcase(generatePng(), seed, "grammar:PNG");
                    } catch (IOException ex) {
                        throw new RuntimeException("PNG generation failed", ex);
                    }
                }
            }
        };
    }
    
    /**
     * [问题3 修复] 基于解析的 seed 进行结构感知变异
     * 根据变异类型精细控制 CRC 修复策略
     */
    private byte[] mutateFromSeed(ScanResult result) throws IOException {
        byte[] data = result.getOriginalData().clone();
        List<BinaryChunk> chunks = result.getChunks();
        ThreadLocalRandom rand = ThreadLocalRandom.current();
        
        // 记录变异类型，决定是否修复 CRC
        boolean isCrcAttack = false;
        boolean isTypeAttack = false;
        
        // 选择变异策略
        int strategy = rand.nextInt(12);  // 扩展策略数量
        
        if (strategy < 3 && chunks.size() > 2) {
            // 25%: Chunk 操作 (删除、复制、交换)
            data = mutateChunkStructure(data, chunks, rand);
        } else if (strategy < 5) {
            // 17%: 长度字段变异 (同步调整数据大小)
            data = mutateLengthFields(data, chunks, rand);
        } else if (strategy < 7) {
            // 17%: 数据区域位翻转
            data = mutateDataRegions(data, chunks, rand);
        } else if (strategy < 9) {
            // 17%: CRC 破坏 (不修复 CRC)
            data = mutateCrc(data, chunks, rand);
            isCrcAttack = true;
        } else if (strategy < 11) {
            // 17%: Chunk Type 变异
            data = mutateChunkTypes(data, chunks, rand);
            isTypeAttack = true;
        } else {
            // 8%: 使用 EVIL_INTS 进行长度攻击
            data = mutateWithEvilInts(data, chunks, rand);
        }
        
        // [问题3 修复] 精细的 CRC 修复策略
        if (!isCrcAttack && !isTypeAttack) {
            // 非 CRC 攻击和非 Type 攻击时，80% 概率修复 CRC
            if (rand.nextInt(10) > 1) {
                data = ConstraintFixer.fixAllPngCrcs(data);
            }
        }
        // CRC 攻击时不修复 CRC
        // Type 攻击时也不修复（因为 CRC 基于 Type 计算）
        
        // 确保 Magic 正确 (否则解析器直接拒绝)
        if (rand.nextInt(10) > 1) {
            data = ConstraintFixer.restorePngMagic(data);
        }
        
        return data;
    }
    
    /**
     * [问题2 修复] 检查两个 chunk 是否可以交换位置
     * 根据 PNG 规范的顺序约束判断
     */
    private boolean canSwap(BinaryChunk c1, BinaryChunk c2) {
        String type1 = c1.getChunkType();
        String type2 = c2.getChunkType();
        
        // 如果两者都没有顺序约束，可以交换
        if (!CHUNK_ORDER.containsKey(type1) && !CHUNK_ORDER.containsKey(type2)) {
            return true;
        }
        
        // 获取顺序权重（未知 chunk 默认为 45，介于 PLTE 和 IDAT 之间）
        Integer order1 = CHUNK_ORDER.getOrDefault(type1, 45);
        Integer order2 = CHUNK_ORDER.getOrDefault(type2, 45);
        
        // 如果顺序权重相同，可以交换
        return order1.equals(order2);
    }
    
    /**
     * [问题2 修复] Chunk 结构变异：删除/复制/交换
     * 交换时检查顺序约束
     */
    private byte[] mutateChunkStructure(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) throws IOException {
        // 找到非关键 chunk
        List<BinaryChunk> nonCritical = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            String type = chunk.getChunkType();
            // IHDR 和 IEND 不动
            if (!CRITICAL_CHUNKS.contains(type)) {
                nonCritical.add(chunk);
            }
        }
        
        if (nonCritical.isEmpty()) {
            return data;
        }
        
        int op = rand.nextInt(3);
        
        if (op == 0 && nonCritical.size() > 1) {
            // 删除一个非关键 chunk
            BinaryChunk toDelete = nonCritical.get(rand.nextInt(nonCritical.size()));
            return StructureMutator.deleteChunk(data, toDelete);
            
        } else if (op == 1) {
            // 复制一个 chunk
            BinaryChunk toDuplicate = nonCritical.get(rand.nextInt(nonCritical.size()));
            return StructureMutator.duplicateChunk(data, toDuplicate);
            
        } else if (op == 2 && nonCritical.size() >= 2) {
            // [问题2 修复] 交换两个 chunk，但保持顺序约束
            for (int attempt = 0; attempt < 10; attempt++) {
                int idx1 = rand.nextInt(nonCritical.size());
                int idx2 = rand.nextInt(nonCritical.size());
                if (idx2 == idx1) continue;
                
                BinaryChunk chunk1 = nonCritical.get(idx1);
                BinaryChunk chunk2 = nonCritical.get(idx2);
                
                if (canSwap(chunk1, chunk2)) {
                    return StructureMutator.swapChunks(data, chunk1, chunk2);
                }
            }
            // 如果找不到可交换的，改为复制
            BinaryChunk toDuplicate = nonCritical.get(rand.nextInt(nonCritical.size()));
            return StructureMutator.duplicateChunk(data, toDuplicate);
        }
        
        return data;
    }
    
    /**
     * [问题1 修复] 长度字段变异 - 同步更新实际数据大小
     * [问题4 修复] 保护 IHDR 和 IEND
     */
    private byte[] mutateLengthFields(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        if (chunks.isEmpty()) return data;
        
        // [问题4 修复] 过滤掉关键 chunk
        List<BinaryChunk> mutableChunks = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (!CRITICAL_CHUNKS.contains(chunk.getChunkType())) {
                mutableChunks.add(chunk);
            }
        }
        
        if (mutableChunks.isEmpty()) return data;
        
        BinaryChunk target = mutableChunks.get(rand.nextInt(mutableChunks.size()));
        int oldLength = target.getDataLength();
        
        // 生成新长度 (多种策略)
        int newLength;
        int strategy = rand.nextInt(5);
        switch (strategy) {
            case 0:
                // 截断
                newLength = Math.max(0, oldLength - rand.nextInt(Math.max(1, oldLength)));
                break;
            case 1:
                // 扩展
                newLength = oldLength + rand.nextInt(100) + 1;
                break;
            case 2:
                // 使用恶意整数
                newLength = EVIL_INTS[rand.nextInt(EVIL_INTS.length)];
                if (newLength < 0) newLength = 0;
                if (newLength > 1024 * 1024) newLength = rand.nextInt(10000); // 防止 OOM
                break;
            case 3:
                // 边界值
                newLength = rand.nextBoolean() ? 0 : 0x7FFFFFFF;
                if (newLength > 1024 * 1024) newLength = rand.nextInt(10000);
                break;
            default:
                // 随机
                newLength = rand.nextInt(10000);
        }
        
        // [问题1 修复] 同步修改 chunk 数据大小
        return resizeChunkData(data, target, Math.max(0, Math.min(newLength, 100000)), rand);
    }
    
    /**
     * [问题1 修复] 调整 chunk 数据大小
     * - 如果变小：截断数据
     * - 如果变大：填充随机字节
     * - 重新计算 CRC
     */
    private byte[] resizeChunkData(byte[] data, BinaryChunk chunk, int newLength, ThreadLocalRandom rand) {
        try {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            
            // 写入 chunk 之前的数据
            result.write(data, 0, chunk.getStartOffset());
            
            // 写入新的 length (大端序)
            ByteBuffer lengthBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            lengthBuf.putInt(newLength);
            result.write(lengthBuf.array());
            
            // 写入 type（不变）
            int typeOffset = chunk.getStartOffset() + 4;
            byte[] typeBytes = new byte[4];
            System.arraycopy(data, typeOffset, typeBytes, 0, 4);
            result.write(typeBytes);
            
            // 写入数据区域（截断或填充）
            int oldDataOffset = chunk.getStartOffset() + 8;
            int oldLength = chunk.getDataLength();
            
            byte[] newData;
            if (newLength <= oldLength) {
                // 截断
                newData = new byte[newLength];
                if (newLength > 0 && oldDataOffset + newLength <= data.length) {
                    System.arraycopy(data, oldDataOffset, newData, 0, newLength);
                }
            } else {
                // 复制旧数据 + 填充随机字节
                newData = new byte[newLength];
                int copyLen = Math.min(oldLength, data.length - oldDataOffset);
                if (copyLen > 0) {
                    System.arraycopy(data, oldDataOffset, newData, 0, copyLen);
                }
                byte[] padding = new byte[newLength - copyLen];
                rand.nextBytes(padding);
                System.arraycopy(padding, 0, newData, copyLen, padding.length);
            }
            result.write(newData);
            
            // 重新计算 CRC (type + data)
            CRC32 crc = new CRC32();
            crc.update(typeBytes);
            crc.update(newData);
            ByteBuffer crcBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
            crcBuf.putInt((int) crc.getValue());
            result.write(crcBuf.array());
            
            // 写入剩余数据 (后续 chunks)
            int nextChunkOffset = chunk.getStartOffset() + chunk.getTotalLength();
            if (nextChunkOffset < data.length) {
                result.write(data, nextChunkOffset, data.length - nextChunkOffset);
            }
            
            return result.toByteArray();
            
        } catch (Exception e) {
            return data;
        }
    }
    
    /**
     * [问题4 修复] 数据区域位翻转 - 保护关键 chunk
     */
    private byte[] mutateDataRegions(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // [问题4 修复] 过滤掉关键 chunk
        List<BinaryChunk> withData = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (chunk.getDataLength() > 0 && !CRITICAL_CHUNKS.contains(chunk.getChunkType())) {
                withData.add(chunk);
            }
        }
        
        if (withData.isEmpty()) return data;
        
        BinaryChunk target = withData.get(rand.nextInt(withData.size()));
        
        // PNG chunk 数据从偏移 8 开始 (跳过长度和类型)
        int dataStart = target.getStartOffset() + 8;
        int dataLen = target.getDataLength();
        
        if (dataStart + dataLen > data.length || dataLen <= 0) return data;
        
        return StructureMutator.bitFlipDataRegion(data, dataStart, dataLen, rand);
    }
    
    /**
     * [问题4 修复] CRC 破坏 - 可选保护关键 chunk
     */
    private byte[] mutateCrc(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        if (chunks.isEmpty()) return data;
        
        // 50% 概率保护关键 chunk
        List<BinaryChunk> targetChunks;
        if (rand.nextBoolean()) {
            targetChunks = new ArrayList<>();
            for (BinaryChunk chunk : chunks) {
                if (!CRITICAL_CHUNKS.contains(chunk.getChunkType())) {
                    targetChunks.add(chunk);
                }
            }
            if (targetChunks.isEmpty()) {
                targetChunks = chunks;
            }
        } else {
            targetChunks = chunks;
        }
        
        BinaryChunk target = targetChunks.get(rand.nextInt(targetChunks.size()));
        
        // CRC 在 chunk 末尾 4 字节
        int crcOffset = target.getStartOffset() + target.getTotalLength() - 4;
        
        if (crcOffset + 4 > data.length || crcOffset < 0) return data;
        
        byte[] result = data.clone();
        
        // CRC 破坏策略
        int strategy = rand.nextInt(4);
        switch (strategy) {
            case 0:
                // 位翻转
                for (int i = 0; i < 4; i++) {
                    if (rand.nextBoolean()) {
                        result[crcOffset + i] ^= (1 << rand.nextInt(8));
                    }
                }
                break;
            case 1:
                // 置零
                for (int i = 0; i < 4; i++) {
                    result[crcOffset + i] = 0;
                }
                break;
            case 2:
                // 全 0xFF
                for (int i = 0; i < 4; i++) {
                    result[crcOffset + i] = (byte) 0xFF;
                }
                break;
            default:
                // 完全随机
                for (int i = 0; i < 4; i++) {
                    result[crcOffset + i] = (byte) rand.nextInt(256);
                }
        }
        
        return result;
    }
    
    /**
     * [问题10 新增] Chunk Type 变异
     * 测试解析器对非法/异常 Chunk Type 的处理
     */
    private byte[] mutateChunkTypes(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        if (chunks.isEmpty()) return data;
        
        // 过滤掉 IHDR 和 IEND
        List<BinaryChunk> mutableChunks = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (!CRITICAL_CHUNKS.contains(chunk.getChunkType())) {
                mutableChunks.add(chunk);
            }
        }
        
        if (mutableChunks.isEmpty()) return data;
        
        BinaryChunk target = mutableChunks.get(rand.nextInt(mutableChunks.size()));
        
        byte[] result = data.clone();
        int typeOffset = target.getStartOffset() + 4;
        
        if (typeOffset + 4 > data.length) return data;
        
        int attackType = rand.nextInt(5);
        switch (attackType) {
            case 0:
                // 翻转首字母大小写 (Critical ↔ Ancillary)
                result[typeOffset] ^= 0x20;
                break;
            case 1:
                // 翻转第二个字母大小写 (Public ↔ Private)
                result[typeOffset + 1] ^= 0x20;
                break;
            case 2:
                // 翻转第四个字母大小写 (Safe-to-copy bit)
                result[typeOffset + 3] ^= 0x20;
                break;
            case 3:
                // 注入非法字符 (不在 A-Za-z 范围内)
                int byteIdx = rand.nextInt(4);
                result[typeOffset + byteIdx] = (byte) (rand.nextInt(256));
                break;
            default:
                // 随机修改所有字节
                for (int i = 0; i < 4; i++) {
                    if (rand.nextBoolean()) {
                        result[typeOffset + i] = (byte) (rand.nextInt(256));
                    }
                }
        }
        
        return result;
    }
    
    /**
     * [问题9 新增] 使用 EVIL_INTS 进行长度攻击
     */
    private byte[] mutateWithEvilInts(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        if (chunks.isEmpty()) return data;
        
        // 过滤掉关键 chunk
        List<BinaryChunk> mutableChunks = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (!CRITICAL_CHUNKS.contains(chunk.getChunkType())) {
                mutableChunks.add(chunk);
            }
        }
        
        if (mutableChunks.isEmpty()) return data;
        
        BinaryChunk target = mutableChunks.get(rand.nextInt(mutableChunks.size()));
        int lengthOffset = target.getStartOffset();
        
        if (lengthOffset + 4 > data.length) return data;
        
        byte[] result = data.clone();
        
        // 使用恶意整数覆盖长度字段
        int evilValue = EVIL_INTS[rand.nextInt(EVIL_INTS.length)];
        ByteBuffer.wrap(result, lengthOffset, 4)
                  .order(ByteOrder.BIG_ENDIAN)
                  .putInt(evilValue);
        
        return result;
    }

    /**
     * [问题5, 问题6, 问题7 修复] PNG 生成模式
     */
    private byte[] generatePng() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(baos);
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        // 1. Magic
        out.write(PNG_SIGNATURE);

        // 2. IHDR Config
        int width, height;
        if (rand.nextInt(10) < 2) { // 20% 极端尺寸
            // [问题9 增强] 使用 EVIL_INTS
            width = EVIL_INTS[rand.nextInt(EVIL_INTS.length)];
            height = EVIL_INTS[rand.nextInt(EVIL_INTS.length)];
            // 限制负数范围
            if (width < 0) width = Integer.MAX_VALUE;
            if (height < 0) height = Integer.MAX_VALUE;
        } else { // 80% 正常尺寸 (便于进入解压逻辑)
            width = rand.nextInt(256) + 1;
            height = rand.nextInt(256) + 1;
        }

        // [问题5 修复] 随机选择 ColorType 和 BitDepth
        int[] allColorTypes = {0, 2, 3, 4, 6};  // 添加了 ColorType 4
        int colorType = allColorTypes[rand.nextInt(allColorTypes.length)];
        
        byte bitDepth;
        if (rand.nextInt(10) == 0) {
            // 10% 概率生成非法 BitDepth 组合
            int[] allBitDepths = {1, 2, 4, 8, 16};
            bitDepth = (byte) allBitDepths[rand.nextInt(allBitDepths.length)];
        } else {
            // 90% 概率生成合法 BitDepth
            int[] validDepths = VALID_BIT_DEPTHS.get(colorType);
            bitDepth = (byte) validDepths[rand.nextInt(validDepths.length)];
        }

        // IHDR Write
        ByteArrayOutputStream ihdrBody = new ByteArrayOutputStream();
        DataOutputStream ihdrOut = new DataOutputStream(ihdrBody);
        ihdrOut.writeInt(width);
        ihdrOut.writeInt(height);
        ihdrOut.write(bitDepth);
        ihdrOut.write(colorType);
        ihdrOut.write(0); // Compression
        ihdrOut.write(0); // Filter
        ihdrOut.write(rand.nextInt(2)); // Interlace
        writeChunk(out, "IHDR", ihdrBody.toByteArray(), rand);

        // 3. Ancillary Chunks (辅助块注入)

        // [Attack] cHRM: Primary Chromaticities
        if (rand.nextInt(10) == 0) {
            byte[] chrmData = new byte[32];
            rand.nextBytes(chrmData);
            writeChunk(out, "cHRM", chrmData, rand);
        }

        // [Attack] gAMA: Gamma
        if (rand.nextInt(8) == 0) {
            ByteArrayOutputStream gama = new ByteArrayOutputStream();
            DataOutputStream gamaOut = new DataOutputStream(gama);
            // 使用恶意 gamma 值
            if (rand.nextBoolean()) {
                gamaOut.writeInt(EVIL_INTS[rand.nextInt(EVIL_INTS.length)]);
            } else {
                gamaOut.writeInt(45455); // 正常值 ~1/2.2
            }
            writeChunk(out, "gAMA", gama.toByteArray(), rand);
        }

        // [Attack] iCCP: ICC Profile (历史漏洞高发区)
        if (rand.nextInt(5) == 0) {
            byte[] profileName = "BadProfile".getBytes(StandardCharsets.ISO_8859_1);
            byte[] rawProfile = new byte[rand.nextInt(200) + 10]; // 随机垃圾数据
            rand.nextBytes(rawProfile);
            byte[] compressedProfile = zlibCompress(rawProfile);

            ByteArrayOutputStream iccp = new ByteArrayOutputStream();
            iccp.write(profileName);
            iccp.write(0); // null separator
            iccp.write(0); // compression method
            iccp.write(compressedProfile);
            writeChunk(out, "iCCP", iccp.toByteArray(), rand);
        }

        // [问题7 增强] PLTE 攻击向量
        generatePlteChunk(out, colorType, rand);

        // [Attack] tRNS: 透明度数据，大小必须与 PLTE 匹配或特定格式
        if (rand.nextInt(5) == 0) {
            byte[] trnsData = new byte[rand.nextInt(256) + 1];
            rand.nextBytes(trnsData);
            writeChunk(out, "tRNS", trnsData, rand);
        }

        // [Attack] bKGD: Background Color
        if (rand.nextInt(8) == 0) {
            byte[] bkgdData = new byte[rand.nextInt(10) + 1];
            rand.nextBytes(bkgdData);
            writeChunk(out, "bKGD", bkgdData, rand);
        }

        // [Attack] pHYs: Physical Pixel Dimensions
        if (rand.nextInt(8) == 0) {
            ByteArrayOutputStream phys = new ByteArrayOutputStream();
            DataOutputStream physOut = new DataOutputStream(phys);
            // 使用恶意值
            physOut.writeInt(EVIL_INTS[rand.nextInt(EVIL_INTS.length)]); // X pixels per unit
            physOut.writeInt(EVIL_INTS[rand.nextInt(EVIL_INTS.length)]); // Y pixels per unit
            physOut.write(rand.nextInt(3)); // Unit specifier
            writeChunk(out, "pHYs", phys.toByteArray(), rand);
        }

        // 4. IDAT (Smart Scanlines)
        byte[] idatPayload;
        // [问题6 修复] 安全检查
        if (width > 0 && width < 2000 && height > 0 && height < 2000) {
            idatPayload = generateScanlineData(width, height, colorType, bitDepth, rand);
        } else {
            // 随便塞点数据，反正前面 header 已经乱了
            idatPayload = new byte[100];
            rand.nextBytes(idatPayload);
        }

        // 压缩策略
        byte[] finalIdat;
        int compressionStrategy = rand.nextInt(100);
        if (compressionStrategy < 90) {
            // 90%: 正常 Zlib 压缩
            finalIdat = zlibCompress(idatPayload);
        } else if (compressionStrategy < 95) {
            // 5%: 非压缩数据直接塞进去
            finalIdat = idatPayload;
        } else {
            // 5%: 损坏的 Zlib 头
            finalIdat = zlibCompress(idatPayload);
            if (finalIdat.length > 2) {
                // 破坏 Zlib header
                finalIdat[0] = (byte) rand.nextInt(256);
                finalIdat[1] = (byte) rand.nextInt(256);
            }
        }
        
        // 可能分割 IDAT 成多个块
        if (rand.nextInt(5) == 0 && finalIdat.length > 100) {
            int splitPoint = rand.nextInt(finalIdat.length - 10) + 5;
            byte[] idat1 = new byte[splitPoint];
            byte[] idat2 = new byte[finalIdat.length - splitPoint];
            System.arraycopy(finalIdat, 0, idat1, 0, splitPoint);
            System.arraycopy(finalIdat, splitPoint, idat2, 0, idat2.length);
            writeChunk(out, "IDAT", idat1, rand);
            writeChunk(out, "IDAT", idat2, rand);
        } else {
            writeChunk(out, "IDAT", finalIdat, rand);
        }

        // [Attack] tEXt: Textual Data
        if (rand.nextInt(5) == 0) {
            ByteArrayOutputStream text = new ByteArrayOutputStream();
            text.write("Comment".getBytes(StandardCharsets.ISO_8859_1));
            text.write(0); // null separator
            byte[] textData = new byte[rand.nextInt(200) + 1];
            rand.nextBytes(textData);
            text.write(textData);
            writeChunk(out, "tEXt", text.toByteArray(), rand);
        }

        // 5. IEND
        writeChunk(out, "IEND", new byte[0], rand);

        return baos.toByteArray();
    }
    
    /**
     * [问题7 增强] 生成 PLTE chunk (多种攻击向量)
     */
    private void generatePlteChunk(DataOutputStream out, int colorType, ThreadLocalRandom rand) throws IOException {
        // 决定是否生成 PLTE
        boolean needsPlte = (colorType == 3); // Indexed 模式必须有 PLTE
        boolean generatePlte = needsPlte || rand.nextInt(5) == 0;
        
        if (!generatePlte) return;
        
        int attackType = rand.nextInt(6);
        
        switch (attackType) {
            case 0:
                if (!needsPlte) {
                    // 攻击 1: 完全缺失 PLTE（ColorType=3 时必需）
                    // 不写入 PLTE - 但只有在不需要 PLTE 时才能跳过
                    return;
                }
                // 如果需要 PLTE，fall through 到正常生成
            case 1:
                // 攻击 2: 过短 PLTE (1-10 项)
                int shortEntries = rand.nextInt(10) + 1;
                byte[] shortPlte = new byte[shortEntries * 3];
                rand.nextBytes(shortPlte);
                writeChunk(out, "PLTE", shortPlte, rand);
                break;
            case 2:
                // 攻击 3: 过长 PLTE (超过 256 项)
                int longEntries = 256 + rand.nextInt(100) + 1;
                byte[] longPlte = new byte[longEntries * 3];
                rand.nextBytes(longPlte);
                writeChunk(out, "PLTE", longPlte, rand);
                break;
            case 3:
                // 攻击 4: 非 3 的倍数大小
                int wrongSize = rand.nextInt(256 * 3) + 1;
                if (wrongSize % 3 == 0) wrongSize++; // 确保不是 3 的倍数
                byte[] wrongPlte = new byte[wrongSize];
                rand.nextBytes(wrongPlte);
                writeChunk(out, "PLTE", wrongPlte, rand);
                break;
            case 4:
                // 攻击 5: 空 PLTE
                writeChunk(out, "PLTE", new byte[0], rand);
                break;
            default:
                // 攻击 6: 正常 PLTE (256 项)
                byte[] normalPlte = new byte[256 * 3];
                rand.nextBytes(normalPlte);
                writeChunk(out, "PLTE", normalPlte, rand);
        }
    }

    /**
     * [问题6 修复] 生成带有 Filter Byte 的扫描行数据
     * 增加溢出保护
     */
    private byte[] generateScanlineData(int width, int height, int colorType, int bitDepth, ThreadLocalRandom rand) {
        // 根据 colorType 和 bitDepth 计算每像素字节数
        int bitsPerPixel;
        switch (colorType) {
            case 0: // Grayscale
                bitsPerPixel = bitDepth;
                break;
            case 2: // TrueColor
                bitsPerPixel = bitDepth * 3;
                break;
            case 3: // Indexed
                bitsPerPixel = bitDepth;
                break;
            case 4: // Grayscale + Alpha
                bitsPerPixel = bitDepth * 2;
                break;
            case 6: // TrueColor + Alpha
                bitsPerPixel = bitDepth * 4;
                break;
            default:
                bitsPerPixel = 8;
        }
        
        // [问题6 修复] 安全检查：防止乘法溢出
        if (width <= 0 || height <= 0) {
            return new byte[100];
        }
        
        // 每行字节数 (向上取整)
        long rowBits = (long) width * bitsPerPixel;
        long rowBytes = (rowBits + 7) / 8;  // 向上取整到字节
        
        // 检查溢出
        if (rowBytes > Integer.MAX_VALUE || rowBytes <= 0) {
            return new byte[100];
        }
        
        // 限制总大小防止 OOM (每行 + 1 filter byte)
        long totalSize = (rowBytes + 1) * height;
        if (totalSize > 5 * 1024 * 1024 || totalSize <= 0) {
            return new byte[1024];
        }

        ByteArrayOutputStream scanlines = new ByteArrayOutputStream();
        byte[] rowData = new byte[(int) rowBytes];

        for (int y = 0; y < height; y++) {
            // 每行第一个字节是 Filter Type (0-4)
            // 0:None, 1:Sub, 2:Up, 3:Average, 4:Paeth
            int filterType;
            if (rand.nextInt(10) == 0) {
                // 10% 概率使用非法 filter type
                filterType = rand.nextInt(256);
            } else {
                filterType = rand.nextInt(5);
            }
            scanlines.write(filterType);

            // 像素数据
            // 策略：如果是 Index 模式 (Type 3)，故意生成超过 PLTE 大小的索引 (例如 255)
            rand.nextBytes(rowData);
            try {
                scanlines.write(rowData);
            } catch (IOException e) {
                break;
            }
        }
        return scanlines.toByteArray();
    }

    private void writeChunk(DataOutputStream out, String typeStr, byte[] data, ThreadLocalRandom rand) throws IOException {
        byte[] type = typeStr.getBytes(StandardCharsets.US_ASCII);
        out.writeInt(data.length);
        out.write(type);
        out.write(data);

        CRC32 crc = new CRC32();
        crc.update(type);
        crc.update(data);
        long crcVal = crc.getValue();

        // [Attack] CRC Fuzzing: 5% 概率写入错误的 CRC
        if (rand.nextInt(100) < 5) {
            crcVal = rand.nextInt(); // 随机 CRC
        }

        out.writeInt((int) crcVal);
    }

    private byte[] zlibCompress(byte[] input) {
        Deflater deflater = new Deflater(Deflater.BEST_SPEED);
        deflater.setInput(input);
        deflater.finish();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            baos.write(buffer, 0, count);
        }
        deflater.end();
        return baos.toByteArray();
    }
}
