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
 * 
 * 使用 ConstraintFixer 可选择性地修复 CRC 保持结构合法性
 */
public class PngMutator implements Mutator {

    private static final byte[] PNG_SIGNATURE = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    
    private final PngScanner scanner = new PngScanner();
    private final Random random = new Random();

    // 容易引发溢出的整数
    private static final int[] EVIL_INTS = {
            0, 1, 10000, 65535, 65536,
            Integer.MAX_VALUE, Integer.MIN_VALUE,
            0x7fffffff, 0x80000000
    };

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
     * 基于解析的 seed 进行结构感知变异
     */
    private byte[] mutateFromSeed(ScanResult result) throws IOException {
        byte[] data = result.getOriginalData().clone();
        List<BinaryChunk> chunks = result.getChunks();
        ThreadLocalRandom rand = ThreadLocalRandom.current();
        
        // 选择变异策略
        int strategy = rand.nextInt(10);
        
        if (strategy < 3 && chunks.size() > 2) {
            // 30%: Chunk 操作 (删除、复制、交换)
            data = mutateChunkStructure(data, chunks, rand);
        } else if (strategy < 6) {
            // 30%: 长度字段变异
            data = mutateLengthFields(data, chunks, rand);
        } else if (strategy < 8) {
            // 20%: 数据区域位翻转
            data = mutateDataRegions(data, chunks, rand);
        } else {
            // 20%: CRC 破坏
            data = mutateCrc(data, chunks, rand);
        }
        
        // 50% 概率修复 CRC (让解析器走得更深)
        if (rand.nextBoolean()) {
            data = ConstraintFixer.fixAllPngCrcs(data);
        }
        
        // 确保 Magic 正确 (否则解析器直接拒绝)
        if (rand.nextInt(10) > 1) {
            data = ConstraintFixer.restorePngMagic(data);
        }
        
        return data;
    }
    
    /**
     * Chunk 结构变异：删除/复制/交换
     */
    private byte[] mutateChunkStructure(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) throws IOException {
        // 找到非关键 chunk
        List<BinaryChunk> nonCritical = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            String type = chunk.getChunkType();
            // IHDR 和 IEND 不动
            if (!type.equals("IHDR") && !type.equals("IEND")) {
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
            // 交换两个 chunk
            int idx1 = rand.nextInt(nonCritical.size());
            int idx2 = rand.nextInt(nonCritical.size());
            while (idx2 == idx1) idx2 = rand.nextInt(nonCritical.size());
            return StructureMutator.swapChunks(data, nonCritical.get(idx1), nonCritical.get(idx2));
        }
        
        return data;
    }
    
    /**
     * 长度字段变异
     */
    private byte[] mutateLengthFields(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // PNG chunk 格式: [4字节长度][4字节类型][数据][4字节CRC]
        // 找一个 chunk 的长度字段进行变异
        
        if (chunks.isEmpty()) return data;
        
        BinaryChunk target = chunks.get(rand.nextInt(chunks.size()));
        int lengthOffset = target.getStartOffset();
        
        if (lengthOffset + 4 > data.length) return data;
        
        // 创建一个假的长度字段映射
        FieldMapping lengthField = new FieldMapping(lengthOffset, 4, FieldType.LENGTH, 
                                                     ByteOrder.BIG_ENDIAN, "chunk_length");
        
        return StructureMutator.mutateLength(data, lengthField, rand);
    }
    
    /**
     * 数据区域位翻转
     */
    private byte[] mutateDataRegions(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // 找一个有数据的 chunk
        List<BinaryChunk> withData = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (chunk.getDataLength() > 0) {
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
     * CRC 破坏
     */
    private byte[] mutateCrc(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        if (chunks.isEmpty()) return data;
        
        BinaryChunk target = chunks.get(rand.nextInt(chunks.size()));
        
        // CRC 在 chunk 末尾 4 字节
        int crcOffset = target.getStartOffset() + target.getTotalLength() - 4;
        
        if (crcOffset + 4 > data.length || crcOffset < 0) return data;
        
        // 随机修改 CRC
        byte[] result = data.clone();
        for (int i = 0; i < 4; i++) {
            if (rand.nextBoolean()) {
                result[crcOffset + i] ^= (1 << rand.nextInt(8));
            }
        }
        
        return result;
    }

    private byte[] generatePng() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(baos);
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        // 1. Magic
        out.write(PNG_SIGNATURE);

        // 2. IHDR Config
        int width, height;
        if (rand.nextInt(10) < 2) { // 20% 极端尺寸
            width = EVIL_INTS[rand.nextInt(EVIL_INTS.length)];
            height = EVIL_INTS[rand.nextInt(EVIL_INTS.length)];
        } else { // 80% 正常尺寸 (便于进入解压逻辑)
            width = rand.nextInt(256) + 1;
            height = rand.nextInt(256) + 1;
        }

        // 随机选择 ColorType 和 BitDepth (简化版，只选常见组合以保证能走到渲染层)
        // Type 3 = Indexed (需要 PLTE), Type 2 = TrueColor, Type 6 = TrueColor + Alpha
        int[] validTypes = {0, 2, 3, 6};
        byte colorType = (byte) validTypes[rand.nextInt(validTypes.length)];
        byte bitDepth = 8;

        // IHDR Write
        ByteArrayOutputStream ihdrBody = new ByteArrayOutputStream();
        DataOutputStream ihdrOut = new DataOutputStream(ihdrBody);
        ihdrOut.writeInt(width);
        ihdrOut.writeInt(height);
        ihdrOut.write(bitDepth); // BitDepth
        ihdrOut.write(colorType); // ColorType
        ihdrOut.write(0); // Compression
        ihdrOut.write(0); // Filter
        ihdrOut.write(rand.nextInt(2)); // Interlace
        writeChunk(out, "IHDR", ihdrBody.toByteArray(), rand);

        // 3. Ancillary Chunks (辅助块注入)

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

        // [Attack] PLTE: 如果是 Type 3，必须有；如果是 Type 2/6，提供了可能导致混淆
        // 策略：如果是 Index 类型，故意提供过短的 PLTE，测试越界读取
        if (colorType == 3 || rand.nextInt(5) == 0) {
            int numEntries = rand.nextBoolean() ? 256 : rand.nextInt(10) + 1; // 正常或极短
            byte[] plteData = new byte[numEntries * 3];
            rand.nextBytes(plteData);
            writeChunk(out, "PLTE", plteData, rand);
        }

        // [Attack] tRNS: 透明度数据，大小必须与 PLTE 匹配或特定格式
        if (rand.nextInt(5) == 0) {
            byte[] trnsData = new byte[rand.nextInt(100) + 1];
            rand.nextBytes(trnsData);
            writeChunk(out, "tRNS", trnsData, rand);
        }

        // 4. IDAT (Smart Scanlines)
        // 只有当宽高 "正常" 时才生成有效的图像数据，否则生成随机垃圾测试 DoS
        byte[] idatPayload;
        if (width > 0 && width < 2000 && height > 0 && height < 2000) {
            idatPayload = generateScanlineData(width, height, colorType, rand);
        } else {
            // 随便塞点数据，反正前面 header 已经乱了
            idatPayload = new byte[100];
            rand.nextBytes(idatPayload);
        }

        // 50% 概率压缩，50% 概率存非压缩数据（虽然非法，但看解析器反应）或者损坏的 Zlib
        byte[] finalIdat;
        if (rand.nextInt(100) > 5) {
            finalIdat = zlibCompress(idatPayload);
        } else {
            finalIdat = idatPayload; // 非压缩数据直接塞进去
        }
        writeChunk(out, "IDAT", finalIdat, rand);

        // 5. IEND
        writeChunk(out, "IEND", new byte[0], rand);

        return baos.toByteArray();
    }

    /**
     * 生成带有 Filter Byte 的扫描行数据
     * 这比纯随机数据更容易进入 Filter 处理逻辑 (Paeth, Sub, Up 等)
     */
    private byte[] generateScanlineData(int width, int height, int colorType, ThreadLocalRandom rand) {
        int bytesPerPixel = (colorType == 2) ? 3 : (colorType == 6 ? 4 : 1);
        long rowBytes = (long) width * bytesPerPixel;

        // 限制一下大小防止 OOM
        if (rowBytes * height > 5 * 1024 * 1024) return new byte[1024];

        ByteArrayOutputStream scanlines = new ByteArrayOutputStream();
        byte[] rowData = new byte[(int) rowBytes];

        for (int y = 0; y < height; y++) {
            // 每行第一个字节是 Filter Type (0-4)
            // 0:None, 1:Sub, 2:Up, 3:Average, 4:Paeth
            int filterType = rand.nextInt(5);
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