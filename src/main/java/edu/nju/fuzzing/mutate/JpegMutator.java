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

/**
 * 结构感知型 JPEG 变异器
 *
 * 使用 JpegScanner 解析 seed 数据，提取 marker segment 结构，
 * 然后通过 StructureMutator 进行有针对性的变异：
 * 1. 长度字段变异 (Length Spoofing)
 * 2. Segment 删除/复制/交换
 * 3. 数据区域位翻转
 * 4. Marker 混淆攻击
 * 
 * 保留生成模式作为回退
 */
public class JpegMutator implements Mutator {

    // Markers
    private static final int SOI = 0xD8;
    private static final int EOI = 0xD9;
    private static final int SOS = 0xDA;
    private static final int DQT = 0xDB;
    private static final int DRI = 0xDD; // Define Restart Interval
    private static final int SOF0 = 0xC0; // Baseline
    private static final int SOF2 = 0xC2; // Progressive (Complex logic)
    private static final int DHT = 0xC4;
    private static final int COM = 0xFE;
    private static final int APP0 = 0xE0; // JFIF
    private static final int APP1 = 0xE1; // Exif (High Risk)
    private static final int RST0 = 0xD0; // Restart markers D0-D7

    private static final int[] EVIL_DIMS = {
            0, 1, 8, 10000, 32768, 65535, 65536 // 0 and 65536 are classic edges
    };
    
    private final JpegScanner scanner = new JpegScanner();
    private final Random random = new Random();

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
                    byte[] jpegData;
                    
                    // 如果成功解析了 seed，使用结构感知变异
                    if (finalScanResult != null && finalScanResult.isValid()) {
                        jpegData = mutateFromSeed(finalScanResult);
                    } else {
                        // 回退到生成模式
                        jpegData = generateJpeg();
                    }
                    
                    return new Testcase(jpegData, seed, "structure:JPEG");
                } catch (Exception e) {
                    try {
                        return new Testcase(generateJpeg(), seed, "grammar:JPEG");
                    } catch (IOException ex) {
                        throw new RuntimeException(ex);
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
            // 30%: Segment 操作 (删除、复制、交换)
            data = mutateSegmentStructure(data, chunks, rand);
        } else if (strategy < 6) {
            // 30%: 长度字段变异 (Length Spoofing)
            data = mutateLengthFields(data, chunks, rand);
        } else if (strategy < 8) {
            // 20%: 数据区域位翻转
            data = mutateDataRegions(data, chunks, rand);
        } else {
            // 20%: Marker 混淆攻击
            data = mutateMarkers(data, chunks, rand);
        }
        
        // 确保 SOI 和 EOI 正确
        if (rand.nextInt(10) > 1) {
            data = ConstraintFixer.restoreJpegMagic(data);
            data = ConstraintFixer.ensureJpegEoi(data);
        }
        
        return data;
    }
    
    /**
     * Segment 结构变异：删除/复制/交换
     */
    private byte[] mutateSegmentStructure(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) throws IOException {
        // 找到可变异的 segment (排除 SOI, EOI, SOS)
        List<BinaryChunk> mutable = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            String type = chunk.getChunkType();
            if (!type.equals("SOI") && !type.equals("EOI") && !type.startsWith("SOS")) {
                mutable.add(chunk);
            }
        }
        
        if (mutable.isEmpty()) {
            return data;
        }
        
        int op = rand.nextInt(3);
        
        if (op == 0 && mutable.size() > 1) {
            // 删除一个非关键 segment
            BinaryChunk toDelete = mutable.get(rand.nextInt(mutable.size()));
            return StructureMutator.deleteChunk(data, toDelete);
            
        } else if (op == 1) {
            // 复制一个 segment
            BinaryChunk toDuplicate = mutable.get(rand.nextInt(mutable.size()));
            return StructureMutator.duplicateChunk(data, toDuplicate);
            
        } else if (op == 2 && mutable.size() >= 2) {
            // 交换两个 segment
            int idx1 = rand.nextInt(mutable.size());
            int idx2 = rand.nextInt(mutable.size());
            while (idx2 == idx1) idx2 = rand.nextInt(mutable.size());
            return StructureMutator.swapChunks(data, mutable.get(idx1), mutable.get(idx2));
        }
        
        return data;
    }
    
    /**
     * 长度字段变异 (Length Spoofing)
     */
    private byte[] mutateLengthFields(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // 找有长度字段的 segment
        List<BinaryChunk> withLength = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            for (FieldMapping field : chunk.getFields()) {
                if (field.getType() == FieldType.LENGTH) {
                    withLength.add(chunk);
                    break;
                }
            }
        }
        
        if (withLength.isEmpty()) return data;
        
        BinaryChunk target = withLength.get(rand.nextInt(withLength.size()));
        
        // 找到长度字段
        for (FieldMapping field : target.getFields()) {
            if (field.getType() == FieldType.LENGTH) {
                int globalOffset = target.getStartOffset() + field.getOffset();
                FieldMapping globalField = new FieldMapping(globalOffset, field.getLength(), 
                        field.getType(), field.getByteOrder(), field.getName());
                return StructureMutator.mutateLength(data, globalField, rand);
            }
        }
        
        return data;
    }
    
    /**
     * 数据区域位翻转
     */
    private byte[] mutateDataRegions(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        List<BinaryChunk> withData = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (chunk.getDataLength() > 0) {
                withData.add(chunk);
            }
        }
        
        if (withData.isEmpty()) return data;
        
        BinaryChunk target = withData.get(rand.nextInt(withData.size()));
        int dataStart = target.getStartOffset() + target.getDataOffset();
        int dataLen = target.getDataLength();
        
        if (dataStart + dataLen > data.length || dataLen <= 0) return data;
        
        return StructureMutator.bitFlipDataRegion(data, dataStart, dataLen, rand);
    }
    
    /**
     * Marker 混淆攻击
     */
    private byte[] mutateMarkers(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        if (chunks.size() < 2) return data;
        
        // 随机选择一个 segment 修改其 marker
        BinaryChunk target = chunks.get(rand.nextInt(chunks.size()));
        String type = target.getChunkType();
        
        // 跳过 SOI 和 EOI
        if (type.equals("SOI") || type.equals("EOI")) return data;
        
        int markerOffset = target.getStartOffset() + 1;  // 跳过 0xFF
        if (markerOffset >= data.length) return data;
        
        byte[] result = data.clone();
        
        // 随机改变 marker 类型
        int newMarker = rand.nextInt(256);
        result[markerOffset] = (byte) newMarker;
        
        return result;
    }

    private byte[] generateJpeg() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(baos);
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        out.write(0xFF);
        out.write(SOI);

        // [New] APP1 Exif Attack (20% probability)
        if (rand.nextInt(5) == 0) writeApp1Exif(out, rand);
        else if (rand.nextBoolean()) writeApp0(out);

        // DQTs
        int dqtCount = 1 + rand.nextInt(3);
        for (int i = 0; i < dqtCount; i++) writeDqt(out, rand);

        // [New] DRI (Restart Interval)
        if (rand.nextInt(10) == 0) writeDri(out, rand);

        // SOF (Baseline or Progressive)
        writeSof(out, rand);

        // DHTs
        int dhtCount = 1 + rand.nextInt(4);
        for (int i = 0; i < dhtCount; i++) writeDht(out, rand);

        // SOS and Scan Data
        writeSosAndData(out, rand);

        out.write(0xFF);
        out.write(EOI);

        return baos.toByteArray();
    }

    // --- Enhanced Segment Writers ---

    private void writeApp0(DataOutputStream out) throws IOException {
        byte[] body = new byte[14];
        System.arraycopy("JFIF\0".getBytes(StandardCharsets.US_ASCII), 0, body, 0, 5);
        body[5] = 1; body[6] = 1; body[7] = 1; // Version 1.1, Unit
        body[9] = 72; body[11] = 72; // Density
        writeMarker(out, APP0, body, false);
    }

    /**
     * [Critical Attack Surface] APP1 / Exif
     * Exif 解析器通常很脆弱。这里构造一个基本的 TIFF Header 结构。
     */
    private void writeApp1Exif(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write("Exif\0\0".getBytes(StandardCharsets.US_ASCII));

        // TIFF Header
        // Byte Order: II (Intel) or MM (Motorola)
        boolean littleEndian = rand.nextBoolean();
        if (littleEndian) {
            body.write('I'); body.write('I');
            body.write(42);  body.write(0); // 42
        } else {
            body.write('M'); body.write('M');
            body.write(0);   body.write(42);
        }

        // Offset to IFD0 (Image File Directory)
        // [Attack] Pointing to OOB location or very large offset
        int offset = rand.nextInt(20) == 0 ? 0xFFFFFF : 8;
        writeInt(body, offset, littleEndian);

        // 我们只写 Header，不写具体的 IFD 标签，测试解析器在处理畸形 offset 时的反应
        // 或者填充一些垃圾数据模拟 IFD
        byte[] junk = new byte[rand.nextInt(50)];
        rand.nextBytes(junk);
        body.write(junk);

        writeMarker(out, APP1, body.toByteArray(), false);
    }

    private void writeDri(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        // DRI payload is always 2 bytes (Restart Interval)
        byte[] interval = new byte[2];
        // [Attack] Tiny interval causes massive overhead / state resets
        int val = rand.nextInt(100);
        interval[0] = (byte) (val >> 8);
        interval[1] = (byte) val;
        writeMarker(out, DRI, interval, false);
    }

    private void writeDqt(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        byte info = (byte) rand.nextInt(16); // Precision + ID
        byte[] table = new byte[64];
        // [Attack] Quantization table with all zeros implies division by zero in some IDCT impls
        if (rand.nextInt(20) != 0) rand.nextBytes(table);

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(info);
        body.write(table);
        writeMarker(out, DQT, body.toByteArray(), false);
    }

    private void writeSof(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        DataOutputStream bodyOut = new DataOutputStream(body);

        bodyOut.write(8); // Precision

        // Height & Width
        int h = (rand.nextInt(10) < 3) ? EVIL_DIMS[rand.nextInt(EVIL_DIMS.length)] : rand.nextInt(2000) + 1;
        int w = (rand.nextInt(10) < 3) ? EVIL_DIMS[rand.nextInt(EVIL_DIMS.length)] : rand.nextInt(2000) + 1;
        bodyOut.writeShort(h);
        bodyOut.writeShort(w);

        int components = rand.nextInt(4) + 1; // 1, 2, 3, 4
        bodyOut.write(components);

        for (int i = 0; i < components; i++) {
            bodyOut.write(i + 1); // Component ID

            // [Attack] Sampling Factor: H(4bit) + V(4bit)
            // Valid are usually 1x1, 1x2, 2x1, 2x2.
            // 4x4 or 0x0 can cause buffer calc errors.
            int samp = rand.nextInt(10) == 0 ? 0 : (rand.nextInt(4) << 4 | rand.nextInt(4));
            bodyOut.write(samp);
            bodyOut.write(rand.nextInt(3)); // Quant Table ID
        }

        // 随机选择 SOF0 (Baseline) 或 SOF2 (Progressive)
        writeMarker(out, rand.nextBoolean() ? SOF0 : SOF2, body.toByteArray(), false);
    }

    private void writeDht(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(rand.nextInt(4) << 4 | rand.nextInt(4)); // Class | ID

        byte[] counts = new byte[16];
        // Make sure sum of counts is reasonable to pass basic checks, or total garbage
        int totalSymbols = 0;
        if (rand.nextBoolean()) {
            for(int i=0; i<16; i++) {
                counts[i] = (byte) rand.nextInt(10);
                totalSymbols += counts[i];
            }
        } else {
            // Garbage counts
            rand.nextBytes(counts);
            totalSymbols = rand.nextInt(200);
        }
        body.write(counts);

        byte[] symbols = new byte[totalSymbols];
        rand.nextBytes(symbols);
        body.write(symbols);

        writeMarker(out, DHT, body.toByteArray(), false);
    }

    private void writeSosAndData(DataOutputStream out, ThreadLocalRandom rand) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(3); // Component count
        // Selectors
        body.write(1); body.write(0);
        body.write(2); body.write(0);
        body.write(3); body.write(0);

        // Spectral Selection (Start/End) & Approx (High/Low)
        // [Attack] Invalid ranges here cause loops in Progressive JPEG decoders
        body.write(rand.nextInt(64)); // Ss
        body.write(rand.nextInt(64)); // Se
        body.write(rand.nextInt(16) << 4 | rand.nextInt(16)); // Ah | Al

        writeMarker(out, SOS, body.toByteArray(), false);

        // Entropy Data
        // 随机插入 RST Markers (如果定义了 DRI)
        int dataLen = rand.nextInt(2048);
        for (int i = 0; i < dataLen; i++) {
            int b = rand.nextInt(256);
            out.write(b);

            // 0xFF Escaping Logic
            if (b == 0xFF) {
                // 95% 正常转义, 5% 注入攻击
                if (rand.nextInt(20) != 0) {
                    out.write(0x00);
                } else {
                    // Marker Confusion Attack
                    // 只有在这里才可能出现未转义的 FF，或者恶意的 RSTm
                    int next = rand.nextBoolean() ? RST0 + rand.nextInt(8) : rand.nextInt(256);
                    out.write(next);
                }
            }
        }
    }

    /**
     * 核心改进：支持 Length Spoofing
     * @param spoofLength 如果为 true，则随机写入一个假的 Length，导致 OOB Read
     */
    private void writeMarker(DataOutputStream out, int marker, byte[] payload, boolean spoofLength) throws IOException {
        out.write(0xFF);
        out.write(marker);

        int realLen = payload.length + 2;
        int writtenLen = realLen;

        // [Attack] Buffer Over-read
        // 声明长度为 1000，但实际只提供 10 字节数据
        // 许多解析器会先 malloc(len)，然后 read(len)，导致读取到未初始化内存或文件末尾
        if (spoofLength || ThreadLocalRandom.current().nextInt(20) == 0) {
            writtenLen = realLen + ThreadLocalRandom.current().nextInt(5000);
            if (writtenLen > 65535) writtenLen = 65535;
        }

        out.writeShort(writtenLen);
        out.write(payload);
    }

    // Helper for Little Endian writing in Exif
    private void writeInt(ByteArrayOutputStream out, int v, boolean littleEndian) {
        if (littleEndian) {
            out.write(v & 0xFF);
            out.write((v >>> 8) & 0xFF);
            out.write((v >>> 16) & 0xFF);
            out.write((v >>> 24) & 0xFF);
        } else {
            out.write((v >>> 24) & 0xFF);
            out.write((v >>> 16) & 0xFF);
            out.write((v >>> 8) & 0xFF);
            out.write(v & 0xFF);
        }
    }
}