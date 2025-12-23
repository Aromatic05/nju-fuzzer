package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 增强型 JPEG 变异器
 *
 * 新增特性：
 * 1. APP1 (Exif) 伪造：构造畸形的 TIFF 结构测试 Metadata 解析器。
 * 2. Progressive JPEG (SOF2)：测试复杂的渐进式扫描重组逻辑。
 * 3. Length Spoofing：声明长度 > 实际数据，诱发 Buffer Over-read。
 * 4. Restart Interval (DRI)：测试解码状态机重置。
 * 5. Sampling Factor Attack：非法的 MCU 尺寸计算。
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

    @Override
    public Iterator<Testcase> mutate(Seed seed, int energy) {
        int count = Math.max(1, energy);
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
                    return new Testcase(generateJpeg(), seed, "grammar:AdvancedJPEG");
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        };
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