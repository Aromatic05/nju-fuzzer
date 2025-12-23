package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

/**
 * 增强型 PNG 变异器
 *
 * 新增特性：
 * 1. Palette (PLTE) 越界攻击：声明少量的调色板，使用大的索引。
 * 2. Smart Scanlines：构造符合 Filter 逻辑的像素数据，深入测试滤镜算法。
 * 3. Ancillary Chunks：注入 iCCP, tRNS, pHYs 等容易出错的块。
 * 4. CRC Fuzzing：小概率生成错误的 CRC。
 */
public class PngMutator implements Mutator {

    private static final byte[] PNG_SIGNATURE = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

    // 容易引发溢出的整数
    private static final int[] EVIL_INTS = {
            0, 1, 10000, 65535, 65536,
            Integer.MAX_VALUE, Integer.MIN_VALUE,
            0x7fffffff, 0x80000000
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
                    byte[] pngData = generatePng();
                    return new Testcase(pngData, seed, "grammar:AdvancedPNG");
                } catch (IOException e) {
                    throw new RuntimeException("PNG generation failed", e);
                }
            }
        };
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