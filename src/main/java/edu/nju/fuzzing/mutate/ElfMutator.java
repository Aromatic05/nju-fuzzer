package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class ElfMutator implements Mutator {

    private static final byte[] ELF_MAGIC = {0x7F, 'E', 'L', 'F'};

    private static final String[] SECTION_NAMES = {
            "", ".text", ".data", ".bss", ".rodata", ".shstrtab", ".symtab", ".strtab", ".rela.text", ".init", ".fini"
    };

    @Override
    public Iterator<Testcase> mutate(Seed seed, int energy) {
        // [修正1] 能量即数量，不再除以 5，确保测试用例能获得足够的样本
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
                return new Testcase(generateElf(), seed, "grammar:AdvancedELF");
            }
        };
    }

    private byte[] generateElf() {
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        try {
            ByteArrayOutputStream fileBuffer = new ByteArrayOutputStream();

            // 1. 预留 ELF Header 空间 (64 bytes)
            byte[] headerPlaceHolder = new byte[64];
            fileBuffer.write(headerPlaceHolder);

            // 2. 生成 Program Headers
            long phOffset = fileBuffer.size();
            int phNum = rand.nextInt(5) + 1;
            int declaredPhNum = (rand.nextInt(20) == 0) ? 0xFFFF : phNum; // Allocation Bomb

            for (int i = 0; i < phNum; i++) {
                fileBuffer.write(generateProgramHeader(rand));
            }

            // 3. 生成 String Table 数据
            long strTabOffset = fileBuffer.size();
            byte[] strTab = generateStringTable();
            fileBuffer.write(strTab);
            long strTabSize = strTab.length;

            // 4. 生成随机数据段
            long dataSectionOffset = fileBuffer.size();
            byte[] randomData = new byte[rand.nextInt(100) + 10];
            rand.nextBytes(randomData);
            fileBuffer.write(randomData);

            // 5. 生成 Section Headers
            long shOffset = fileBuffer.size();
            int shNum = 3;
            int declaredShNum = (rand.nextInt(20) == 0) ? 0xFFFF : shNum; // Allocation Bomb

            // Section 0: NULL
            fileBuffer.write(new byte[64]);

            // Section 1: .text
            int nameIdx1 = findStringIndex(".text");
            fileBuffer.write(generateSectionHeader(rand, nameIdx1, 1, 6, dataSectionOffset, randomData.length, 0));

            // Section 2: .shstrtab
            int nameIdx2 = findStringIndex(".shstrtab");
            // [Attack] Circular Link
            int link = (rand.nextInt(20) == 0) ? 1 : 0;
            fileBuffer.write(generateSectionHeader(rand, nameIdx2, 3, 0, strTabOffset, strTabSize, link));

            // [Attack] Extra Malformed Sections (OOB Offset)
            if (rand.nextBoolean()) {
                fileBuffer.write(generateSectionHeader(rand, 0, 0, 0, 0xFFFFFFFFL, 1000, 0));
                declaredShNum++;
            }

            // 6. 回填 ELF Header
            byte[] fileBytes = fileBuffer.toByteArray();
            ByteBuffer bb = ByteBuffer.wrap(fileBytes).order(ByteOrder.LITTLE_ENDIAN);

            // Magic & Class
            System.arraycopy(ELF_MAGIC, 0, fileBytes, 0, 4);
            bb.put(4, (byte) 2); // Class: 64-bit
            bb.put(5, (byte) 1); // Data: Little Endian
            bb.put(6, (byte) 1); // Version
            bb.put(7, (byte) 0); // OS ABI

            // [修正2] 使用 putShort 写入 e_type (2 bytes)
            bb.putShort(16, (short) (rand.nextBoolean() ? 2 : 3));
            bb.putShort(18, (short) 0x3E); // Machine: AMD64
            bb.putInt(20, 1); // Version

            bb.putLong(24, 0x400000); // Entry
            bb.putLong(32, phOffset); // Phdr Offset
            bb.putLong(40, shOffset); // Shdr Offset

            bb.putInt(48, 0); // Flags
            bb.putShort(52, (short) 64); // Ehdr size
            bb.putShort(54, (short) 56); // Phdr size
            bb.putShort(56, (short) declaredPhNum);
            bb.putShort(58, (short) 64); // Shdr size
            bb.putShort(60, (short) declaredShNum);
            bb.putShort(62, (short) 2); // e_shstrndx

            // [Attack] OOB Header Offsets (2% probability)
            if (rand.nextInt(50) == 0) bb.putLong(32, -1L); // Bad Phdr Offset
            if (rand.nextInt(50) == 0) bb.putLong(40, fileBytes.length + 100); // Bad Shdr Offset

            return fileBytes;

        } catch (IOException e) {
            return new byte[0];
        }
    }

    private byte[] generateProgramHeader(ThreadLocalRandom rand) {
        byte[] buf = new byte[56];
        ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN);

        int type = rand.nextInt(10);
        // [Attack] PT_NOTE (10% probability)
        if (rand.nextInt(10) == 0) type = 4;
        bb.putInt(0, type);

        bb.putInt(4, rand.nextInt(8)); // Flags
        long offset = rand.nextInt(4096);
        bb.putLong(8, offset);
        bb.putLong(16, 0x400000 + offset);
        bb.putLong(24, 0x400000 + offset);

        long filesz = rand.nextInt(1024);
        long memsz = filesz;
        bb.putLong(32, filesz);
        bb.putLong(40, memsz);
        bb.putLong(48, rand.nextBoolean() ? 0x1000 : 1);

        return buf;
    }

    private byte[] generateSectionHeader(ThreadLocalRandom rand, int nameIdx, int type, int flags, long offset, long size, int link) {
        byte[] buf = new byte[64];
        ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN);

        bb.putInt(0, nameIdx);
        if (type == -1) type = rand.nextInt(20);
        bb.putInt(4, type);
        bb.putLong(8, flags);
        bb.putLong(16, 0);

        // [Attack] OOB Section Offset
        if (rand.nextInt(20) == 0) offset = -1L;
        bb.putLong(24, offset);

        bb.putLong(32, size);

        if (link == -1) link = rand.nextInt(10);
        bb.putInt(40, link);

        bb.putInt(44, 0);
        bb.putLong(48, 4);
        bb.putLong(56, 0);

        return buf;
    }

    private byte[] generateStringTable() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (String s : SECTION_NAMES) {
            baos.write(s.getBytes(StandardCharsets.US_ASCII));
            baos.write(0);
        }
        return baos.toByteArray();
    }

    private int findStringIndex(String target) {
        int index = 0;
        for (String s : SECTION_NAMES) {
            if (s.equals(target)) return index;
            index += s.length() + 1;
        }
        return 0;
    }
}