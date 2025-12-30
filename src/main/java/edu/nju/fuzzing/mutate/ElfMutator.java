package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.binary.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 结构感知型 ELF 变异器
 *
 * 使用 ElfScanner 解析 seed 数据，提取 header 和 section 结构，
 * 然后通过 StructureMutator 进行有针对性的变异：
 * 1. Offset 字段变异 (e_phoff, e_shoff, sh_offset 等)
 * 2. Count 字段变异 (e_phnum, e_shnum)
 * 3. Section/Program Header 删除/复制
 * 4. Header 位翻转
 * 
 * 保留生成模式作为回退
 */
public class ElfMutator implements Mutator {

    private static final byte[] ELF_MAGIC = {0x7F, 'E', 'L', 'F'};

    private static final String[] SECTION_NAMES = {
            "", ".text", ".data", ".bss", ".rodata", ".shstrtab", ".symtab", ".strtab", ".rela.text", ".init", ".fini"
    };
    
    private final ElfScanner scanner = new ElfScanner();
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
                    byte[] elfData;
                    
                    // 如果成功解析了 seed，使用结构感知变异
                    if (finalScanResult != null && finalScanResult.isValid()) {
                        elfData = mutateFromSeed(finalScanResult);
                    } else {
                        // 回退到生成模式
                        elfData = generateElf();
                    }
                    
                    return new Testcase(elfData, seed, "structure:ELF");
                } catch (Exception e) {
                    return new Testcase(generateElf(), seed, "grammar:ELF");
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
        ByteOrder order = result.getByteOrder();
        boolean is64Bit = result.is64Bit();
        ThreadLocalRandom rand = ThreadLocalRandom.current();
        
        // 选择变异策略
        int strategy = rand.nextInt(10);
        
        if (strategy < 3) {
            // 30%: Offset 字段变异 (OOB 读取攻击)
            data = mutateOffsetFields(data, chunks, order, is64Bit, rand);
        } else if (strategy < 5) {
            // 20%: Count 字段变异 (分配炸弹)
            data = mutateCountFields(data, result.getGlobalFields(), order, is64Bit, rand);
        } else if (strategy < 7 && chunks.size() > 2) {
            // 20%: Header 删除/复制
            data = mutateHeaderStructure(data, chunks, rand);
        } else if (strategy < 9) {
            // 20%: 头部位翻转
            data = mutateHeaderBits(data, chunks, rand);
        } else {
            // 10%: Flags 变异
            data = mutateFlagsFields(data, chunks, rand);
        }
        
        // 确保 Magic 正确 (否则加载器直接拒绝)
        if (rand.nextInt(10) > 1) {
            data = ConstraintFixer.restoreElfMagic(data);
        }
        
        return data;
    }
    
    /**
     * Offset 字段变异 (e_phoff, e_shoff, sh_offset, p_offset)
     */
    private byte[] mutateOffsetFields(byte[] data, List<BinaryChunk> chunks, 
                                       ByteOrder order, boolean is64Bit, ThreadLocalRandom rand) {
        // 收集所有 offset 字段
        List<FieldMapping> offsetFields = new ArrayList<>();
        
        for (BinaryChunk chunk : chunks) {
            for (FieldMapping field : chunk.getFields()) {
                if (field.getType() == FieldType.OFFSET) {
                    int globalOffset = chunk.getStartOffset() + field.getOffset();
                    offsetFields.add(new FieldMapping(globalOffset, field.getLength(), 
                            field.getType(), order, field.getName()));
                }
            }
        }
        
        if (offsetFields.isEmpty()) return data;
        
        FieldMapping target = offsetFields.get(rand.nextInt(offsetFields.size()));
        return StructureMutator.mutateOffset(data, target, rand);
    }
    
    /**
     * Count 字段变异 (e_phnum, e_shnum) - 分配炸弹攻击
     */
    private byte[] mutateCountFields(byte[] data, List<FieldMapping> globalFields, 
                                      ByteOrder order, boolean is64Bit, ThreadLocalRandom rand) {
        // 找 e_phnum 或 e_shnum
        for (FieldMapping field : globalFields) {
            if (field.getType() == FieldType.COUNT && rand.nextBoolean()) {
                return StructureMutator.mutateCount(data, field, rand);
            }
        }
        return data;
    }
    
    /**
     * Header 结构变异：删除/复制 program/section header
     */
    private byte[] mutateHeaderStructure(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) throws IOException {
        // 找到 PHDR 或 SHDR chunks
        List<BinaryChunk> headers = new ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            String type = chunk.getChunkType();
            if (type.startsWith("PHDR_") || type.startsWith("SHDR_")) {
                // 跳过 NULL section
                if (!type.contains("NULL")) {
                    headers.add(chunk);
                }
            }
        }
        
        if (headers.isEmpty()) {
            return data;
        }
        
        int op = rand.nextInt(2);
        
        if (op == 0 && headers.size() > 1) {
            // 删除一个 header
            BinaryChunk toDelete = headers.get(rand.nextInt(headers.size()));
            return StructureMutator.deleteChunk(data, toDelete);
        } else {
            // 复制一个 header
            BinaryChunk toDuplicate = headers.get(rand.nextInt(headers.size()));
            return StructureMutator.duplicateChunk(data, toDuplicate);
        }
    }
    
    /**
     * 头部位翻转
     */
    private byte[] mutateHeaderBits(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // 找到 ELF_HEADER chunk
        BinaryChunk elfHeader = null;
        for (BinaryChunk chunk : chunks) {
            if ("ELF_HEADER".equals(chunk.getChunkType())) {
                elfHeader = chunk;
                break;
            }
        }
        
        if (elfHeader == null) return data;
        
        // 对头部进行位翻转 (跳过 magic)
        int startOffset = elfHeader.getStartOffset() + 4; // 跳过 magic
        int headerLen = elfHeader.getTotalLength() - 4;
        
        if (startOffset + headerLen > data.length || headerLen <= 0) return data;
        
        return StructureMutator.bitFlipDataRegion(data, startOffset, headerLen, rand);
    }
    
    /**
     * Flags 字段变异
     */
    private byte[] mutateFlagsFields(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        List<FieldMapping> flagsFields = new ArrayList<>();
        
        for (BinaryChunk chunk : chunks) {
            for (FieldMapping field : chunk.getFields()) {
                if (field.getType() == FieldType.FLAGS) {
                    int globalOffset = chunk.getStartOffset() + field.getOffset();
                    flagsFields.add(new FieldMapping(globalOffset, field.getLength(), 
                            field.getType(), field.getByteOrder(), field.getName()));
                }
            }
        }
        
        if (flagsFields.isEmpty()) return data;
        
        FieldMapping target = flagsFields.get(rand.nextInt(flagsFields.size()));
        return StructureMutator.mutateFlags(data, target, rand);
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