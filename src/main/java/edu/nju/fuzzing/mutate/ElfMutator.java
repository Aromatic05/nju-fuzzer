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
 * 
 * 变异策略（共15种）：
 * 1. Offset 字段变异 (e_phoff, e_shoff, sh_offset 等) - 触发 OOB 读取
 * 2. Count 字段变异 (e_phnum, e_shnum) - 分配炸弹攻击
 * 3. Section/Program Header 删除/复制 - 同步更新计数
 * 4. Header 位翻转 (跳过 e_ident 前16字节)
 * 5. Flags 变异
 * 6. Section Type 变异 - 触发特殊类型处理
 * 7. Entry Point 变异 - 触发地址验证
 * 8. Machine Type 变异 - 触发架构兼容性检查
 * 9. 耦合字段变异 - offset + size 同步
 * 10. Overlapping Sections - 触发区域重叠检查
 * 11. 组合变异 - 多种策略同时应用
 * 12. 激进变异 - 用于边界测试
 * 
 * 生成模式改进：
 * - Program Header 指向真实数据
 * - Section 数据区实际存在
 * - String Table 位置正确
 * - 支持 Big Endian
 * 
 * 约束保护：
 * - 95% 概率保护必需字段 (Magic, CLASS, DATA, VERSION, EHSIZE)
 */
public class ElfMutator implements Mutator {

    private static final byte[] ELF_MAGIC = { 0x7F, 'E', 'L', 'F' };

    private static final String[] SECTION_NAMES = {
            "", ".text", ".data", ".bss", ".rodata", ".shstrtab", ".symtab",
            ".strtab", ".rela.text", ".init", ".fini", ".dynamic", ".dynsym"
    };

    private final ElfScanner scanner = new ElfScanner();

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
                if (remaining <= 0)
                    throw new NoSuchElementException();
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

        // 选择变异策略 (扩展到15种策略)
        int strategy = rand.nextInt(15);

        if (strategy < 2) {
            // 13%: Offset 字段变异 (OOB 读取攻击)
            data = mutateOffsetFields(data, chunks, order, is64Bit, rand);
        } else if (strategy < 4) {
            // 13%: 耦合字段变异 (Offset + Size 同步)
            data = mutateCoupledFields(data, chunks, order, is64Bit, rand);
        } else if (strategy < 5) {
            // 7%: Count 字段变异 (分配炸弹)
            data = mutateCountFields(data, result.getGlobalFields(), order, is64Bit, rand);
        } else if (strategy < 7 && chunks.size() > 2) {
            // 13%: Header 删除/复制 (同步更新计数)
            data = mutateHeaderStructure(data, chunks, is64Bit, rand);
        } else if (strategy < 8) {
            // 7%: 头部位翻转 (跳过 e_ident)
            data = mutateHeaderBits(data, chunks, rand);
        } else if (strategy < 9) {
            // 7%: Flags 变异
            data = mutateFlagsFields(data, chunks, rand);
        } else if (strategy < 10) {
            // 7%: Section Type 变异
            data = mutateSectionTypes(data, chunks, rand);
        } else if (strategy < 11) {
            // 7%: Entry Point 变异
            data = mutateEntryPoint(data, result.getGlobalFields(), rand);
        } else if (strategy < 12) {
            // 7%: Machine Type 变异
            data = mutateMachineType(data, result.getGlobalFields(), rand);
        } else if (strategy < 13) {
            // 7%: Overlapping Sections
            data = createOverlappingSections(data, chunks, order, is64Bit, rand);
        } else if (strategy < 14) {
            // 7%: 组合变异 (多种策略)
            data = combinedMutation(data, chunks, result.getGlobalFields(), order, is64Bit, rand);
        } else {
            // 7%: 激进破坏 (用于边界测试)
            data = aggressiveMutation(data, chunks, rand);
        }

        // 保护必需字段 (95% 概率)
        if (rand.nextInt(20) > 0) {
            data = ConstraintFixer.fixElfHeaderEssentials(data, true);
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

        if (offsetFields.isEmpty())
            return data;

        FieldMapping target = offsetFields.get(rand.nextInt(offsetFields.size()));
        return StructureMutator.mutateOffset(data, target, rand);
    }

    /**
     * 耦合字段变异 - Offset 和 Size 同步变异
     */
    private byte[] mutateCoupledFields(byte[] data, List<BinaryChunk> chunks,
            ByteOrder order, boolean is64Bit, ThreadLocalRandom rand) {
        // 查找 offset-size 配对
        List<FieldMapping[]> pairs = new ArrayList<>();

        for (BinaryChunk chunk : chunks) {
            List<FieldMapping> fields = chunk.getFields();
            FieldMapping offsetField = null;
            FieldMapping sizeField = null;

            for (FieldMapping field : fields) {
                String name = field.getName();
                if (field.getType() == FieldType.OFFSET &&
                        (name.contains("offset") || name.contains("_off"))) {
                    offsetField = new FieldMapping(
                            chunk.getStartOffset() + field.getOffset(),
                            field.getLength(), field.getType(), order, name);
                } else if (field.getType() == FieldType.LENGTH &&
                        (name.contains("size") || name.contains("filesz"))) {
                    sizeField = new FieldMapping(
                            chunk.getStartOffset() + field.getOffset(),
                            field.getLength(), field.getType(), order, name);
                }
            }

            if (offsetField != null && sizeField != null) {
                pairs.add(new FieldMapping[] { offsetField, sizeField });
            }
        }

        if (pairs.isEmpty())
            return data;

        FieldMapping[] pair = pairs.get(rand.nextInt(pairs.size()));
        return StructureMutator.mutateCoupledOffsetSize(data, pair[0], pair[1], rand);
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
     * 同步更新 e_phnum/e_shnum 计数
     */
    private byte[] mutateHeaderStructure(byte[] data, List<BinaryChunk> chunks,
            boolean is64Bit, ThreadLocalRandom rand) throws IOException {
        // 找到 PHDR 或 SHDR chunks
        List<BinaryChunk> phdrs = new ArrayList<>();
        List<BinaryChunk> shdrs = new ArrayList<>();

        for (BinaryChunk chunk : chunks) {
            String type = chunk.getChunkType();
            if (type.startsWith("PHDR_") && !type.contains("NULL")) {
                phdrs.add(chunk);
            } else if (type.startsWith("SHDR_") && !type.contains("NULL")) {
                shdrs.add(chunk);
            }
        }

        boolean usePhdrs = rand.nextBoolean();
        List<BinaryChunk> headers = usePhdrs ? phdrs : shdrs;

        if (headers.isEmpty()) {
            headers = usePhdrs ? shdrs : phdrs;
            usePhdrs = !usePhdrs;
        }

        if (headers.isEmpty())
            return data;

        int op = rand.nextInt(3);

        if (op == 0 && headers.size() > 1) {
            // 删除一个 header，同步递减计数
            BinaryChunk toDelete = headers.get(rand.nextInt(headers.size()));
            data = StructureMutator.deleteChunk(data, toDelete);

            // 更新计数
            if (usePhdrs) {
                data = ConstraintFixer.decrementElfPhnum(data, is64Bit);
            } else {
                data = ConstraintFixer.decrementElfShnum(data, is64Bit);
            }
        } else if (op == 1) {
            // 复制一个 header，同步递增计数
            BinaryChunk toDuplicate = headers.get(rand.nextInt(headers.size()));
            data = StructureMutator.duplicateChunk(data, toDuplicate);

            // 更新计数
            if (usePhdrs) {
                data = ConstraintFixer.incrementElfPhnum(data, is64Bit);
            } else {
                data = ConstraintFixer.incrementElfShnum(data, is64Bit);
            }
        } else {
            // 故意不更新计数 (触发不一致检测)
            BinaryChunk toDelete = headers.get(rand.nextInt(headers.size()));
            data = StructureMutator.deleteChunk(data, toDelete);
            // 不更新计数，制造不一致
        }

        return data;
    }

    /**
     * 头部位翻转 - 跳过整个 e_ident (前16字节)
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

        if (elfHeader == null)
            return data;

        // 对头部进行位翻转 (跳过整个 e_ident，即前16字节)
        int startOffset = elfHeader.getStartOffset() + 16; // 跳过 e_ident
        int headerLen = elfHeader.getTotalLength() - 16;

        if (startOffset + headerLen > data.length || headerLen <= 0)
            return data;

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

        if (flagsFields.isEmpty())
            return data;

        FieldMapping target = flagsFields.get(rand.nextInt(flagsFields.size()));
        return StructureMutator.mutateFlags(data, target, rand);
    }

    /**
     * Section Type 变异 - 触发特殊类型处理逻辑
     */
    private byte[] mutateSectionTypes(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        List<FieldMapping> typeFields = new ArrayList<>();

        for (BinaryChunk chunk : chunks) {
            if (chunk.getChunkType().startsWith("SHDR_")) {
                for (FieldMapping field : chunk.getFields()) {
                    if ("sh_type".equals(field.getName())) {
                        int globalOffset = chunk.getStartOffset() + field.getOffset();
                        typeFields.add(new FieldMapping(globalOffset, field.getLength(),
                                field.getType(), field.getByteOrder(), field.getName()));
                    }
                }
            }
        }

        if (typeFields.isEmpty())
            return data;

        FieldMapping target = typeFields.get(rand.nextInt(typeFields.size()));
        return StructureMutator.mutateElfSectionType(data, target, rand);
    }

    /**
     * Entry Point 变异
     */
    private byte[] mutateEntryPoint(byte[] data, List<FieldMapping> globalFields, ThreadLocalRandom rand) {
        for (FieldMapping field : globalFields) {
            if ("e_entry".equals(field.getName())) {
                return StructureMutator.mutateElfEntryPoint(data, field, rand);
            }
        }
        return data;
    }

    /**
     * Machine Type 变异
     */
    private byte[] mutateMachineType(byte[] data, List<FieldMapping> globalFields, ThreadLocalRandom rand) {
        for (FieldMapping field : globalFields) {
            if ("e_machine".equals(field.getName())) {
                return StructureMutator.mutateElfMachineType(data, field, rand);
            }
        }
        return data;
    }

    /**
     * 创建重叠的 Sections
     */
    private byte[] createOverlappingSections(byte[] data, List<BinaryChunk> chunks,
            ByteOrder order, boolean is64Bit, ThreadLocalRandom rand) {
        // 找到两个 Section Header 的 offset 字段
        List<FieldMapping> shOffsets = new ArrayList<>();

        for (BinaryChunk chunk : chunks) {
            if (chunk.getChunkType().startsWith("SHDR_")) {
                for (FieldMapping field : chunk.getFields()) {
                    if ("sh_offset".equals(field.getName())) {
                        int globalOffset = chunk.getStartOffset() + field.getOffset();
                        shOffsets.add(new FieldMapping(globalOffset, field.getLength(),
                                field.getType(), order, field.getName()));
                    }
                }
            }
        }

        if (shOffsets.size() < 2)
            return data;

        int idx1 = rand.nextInt(shOffsets.size());
        int idx2;
        do {
            idx2 = rand.nextInt(shOffsets.size());
        } while (idx2 == idx1);

        return StructureMutator.createOverlappingSections(data, shOffsets.get(idx1), shOffsets.get(idx2), rand);
    }

    /**
     * 组合变异 - 同时应用多种策略
     */
    private byte[] combinedMutation(byte[] data, List<BinaryChunk> chunks,
            List<FieldMapping> globalFields,
            ByteOrder order, boolean is64Bit, ThreadLocalRandom rand) {
        int mutations = 2 + rand.nextInt(3); // 2-4 次变异

        for (int i = 0; i < mutations; i++) {
            int choice = rand.nextInt(6);
            switch (choice) {
                case 0:
                    data = mutateOffsetFields(data, chunks, order, is64Bit, rand);
                    break;
                case 1:
                    data = mutateFlagsFields(data, chunks, rand);
                    break;
                case 2:
                    data = mutateSectionTypes(data, chunks, rand);
                    break;
                case 3:
                    data = mutateEntryPoint(data, globalFields, rand);
                    break;
                case 4:
                    data = mutateMachineType(data, globalFields, rand);
                    break;
                case 5:
                    data = mutateHeaderBits(data, chunks, rand);
                    break;
            }
        }

        return data;
    }

    /**
     * 激进变异 - 用于边界测试
     */
    private byte[] aggressiveMutation(byte[] data, List<BinaryChunk> chunks, ThreadLocalRandom rand) {
        // 随机区域的大量位翻转
        int regionStart = 16 + rand.nextInt(Math.max(1, data.length - 32));
        int regionLen = Math.min(64, data.length - regionStart);

        data = StructureMutator.bitFlipDataRegion(data, regionStart, regionLen, rand);

        // 可能破坏 Magic (5% 概率)
        if (rand.nextInt(20) == 0) {
            data[rand.nextInt(4)] ^= (byte) (rand.nextInt(255) + 1);
        }

        return data;
    }

    /**
     * 生成有效的 ELF 文件 (改进版)
     * 
     * 改进点：
     * 1. Section 数据实际存在
     * 2. Program Header 指向真实数据
     * 3. String Table 位置正确
     * 4. 支持大端序 (15% 概率)
     */
    private byte[] generateElf() {
        ThreadLocalRandom rand = ThreadLocalRandom.current();

        try {
            ByteArrayOutputStream fileBuffer = new ByteArrayOutputStream();

            // 随机选择字节序 (15% 大端序)
            boolean useBigEndian = rand.nextInt(100) < 15;
            ByteOrder byteOrder = useBigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;

            // 1. 预留 ELF Header 空间 (64 bytes)
            byte[] headerPlaceHolder = new byte[64];
            fileBuffer.write(headerPlaceHolder);

            // 2. 生成 Program Headers
            long phOffset = fileBuffer.size();
            int phNum = rand.nextInt(5) + 1;
            int declaredPhNum = (rand.nextInt(20) == 0) ? 0xFFFF : phNum; // 5% Allocation Bomb

            for (int i = 0; i < phNum; i++) {
                fileBuffer.write(generateProgramHeaderPlaceholder(rand, byteOrder));
            }

            // 3. 生成 String Table 数据
            long strTabOffset = fileBuffer.size();
            byte[] strTab = generateStringTable();
            fileBuffer.write(strTab);
            long strTabSize = strTab.length;

            // 4. 生成实际的数据段 (记录 offset 和 size)
            Map<String, long[]> sectionData = new LinkedHashMap<>();

            // .text section
            long textOffset = fileBuffer.size();
            byte[] textData = new byte[rand.nextInt(200) + 50];
            rand.nextBytes(textData);
            fileBuffer.write(textData);
            sectionData.put(".text", new long[] { textOffset, textData.length });

            // .data section
            long dataOffset = fileBuffer.size();
            byte[] dataData = new byte[rand.nextInt(100) + 20];
            rand.nextBytes(dataData);
            fileBuffer.write(dataData);
            sectionData.put(".data", new long[] { dataOffset, dataData.length });

            // .rodata section
            long rodataOffset = fileBuffer.size();
            byte[] rodataData = "Hello, ELF Fuzzer!\0Test string data\0".getBytes(StandardCharsets.US_ASCII);
            fileBuffer.write(rodataData);
            sectionData.put(".rodata", new long[] { rodataOffset, rodataData.length });

            // 5. 生成 Section Headers
            long shOffset = fileBuffer.size();
            int shNum = 5; // NULL, .text, .data, .rodata, .shstrtab
            int declaredShNum = (rand.nextInt(20) == 0) ? 0xFFFF : shNum; // 5% Allocation Bomb

            // Section 0: NULL
            fileBuffer.write(new byte[64]);

            // Section 1: .text
            fileBuffer.write(generateSectionHeader(rand, byteOrder, findStringIndex(".text"),
                    1, 6, sectionData.get(".text")[0], sectionData.get(".text")[1], 0));

            // Section 2: .data
            fileBuffer.write(generateSectionHeader(rand, byteOrder, findStringIndex(".data"),
                    1, 3, sectionData.get(".data")[0], sectionData.get(".data")[1], 0));

            // Section 3: .rodata
            fileBuffer.write(generateSectionHeader(rand, byteOrder, findStringIndex(".rodata"),
                    1, 2, sectionData.get(".rodata")[0], sectionData.get(".rodata")[1], 0));

            // Section 4: .shstrtab
            int shstrtabIdx = 4;
            fileBuffer.write(generateSectionHeader(rand, byteOrder, findStringIndex(".shstrtab"),
                    3, 0, strTabOffset, strTabSize, 0));

            // [Attack] 额外畸形 Section (5% OOB Offset)
            if (rand.nextInt(20) == 0) {
                fileBuffer.write(generateSectionHeader(rand, byteOrder, 0, 0, 0, 0xFFFFFFFFL, 1000, 0));
                declaredShNum++;
            }

            // 6. 回填 ELF Header
            byte[] fileBytes = fileBuffer.toByteArray();
            ByteBuffer bb = ByteBuffer.wrap(fileBytes).order(byteOrder);

            // Magic & e_ident
            System.arraycopy(ELF_MAGIC, 0, fileBytes, 0, 4);
            fileBytes[4] = 2; // Class: 64-bit (直接数组操作)
            fileBytes[5] = (byte) (useBigEndian ? 2 : 1); // Data encoding
            fileBytes[6] = 1; // Version
            fileBytes[7] = 0; // OS ABI

            // e_type, e_machine
            bb.putShort(16, (short) (rand.nextBoolean() ? 2 : 3)); // ET_EXEC or ET_DYN
            bb.putShort(18, (short) 0x3E); // Machine: AMD64
            bb.putInt(20, 1); // Version

            bb.putLong(24, 0x400000 + sectionData.get(".text")[0]); // Entry - 指向 .text
            bb.putLong(32, phOffset); // Phdr Offset
            bb.putLong(40, shOffset); // Shdr Offset

            bb.putInt(48, 0); // Flags
            bb.putShort(52, (short) 64); // Ehdr size
            bb.putShort(54, (short) 56); // Phdr size
            bb.putShort(56, (short) declaredPhNum);
            bb.putShort(58, (short) 64); // Shdr size
            bb.putShort(60, (short) declaredShNum);
            bb.putShort(62, (short) shstrtabIdx); // e_shstrndx

            // 7. 回填 Program Headers (指向真实数据)
            int phdrPos = (int) phOffset;
            for (String secName : new String[] { ".text", ".data", ".rodata" }) {
                if (phdrPos + 56 > fileBytes.length)
                    break;
                if (!sectionData.containsKey(secName))
                    continue;

                long[] info = sectionData.get(secName);

                // 使用主 ByteBuffer 的绝对位置操作
                int pType = secName.equals(".text") ? 1 : (rand.nextInt(5) + 1); // PT_LOAD for .text
                bb.putInt(phdrPos, pType);
                bb.putInt(phdrPos + 4, secName.equals(".text") ? 5 : 6); // Flags: RE or RW
                bb.putLong(phdrPos + 8, info[0]); // p_offset - 指向真实数据
                bb.putLong(phdrPos + 16, 0x400000 + info[0]); // p_vaddr
                bb.putLong(phdrPos + 24, 0x400000 + info[0]); // p_paddr
                bb.putLong(phdrPos + 32, info[1]); // p_filesz - 真实大小
                bb.putLong(phdrPos + 40, info[1]); // p_memsz
                bb.putLong(phdrPos + 48, 0x1000); // p_align

                phdrPos += 56;
            }

            // [Attack] OOB Header Offsets (2% probability)
            if (rand.nextInt(50) == 0)
                bb.putLong(32, -1L); // Bad Phdr Offset
            if (rand.nextInt(50) == 0)
                bb.putLong(40, fileBytes.length + 100); // Bad Shdr Offset

            return fileBytes;

        } catch (IOException e) {
            return new byte[0];
        }
    }

    private byte[] generateProgramHeaderPlaceholder(ThreadLocalRandom rand, ByteOrder order) {
        byte[] buf = new byte[56];
        ByteBuffer bb = ByteBuffer.wrap(buf).order(order);

        // 占位，后续回填
        bb.putInt(0, 1); // PT_LOAD
        bb.putInt(4, 5); // PF_R | PF_X
        bb.putLong(48, 0x1000); // align

        return buf;
    }

    private byte[] generateSectionHeader(ThreadLocalRandom rand, ByteOrder order,
            int nameIdx, int type, int flags,
            long offset, long size, int link) {
        byte[] buf = new byte[64];
        ByteBuffer bb = ByteBuffer.wrap(buf).order(order);

        bb.putInt(0, nameIdx);
        bb.putInt(4, type);
        bb.putLong(8, flags);
        bb.putLong(16, 0); // sh_addr

        // [Attack] 偶尔使用 OOB offset (2%)
        if (rand.nextInt(50) == 0)
            offset = -1L;
        bb.putLong(24, offset);

        bb.putLong(32, size);
        bb.putInt(40, link);
        bb.putInt(44, 0); // sh_info
        bb.putLong(48, 4); // sh_addralign
        bb.putLong(56, 0); // sh_entsize

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
            if (s.equals(target))
                return index;
            index += s.length() + 1;
        }
        return 0;
    }
}
