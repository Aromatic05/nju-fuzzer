package edu.nju.fuzzing.mutate.binary;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * ElfScanner 单元测试
 * 
 * 验证点：
 * 1. Magic 识别
 * 2. ELF Header 解析 (32/64 位)
 * 3. Program Header 解析
 * 4. Section Header 解析
 * 5. 字段映射正确性
 */
class ElfScannerTest {

    private ElfScanner scanner;
    private static final byte[] ELF_MAGIC = { 0x7F, 'E', 'L', 'F' };

    @BeforeEach
    void setUp() {
        scanner = new ElfScanner();
    }

    // ==========================================
    // Magic 识别测试
    // ==========================================

    @Test
    @DisplayName("matches() - 有效 ELF 签名")
    void testMatchesValidElf() {
        byte[] elf = createMinimalElf64();
        assertTrue(scanner.matches(elf));
    }

    @Test
    @DisplayName("matches() - 无效签名被拒绝")
    void testMatchesInvalidSignature() {
        byte[] invalid = { 0x00, 0x01, 0x02, 0x03 };
        assertFalse(scanner.matches(invalid));
    }

    @Test
    @DisplayName("matches() - 空数据被拒绝")
    void testMatchesEmptyData() {
        assertFalse(scanner.matches(new byte[0]));
        assertFalse(scanner.matches(null));
    }

    @Test
    @DisplayName("matches() - 太短的数据被拒绝")
    void testMatchesTooShort() {
        byte[] tooShort = { 0x7F, 'E', 'L' };
        assertFalse(scanner.matches(tooShort));
    }

    // ==========================================
    // ELF Header 解析测试
    // ==========================================

    @Test
    @DisplayName("scan() - 解析 64 位 ELF Header")
    void testScan64BitElf() {
        byte[] elf = createMinimalElf64();
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());
        assertEquals("ELF", result.getFormatType());
        assertTrue(result.is64Bit());
        assertEquals(ByteOrder.LITTLE_ENDIAN, result.getByteOrder());

        List<BinaryChunk> chunks = result.getChunks();
        assertFalse(chunks.isEmpty());

        BinaryChunk header = chunks.get(0);
        assertEquals("ELF_HEADER", header.getChunkType());
        assertTrue(header.isCritical());
    }

    @Test
    @DisplayName("scan() - 解析 32 位 ELF Header")
    void testScan32BitElf() {
        byte[] elf = createMinimalElf32();
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());
        assertFalse(result.is64Bit());
    }

    @Test
    @DisplayName("scan() - Header 字段映射正确")
    void testHeaderFieldMappings() {
        byte[] elf = createMinimalElf64();
        ScanResult result = scanner.scan(elf);

        List<FieldMapping> globalFields = result.getGlobalFields();
        assertFalse(globalFields.isEmpty());

        // 验证 magic 字段
        boolean hasMagic = globalFields.stream()
                .anyMatch(f -> "e_ident_magic".equals(f.getName()) && f.getType() == FieldType.MAGIC);
        assertTrue(hasMagic, "应该有 e_ident_magic 字段");

        // 验证 e_type 字段
        boolean hasType = globalFields.stream()
                .anyMatch(f -> "e_type".equals(f.getName()) && f.getType() == FieldType.TYPE);
        assertTrue(hasType, "应该有 e_type 字段");

        // 验证 e_phoff 字段
        boolean hasPhoff = globalFields.stream()
                .anyMatch(f -> "e_phoff".equals(f.getName()) && f.getType() == FieldType.OFFSET);
        assertTrue(hasPhoff, "应该有 e_phoff 字段");

        // 验证 e_shoff 字段
        boolean hasShoff = globalFields.stream()
                .anyMatch(f -> "e_shoff".equals(f.getName()) && f.getType() == FieldType.OFFSET);
        assertTrue(hasShoff, "应该有 e_shoff 字段");

        // 验证 e_phnum 字段
        boolean hasPhnum = globalFields.stream()
                .anyMatch(f -> "e_phnum".equals(f.getName()) && f.getType() == FieldType.COUNT);
        assertTrue(hasPhnum, "应该有 e_phnum 字段");

        // 验证 e_shnum 字段
        boolean hasShnum = globalFields.stream()
                .anyMatch(f -> "e_shnum".equals(f.getName()) && f.getType() == FieldType.COUNT);
        assertTrue(hasShnum, "应该有 e_shnum 字段");
    }

    // ==========================================
    // Program Header 解析测试
    // ==========================================

    @Test
    @DisplayName("scan() - 解析 Program Headers")
    void testScanProgramHeaders() {
        byte[] elf = createElfWithProgramHeaders(2);
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());

        long phdrCount = result.getChunks().stream()
                .filter(c -> c.getChunkType().startsWith("PHDR_"))
                .count();
        assertEquals(2, phdrCount);
    }

    @Test
    @DisplayName("scan() - Program Header 字段映射")
    void testProgramHeaderFields() {
        byte[] elf = createElfWithProgramHeaders(1);
        ScanResult result = scanner.scan(elf);

        BinaryChunk phdr = result.getChunks().stream()
                .filter(c -> c.getChunkType().startsWith("PHDR_"))
                .findFirst()
                .orElse(null);
        assertNotNull(phdr);

        List<FieldMapping> fields = phdr.getFields();

        // 验证 p_type 字段
        boolean hasPType = fields.stream()
                .anyMatch(f -> "p_type".equals(f.getName()) && f.getType() == FieldType.TYPE);
        assertTrue(hasPType, "应该有 p_type 字段");

        // 验证 p_offset 字段
        boolean hasPOffset = fields.stream()
                .anyMatch(f -> "p_offset".equals(f.getName()) && f.getType() == FieldType.OFFSET);
        assertTrue(hasPOffset, "应该有 p_offset 字段");

        // 验证 p_filesz 字段
        boolean hasPFilesz = fields.stream()
                .anyMatch(f -> "p_filesz".equals(f.getName()) && f.getType() == FieldType.LENGTH);
        assertTrue(hasPFilesz, "应该有 p_filesz 字段");
    }

    // ==========================================
    // Section Header 解析测试
    // ==========================================

    @Test
    @DisplayName("scan() - 解析 Section Headers")
    void testScanSectionHeaders() {
        byte[] elf = createElfWithSectionHeaders(3);
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());

        long shdrCount = result.getChunks().stream()
                .filter(c -> c.getChunkType().startsWith("SHDR_"))
                .count();
        assertEquals(3, shdrCount);
    }

    @Test
    @DisplayName("scan() - Section Header 字段映射")
    void testSectionHeaderFields() {
        byte[] elf = createElfWithSectionHeaders(1);
        ScanResult result = scanner.scan(elf);

        BinaryChunk shdr = result.getChunks().stream()
                .filter(c -> c.getChunkType().startsWith("SHDR_"))
                .findFirst()
                .orElse(null);
        assertNotNull(shdr);

        List<FieldMapping> fields = shdr.getFields();

        // 验证 sh_type 字段
        boolean hasShType = fields.stream()
                .anyMatch(f -> "sh_type".equals(f.getName()) && f.getType() == FieldType.TYPE);
        assertTrue(hasShType, "应该有 sh_type 字段");

        // 验证 sh_offset 字段
        boolean hasShOffset = fields.stream()
                .anyMatch(f -> "sh_offset".equals(f.getName()) && f.getType() == FieldType.OFFSET);
        assertTrue(hasShOffset, "应该有 sh_offset 字段");

        // 验证 sh_size 字段
        boolean hasShSize = fields.stream()
                .anyMatch(f -> "sh_size".equals(f.getName()) && f.getType() == FieldType.LENGTH);
        assertTrue(hasShSize, "应该有 sh_size 字段");
    }

    // ==========================================
    // 边界条件测试
    // ==========================================

    @Test
    @DisplayName("scan() - 无效数据返回无效结果")
    void testScanInvalidData() {
        byte[] invalid = { 0x00, 0x01, 0x02, 0x03 };
        ScanResult result = scanner.scan(invalid);
        assertFalse(result.isValid());
    }

    @Test
    @DisplayName("scan() - 仅 Header (无 Program/Section Headers)")
    void testScanHeaderOnly() {
        byte[] elf = createMinimalElf64();
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());
        // 仅有 ELF Header
        assertEquals(1, result.getChunks().size());
    }

    @Test
    @DisplayName("getFormatName() - 返回 ELF")
    void testGetFormatName() {
        assertEquals("ELF", scanner.getFormatName());
    }

    // ==========================================
    // 辅助方法
    // ==========================================

    private byte[] createMinimalElf64() {
        byte[] elf = new byte[64];
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        // e_ident
        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT

        // e_type
        bb.putShort(16, (short) 2); // ET_EXEC
        // e_machine
        bb.putShort(18, (short) 0x3E); // EM_X86_64
        // e_version
        bb.putInt(20, 1);
        // e_entry
        bb.putLong(24, 0x400000);
        // e_phoff
        bb.putLong(32, 0);
        // e_shoff
        bb.putLong(40, 0);
        // e_flags
        bb.putInt(48, 0);
        // e_ehsize
        bb.putShort(52, (short) 64);
        // e_phentsize
        bb.putShort(54, (short) 56);
        // e_phnum
        bb.putShort(56, (short) 0);
        // e_shentsize
        bb.putShort(58, (short) 64);
        // e_shnum
        bb.putShort(60, (short) 0);
        // e_shstrndx
        bb.putShort(62, (short) 0);

        return elf;
    }

    private byte[] createMinimalElf32() {
        byte[] elf = new byte[52];
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        // e_ident
        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 1; // ELFCLASS32
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT

        // e_type
        bb.putShort(16, (short) 2); // ET_EXEC
        // e_machine
        bb.putShort(18, (short) 3); // EM_386
        // e_version
        bb.putInt(20, 1);
        // e_entry
        bb.putInt(24, 0x8048000);
        // e_phoff
        bb.putInt(28, 0);
        // e_shoff
        bb.putInt(32, 0);
        // e_flags
        bb.putInt(36, 0);
        // e_ehsize
        bb.putShort(40, (short) 52);
        // e_phentsize
        bb.putShort(42, (short) 32);
        // e_phnum
        bb.putShort(44, (short) 0);
        // e_shentsize
        bb.putShort(46, (short) 40);
        // e_shnum
        bb.putShort(48, (short) 0);
        // e_shstrndx
        bb.putShort(50, (short) 0);

        return elf;
    }

    private byte[] createElfWithProgramHeaders(int count) {
        int phoff = 64;
        int phentsize = 56;
        int totalSize = 64 + count * phentsize;

        byte[] elf = new byte[totalSize];
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        // ELF Header
        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1;

        bb.putShort(16, (short) 2);
        bb.putShort(18, (short) 0x3E);
        bb.putInt(20, 1);
        bb.putLong(24, 0x400000);
        bb.putLong(32, phoff); // e_phoff
        bb.putLong(40, 0); // e_shoff
        bb.putInt(48, 0);
        bb.putShort(52, (short) 64);
        bb.putShort(54, (short) phentsize);
        bb.putShort(56, (short) count); // e_phnum
        bb.putShort(58, (short) 64);
        bb.putShort(60, (short) 0);
        bb.putShort(62, (short) 0);

        // Program Headers
        for (int i = 0; i < count; i++) {
            int offset = phoff + i * phentsize;
            bb.putInt(offset, 1); // p_type = PT_LOAD
            bb.putInt(offset + 4, 5); // p_flags = PF_R | PF_X
            bb.putLong(offset + 8, 0); // p_offset
            bb.putLong(offset + 16, 0x400000); // p_vaddr
            bb.putLong(offset + 24, 0x400000); // p_paddr
            bb.putLong(offset + 32, 0x1000); // p_filesz
            bb.putLong(offset + 40, 0x1000); // p_memsz
            bb.putLong(offset + 48, 0x1000); // p_align
        }

        return elf;
    }

    private byte[] createElfWithSectionHeaders(int count) {
        int shoff = 64;
        int shentsize = 64;
        int totalSize = 64 + count * shentsize;

        byte[] elf = new byte[totalSize];
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        // ELF Header
        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1;

        bb.putShort(16, (short) 2);
        bb.putShort(18, (short) 0x3E);
        bb.putInt(20, 1);
        bb.putLong(24, 0x400000);
        bb.putLong(32, 0); // e_phoff
        bb.putLong(40, shoff); // e_shoff
        bb.putInt(48, 0);
        bb.putShort(52, (short) 64);
        bb.putShort(54, (short) 56);
        bb.putShort(56, (short) 0);
        bb.putShort(58, (short) shentsize);
        bb.putShort(60, (short) count); // e_shnum
        bb.putShort(62, (short) 0);

        // Section Headers
        for (int i = 0; i < count; i++) {
            int offset = shoff + i * shentsize;
            bb.putInt(offset, 0); // sh_name
            bb.putInt(offset + 4, 1); // sh_type = SHT_PROGBITS
            bb.putLong(offset + 8, 6); // sh_flags = SHF_ALLOC | SHF_EXECINSTR
            bb.putLong(offset + 16, 0x400000); // sh_addr
            bb.putLong(offset + 24, 0); // sh_offset
            bb.putLong(offset + 32, 0x100); // sh_size
            bb.putInt(offset + 40, 0); // sh_link
            bb.putInt(offset + 44, 0); // sh_info
            bb.putLong(offset + 48, 16); // sh_addralign
            bb.putLong(offset + 56, 0); // sh_entsize
        }

        return elf;
    }

    // ==========================================
    // 32位 ELF 带 Headers 测试
    // ==========================================

    @Test
    @DisplayName("scan() - 32位 ELF 带 Program Headers")
    void testScan32BitWithProgramHeaders() {
        byte[] elf = createElf32WithProgramHeaders(2);
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());
        assertFalse(result.is64Bit());

        long phdrCount = result.getChunks().stream()
                .filter(c -> c.getChunkType().startsWith("PHDR_"))
                .count();
        assertEquals(2, phdrCount);
    }

    @Test
    @DisplayName("scan() - 32位 ELF 带 Section Headers")
    void testScan32BitWithSectionHeaders() {
        byte[] elf = createElf32WithSectionHeaders(2);
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());
        assertFalse(result.is64Bit());

        long shdrCount = result.getChunks().stream()
                .filter(c -> c.getChunkType().startsWith("SHDR_"))
                .count();
        assertEquals(2, shdrCount);
    }

    @Test
    @DisplayName("scan() - 32位 Program Header 字段映射")
    void testProgramHeader32Fields() {
        byte[] elf = createElf32WithProgramHeaders(1);
        ScanResult result = scanner.scan(elf);

        BinaryChunk phdr = result.getChunks().stream()
                .filter(c -> c.getChunkType().startsWith("PHDR_"))
                .findFirst()
                .orElse(null);
        assertNotNull(phdr);

        List<FieldMapping> fields = phdr.getFields();

        // 32位 ELF p_flags 在偏移 24
        boolean hasFlags = fields.stream()
                .anyMatch(f -> "p_flags".equals(f.getName()) && f.getType() == FieldType.FLAGS);
        assertTrue(hasFlags, "32位应该有 p_flags 字段");
    }

    @Test
    @DisplayName("scan() - 32位 Section Header 字段映射")
    void testSectionHeader32Fields() {
        byte[] elf = createElf32WithSectionHeaders(1);
        ScanResult result = scanner.scan(elf);

        BinaryChunk shdr = result.getChunks().stream()
                .filter(c -> c.getChunkType().startsWith("SHDR_"))
                .findFirst()
                .orElse(null);
        assertNotNull(shdr);

        List<FieldMapping> fields = shdr.getFields();
        assertEquals(10, fields.size()); // 32位有10个字段
    }

    // ==========================================
    // 大端序 (Big Endian) 测试
    // ==========================================

    @Test
    @DisplayName("scan() - 大端序 64位 ELF")
    void testScanBigEndian64() {
        byte[] elf = createBigEndianElf64();
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());
        assertEquals(ByteOrder.BIG_ENDIAN, result.getByteOrder());
        assertTrue(result.is64Bit());
    }

    @Test
    @DisplayName("scan() - 大端序 32位 ELF")
    void testScanBigEndian32() {
        byte[] elf = createBigEndianElf32();
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());
        assertEquals(ByteOrder.BIG_ENDIAN, result.getByteOrder());
        assertFalse(result.is64Bit());
    }

    // ==========================================
    // 段类型名称测试 (getSegmentTypeName)
    // ==========================================

    @Test
    @DisplayName("scan() - 各种 Program Header 类型")
    void testVariousProgramHeaderTypes() {
        // 创建包含多种段类型的 ELF
        int[] segmentTypes = { 0, 1, 2, 3, 4, 5, 6, 7, 0x6474e550 }; // NULL, LOAD, DYNAMIC, INTERP, NOTE, SHLIB, PHDR,
                                                                     // TLS, 未知
        byte[] elf = createElfWithVariousProgramHeaders(segmentTypes);
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());

        List<BinaryChunk> chunks = result.getChunks();
        // 验证有对应的段
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("NULL")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("LOAD")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("DYNAMIC")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("INTERP")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("NOTE")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("SHLIB")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("PHDR")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("TLS")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("0x"))); // 未知类型
    }

    // ==========================================
    // 节类型名称测试 (getSectionTypeName)
    // ==========================================

    @Test
    @DisplayName("scan() - 各种 Section Header 类型")
    void testVariousSectionHeaderTypes() {
        // 创建包含多种节类型的 ELF
        int[] sectionTypes = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 0x7FFFFFFF };
        // NULL, PROGBITS, SYMTAB, STRTAB, RELA, HASH, DYNAMIC, NOTE, NOBITS, REL,
        // DYNSYM, 未知
        byte[] elf = createElfWithVariousSectionHeaders(sectionTypes);
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());

        List<BinaryChunk> chunks = result.getChunks();
        // 验证各种节类型
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("NULL")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("PROGBITS")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("SYMTAB")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("STRTAB")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("RELA")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("HASH")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("DYNAMIC")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("NOTE")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("NOBITS")));
        assertTrue(
                chunks.stream().anyMatch(c -> c.getChunkType().contains("REL") && !c.getChunkType().contains("RELA")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("DYNSYM")));
        assertTrue(chunks.stream().anyMatch(c -> c.getChunkType().contains("0x"))); // 未知类型
    }

    @Test
    @DisplayName("scan() - 关键节类型标记为 critical")
    void testCriticalSectionTypes() {
        // DYNAMIC(6), SYMTAB(2), DYNSYM(11) 应该是 critical
        int[] sectionTypes = { 1, 2, 6, 11 };
        byte[] elf = createElfWithVariousSectionHeaders(sectionTypes);
        ScanResult result = scanner.scan(elf);

        assertTrue(result.isValid());

        List<BinaryChunk> criticalChunks = result.getCriticalChunks();
        // ELF_HEADER 也是 critical，所以至少有 4 个 (header + SYMTAB + DYNAMIC + DYNSYM)
        assertTrue(criticalChunks.size() >= 4);
    }

    // ==========================================
    // 边界条件测试
    // ==========================================

    @Test
    @DisplayName("scan() - Header 太短无法解析")
    void testScanHeaderTooShort() {
        byte[] elf = new byte[30]; // 太短
        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 2; // ELFCLASS64

        ScanResult result = scanner.scan(elf);
        assertFalse(result.isValid());
    }

    @Test
    @DisplayName("scan() - Program Header 偏移超出文件范围")
    void testScanProgramHeaderOutOfBounds() {
        byte[] elf = createMinimalElf64();
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        bb.putLong(32, 1000); // e_phoff 指向超出范围
        bb.putShort(56, (short) 2); // e_phnum = 2

        ScanResult result = scanner.scan(elf);
        // 应该成功但没有 program headers
        assertTrue(result.isValid());
        long phdrCount = result.getChunks().stream()
                .filter(c -> c.getChunkType().startsWith("PHDR_"))
                .count();
        assertEquals(0, phdrCount);
    }

    @Test
    @DisplayName("scan() - Section Header 偏移超出文件范围")
    void testScanSectionHeaderOutOfBounds() {
        byte[] elf = createMinimalElf64();
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        bb.putLong(40, 1000); // e_shoff 指向超出范围
        bb.putShort(60, (short) 2); // e_shnum = 2

        ScanResult result = scanner.scan(elf);
        assertTrue(result.isValid());
        long shdrCount = result.getChunks().stream()
                .filter(c -> c.getChunkType().startsWith("SHDR_"))
                .count();
        assertEquals(0, shdrCount);
    }

    @Test
    @DisplayName("scan() - 声明的 Header 数量超过实际空间")
    void testScanDeclaredHeadersExceedSpace() {
        // 创建一个 ELF，声称有3个 program headers，但文件只有1个的空间
        // 代码会检查 phoff + phnum * phentsize <= data.length
        // 如果失败，整个 program header 解析被跳过
        int phoff = 64;
        int phentsize = 56;
        // 只有第一个 header 的空间
        byte[] elf = new byte[64 + phentsize];
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;

        bb.putShort(16, (short) 2);
        bb.putShort(18, (short) 0x3E);
        bb.putInt(20, 1);
        bb.putLong(24, 0x400000);
        bb.putLong(32, phoff);
        bb.putLong(40, 0);
        bb.putInt(48, 0);
        bb.putShort(52, (short) 64);
        bb.putShort(54, (short) phentsize);
        bb.putShort(56, (short) 3); // 声称有3个，但只有1个的空间
        bb.putShort(58, (short) 64);
        bb.putShort(60, (short) 0);
        bb.putShort(62, (short) 0);

        // 第一个 program header
        bb.putInt(phoff, 1); // p_type = PT_LOAD

        ScanResult result = scanner.scan(elf);
        assertTrue(result.isValid());
        // 由于 phoff + phnum * phentsize > data.length，整个 program header 解析被跳过
        // 所以应该有 0 个 program headers
        long phdrCount = result.getChunks().stream()
                .filter(c -> c.getChunkType().startsWith("PHDR_"))
                .count();
        assertEquals(0, phdrCount);
    }

    // ==========================================
    // 32位辅助方法
    // ==========================================

    private byte[] createElf32WithProgramHeaders(int count) {
        int phoff = 52;
        int phentsize = 32;
        int totalSize = 52 + count * phentsize;

        byte[] elf = new byte[totalSize];
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        // ELF Header
        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 1; // ELFCLASS32
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1;

        bb.putShort(16, (short) 2);
        bb.putShort(18, (short) 3); // EM_386
        bb.putInt(20, 1);
        bb.putInt(24, 0x8048000); // e_entry
        bb.putInt(28, phoff); // e_phoff
        bb.putInt(32, 0); // e_shoff
        bb.putInt(36, 0);
        bb.putShort(40, (short) 52);
        bb.putShort(42, (short) phentsize);
        bb.putShort(44, (short) count); // e_phnum
        bb.putShort(46, (short) 40);
        bb.putShort(48, (short) 0);
        bb.putShort(50, (short) 0);

        // Program Headers (32位格式)
        for (int i = 0; i < count; i++) {
            int offset = phoff + i * phentsize;
            bb.putInt(offset, 1); // p_type = PT_LOAD
            bb.putInt(offset + 4, 0); // p_offset
            bb.putInt(offset + 8, 0x8048000); // p_vaddr
            bb.putInt(offset + 12, 0x8048000); // p_paddr
            bb.putInt(offset + 16, 0x1000); // p_filesz
            bb.putInt(offset + 20, 0x1000); // p_memsz
            bb.putInt(offset + 24, 5); // p_flags = PF_R | PF_X
            bb.putInt(offset + 28, 0x1000); // p_align
        }

        return elf;
    }

    private byte[] createElf32WithSectionHeaders(int count) {
        int shoff = 52;
        int shentsize = 40;
        int totalSize = 52 + count * shentsize;

        byte[] elf = new byte[totalSize];
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        // ELF Header
        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 1; // ELFCLASS32
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1;

        bb.putShort(16, (short) 2);
        bb.putShort(18, (short) 3);
        bb.putInt(20, 1);
        bb.putInt(24, 0x8048000);
        bb.putInt(28, 0); // e_phoff
        bb.putInt(32, shoff); // e_shoff
        bb.putInt(36, 0);
        bb.putShort(40, (short) 52);
        bb.putShort(42, (short) 32);
        bb.putShort(44, (short) 0);
        bb.putShort(46, (short) shentsize);
        bb.putShort(48, (short) count); // e_shnum
        bb.putShort(50, (short) 0);

        // Section Headers (32位格式)
        for (int i = 0; i < count; i++) {
            int offset = shoff + i * shentsize;
            bb.putInt(offset, 0); // sh_name
            bb.putInt(offset + 4, 1); // sh_type = SHT_PROGBITS
            bb.putInt(offset + 8, 6); // sh_flags
            bb.putInt(offset + 12, 0x8048000); // sh_addr
            bb.putInt(offset + 16, 0); // sh_offset
            bb.putInt(offset + 20, 0x100); // sh_size
            bb.putInt(offset + 24, 0); // sh_link
            bb.putInt(offset + 28, 0); // sh_info
            bb.putInt(offset + 32, 16); // sh_addralign
            bb.putInt(offset + 36, 0); // sh_entsize
        }

        return elf;
    }

    // ==========================================
    // 大端序辅助方法
    // ==========================================

    private byte[] createBigEndianElf64() {
        byte[] elf = new byte[64];
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.BIG_ENDIAN);

        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 2; // ELFCLASS64
        elf[5] = 2; // ELFDATA2MSB (大端)
        elf[6] = 1;

        bb.putShort(16, (short) 2);
        bb.putShort(18, (short) 0x15); // EM_PARISC (使用大端的架构)
        bb.putInt(20, 1);
        bb.putLong(24, 0x400000);
        bb.putLong(32, 0);
        bb.putLong(40, 0);
        bb.putInt(48, 0);
        bb.putShort(52, (short) 64);
        bb.putShort(54, (short) 56);
        bb.putShort(56, (short) 0);
        bb.putShort(58, (short) 64);
        bb.putShort(60, (short) 0);
        bb.putShort(62, (short) 0);

        return elf;
    }

    private byte[] createBigEndianElf32() {
        byte[] elf = new byte[52];
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.BIG_ENDIAN);

        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 1; // ELFCLASS32
        elf[5] = 2; // ELFDATA2MSB (大端)
        elf[6] = 1;

        bb.putShort(16, (short) 2);
        bb.putShort(18, (short) 0x14); // EM_PPC
        bb.putInt(20, 1);
        bb.putInt(24, 0x10000000);
        bb.putInt(28, 0);
        bb.putInt(32, 0);
        bb.putInt(36, 0);
        bb.putShort(40, (short) 52);
        bb.putShort(42, (short) 32);
        bb.putShort(44, (short) 0);
        bb.putShort(46, (short) 40);
        bb.putShort(48, (short) 0);
        bb.putShort(50, (short) 0);

        return elf;
    }

    // ==========================================
    // 多种类型辅助方法
    // ==========================================

    private byte[] createElfWithVariousProgramHeaders(int[] types) {
        int phoff = 64;
        int phentsize = 56;
        int totalSize = 64 + types.length * phentsize;

        byte[] elf = new byte[totalSize];
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;

        bb.putShort(16, (short) 2);
        bb.putShort(18, (short) 0x3E);
        bb.putInt(20, 1);
        bb.putLong(24, 0x400000);
        bb.putLong(32, phoff);
        bb.putLong(40, 0);
        bb.putInt(48, 0);
        bb.putShort(52, (short) 64);
        bb.putShort(54, (short) phentsize);
        bb.putShort(56, (short) types.length);
        bb.putShort(58, (short) 64);
        bb.putShort(60, (short) 0);
        bb.putShort(62, (short) 0);

        for (int i = 0; i < types.length; i++) {
            int offset = phoff + i * phentsize;
            bb.putInt(offset, types[i]); // p_type
            bb.putInt(offset + 4, 5);
            bb.putLong(offset + 8, 0);
            bb.putLong(offset + 16, 0x400000);
            bb.putLong(offset + 24, 0x400000);
            bb.putLong(offset + 32, 0x1000);
            bb.putLong(offset + 40, 0x1000);
            bb.putLong(offset + 48, 0x1000);
        }

        return elf;
    }

    private byte[] createElfWithVariousSectionHeaders(int[] types) {
        int shoff = 64;
        int shentsize = 64;
        int totalSize = 64 + types.length * shentsize;

        byte[] elf = new byte[totalSize];
        ByteBuffer bb = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);

        System.arraycopy(ELF_MAGIC, 0, elf, 0, 4);
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;

        bb.putShort(16, (short) 2);
        bb.putShort(18, (short) 0x3E);
        bb.putInt(20, 1);
        bb.putLong(24, 0x400000);
        bb.putLong(32, 0);
        bb.putLong(40, shoff);
        bb.putInt(48, 0);
        bb.putShort(52, (short) 64);
        bb.putShort(54, (short) 56);
        bb.putShort(56, (short) 0);
        bb.putShort(58, (short) shentsize);
        bb.putShort(60, (short) types.length);
        bb.putShort(62, (short) 0);

        for (int i = 0; i < types.length; i++) {
            int offset = shoff + i * shentsize;
            bb.putInt(offset, 0); // sh_name
            bb.putInt(offset + 4, types[i]); // sh_type
            bb.putLong(offset + 8, 6);
            bb.putLong(offset + 16, 0x400000);
            bb.putLong(offset + 24, 0);
            bb.putLong(offset + 32, 0x100);
            bb.putInt(offset + 40, 0);
            bb.putInt(offset + 44, 0);
            bb.putLong(offset + 48, 16);
            bb.putLong(offset + 56, 0);
        }

        return elf;
    }
}
