package edu.nju.fuzzing.mutate.binary;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * ELF 格式扫描器 (Offset 模式)
 * 
 * ELF 结构：
 * - ELF Header (52/64 bytes for 32/64-bit)
 * - Program Headers (可选)
 * - Section Headers
 * - 各个 Section 数据
 * 
 * 使用 Offset 模式而非 TLV 模式，因为 ELF 头部包含指向各表的偏移量
 */
public class ElfScanner implements FormatScanner {
    
    // ELF Magic: 0x7F 'E' 'L' 'F'
    public static final byte[] ELF_MAGIC = {0x7F, 'E', 'L', 'F'};
    
    // ELF Class
    public static final int ELFCLASS32 = 1;
    public static final int ELFCLASS64 = 2;
    
    // ELF Data Encoding
    public static final int ELFDATA2LSB = 1;  // Little Endian
    public static final int ELFDATA2MSB = 2;  // Big Endian
    
    // ELF Type
    public static final int ET_NONE = 0;
    public static final int ET_REL = 1;
    public static final int ET_EXEC = 2;
    public static final int ET_DYN = 3;
    public static final int ET_CORE = 4;
    
    // Section Types
    public static final int SHT_NULL = 0;
    public static final int SHT_PROGBITS = 1;
    public static final int SHT_SYMTAB = 2;
    public static final int SHT_STRTAB = 3;
    public static final int SHT_RELA = 4;
    public static final int SHT_HASH = 5;
    public static final int SHT_DYNAMIC = 6;
    public static final int SHT_NOTE = 7;
    public static final int SHT_NOBITS = 8;
    public static final int SHT_REL = 9;
    public static final int SHT_DYNSYM = 11;
    
    @Override
    public String getFormatName() {
        return "ELF";
    }
    
    @Override
    public boolean matches(byte[] data) {
        if (data == null || data.length < 16) return false;
        
        return data[0] == ELF_MAGIC[0] &&
               data[1] == ELF_MAGIC[1] &&
               data[2] == ELF_MAGIC[2] &&
               data[3] == ELF_MAGIC[3];
    }
    
    @Override
    public ScanResult scan(byte[] data) {
        List<BinaryChunk> chunks = new ArrayList<>();
        List<FieldMapping> globalFields = new ArrayList<>();
        
        if (!matches(data) || data.length < 52) {
            return new ScanResult(false, "ELF", data, chunks, globalFields);
        }
        
        // 确定 32/64 位
        int elfClass = data[4] & 0xFF;
        boolean is64Bit = (elfClass == ELFCLASS64);
        
        // 确定字节序
        int encoding = data[5] & 0xFF;
        ByteOrder order = (encoding == ELFDATA2MSB) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        
        int headerSize = is64Bit ? 64 : 52;
        if (data.length < headerSize) {
            return new ScanResult(false, "ELF", data, chunks, globalFields);
        }
        
        ByteBuffer bb = ByteBuffer.wrap(data).order(order);
        
        // 解析 ELF Header
        int type = bb.getShort(16) & 0xFFFF;
        int machine = bb.getShort(18) & 0xFFFF;
        int version = bb.getInt(20);
        
        long entry, phoff, shoff;
        int flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
        
        if (is64Bit) {
            entry = bb.getLong(24);
            phoff = bb.getLong(32);
            shoff = bb.getLong(40);
            flags = bb.getInt(48);
            ehsize = bb.getShort(52) & 0xFFFF;
            phentsize = bb.getShort(54) & 0xFFFF;
            phnum = bb.getShort(56) & 0xFFFF;
            shentsize = bb.getShort(58) & 0xFFFF;
            shnum = bb.getShort(60) & 0xFFFF;
            shstrndx = bb.getShort(62) & 0xFFFF;
        } else {
            entry = bb.getInt(24) & 0xFFFFFFFFL;
            phoff = bb.getInt(28) & 0xFFFFFFFFL;
            shoff = bb.getInt(32) & 0xFFFFFFFFL;
            flags = bb.getInt(36);
            ehsize = bb.getShort(40) & 0xFFFF;
            phentsize = bb.getShort(42) & 0xFFFF;
            phnum = bb.getShort(44) & 0xFFFF;
            shentsize = bb.getShort(46) & 0xFFFF;
            shnum = bb.getShort(48) & 0xFFFF;
            shstrndx = bb.getShort(50) & 0xFFFF;
        }
        
        // 添加 ELF Header 全局字段
        globalFields.add(new FieldMapping(0, 4, FieldType.MAGIC, order, "e_ident_magic"));
        globalFields.add(new FieldMapping(4, 1, FieldType.FLAGS, order, "e_ident_class", elfClass));
        globalFields.add(new FieldMapping(5, 1, FieldType.FLAGS, order, "e_ident_data", encoding));
        globalFields.add(new FieldMapping(16, 2, FieldType.TYPE, order, "e_type", type));
        globalFields.add(new FieldMapping(18, 2, FieldType.TYPE, order, "e_machine", machine));
        globalFields.add(new FieldMapping(20, 4, FieldType.VERSION, order, "e_version", version));
        
        if (is64Bit) {
            globalFields.add(new FieldMapping(24, 8, FieldType.OFFSET, order, "e_entry", entry));
            globalFields.add(new FieldMapping(32, 8, FieldType.OFFSET, order, "e_phoff", phoff));
            globalFields.add(new FieldMapping(40, 8, FieldType.OFFSET, order, "e_shoff", shoff));
            globalFields.add(new FieldMapping(48, 4, FieldType.FLAGS, order, "e_flags", flags));
            globalFields.add(new FieldMapping(52, 2, FieldType.LENGTH, order, "e_ehsize", ehsize));
            globalFields.add(new FieldMapping(54, 2, FieldType.LENGTH, order, "e_phentsize", phentsize));
            globalFields.add(new FieldMapping(56, 2, FieldType.COUNT, order, "e_phnum", phnum));
            globalFields.add(new FieldMapping(58, 2, FieldType.LENGTH, order, "e_shentsize", shentsize));
            globalFields.add(new FieldMapping(60, 2, FieldType.COUNT, order, "e_shnum", shnum));
            globalFields.add(new FieldMapping(62, 2, FieldType.OFFSET, order, "e_shstrndx", shstrndx));
        } else {
            globalFields.add(new FieldMapping(24, 4, FieldType.OFFSET, order, "e_entry", (int) entry));
            globalFields.add(new FieldMapping(28, 4, FieldType.OFFSET, order, "e_phoff", (int) phoff));
            globalFields.add(new FieldMapping(32, 4, FieldType.OFFSET, order, "e_shoff", (int) shoff));
            globalFields.add(new FieldMapping(36, 4, FieldType.FLAGS, order, "e_flags", flags));
            globalFields.add(new FieldMapping(40, 2, FieldType.LENGTH, order, "e_ehsize", ehsize));
            globalFields.add(new FieldMapping(42, 2, FieldType.LENGTH, order, "e_phentsize", phentsize));
            globalFields.add(new FieldMapping(44, 2, FieldType.COUNT, order, "e_phnum", phnum));
            globalFields.add(new FieldMapping(46, 2, FieldType.LENGTH, order, "e_shentsize", shentsize));
            globalFields.add(new FieldMapping(48, 2, FieldType.COUNT, order, "e_shnum", shnum));
            globalFields.add(new FieldMapping(50, 2, FieldType.OFFSET, order, "e_shstrndx", shstrndx));
        }
        
        // 创建 ELF Header 块
        byte[] headerData = new byte[headerSize];
        System.arraycopy(data, 0, headerData, 0, headerSize);
        BinaryChunk headerChunk = new BinaryChunk(0, headerSize, "ELF_HEADER", headerData);
        headerChunk.setCritical(true);
        for (FieldMapping f : globalFields) {
            headerChunk.addField(f);
        }
        chunks.add(headerChunk);
        
        // 解析 Program Headers
        if (phoff > 0 && phnum > 0 && phoff + (long) phnum * phentsize <= data.length) {
            for (int i = 0; i < phnum && i < 256; i++) {
                BinaryChunk phChunk = parseProgramHeader(data, (int) phoff + i * phentsize, 
                                                          phentsize, i, is64Bit, order);
                if (phChunk != null) {
                    chunks.add(phChunk);
                }
            }
        }
        
        // 解析 Section Headers
        if (shoff > 0 && shnum > 0 && shoff + (long) shnum * shentsize <= data.length) {
            for (int i = 0; i < shnum && i < 256; i++) {
                BinaryChunk shChunk = parseSectionHeader(data, (int) shoff + i * shentsize, 
                                                          shentsize, i, is64Bit, order);
                if (shChunk != null) {
                    chunks.add(shChunk);
                }
            }
        }
        
        ScanResult result = new ScanResult(true, "ELF", data, chunks, globalFields);
        result.setByteOrder(order);
        result.setHeaderSize(headerSize);
        result.setIs64Bit(is64Bit);
        
        return result;
    }
    
    /**
     * 解析单个 Program Header
     */
    private BinaryChunk parseProgramHeader(byte[] data, int offset, int size, 
                                            int index, boolean is64Bit, ByteOrder order) {
        if (offset + size > data.length) return null;
        
        ByteBuffer bb = ByteBuffer.wrap(data).order(order);
        
        int type = bb.getInt(offset);
        long pOffset, vaddr, paddr, filesz, memsz;
        int flags;
        
        if (is64Bit) {
            flags = bb.getInt(offset + 4);
            pOffset = bb.getLong(offset + 8);
            vaddr = bb.getLong(offset + 16);
            paddr = bb.getLong(offset + 24);
            filesz = bb.getLong(offset + 32);
            memsz = bb.getLong(offset + 40);
        } else {
            pOffset = bb.getInt(offset + 4) & 0xFFFFFFFFL;
            vaddr = bb.getInt(offset + 8) & 0xFFFFFFFFL;
            paddr = bb.getInt(offset + 12) & 0xFFFFFFFFL;
            filesz = bb.getInt(offset + 16) & 0xFFFFFFFFL;
            memsz = bb.getInt(offset + 20) & 0xFFFFFFFFL;
            flags = bb.getInt(offset + 24);
        }
        
        byte[] rawData = new byte[size];
        System.arraycopy(data, offset, rawData, 0, size);
        
        String chunkType = String.format("PHDR_%d_%s", index, getSegmentTypeName(type));
        BinaryChunk chunk = new BinaryChunk(offset, size, chunkType, rawData);
        chunk.setCritical(type == 1 || type == 2);  // PT_LOAD 或 PT_DYNAMIC
        
        // 添加字段映射
        chunk.addField(new FieldMapping(0, 4, FieldType.TYPE, order, "p_type", type));
        
        if (is64Bit) {
            chunk.addField(new FieldMapping(4, 4, FieldType.FLAGS, order, "p_flags", flags));
            chunk.addField(new FieldMapping(8, 8, FieldType.OFFSET, order, "p_offset", pOffset));
            chunk.addField(new FieldMapping(16, 8, FieldType.OFFSET, order, "p_vaddr", vaddr));
            chunk.addField(new FieldMapping(24, 8, FieldType.OFFSET, order, "p_paddr", paddr));
            chunk.addField(new FieldMapping(32, 8, FieldType.LENGTH, order, "p_filesz", filesz));
            chunk.addField(new FieldMapping(40, 8, FieldType.LENGTH, order, "p_memsz", memsz));
        } else {
            chunk.addField(new FieldMapping(4, 4, FieldType.OFFSET, order, "p_offset", (int) pOffset));
            chunk.addField(new FieldMapping(8, 4, FieldType.OFFSET, order, "p_vaddr", (int) vaddr));
            chunk.addField(new FieldMapping(12, 4, FieldType.OFFSET, order, "p_paddr", (int) paddr));
            chunk.addField(new FieldMapping(16, 4, FieldType.LENGTH, order, "p_filesz", (int) filesz));
            chunk.addField(new FieldMapping(20, 4, FieldType.LENGTH, order, "p_memsz", (int) memsz));
            chunk.addField(new FieldMapping(24, 4, FieldType.FLAGS, order, "p_flags", flags));
        }
        
        return chunk;
    }
    
    /**
     * 解析单个 Section Header
     */
    private BinaryChunk parseSectionHeader(byte[] data, int offset, int size, 
                                            int index, boolean is64Bit, ByteOrder order) {
        if (offset + size > data.length) return null;
        
        ByteBuffer bb = ByteBuffer.wrap(data).order(order);
        
        int nameIdx = bb.getInt(offset);
        int type = bb.getInt(offset + 4);
        long sFlags, addr, sOffset, sSize, link, info, addralign, entsize;
        
        if (is64Bit) {
            sFlags = bb.getLong(offset + 8);
            addr = bb.getLong(offset + 16);
            sOffset = bb.getLong(offset + 24);
            sSize = bb.getLong(offset + 32);
            link = bb.getInt(offset + 40) & 0xFFFFFFFFL;
            info = bb.getInt(offset + 44) & 0xFFFFFFFFL;
            addralign = bb.getLong(offset + 48);
            entsize = bb.getLong(offset + 56);
        } else {
            sFlags = bb.getInt(offset + 8) & 0xFFFFFFFFL;
            addr = bb.getInt(offset + 12) & 0xFFFFFFFFL;
            sOffset = bb.getInt(offset + 16) & 0xFFFFFFFFL;
            sSize = bb.getInt(offset + 20) & 0xFFFFFFFFL;
            link = bb.getInt(offset + 24) & 0xFFFFFFFFL;
            info = bb.getInt(offset + 28) & 0xFFFFFFFFL;
            addralign = bb.getInt(offset + 32) & 0xFFFFFFFFL;
            entsize = bb.getInt(offset + 36) & 0xFFFFFFFFL;
        }
        
        byte[] rawData = new byte[size];
        System.arraycopy(data, offset, rawData, 0, size);
        
        String chunkType = String.format("SHDR_%d_%s", index, getSectionTypeName(type));
        BinaryChunk chunk = new BinaryChunk(offset, size, chunkType, rawData);
        chunk.setCritical(type == SHT_DYNAMIC || type == SHT_SYMTAB || type == SHT_DYNSYM);
        
        // 添加字段映射
        chunk.addField(new FieldMapping(0, 4, FieldType.OFFSET, order, "sh_name", nameIdx));
        chunk.addField(new FieldMapping(4, 4, FieldType.TYPE, order, "sh_type", type));
        
        if (is64Bit) {
            chunk.addField(new FieldMapping(8, 8, FieldType.FLAGS, order, "sh_flags", sFlags));
            chunk.addField(new FieldMapping(16, 8, FieldType.OFFSET, order, "sh_addr", addr));
            chunk.addField(new FieldMapping(24, 8, FieldType.OFFSET, order, "sh_offset", sOffset));
            chunk.addField(new FieldMapping(32, 8, FieldType.LENGTH, order, "sh_size", sSize));
            chunk.addField(new FieldMapping(40, 4, FieldType.OFFSET, order, "sh_link", (int) link));
            chunk.addField(new FieldMapping(44, 4, FieldType.FLAGS, order, "sh_info", (int) info));
            chunk.addField(new FieldMapping(48, 8, FieldType.LENGTH, order, "sh_addralign", addralign));
            chunk.addField(new FieldMapping(56, 8, FieldType.LENGTH, order, "sh_entsize", entsize));
        } else {
            chunk.addField(new FieldMapping(8, 4, FieldType.FLAGS, order, "sh_flags", (int) sFlags));
            chunk.addField(new FieldMapping(12, 4, FieldType.OFFSET, order, "sh_addr", (int) addr));
            chunk.addField(new FieldMapping(16, 4, FieldType.OFFSET, order, "sh_offset", (int) sOffset));
            chunk.addField(new FieldMapping(20, 4, FieldType.LENGTH, order, "sh_size", (int) sSize));
            chunk.addField(new FieldMapping(24, 4, FieldType.OFFSET, order, "sh_link", (int) link));
            chunk.addField(new FieldMapping(28, 4, FieldType.FLAGS, order, "sh_info", (int) info));
            chunk.addField(new FieldMapping(32, 4, FieldType.LENGTH, order, "sh_addralign", (int) addralign));
            chunk.addField(new FieldMapping(36, 4, FieldType.LENGTH, order, "sh_entsize", (int) entsize));
        }
        
        return chunk;
    }
    
    /**
     * 获取段类型名称
     */
    private String getSegmentTypeName(int type) {
        switch (type) {
            case 0: return "NULL";
            case 1: return "LOAD";
            case 2: return "DYNAMIC";
            case 3: return "INTERP";
            case 4: return "NOTE";
            case 5: return "SHLIB";
            case 6: return "PHDR";
            case 7: return "TLS";
            default: return String.format("0x%X", type);
        }
    }
    
    /**
     * 获取节类型名称
     */
    private String getSectionTypeName(int type) {
        switch (type) {
            case SHT_NULL: return "NULL";
            case SHT_PROGBITS: return "PROGBITS";
            case SHT_SYMTAB: return "SYMTAB";
            case SHT_STRTAB: return "STRTAB";
            case SHT_RELA: return "RELA";
            case SHT_HASH: return "HASH";
            case SHT_DYNAMIC: return "DYNAMIC";
            case SHT_NOTE: return "NOTE";
            case SHT_NOBITS: return "NOBITS";
            case SHT_REL: return "REL";
            case SHT_DYNSYM: return "DYNSYM";
            default: return String.format("0x%X", type);
        }
    }
}
