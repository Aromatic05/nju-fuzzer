package edu.nju.fuzzing.mutate.binary;

import java.util.List;

/**
 * 格式扫描结果 - 包含文件的完整结构信息
 */
public class ScanResult {
    
    private final boolean valid;            // 文件格式是否有效
    private final String formatType;        // 格式类型（PNG, JPEG, ELF, PCAP）
    private final byte[] originalData;      // 原始文件数据
    private final List<BinaryChunk> chunks; // 识别出的所有块
    private final List<FieldMapping> globalFields;  // 全局字段（如文件头）
    
    // 格式特定信息
    private java.nio.ByteOrder byteOrder;   // 文件字节序
    private int headerSize;                 // 头部大小
    private boolean is64Bit;                // ELF 64位标志
    
    public ScanResult(boolean valid, String formatType, byte[] originalData, 
                      List<BinaryChunk> chunks, List<FieldMapping> globalFields) {
        this.valid = valid;
        this.formatType = formatType;
        this.originalData = originalData;
        this.chunks = chunks;
        this.globalFields = globalFields;
        this.byteOrder = java.nio.ByteOrder.BIG_ENDIAN;
        this.headerSize = 0;
        this.is64Bit = false;
    }
    
    // === Getters ===
    
    public boolean isValid() {
        return valid;
    }
    
    public String getFormatType() {
        return formatType;
    }
    
    public byte[] getOriginalData() {
        return originalData;
    }
    
    public List<BinaryChunk> getChunks() {
        return chunks;
    }
    
    public List<FieldMapping> getGlobalFields() {
        return globalFields;
    }
    
    public java.nio.ByteOrder getByteOrder() {
        return byteOrder;
    }
    
    public void setByteOrder(java.nio.ByteOrder byteOrder) {
        this.byteOrder = byteOrder;
    }
    
    public int getHeaderSize() {
        return headerSize;
    }
    
    public void setHeaderSize(int headerSize) {
        this.headerSize = headerSize;
    }
    
    public boolean is64Bit() {
        return is64Bit;
    }
    
    public void setIs64Bit(boolean is64Bit) {
        this.is64Bit = is64Bit;
    }
    
    /**
     * 根据类型名称查找块
     */
    public BinaryChunk findChunkByType(String type) {
        for (BinaryChunk chunk : chunks) {
            if (type.equals(chunk.getChunkType())) {
                return chunk;
            }
        }
        return null;
    }
    
    /**
     * 查找所有指定类型的块
     */
    public java.util.List<BinaryChunk> findAllChunksByType(String type) {
        java.util.List<BinaryChunk> result = new java.util.ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (type.equals(chunk.getChunkType())) {
                result.add(chunk);
            }
        }
        return result;
    }
    
    /**
     * 获取关键块（不可删除的块）
     */
    public java.util.List<BinaryChunk> getCriticalChunks() {
        java.util.List<BinaryChunk> result = new java.util.ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (chunk.isCritical()) {
                result.add(chunk);
            }
        }
        return result;
    }
    
    /**
     * 获取非关键块（可安全删除的块）
     */
    public java.util.List<BinaryChunk> getNonCriticalChunks() {
        java.util.List<BinaryChunk> result = new java.util.ArrayList<>();
        for (BinaryChunk chunk : chunks) {
            if (!chunk.isCritical()) {
                result.add(chunk);
            }
        }
        return result;
    }
    
    @Override
    public String toString() {
        return String.format("ScanResult[%s, valid=%s, chunks=%d, globalFields=%d]",
            formatType, valid, chunks.size(), globalFields.size());
    }
}
