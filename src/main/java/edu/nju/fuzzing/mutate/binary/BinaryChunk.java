package edu.nju.fuzzing.mutate.binary;

import java.util.ArrayList;
import java.util.List;

/**
 * 二进制块 - 表示文件中的一个逻辑单元
 * 
 * 适用于 TLV 模式（PNG chunks, JPEG segments）和 Header-Section 模式（ELF sections）
 */
public class BinaryChunk {
    
    private final int startOffset;      // 块在文件中的起始位置
    private final int totalLength;      // 块的总长度（包括头部）
    private final String chunkType;     // 块类型标识（如 "IHDR", "SOF0", ".text"）
    private final byte[] rawData;       // 块的原始数据
    private final List<FieldMapping> fields;  // 块内的字段映射
    
    // 块的语义属性
    private boolean critical;           // 是否为关键块（不可删除）
    private boolean hasChecksum;        // 是否有校验和
    private int checksumOffset;         // 校验和在块内的偏移
    private int dataOffset;             // 数据区在块内的偏移
    private int dataLength;             // 数据区长度
    
    public BinaryChunk(int startOffset, int totalLength, String chunkType, byte[] rawData) {
        this.startOffset = startOffset;
        this.totalLength = totalLength;
        this.chunkType = chunkType;
        this.rawData = rawData;
        this.fields = new ArrayList<>();
        this.critical = false;
        this.hasChecksum = false;
        this.checksumOffset = -1;
        this.dataOffset = 0;
        this.dataLength = totalLength;
    }
    
    // === Field Management ===
    
    public void addField(FieldMapping field) {
        fields.add(field);
    }
    
    public List<FieldMapping> getFields() {
        return fields;
    }
    
    public List<FieldMapping> getFieldsByType(FieldType type) {
        List<FieldMapping> result = new ArrayList<>();
        for (FieldMapping f : fields) {
            if (f.getType() == type) {
                result.add(f);
            }
        }
        return result;
    }
    
    /**
     * 获取块内指定偏移处的字段
     */
    public FieldMapping getFieldAt(int localOffset) {
        for (FieldMapping f : fields) {
            if (f.contains(localOffset)) {
                return f;
            }
        }
        return null;
    }
    
    // === Getters & Setters ===
    
    public int getStartOffset() {
        return startOffset;
    }
    
    public int getTotalLength() {
        return totalLength;
    }
    
    public int getEndOffset() {
        return startOffset + totalLength;
    }
    
    public String getChunkType() {
        return chunkType;
    }
    
    public byte[] getRawData() {
        return rawData;
    }
    
    public boolean isCritical() {
        return critical;
    }
    
    public void setCritical(boolean critical) {
        this.critical = critical;
    }
    
    public boolean hasChecksum() {
        return hasChecksum;
    }
    
    public void setHasChecksum(boolean hasChecksum) {
        this.hasChecksum = hasChecksum;
    }
    
    public int getChecksumOffset() {
        return checksumOffset;
    }
    
    public void setChecksumOffset(int checksumOffset) {
        this.checksumOffset = checksumOffset;
        this.hasChecksum = (checksumOffset >= 0);
    }
    
    public int getDataOffset() {
        return dataOffset;
    }
    
    public void setDataOffset(int dataOffset) {
        this.dataOffset = dataOffset;
    }
    
    public int getDataLength() {
        return dataLength;
    }
    
    public void setDataLength(int dataLength) {
        this.dataLength = dataLength;
    }
    
    /**
     * 获取块的数据区（排除头部和校验和）
     */
    public byte[] getDataSection() {
        if (rawData == null || dataOffset >= rawData.length) {
            return new byte[0];
        }
        int len = Math.min(dataLength, rawData.length - dataOffset);
        byte[] data = new byte[len];
        System.arraycopy(rawData, dataOffset, data, 0, len);
        return data;
    }
    
    @Override
    public String toString() {
        return String.format("Chunk[%s @ %d, len=%d, critical=%s, fields=%d]",
            chunkType, startOffset, totalLength, critical, fields.size());
    }
}
