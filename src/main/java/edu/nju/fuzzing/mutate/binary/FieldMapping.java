package edu.nju.fuzzing.mutate.binary;

import java.nio.ByteOrder;

/**
 * 字段映射 - 记录二进制文件中某个字段的位置、类型和元信息
 */
public class FieldMapping {
    
    private final int offset;           // 字段在文件/块中的偏移
    private final int length;           // 字段的长度（字节数）
    private final FieldType type;       // 字段类型
    private final ByteOrder byteOrder;  // 字节序
    private final String name;          // 字段名称（调试用）
    private final long originalValue;   // 原始值（用于数值型字段）
    
    public FieldMapping(int offset, int length, FieldType type, ByteOrder byteOrder, String name) {
        this(offset, length, type, byteOrder, name, 0);
    }
    
    public FieldMapping(int offset, int length, FieldType type, ByteOrder byteOrder, String name, long originalValue) {
        this.offset = offset;
        this.length = length;
        this.type = type;
        this.byteOrder = byteOrder;
        this.name = name;
        this.originalValue = originalValue;
    }
    
    // === Getters ===
    
    public int getOffset() {
        return offset;
    }
    
    public int getLength() {
        return length;
    }
    
    public FieldType getType() {
        return type;
    }
    
    public ByteOrder getByteOrder() {
        return byteOrder;
    }
    
    public String getName() {
        return name;
    }
    
    public long getOriginalValue() {
        return originalValue;
    }
    
    /**
     * 计算字段的结束位置
     */
    public int getEndOffset() {
        return offset + length;
    }
    
    /**
     * 检查某个位置是否在此字段范围内
     */
    public boolean contains(int pos) {
        return pos >= offset && pos < getEndOffset();
    }
    
    /**
     * 检查此字段是否与给定范围重叠
     */
    public boolean overlaps(int start, int end) {
        return offset < end && getEndOffset() > start;
    }
    
    @Override
    public String toString() {
        return String.format("Field[%s: %s @ %d, len=%d, order=%s, val=%d]", 
            name, type, offset, length, byteOrder, originalValue);
    }
}
