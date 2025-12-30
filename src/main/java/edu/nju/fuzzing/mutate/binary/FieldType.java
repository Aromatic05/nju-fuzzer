package edu.nju.fuzzing.mutate.binary;

/**
 * 字段类型枚举
 * 
 * 标识二进制文件中不同类型的控制字段
 */
public enum FieldType {
    /**
     * 魔数/签名 - 文件头或块头的标识符
     * 通常不应修改，否则会被文件类型检查拒绝
     */
    MAGIC,
    
    /**
     * 类型标识 - 块类型、段类型等
     */
    TYPE,
    
    /**
     * 长度/大小字段 - 描述数据大小的整型值
     * 修改可能导致 Buffer Over-read/Overflow
     */
    LENGTH,
    
    /**
     * 偏移量/指针 - 指向文件其他位置的地址
     * 对 ELF/PE 等格式尤为重要
     */
    OFFSET,
    
    /**
     * 数量/计数 - 元素个数等
     */
    COUNT,
    
    /**
     * 校验和/CRC - 数据的完整性校验值
     * 变异后需要重新计算
     */
    CHECKSUM,
    
    /**
     * 标志位 - 各种布尔标志
     */
    FLAGS,
    
    /**
     * 版本号
     */
    VERSION,
    
    /**
     * 数据区 - 可以随意变异的区域
     */
    DATA,
    
    /**
     * 填充/对齐
     */
    PADDING,
    
    /**
     * 未知/其他
     */
    UNKNOWN
}
