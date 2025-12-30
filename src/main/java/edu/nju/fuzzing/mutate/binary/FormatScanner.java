package edu.nju.fuzzing.mutate.binary;

/**
 * 格式扫描器接口
 * 
 * 识别文件的逻辑边界，将连续的字节流切分为"块"或"节"
 * 
 * 两种模式：
 * - TLV 模式 (Tag-Length-Value)：适用于 PNG, JPEG, Pcap
 * - Offset 模式 (Header-Section)：适用于 ELF, PE
 */
public interface FormatScanner {
    
    /**
     * 扫描文件，识别结构
     * 
     * @param data 原始文件数据
     * @return 扫描结果，包含所有识别出的块和字段映射
     */
    ScanResult scan(byte[] data);
    
    /**
     * 检查文件是否符合此格式
     * 
     * @param data 文件数据
     * @return 如果匹配此格式返回 true
     */
    boolean matches(byte[] data);
    
    /**
     * 获取格式名称
     */
    String getFormatName();
}
