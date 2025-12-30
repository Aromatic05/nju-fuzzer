package edu.nju.fuzzing.mutate.binary;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * PNG 格式扫描器
 * 
 * PNG 使用 TLV 模式：
 * - Length (4 bytes, Big Endian)
 * - Type (4 bytes, ASCII)
 * - Data (Length bytes)
 * - CRC32 (4 bytes)
 */
public class PngScanner implements FormatScanner {
    
    private static final byte[] PNG_SIGNATURE = {
        (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };
    
    // 关键块类型（必须存在）
    private static final Set<String> CRITICAL_CHUNKS = new HashSet<>();
    static {
        CRITICAL_CHUNKS.add("IHDR");
        CRITICAL_CHUNKS.add("IDAT");
        CRITICAL_CHUNKS.add("IEND");
    }
    
    @Override
    public String getFormatName() {
        return "PNG";
    }
    
    @Override
    public boolean matches(byte[] data) {
        if (data == null || data.length < 8) return false;
        
        for (int i = 0; i < 8; i++) {
            if (data[i] != PNG_SIGNATURE[i]) return false;
        }
        return true;
    }
    
    @Override
    public ScanResult scan(byte[] data) {
        List<BinaryChunk> chunks = new ArrayList<>();
        List<FieldMapping> globalFields = new ArrayList<>();
        
        if (!matches(data)) {
            return new ScanResult(false, "PNG", data, chunks, globalFields);
        }
        
        // 添加全局 Magic 字段
        globalFields.add(new FieldMapping(0, 8, FieldType.MAGIC, ByteOrder.BIG_ENDIAN, "PNG_SIGNATURE"));
        
        int offset = 8;  // 跳过签名
        
        while (offset + 12 <= data.length) {  // 最小块：4(len) + 4(type) + 0(data) + 4(crc) = 12
            BinaryChunk chunk = parseChunk(data, offset);
            if (chunk == null) {
                break;  // 解析失败，停止
            }
            
            chunks.add(chunk);
            offset = chunk.getEndOffset();
            
            // 遇到 IEND 就停止
            if ("IEND".equals(chunk.getChunkType())) {
                break;
            }
        }
        
        ScanResult result = new ScanResult(true, "PNG", data, chunks, globalFields);
        result.setByteOrder(ByteOrder.BIG_ENDIAN);
        result.setHeaderSize(8);
        
        return result;
    }
    
    /**
     * 解析单个 PNG 块
     */
    private BinaryChunk parseChunk(byte[] data, int offset) {
        if (offset + 12 > data.length) return null;
        
        ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        
        // 读取长度
        int length = bb.getInt(offset);
        
        // 防御性检查
        if (length < 0 || offset + 12 + length > data.length) {
            // 畸形长度，尝试创建一个包含剩余数据的块
            length = Math.max(0, data.length - offset - 12);
        }
        
        // 读取类型
        byte[] typeBytes = new byte[4];
        System.arraycopy(data, offset + 4, typeBytes, 0, 4);
        String chunkType = new String(typeBytes, java.nio.charset.StandardCharsets.US_ASCII);
        
        // 提取块数据
        int totalLength = 12 + length;  // len(4) + type(4) + data(length) + crc(4)
        if (offset + totalLength > data.length) {
            totalLength = data.length - offset;
        }
        
        byte[] rawData = new byte[totalLength];
        System.arraycopy(data, offset, rawData, 0, Math.min(totalLength, data.length - offset));
        
        BinaryChunk chunk = new BinaryChunk(offset, totalLength, chunkType, rawData);
        
        // 设置块属性
        chunk.setCritical(CRITICAL_CHUNKS.contains(chunkType));
        chunk.setDataOffset(8);  // type 之后
        chunk.setDataLength(length);
        chunk.setChecksumOffset(8 + length);  // CRC 在数据之后
        
        // 添加字段映射
        chunk.addField(new FieldMapping(0, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, 
                                         "chunk_length", length));
        chunk.addField(new FieldMapping(4, 4, FieldType.TYPE, ByteOrder.BIG_ENDIAN, 
                                         "chunk_type"));
        
        if (length > 0) {
            chunk.addField(new FieldMapping(8, length, FieldType.DATA, ByteOrder.BIG_ENDIAN, 
                                             "chunk_data"));
        }
        
        // CRC 字段
        if (8 + length + 4 <= totalLength) {
            long crcValue = bb.getInt(offset + 8 + length) & 0xFFFFFFFFL;
            chunk.addField(new FieldMapping(8 + length, 4, FieldType.CHECKSUM, ByteOrder.BIG_ENDIAN, 
                                             "chunk_crc", crcValue));
        }
        
        // 解析特定块的内部结构
        parseChunkInternals(chunk, data, offset);
        
        return chunk;
    }
    
    /**
     * 解析特定块类型的内部结构
     */
    private void parseChunkInternals(BinaryChunk chunk, byte[] data, int offset) {
        String type = chunk.getChunkType();
        int dataStart = offset + 8;  // 跳过 length 和 type
        
        if ("IHDR".equals(type) && chunk.getDataLength() >= 13) {
            // IHDR: Width(4) + Height(4) + BitDepth(1) + ColorType(1) + Compression(1) + Filter(1) + Interlace(1)
            ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
            
            int width = bb.getInt(dataStart);
            int height = bb.getInt(dataStart + 4);
            
            // 相对于块起始的偏移
            chunk.addField(new FieldMapping(8, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "width", width));
            chunk.addField(new FieldMapping(12, 4, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "height", height));
            chunk.addField(new FieldMapping(16, 1, FieldType.FLAGS, ByteOrder.BIG_ENDIAN, "bit_depth"));
            chunk.addField(new FieldMapping(17, 1, FieldType.FLAGS, ByteOrder.BIG_ENDIAN, "color_type"));
            chunk.addField(new FieldMapping(18, 1, FieldType.FLAGS, ByteOrder.BIG_ENDIAN, "compression"));
            chunk.addField(new FieldMapping(19, 1, FieldType.FLAGS, ByteOrder.BIG_ENDIAN, "filter"));
            chunk.addField(new FieldMapping(20, 1, FieldType.FLAGS, ByteOrder.BIG_ENDIAN, "interlace"));
        }
        else if ("PLTE".equals(type)) {
            // PLTE: RGB entries (每项3字节)
            // 标记整个数据为 DATA 类型
        }
        else if ("tRNS".equals(type) || "iCCP".equals(type) || "sRGB".equals(type)) {
            // 辅助块，可以安全删除或变异
        }
    }
    
    /**
     * 获取指定类型的块
     */
    public static BinaryChunk findChunk(ScanResult result, String type) {
        for (BinaryChunk chunk : result.getChunks()) {
            if (type.equals(chunk.getChunkType())) {
                return chunk;
            }
        }
        return null;
    }
    
    /**
     * 获取所有指定类型的块
     */
    public static List<BinaryChunk> findAllChunks(ScanResult result, String type) {
        List<BinaryChunk> found = new ArrayList<>();
        for (BinaryChunk chunk : result.getChunks()) {
            if (type.equals(chunk.getChunkType())) {
                found.add(chunk);
            }
        }
        return found;
    }
}
