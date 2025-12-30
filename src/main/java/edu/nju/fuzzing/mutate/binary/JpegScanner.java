package edu.nju.fuzzing.mutate.binary;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * JPEG 格式扫描器
 * 
 * JPEG 使用标记段模式：
 * - 0xFF + Marker (1 byte)
 * - Length (2 bytes, Big Endian) - 仅部分标记有
 * - Data (Length - 2 bytes)
 */
public class JpegScanner implements FormatScanner {
    
    // 标记定义
    public static final int SOI = 0xD8;   // Start of Image
    public static final int EOI = 0xD9;   // End of Image
    public static final int SOS = 0xDA;   // Start of Scan
    public static final int DQT = 0xDB;   // Define Quantization Table
    public static final int DHT = 0xC4;   // Define Huffman Table
    public static final int DRI = 0xDD;   // Define Restart Interval
    public static final int SOF0 = 0xC0;  // Baseline DCT
    public static final int SOF2 = 0xC2;  // Progressive DCT
    public static final int COM = 0xFE;   // Comment
    public static final int APP0 = 0xE0;  // JFIF
    public static final int APP1 = 0xE1;  // Exif
    
    // 关键标记（必须存在）
    private static final Set<Integer> CRITICAL_MARKERS = new HashSet<>();
    static {
        CRITICAL_MARKERS.add(SOI);
        CRITICAL_MARKERS.add(EOI);
        CRITICAL_MARKERS.add(SOS);
    }
    
    // 无长度字段的标记
    private static final Set<Integer> NO_LENGTH_MARKERS = new HashSet<>();
    static {
        NO_LENGTH_MARKERS.add(SOI);
        NO_LENGTH_MARKERS.add(EOI);
        // RST0 - RST7 (0xD0 - 0xD7)
        for (int i = 0xD0; i <= 0xD7; i++) {
            NO_LENGTH_MARKERS.add(i);
        }
    }
    
    @Override
    public String getFormatName() {
        return "JPEG";
    }
    
    @Override
    public boolean matches(byte[] data) {
        if (data == null || data.length < 2) return false;
        return (data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == SOI;
    }
    
    @Override
    public ScanResult scan(byte[] data) {
        List<BinaryChunk> chunks = new ArrayList<>();
        List<FieldMapping> globalFields = new ArrayList<>();
        
        if (!matches(data)) {
            return new ScanResult(false, "JPEG", data, chunks, globalFields);
        }
        
        // 添加 SOI 标记
        globalFields.add(new FieldMapping(0, 2, FieldType.MAGIC, ByteOrder.BIG_ENDIAN, "SOI"));
        
        int offset = 2;  // 跳过 SOI
        
        while (offset < data.length) {
            // 寻找 0xFF
            if ((data[offset] & 0xFF) != 0xFF) {
                offset++;
                continue;
            }
            
            // 跳过填充的 0xFF
            while (offset < data.length && (data[offset] & 0xFF) == 0xFF) {
                offset++;
            }
            
            if (offset >= data.length) break;
            
            int marker = data[offset] & 0xFF;
            offset++;  // 跳过标记字节
            
            // 创建块
            int segmentStart = offset - 2;  // 从 0xFF 开始
            BinaryChunk chunk = parseSegment(data, segmentStart, marker);
            
            if (chunk != null) {
                chunks.add(chunk);
                offset = chunk.getEndOffset();
                
                // SOS 之后是熵编码数据，需要特殊处理
                if (marker == SOS) {
                    int scanDataEnd = findScanDataEnd(data, offset);
                    if (scanDataEnd > offset) {
                        // 创建一个表示扫描数据的虚拟块
                        int scanLen = scanDataEnd - offset;
                        byte[] scanData = new byte[scanLen];
                        System.arraycopy(data, offset, scanData, 0, scanLen);
                        
                        BinaryChunk scanChunk = new BinaryChunk(offset, scanLen, "SCAN_DATA", scanData);
                        scanChunk.setDataOffset(0);
                        scanChunk.setDataLength(scanLen);
                        scanChunk.addField(new FieldMapping(0, scanLen, FieldType.DATA, 
                                           ByteOrder.BIG_ENDIAN, "entropy_data"));
                        chunks.add(scanChunk);
                        
                        offset = scanDataEnd;
                    }
                }
                
                // EOI 结束
                if (marker == EOI) {
                    break;
                }
            } else {
                // 无法解析，跳过
                break;
            }
        }
        
        ScanResult result = new ScanResult(true, "JPEG", data, chunks, globalFields);
        result.setByteOrder(ByteOrder.BIG_ENDIAN);
        result.setHeaderSize(2);
        
        return result;
    }
    
    /**
     * 解析单个 JPEG 段
     */
    private BinaryChunk parseSegment(byte[] data, int offset, int marker) {
        if (offset + 2 > data.length) return null;
        
        String markerName = getMarkerName(marker);
        
        if (NO_LENGTH_MARKERS.contains(marker)) {
            // 无长度字段的标记
            byte[] rawData = new byte[2];
            System.arraycopy(data, offset, rawData, 0, 2);
            
            BinaryChunk chunk = new BinaryChunk(offset, 2, markerName, rawData);
            chunk.setCritical(CRITICAL_MARKERS.contains(marker));
            chunk.setDataOffset(2);
            chunk.setDataLength(0);
            
            chunk.addField(new FieldMapping(0, 2, FieldType.MAGIC, ByteOrder.BIG_ENDIAN, "marker"));
            
            return chunk;
        }
        
        // 有长度字段的标记
        if (offset + 4 > data.length) return null;
        
        int length = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        
        // 防御性检查
        if (length < 2) length = 2;
        int totalLength = 2 + length;  // marker(2) + length(2) + data(length-2)
        
        if (offset + totalLength > data.length) {
            totalLength = data.length - offset;
        }
        
        byte[] rawData = new byte[totalLength];
        System.arraycopy(data, offset, rawData, 0, Math.min(totalLength, data.length - offset));
        
        BinaryChunk chunk = new BinaryChunk(offset, totalLength, markerName, rawData);
        chunk.setCritical(CRITICAL_MARKERS.contains(marker));
        chunk.setDataOffset(4);  // 跳过 marker 和 length
        chunk.setDataLength(length - 2);
        
        // 添加字段映射
        chunk.addField(new FieldMapping(0, 2, FieldType.MAGIC, ByteOrder.BIG_ENDIAN, "marker"));
        chunk.addField(new FieldMapping(2, 2, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, "length", length));
        
        if (length > 2) {
            chunk.addField(new FieldMapping(4, length - 2, FieldType.DATA, 
                           ByteOrder.BIG_ENDIAN, "segment_data"));
        }
        
        // 解析特定段的内部结构
        parseSegmentInternals(chunk, data, offset, marker);
        
        return chunk;
    }
    
    /**
     * 解析特定段类型的内部结构
     */
    private void parseSegmentInternals(BinaryChunk chunk, byte[] data, int offset, int marker) {
        if (marker >= SOF0 && marker <= SOF0 + 15 && marker != DHT) {
            // SOF 段：包含图像尺寸
            if (chunk.getDataLength() >= 6) {
                ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
                int precision = data[offset + 4] & 0xFF;
                int height = bb.getShort(offset + 5) & 0xFFFF;
                int width = bb.getShort(offset + 7) & 0xFFFF;
                int components = data[offset + 9] & 0xFF;
                
                chunk.addField(new FieldMapping(4, 1, FieldType.FLAGS, ByteOrder.BIG_ENDIAN, 
                               "precision", precision));
                chunk.addField(new FieldMapping(5, 2, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, 
                               "height", height));
                chunk.addField(new FieldMapping(7, 2, FieldType.LENGTH, ByteOrder.BIG_ENDIAN, 
                               "width", width));
                chunk.addField(new FieldMapping(9, 1, FieldType.COUNT, ByteOrder.BIG_ENDIAN, 
                               "components", components));
            }
        }
        else if (marker == DRI) {
            // DRI: Restart Interval
            if (chunk.getDataLength() >= 2) {
                int interval = ((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF);
                chunk.addField(new FieldMapping(4, 2, FieldType.COUNT, ByteOrder.BIG_ENDIAN, 
                               "restart_interval", interval));
            }
        }
    }
    
    /**
     * 查找扫描数据的结束位置
     */
    private int findScanDataEnd(byte[] data, int start) {
        int pos = start;
        while (pos < data.length - 1) {
            if ((data[pos] & 0xFF) == 0xFF) {
                int next = data[pos + 1] & 0xFF;
                // 0xFF00 是转义，RST0-RST7 是重启标记
                if (next != 0 && (next < 0xD0 || next > 0xD7)) {
                    return pos;  // 找到新标记
                }
            }
            pos++;
        }
        return data.length;
    }
    
    /**
     * 获取标记名称
     */
    private String getMarkerName(int marker) {
        switch (marker) {
            case SOI: return "SOI";
            case EOI: return "EOI";
            case SOS: return "SOS";
            case DQT: return "DQT";
            case DHT: return "DHT";
            case DRI: return "DRI";
            case SOF0: return "SOF0";
            case SOF2: return "SOF2";
            case COM: return "COM";
            case APP0: return "APP0";
            case APP1: return "APP1";
            default:
                if (marker >= 0xE0 && marker <= 0xEF) {
                    return "APP" + (marker - 0xE0);
                }
                if (marker >= 0xD0 && marker <= 0xD7) {
                    return "RST" + (marker - 0xD0);
                }
                if (marker >= 0xC0 && marker <= 0xCF) {
                    return "SOF" + (marker - 0xC0);
                }
                return String.format("0x%02X", marker);
        }
    }
}
