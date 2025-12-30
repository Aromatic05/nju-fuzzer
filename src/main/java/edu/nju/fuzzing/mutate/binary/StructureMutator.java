package edu.nju.fuzzing.mutate.binary;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 结构感知变异策略
 * 
 * 提供静态方法用于二进制文件的结构感知变异
 */
public final class StructureMutator {
    
    // 容易引发溢出的整数值
    public static final long[] EVIL_INTEGERS = {
        0L, 1L, -1L,
        0x7FL, 0x80L, 0xFFL,                          // 8-bit boundaries
        0x7FFFL, 0x8000L, 0xFFFFL,                    // 16-bit boundaries
        0x7FFFFFFFL, 0x80000000L, 0xFFFFFFFFL,        // 32-bit boundaries
        0x7FFFFFFFFFFFFFFFL, 0x8000000000000000L,     // 64-bit boundaries
        127, 128, 255, 256,
        32767, 32768, 65535, 65536,
        Integer.MAX_VALUE, Integer.MIN_VALUE,
        Long.MAX_VALUE, Long.MIN_VALUE
    };
    
    // 常用攻击偏移值
    public static final long[] EVIL_OFFSETS = {
        0L, 1L, -1L,
        0xFFFFFFFFL,              // Max 32-bit
        0xFFFFFFFFFFFFFFFFL,      // -1 as unsigned
        0xDEADBEEFL,              // Debug marker
        0x41414141L,              // 'AAAA' pattern
    };
    
    private StructureMutator() {}
    
    // ===========================================
    // 整数溢出攻击 (Integer Anomalies)
    // ===========================================
    
    /**
     * 对 LENGTH 字段进行变异
     */
    public static byte[] mutateLength(byte[] data, FieldMapping lengthField, ThreadLocalRandom rand) {
        byte[] result = data.clone();
        long originalValue = lengthField.getOriginalValue();
        long newValue;
        
        int strategy = rand.nextInt(10);
        if (strategy < 2) {
            newValue = rand.nextInt(2);
        } else if (strategy < 4) {
            newValue = EVIL_INTEGERS[rand.nextInt(EVIL_INTEGERS.length)];
        } else if (strategy < 6) {
            newValue = originalValue + rand.nextInt(1000) + 1;
        } else if (strategy < 8) {
            newValue = Math.max(0, originalValue - rand.nextInt(100) - 1);
        } else {
            newValue = rand.nextLong() & 0xFFFFFFFFL;
        }
        
        writeInteger(result, lengthField.getOffset(), lengthField.getLength(), 
                     newValue, lengthField.getByteOrder());
        return result;
    }
    
    /**
     * 对 OFFSET 字段进行变异
     */
    public static byte[] mutateOffset(byte[] data, FieldMapping offsetField, ThreadLocalRandom rand) {
        byte[] result = data.clone();
        int fileSize = data.length;
        long newValue;
        
        int strategy = rand.nextInt(10);
        if (strategy < 2) {
            newValue = fileSize + rand.nextInt(10000);
        } else if (strategy < 4) {
            newValue = rand.nextInt(Math.min(64, fileSize));
        } else if (strategy < 5) {
            newValue = -rand.nextInt(1000) - 1;
        } else if (strategy < 7) {
            newValue = EVIL_OFFSETS[rand.nextInt(EVIL_OFFSETS.length)];
        } else {
            newValue = rand.nextInt(fileSize);
        }
        
        writeInteger(result, offsetField.getOffset(), offsetField.getLength(),
                     newValue, offsetField.getByteOrder());
        return result;
    }
    
    /**
     * 变异 COUNT 字段
     */
    public static byte[] mutateCount(byte[] data, FieldMapping countField, ThreadLocalRandom rand) {
        byte[] result = data.clone();
        long newValue;
        
        int strategy = rand.nextInt(5);
        if (strategy == 0) {
            newValue = 0;
        } else if (strategy == 1) {
            newValue = 0xFFFF;
        } else if (strategy == 2) {
            newValue = 0xFFFFFFFF;
        } else {
            newValue = rand.nextInt(10000);
        }
        
        writeInteger(result, countField.getOffset(), countField.getLength(),
                     newValue, countField.getByteOrder());
        return result;
    }
    
    /**
     * 变异 FLAGS 字段
     */
    public static byte[] mutateFlags(byte[] data, FieldMapping flagsField, ThreadLocalRandom rand) {
        byte[] result = data.clone();
        int offset = flagsField.getOffset();
        int length = flagsField.getLength();
        
        int strategy = rand.nextInt(4);
        if (strategy == 0) {
            for (int i = 0; i < length && offset + i < result.length; i++) {
                result[offset + i] = 0;
            }
        } else if (strategy == 1) {
            for (int i = 0; i < length && offset + i < result.length; i++) {
                result[offset + i] = (byte) 0xFF;
            }
        } else if (strategy == 2) {
            int pos = offset + rand.nextInt(length);
            if (pos < result.length) {
                result[pos] ^= (1 << rand.nextInt(8));
            }
        } else {
            for (int i = 0; i < length && offset + i < result.length; i++) {
                result[offset + i] = (byte) rand.nextInt(256);
            }
        }
        return result;
    }
    
    // ===========================================
    // 块重排 (Chunk Shuffling)
    // ===========================================
    
    /**
     * 重复某个块
     */
    public static byte[] duplicateChunk(byte[] data, BinaryChunk chunk) {
        return duplicateChunk(data, chunk, 1);
    }
    
    /**
     * 重复某个块多次
     */
    public static byte[] duplicateChunk(byte[] data, BinaryChunk chunk, int times) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(data, 0, chunk.getEndOffset());
            
            for (int i = 0; i < times; i++) {
                out.write(chunk.getRawData());
            }
            
            if (chunk.getEndOffset() < data.length) {
                out.write(data, chunk.getEndOffset(), data.length - chunk.getEndOffset());
            }
            
            return out.toByteArray();
        } catch (Exception e) {
            return data;
        }
    }
    
    /**
     * 删除某个块
     */
    public static byte[] deleteChunk(byte[] data, BinaryChunk chunk) {
        if (chunk.isCritical()) {
            return clearChunkData(data, chunk);
        }
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            if (chunk.getStartOffset() > 0) {
                out.write(data, 0, chunk.getStartOffset());
            }
            
            if (chunk.getEndOffset() < data.length) {
                out.write(data, chunk.getEndOffset(), data.length - chunk.getEndOffset());
            }
            
            return out.toByteArray();
        } catch (Exception e) {
            return data;
        }
    }
    
    /**
     * 清空块的数据区（保留头部结构）
     */
    public static byte[] clearChunkData(byte[] data, BinaryChunk chunk) {
        byte[] result = data.clone();
        int dataStart = chunk.getStartOffset() + chunk.getDataOffset();
        int dataEnd = Math.min(dataStart + chunk.getDataLength(), result.length);
        
        for (int i = dataStart; i < dataEnd; i++) {
            result[i] = 0;
        }
        return result;
    }
    
    /**
     * 交换两个块的位置
     */
    public static byte[] swapChunks(byte[] data, BinaryChunk chunk1, BinaryChunk chunk2) {
        if (chunk1.getStartOffset() > chunk2.getStartOffset()) {
            BinaryChunk temp = chunk1;
            chunk1 = chunk2;
            chunk2 = temp;
        }
        
        if (chunk1.getEndOffset() > chunk2.getStartOffset()) {
            return data;
        }
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(data, 0, chunk1.getStartOffset());
            out.write(chunk2.getRawData());
            
            if (chunk1.getEndOffset() < chunk2.getStartOffset()) {
                out.write(data, chunk1.getEndOffset(), 
                         chunk2.getStartOffset() - chunk1.getEndOffset());
            }
            
            out.write(chunk1.getRawData());
            
            if (chunk2.getEndOffset() < data.length) {
                out.write(data, chunk2.getEndOffset(), data.length - chunk2.getEndOffset());
            }
            
            return out.toByteArray();
        } catch (Exception e) {
            return data;
        }
    }
    
    // ===========================================
    // 位翻转 (Bit Flipping)
    // ===========================================
    
    /**
     * 对数据区进行位翻转
     */
    public static byte[] bitFlipDataRegion(byte[] data, int dataStart, int dataLen, ThreadLocalRandom rand) {
        byte[] result = data.clone();
        if (dataLen <= 0) return result;
        
        int flips = rand.nextInt(8) + 1;
        for (int i = 0; i < flips; i++) {
            int pos = dataStart + rand.nextInt(dataLen);
            if (pos < result.length) {
                int bit = rand.nextInt(8);
                result[pos] ^= (1 << bit);
            }
        }
        return result;
    }
    
    /**
     * 对块的数据区进行位翻转
     */
    public static byte[] bitFlipChunkData(byte[] data, BinaryChunk chunk, ThreadLocalRandom rand) {
        int dataStart = chunk.getStartOffset() + chunk.getDataOffset();
        int dataLen = chunk.getDataLength();
        return bitFlipDataRegion(data, dataStart, dataLen, rand);
    }
    
    /**
     * 对指定范围进行随机字节替换
     */
    public static byte[] randomizeRegion(byte[] data, int start, int length, ThreadLocalRandom rand) {
        byte[] result = data.clone();
        int end = Math.min(start + length, result.length);
        
        for (int i = start; i < end; i++) {
            result[i] = (byte) rand.nextInt(256);
        }
        return result;
    }
    
    /**
     * 破坏 Magic
     */
    public static byte[] corruptMagic(byte[] data, FieldMapping magicField, ThreadLocalRandom rand) {
        byte[] result = data.clone();
        int offset = magicField.getOffset();
        int length = magicField.getLength();
        
        if (offset + length <= result.length && length > 0) {
            int pos = offset + rand.nextInt(length);
            result[pos] ^= (byte) (rand.nextInt(255) + 1);
        }
        return result;
    }
    
    // ===========================================
    // 辅助方法
    // ===========================================
    
    /**
     * 写入整数值到字节数组
     */
    public static void writeInteger(byte[] data, int offset, int length, long value, ByteOrder order) {
        if (offset + length > data.length) return;
        
        ByteBuffer bb = ByteBuffer.wrap(data, offset, length).order(order);
        switch (length) {
            case 1:
                bb.put((byte) value);
                break;
            case 2:
                bb.putShort((short) value);
                break;
            case 4:
                bb.putInt((int) value);
                break;
            case 8:
                bb.putLong(value);
                break;
        }
    }
    
    /**
     * 从字节数组读取整数值
     */
    public static long readInteger(byte[] data, int offset, int length, ByteOrder order) {
        if (offset + length > data.length) return 0;
        
        ByteBuffer bb = ByteBuffer.wrap(data, offset, length).order(order);
        switch (length) {
            case 1:
                return bb.get() & 0xFFL;
            case 2:
                return bb.getShort() & 0xFFFFL;
            case 4:
                return bb.getInt() & 0xFFFFFFFFL;
            case 8:
                return bb.getLong();
            default:
                return 0;
        }
    }
    
    /**
     * 在随机块中选择一个进行变异
     */
    public static BinaryChunk selectRandomChunk(List<BinaryChunk> chunks, boolean preferNonCritical, ThreadLocalRandom rand) {
        if (chunks.isEmpty()) return null;
        
        if (preferNonCritical) {
            List<BinaryChunk> nonCritical = new ArrayList<>();
            for (BinaryChunk c : chunks) {
                if (!c.isCritical()) {
                    nonCritical.add(c);
                }
            }
            if (!nonCritical.isEmpty()) {
                return nonCritical.get(rand.nextInt(nonCritical.size()));
            }
        }
        
        return chunks.get(rand.nextInt(chunks.size()));
    }
    
    /**
     * 在块的字段中选择一个进行变异
     */
    public static FieldMapping selectRandomField(BinaryChunk chunk, ThreadLocalRandom rand, FieldType... preferredTypes) {
        List<FieldMapping> fields = chunk.getFields();
        if (fields.isEmpty()) return null;
        
        if (preferredTypes.length > 0) {
            List<FieldMapping> preferred = new ArrayList<>();
            for (FieldMapping f : fields) {
                for (FieldType t : preferredTypes) {
                    if (f.getType() == t) {
                        preferred.add(f);
                        break;
                    }
                }
            }
            if (!preferred.isEmpty()) {
                return preferred.get(rand.nextInt(preferred.size()));
            }
        }
        
        return fields.get(rand.nextInt(fields.size()));
    }
}
