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
            0x7FL, 0x80L, 0xFFL, // 8-bit boundaries
            0x7FFFL, 0x8000L, 0xFFFFL, // 16-bit boundaries
            0x7FFFFFFFL, 0x80000000L, 0xFFFFFFFFL, // 32-bit boundaries
            0x7FFFFFFFFFFFFFFFL, 0x8000000000000000L, // 64-bit boundaries
            127, 128, 255, 256,
            32767, 32768, 65535, 65536,
            Integer.MAX_VALUE, Integer.MIN_VALUE,
            Long.MAX_VALUE, Long.MIN_VALUE
    };

    // 常用攻击偏移值
    public static final long[] EVIL_OFFSETS = {
            0L, 1L, -1L,
            0xFFFFFFFFL, // Max 32-bit
            0xFFFFFFFFFFFFFFFFL, // -1 as unsigned
            0xDEADBEEFL, // Debug marker
            0x41414141L, // 'AAAA' pattern
    };

    private StructureMutator() {
    }

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
        if (dataLen <= 0)
            return result;

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
        if (offset + length > data.length)
            return;

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
        if (offset + length > data.length)
            return 0;

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
    public static BinaryChunk selectRandomChunk(List<BinaryChunk> chunks, boolean preferNonCritical,
            ThreadLocalRandom rand) {
        if (chunks.isEmpty())
            return null;

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
    public static FieldMapping selectRandomField(BinaryChunk chunk, ThreadLocalRandom rand,
            FieldType... preferredTypes) {
        List<FieldMapping> fields = chunk.getFields();
        if (fields.isEmpty())
            return null;

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

    // ===========================================
    // 耦合字段变异 (Coupled Field Mutation)
    // ===========================================

    /**
     * 变异 Offset 字段时同步调整对应的 Size 字段
     * 确保 offset + size <= fileSize，使解析器能进入更深层处理
     *
     * @param data        原始数据
     * @param offsetField 偏移字段
     * @param sizeField   大小字段
     * @param rand        随机数生成器
     * @return 变异后的数据
     */
    public static byte[] mutateCoupledOffsetSize(byte[] data, FieldMapping offsetField,
            FieldMapping sizeField, ThreadLocalRandom rand) {
        byte[] result = data.clone();
        int fileSize = data.length;

        int strategy = rand.nextInt(10);
        long newOffset;
        long newSize;

        if (strategy < 3) {
            // 30%: 有效范围内的随机偏移
            newOffset = rand.nextInt(Math.max(1, fileSize - 64)) + 64; // 跳过头部
            long maxSize = fileSize - newOffset;
            newSize = rand.nextLong(Math.max(1, maxSize));
        } else if (strategy < 5) {
            // 20%: 偏移刚好越界 (触发边界检查)
            newOffset = fileSize + rand.nextInt(100);
            newSize = rand.nextInt(1000);
        } else if (strategy < 7) {
            // 20%: 偏移有效但 size 过大 (触发长度检查)
            newOffset = rand.nextInt(Math.max(1, fileSize / 2));
            newSize = fileSize * 2L + rand.nextInt(10000);
        } else if (strategy < 8) {
            // 10%: 负偏移 (触发符号扩展漏洞)
            newOffset = -rand.nextInt(1000) - 1;
            newSize = rand.nextInt(1000);
        } else {
            // 20%: 使用恶意值
            newOffset = EVIL_OFFSETS[rand.nextInt(EVIL_OFFSETS.length)];
            newSize = EVIL_INTEGERS[rand.nextInt(EVIL_INTEGERS.length)];
        }

        writeInteger(result, offsetField.getOffset(), offsetField.getLength(),
                newOffset, offsetField.getByteOrder());
        writeInteger(result, sizeField.getOffset(), sizeField.getLength(),
                newSize, sizeField.getByteOrder());

        return result;
    }

    /**
     * 变异 ELF Section Type 字段
     * 
     * @param data      原始数据
     * @param typeField sh_type 字段
     * @param rand      随机数生成器
     * @return 变异后的数据
     */
    public static byte[] mutateElfSectionType(byte[] data, FieldMapping typeField, ThreadLocalRandom rand) {
        byte[] result = data.clone();

        int strategy = rand.nextInt(10);
        int newType;

        if (strategy < 2) {
            // 20%: 无效类型
            newType = 0xFFFFFFFF;
        } else if (strategy < 4) {
            // 20%: 敏感类型 (触发特殊处理)
            int[] sensitiveTypes = {
                    2, // SHT_SYMTAB
                    6, // SHT_DYNAMIC
                    11, // SHT_DYNSYM
                    7, // SHT_NOTE
            };
            newType = sensitiveTypes[rand.nextInt(sensitiveTypes.length)];
        } else if (strategy < 6) {
            // 20%: GNU 扩展类型
            int[] gnuTypes = {
                    0x6ffffff6, // SHT_GNU_HASH
                    0x6ffffffd, // SHT_GNU_verdef
                    0x6ffffffe, // SHT_GNU_verneed
                    0x6fffffff, // SHT_GNU_versym
            };
            newType = gnuTypes[rand.nextInt(gnuTypes.length)];
        } else if (strategy < 8) {
            // 20%: 标准类型
            newType = rand.nextInt(20);
        } else {
            // 20%: 随机类型
            newType = rand.nextInt();
        }

        writeInteger(result, typeField.getOffset(), typeField.getLength(),
                newType, typeField.getByteOrder());
        return result;
    }

    /**
     * 变异 ELF Entry Point 字段
     */
    public static byte[] mutateElfEntryPoint(byte[] data, FieldMapping entryField, ThreadLocalRandom rand) {
        byte[] result = data.clone();

        int strategy = rand.nextInt(10);
        long newEntry;

        if (strategy < 2) {
            // 20%: NULL entry
            newEntry = 0;
        } else if (strategy < 4) {
            // 20%: 最大值
            newEntry = entryField.getLength() == 8 ? 0xFFFFFFFFFFFFFFFFL : 0xFFFFFFFFL;
        } else if (strategy < 6) {
            // 20%: 常见基地址附近
            long[] bases = { 0x400000, 0x8048000, 0x10000 };
            long base = bases[rand.nextInt(bases.length)];
            newEntry = base + (rand.nextInt(2001) - 1000); // base ± 1000
        } else if (strategy < 8) {
            // 20%: 内核地址空间 (可能触发权限检查)
            newEntry = 0xFFFFFFFF80000000L + rand.nextInt(0x10000000);
        } else {
            // 20%: 随机地址
            newEntry = rand.nextLong();
        }

        writeInteger(result, entryField.getOffset(), entryField.getLength(),
                newEntry, entryField.getByteOrder());
        return result;
    }

    /**
     * 变异 ELF Machine Type 字段
     */
    public static byte[] mutateElfMachineType(byte[] data, FieldMapping machineField, ThreadLocalRandom rand) {
        byte[] result = data.clone();

        int strategy = rand.nextInt(10);
        int newMachine;

        if (strategy < 3) {
            // 30%: 常见架构
            int[] commonMachines = {
                    0x03, // EM_386 (x86)
                    0x3E, // EM_X86_64
                    0x28, // EM_ARM
                    0xB7, // EM_AARCH64
                    0xF3, // EM_RISCV
            };
            newMachine = commonMachines[rand.nextInt(commonMachines.length)];
        } else if (strategy < 5) {
            // 20%: 无效/保留值
            newMachine = 0xFFFF;
        } else if (strategy < 7) {
            // 20%: 老旧/罕见架构
            int[] rareMachines = {
                    0x02, // EM_SPARC
                    0x08, // EM_MIPS
                    0x14, // EM_PPC
                    0x15, // EM_PPC64
            };
            newMachine = rareMachines[rand.nextInt(rareMachines.length)];
        } else {
            // 30%: 随机值
            newMachine = rand.nextInt(0x10000);
        }

        writeInteger(result, machineField.getOffset(), machineField.getLength(),
                newMachine, machineField.getByteOrder());
        return result;
    }

    /**
     * 创建重叠的 Section/Segment
     * 通过修改 offset 使两个 Section 共享数据区域
     */
    public static byte[] createOverlappingSections(byte[] data,
            FieldMapping offset1, FieldMapping offset2,
            ThreadLocalRandom rand) {
        byte[] result = data.clone();

        // 读取第一个偏移
        long off1 = readInteger(data, offset1.getOffset(), offset1.getLength(), offset1.getByteOrder());

        // 设置第二个偏移为第一个的附近，创建重叠
        long off2 = off1 + rand.nextInt(100); // 部分重叠

        writeInteger(result, offset2.getOffset(), offset2.getLength(),
                off2, offset2.getByteOrder());

        return result;
    }
}
