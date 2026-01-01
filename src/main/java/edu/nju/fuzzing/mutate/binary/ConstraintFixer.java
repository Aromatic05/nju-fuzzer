package edu.nju.fuzzing.mutate.binary;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.CRC32;

/**
 * 约束修复器
 * 
 * 在变异完成后，修复文件结构的合法性，确保能骗过解析器的初步检查
 */
public class ConstraintFixer {

    // ===========================================
    // 校验和修复
    // ===========================================

    /**
     * 重新计算并修复 PNG 块的 CRC32
     * 
     * PNG CRC32 计算范围：块类型(4字节) + 块数据
     */
    public static byte[] fixPngChunkCrc(byte[] data, int chunkStart) {
        if (chunkStart + 8 > data.length)
            return data;

        byte[] result = data.clone();

        // 读取块长度
        int length = ByteBuffer.wrap(data, chunkStart, 4).order(ByteOrder.BIG_ENDIAN).getInt();

        // 边界检查
        if (length < 0 || chunkStart + 8 + length + 4 > data.length)
            return data;

        // 计算 CRC（类型 + 数据）
        CRC32 crc = new CRC32();
        crc.update(data, chunkStart + 4, 4 + length); // type(4) + data(length)

        // 写入新的 CRC
        int crcOffset = chunkStart + 8 + length;
        ByteBuffer.wrap(result, crcOffset, 4)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt((int) crc.getValue());

        return result;
    }

    /**
     * 修复所有 PNG 块的 CRC
     */
    public static byte[] fixAllPngCrcs(byte[] data, ScanResult scanResult) {
        byte[] result = data.clone();

        for (BinaryChunk chunk : scanResult.getChunks()) {
            result = fixPngChunkCrc(result, chunk.getStartOffset());
        }

        return result;
    }

    /**
     * 便捷方法：自动扫描并修复所有 PNG CRC
     */
    public static byte[] fixAllPngCrcs(byte[] data) {
        PngScanner scanner = new PngScanner();
        if (!scanner.matches(data)) {
            return data;
        }
        ScanResult result = scanner.scan(data);
        if (!result.isValid()) {
            return data;
        }
        return fixAllPngCrcs(data, result);
    }

    /**
     * 计算 IP 头部校验和
     */
    public static int calculateIpChecksum(byte[] header, int offset, int length) {
        long sum = 0;

        for (int i = 0; i < length; i += 2) {
            int word;
            if (i + 1 < length) {
                word = ((header[offset + i] & 0xFF) << 8) | (header[offset + i + 1] & 0xFF);
            } else {
                word = (header[offset + i] & 0xFF) << 8;
            }
            sum += word;
        }

        // 折叠进位
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return (int) (~sum & 0xFFFF);
    }

    /**
     * 修复 IP 头部校验和
     */
    public static byte[] fixIpChecksum(byte[] data, int ipHeaderOffset, int ihl) {
        if (ipHeaderOffset + ihl * 4 > data.length)
            return data;

        byte[] result = data.clone();

        // 先将校验和字段置零
        result[ipHeaderOffset + 10] = 0;
        result[ipHeaderOffset + 11] = 0;

        // 计算新校验和
        int checksum = calculateIpChecksum(result, ipHeaderOffset, ihl * 4);

        // 写入
        result[ipHeaderOffset + 10] = (byte) (checksum >> 8);
        result[ipHeaderOffset + 11] = (byte) checksum;

        return result;
    }

    // ===========================================
    // 长度对齐修复
    // ===========================================

    /**
     * 更新 PNG 块的长度字段
     */
    public static byte[] fixPngChunkLength(byte[] data, int chunkStart, int newDataLength) {
        if (chunkStart + 4 > data.length)
            return data;

        byte[] result = data.clone();
        ByteBuffer.wrap(result, chunkStart, 4)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(newDataLength);

        return result;
    }

    /**
     * 更新 PCAP 包记录的长度字段
     */
    public static byte[] fixPcapPacketLength(byte[] data, int packetHeaderOffset,
            int inclLen, int origLen, boolean bigEndian) {
        if (packetHeaderOffset + 16 > data.length)
            return data;

        byte[] result = data.clone();
        ByteOrder order = bigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;

        ByteBuffer bb = ByteBuffer.wrap(result, packetHeaderOffset + 8, 8).order(order);
        bb.putInt(inclLen);
        bb.putInt(origLen);

        return result;
    }

    /**
     * 更新 ELF Section 的大小字段
     */
    public static byte[] fixElfSectionSize(byte[] data, int sectionHeaderOffset,
            long newSize, boolean is64Bit) {
        byte[] result = data.clone();
        ByteOrder order = ByteOrder.LITTLE_ENDIAN; // 大多数 ELF 是小端序

        int sizeOffset = sectionHeaderOffset + (is64Bit ? 32 : 20);
        if (sizeOffset + (is64Bit ? 8 : 4) > data.length)
            return data;

        ByteBuffer bb = ByteBuffer.wrap(result, sizeOffset, is64Bit ? 8 : 4).order(order);
        if (is64Bit) {
            bb.putLong(newSize);
        } else {
            bb.putInt((int) newSize);
        }

        return result;
    }

    // ===========================================
    // Magic 恢复
    // ===========================================

    /**
     * 恢复 PNG 文件头
     */
    public static byte[] restorePngMagic(byte[] data) {
        if (data.length < 8)
            return data;

        byte[] result = data.clone();
        byte[] PNG_MAGIC = { (byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };
        System.arraycopy(PNG_MAGIC, 0, result, 0, 8);

        return result;
    }

    /**
     * 恢复 JPEG SOI 标记
     */
    public static byte[] restoreJpegMagic(byte[] data) {
        if (data.length < 2)
            return data;

        byte[] result = data.clone();
        result[0] = (byte) 0xFF;
        result[1] = (byte) 0xD8;

        return result;
    }

    /**
     * 恢复 ELF 文件头
     */
    public static byte[] restoreElfMagic(byte[] data) {
        if (data.length < 4)
            return data;

        byte[] result = data.clone();
        result[0] = 0x7F;
        result[1] = 'E';
        result[2] = 'L';
        result[3] = 'F';

        return result;
    }

    /**
     * 修复 ELF Header 必需字段
     * 
     * 保护以下关键字段：
     * - e_ident[EI_MAGIC] (0-3): 7F 45 4C 46
     * - e_ident[EI_CLASS] (4): 1 (32位) 或 2 (64位)
     * - e_ident[EI_DATA] (5): 1 (小端) 或 2 (大端)
     * - e_ident[EI_VERSION] (6): 1
     * - e_ehsize (52/40): 64 (64位) 或 52 (32位)
     * 
     * @param data          ELF 文件数据
     * @param preserveClass 是否保留原有的 CLASS 值（如果有效）
     * @return 修复后的数据
     */
    public static byte[] fixElfHeaderEssentials(byte[] data, boolean preserveClass) {
        if (data.length < 64)
            return data;

        byte[] result = data.clone();

        // 1. 修复 Magic
        result[0] = 0x7F;
        result[1] = 'E';
        result[2] = 'L';
        result[3] = 'F';

        // 2. 修复 CLASS (EI_CLASS)
        byte originalClass = result[4];
        boolean is64Bit;
        if (preserveClass && (originalClass == 1 || originalClass == 2)) {
            is64Bit = (originalClass == 2);
        } else {
            // 默认使用 64位
            is64Bit = true;
            result[4] = 2;
        }

        // 3. 修复 DATA (EI_DATA)
        if (result[5] != 1 && result[5] != 2) {
            result[5] = 1; // 默认小端序
        }

        // 4. 修复 VERSION (EI_VERSION)
        if (result[6] != 1) {
            result[6] = 1;
        }

        // 5. 修复 EHSIZE
        ByteOrder order = (result[5] == 2) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        int ehsizeOffset = is64Bit ? 52 : 40;
        int expectedEhsize = is64Bit ? 64 : 52;

        if (ehsizeOffset + 2 <= result.length) {
            ByteBuffer bb = ByteBuffer.wrap(result).order(order);
            int currentEhsize = bb.getShort(ehsizeOffset) & 0xFFFF;

            // 如果 ehsize 明显无效，修复它
            if (currentEhsize != expectedEhsize) {
                bb.putShort(ehsizeOffset, (short) expectedEhsize);
            }
        }

        return result;
    }

    /**
     * 修复 ELF Header 必需字段 (使用默认设置)
     */
    public static byte[] fixElfHeaderEssentials(byte[] data) {
        return fixElfHeaderEssentials(data, true);
    }

    /**
     * 更新 ELF Header 中的 Program Header 计数
     */
    public static byte[] updateElfPhnum(byte[] data, int newPhnum, boolean is64Bit) {
        if (data.length < (is64Bit ? 64 : 52))
            return data;

        byte[] result = data.clone();
        ByteOrder order = (data[5] == 2) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        int phnumOffset = is64Bit ? 56 : 44;

        ByteBuffer.wrap(result).order(order).putShort(phnumOffset, (short) newPhnum);
        return result;
    }

    /**
     * 更新 ELF Header 中的 Section Header 计数
     */
    public static byte[] updateElfShnum(byte[] data, int newShnum, boolean is64Bit) {
        if (data.length < (is64Bit ? 64 : 52))
            return data;

        byte[] result = data.clone();
        ByteOrder order = (data[5] == 2) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        int shnumOffset = is64Bit ? 60 : 48;

        ByteBuffer.wrap(result).order(order).putShort(shnumOffset, (short) newShnum);
        return result;
    }

    /**
     * 递增 ELF Header 中的 Program Header 计数
     */
    public static byte[] incrementElfPhnum(byte[] data, boolean is64Bit) {
        if (data.length < (is64Bit ? 64 : 52))
            return data;

        ByteOrder order = (data[5] == 2) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        int phnumOffset = is64Bit ? 56 : 44;
        int currentPhnum = ByteBuffer.wrap(data).order(order).getShort(phnumOffset) & 0xFFFF;

        return updateElfPhnum(data, currentPhnum + 1, is64Bit);
    }

    /**
     * 递减 ELF Header 中的 Program Header 计数
     */
    public static byte[] decrementElfPhnum(byte[] data, boolean is64Bit) {
        if (data.length < (is64Bit ? 64 : 52))
            return data;

        ByteOrder order = (data[5] == 2) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        int phnumOffset = is64Bit ? 56 : 44;
        int currentPhnum = ByteBuffer.wrap(data).order(order).getShort(phnumOffset) & 0xFFFF;

        return updateElfPhnum(data, Math.max(0, currentPhnum - 1), is64Bit);
    }

    /**
     * 递增 ELF Header 中的 Section Header 计数
     */
    public static byte[] incrementElfShnum(byte[] data, boolean is64Bit) {
        if (data.length < (is64Bit ? 64 : 52))
            return data;

        ByteOrder order = (data[5] == 2) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        int shnumOffset = is64Bit ? 60 : 48;
        int currentShnum = ByteBuffer.wrap(data).order(order).getShort(shnumOffset) & 0xFFFF;

        return updateElfShnum(data, currentShnum + 1, is64Bit);
    }

    /**
     * 递减 ELF Header 中的 Section Header 计数
     */
    public static byte[] decrementElfShnum(byte[] data, boolean is64Bit) {
        if (data.length < (is64Bit ? 64 : 52))
            return data;

        ByteOrder order = (data[5] == 2) ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
        int shnumOffset = is64Bit ? 60 : 48;
        int currentShnum = ByteBuffer.wrap(data).order(order).getShort(shnumOffset) & 0xFFFF;

        return updateElfShnum(data, Math.max(0, currentShnum - 1), is64Bit);
    }

    /**
     * 恢复 PCAP 文件头 Magic
     */
    public static byte[] restorePcapMagic(byte[] data, boolean bigEndian) {
        if (data.length < 4)
            return data;

        byte[] result = data.clone();
        // 0xA1B2C3D4 (microseconds)
        if (bigEndian) {
            result[0] = (byte) 0xA1;
            result[1] = (byte) 0xB2;
            result[2] = (byte) 0xC3;
            result[3] = (byte) 0xD4;
        } else {
            result[0] = (byte) 0xD4;
            result[1] = (byte) 0xC3;
            result[2] = (byte) 0xB2;
            result[3] = (byte) 0xA1;
        }

        return result;
    }

    /**
     * 便捷方法：自动检测字节序并恢复 PCAP Magic
     */
    public static byte[] restorePcapMagic(byte[] data) {
        if (data.length < 4)
            return data;

        // 检测当前字节序 (默认使用小端序)
        boolean bigEndian = false;
        int magic = ((data[0] & 0xFF) << 24) | ((data[1] & 0xFF) << 16) |
                ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
        if (magic == 0xA1B2C3D4 || magic == 0xA1B23C4D) {
            bigEndian = true;
        }

        return restorePcapMagic(data, bigEndian);
    }

    // ===========================================
    // JPEG 特定修复
    // ===========================================

    /**
     * 确保 JPEG 以 EOI 结束
     */
    public static byte[] ensureJpegEoi(byte[] data) {
        if (data.length < 2)
            return data;

        // 检查是否已经有 EOI
        if (data[data.length - 2] == (byte) 0xFF && data[data.length - 1] == (byte) 0xD9) {
            return data;
        }

        // 追加 EOI
        byte[] result = new byte[data.length + 2];
        System.arraycopy(data, 0, result, 0, data.length);
        result[result.length - 2] = (byte) 0xFF;
        result[result.length - 1] = (byte) 0xD9;

        return result;
    }

    /**
     * 修复 JPEG 段的长度字段
     */
    public static byte[] fixJpegSegmentLength(byte[] data, int segmentOffset, int newLength) {
        if (segmentOffset + 4 > data.length)
            return data;

        byte[] result = data.clone();
        // 长度包含长度字段自身的2字节
        int lengthValue = newLength + 2;
        result[segmentOffset + 2] = (byte) (lengthValue >> 8);
        result[segmentOffset + 3] = (byte) lengthValue;

        return result;
    }

    // ===========================================
    // 通用修复
    // ===========================================

    /**
     * 根据格式类型选择合适的 Magic 恢复方法
     */
    public static byte[] restoreMagic(byte[] data, String formatType) {
        switch (formatType.toUpperCase()) {
            case "PNG":
                return restorePngMagic(data);
            case "JPEG":
            case "JPG":
                return restoreJpegMagic(data);
            case "ELF":
                return restoreElfMagic(data);
            case "PCAP":
                return restorePcapMagic(data, false); // 默认小端序
            default:
                return data;
        }
    }

    /**
     * 综合修复：恢复 Magic，重算校验和
     */
    public static byte[] fullFix(byte[] data, ScanResult scanResult, boolean fixChecksums) {
        byte[] result = data;

        // 1. 恢复 Magic
        result = restoreMagic(result, scanResult.getFormatType());

        // 2. 修复校验和（如果需要）
        if (fixChecksums) {
            switch (scanResult.getFormatType().toUpperCase()) {
                case "PNG":
                    result = fixAllPngCrcs(result, scanResult);
                    break;
                // 其他格式的校验和修复可以在这里添加
            }
        }

        return result;
    }
}
