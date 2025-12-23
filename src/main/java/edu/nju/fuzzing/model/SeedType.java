package edu.nju.fuzzing.model;

import java.nio.charset.StandardCharsets;

public enum SeedType {
    ELF, JPEG, PNG, PCAP,
    XML, JSON, LUA, CXX,
    UNKNOWN;

    public static SeedType detect(byte[] data) {
        // 1. 基础检查：只拦截空数据
        if (data == null || data.length == 0) return UNKNOWN;

        // 2. 二进制检测：先判断长度，再判断内容 (利用 && 短路特性防止越界)

        // ELF: 4 bytes (7F 45 4C 46)
        if (data.length >= 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') return ELF;

        // PNG: 4 bytes (89 50 4E 47)
        if (data.length >= 4 && (data[0] & 0xFF) == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') return PNG;

        // PCAP: 4 bytes (D4 C3 B2 A1) - 包含大小端
        if (data.length >= 4 &&
                (((data[0] & 0xFF) == 0xD4 && (data[1] & 0xFF) == 0xC3) ||
                        ((data[0] & 0xFF) == 0xA1 && (data[1] & 0xFF) == 0xB2))) return PCAP;

        // JPEG: 2 bytes (FF D8) - 只要2字节就能识别
        if (data.length >= 2 && (data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == 0xD8) return JPEG;

        // 3. 文本检测：转换为字符串后检测
        // 读取前 64 字节即可
        int len = Math.min(data.length, 64);
        String head = new String(data, 0, len, StandardCharsets.ISO_8859_1);
        String trimmed = head.trim();

        // CXX: _Z (2 bytes)
        if (trimmed.startsWith("_Z")) return CXX;

        // XML / JSON (1 byte)
        if (trimmed.startsWith("<")) return XML;
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) return JSON;

        // LUA: 关键字扫描
        // [修复点]：将 "local " 改为 "local"，并增加 "a="，提高极短种子的识别率
        String content = new String(data, 0, Math.min(data.length, 256), StandardCharsets.ISO_8859_1);
        if (content.contains("function") || content.contains("print") ||
                content.contains("local")    || content.contains("a=") ||
                content.contains("end")) {
            return LUA;
        }

        return UNKNOWN;
    }
}