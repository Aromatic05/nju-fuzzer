package edu.nju.fuzzing.cov;

/**
 * Fast xxHash64 implementation for bitmap comparison.
 * 
 * xxHash is a non-cryptographic hash function optimized for speed.
 * This implementation is based on the xxHash64 algorithm by Yann Collet.
 * 
 * Used by HashFilteredStrategy and CoverageDiffStrategyEx for quick
 * bitmap deduplication.
 */
public final class XxHash64 {

    // xxHash64 magic constants
    private static final long PRIME64_1 = 0x9E3779B185EBCA87L;
    private static final long PRIME64_2 = 0xC2B2AE3D27D4EB4FL;
    private static final long PRIME64_3 = 0x165667B19E3779F9L;
    private static final long PRIME64_4 = 0x85EBCA77C2B2AE63L;
    private static final long PRIME64_5 = 0x27D4EB2F165667C5L;

    private XxHash64() {
        // Utility class
    }

    /**
     * Computes xxHash64 of the given byte array.
     *
     * @param data the data to hash
     * @return 64-bit hash value
     */
    public static long hash(byte[] data) {
        return hash(data, 0, data.length, 0L);
    }

    /**
     * Computes xxHash64 of a portion of the byte array.
     *
     * @param data   the data to hash
     * @param offset starting offset
     * @param length number of bytes to hash
     * @return 64-bit hash value
     */
    public static long hash(byte[] data, int offset, int length) {
        return hash(data, offset, length, 0L);
    }

    /**
     * Computes xxHash64 with a seed.
     *
     * @param data   the data to hash
     * @param offset starting offset
     * @param length number of bytes to hash
     * @param seed   seed value
     * @return 64-bit hash value
     */
    public static long hash(byte[] data, int offset, int length, long seed) {
        long h64;
        int end = offset + length;
        int remaining = length;
        int pos = offset;

        if (length >= 32) {
            // Process 32-byte blocks
            long v1 = seed + PRIME64_1 + PRIME64_2;
            long v2 = seed + PRIME64_2;
            long v3 = seed;
            long v4 = seed - PRIME64_1;

            int limit = end - 32;
            while (pos <= limit) {
                v1 = round(v1, getLong(data, pos));
                pos += 8;
                v2 = round(v2, getLong(data, pos));
                pos += 8;
                v3 = round(v3, getLong(data, pos));
                pos += 8;
                v4 = round(v4, getLong(data, pos));
                pos += 8;
            }

            h64 = Long.rotateLeft(v1, 1) + Long.rotateLeft(v2, 7) +
                  Long.rotateLeft(v3, 12) + Long.rotateLeft(v4, 18);

            h64 = mergeRound(h64, v1);
            h64 = mergeRound(h64, v2);
            h64 = mergeRound(h64, v3);
            h64 = mergeRound(h64, v4);

            remaining = end - pos;
        } else {
            h64 = seed + PRIME64_5;
        }

        h64 += length;

        // Process remaining 8-byte blocks
        while (remaining >= 8) {
            long k1 = getLong(data, pos);
            h64 ^= round(0, k1);
            h64 = Long.rotateLeft(h64, 27) * PRIME64_1 + PRIME64_4;
            pos += 8;
            remaining -= 8;
        }

        // Process remaining 4-byte block
        if (remaining >= 4) {
            h64 ^= (getInt(data, pos) & 0xFFFFFFFFL) * PRIME64_1;
            h64 = Long.rotateLeft(h64, 23) * PRIME64_2 + PRIME64_3;
            pos += 4;
            remaining -= 4;
        }

        // Process remaining bytes
        while (remaining > 0) {
            h64 ^= (data[pos] & 0xFF) * PRIME64_5;
            h64 = Long.rotateLeft(h64, 11) * PRIME64_1;
            pos++;
            remaining--;
        }

        // Final mix
        h64 ^= h64 >>> 33;
        h64 *= PRIME64_2;
        h64 ^= h64 >>> 29;
        h64 *= PRIME64_3;
        h64 ^= h64 >>> 32;

        return h64;
    }

    private static long round(long acc, long input) {
        acc += input * PRIME64_2;
        acc = Long.rotateLeft(acc, 31);
        acc *= PRIME64_1;
        return acc;
    }

    private static long mergeRound(long acc, long val) {
        val = round(0, val);
        acc ^= val;
        acc = acc * PRIME64_1 + PRIME64_4;
        return acc;
    }

    private static long getLong(byte[] data, int pos) {
        return ((long) (data[pos] & 0xFF)) |
               ((long) (data[pos + 1] & 0xFF) << 8) |
               ((long) (data[pos + 2] & 0xFF) << 16) |
               ((long) (data[pos + 3] & 0xFF) << 24) |
               ((long) (data[pos + 4] & 0xFF) << 32) |
               ((long) (data[pos + 5] & 0xFF) << 40) |
               ((long) (data[pos + 6] & 0xFF) << 48) |
               ((long) (data[pos + 7] & 0xFF) << 56);
    }

    private static int getInt(byte[] data, int pos) {
        return (data[pos] & 0xFF) |
               ((data[pos + 1] & 0xFF) << 8) |
               ((data[pos + 2] & 0xFF) << 16) |
               ((data[pos + 3] & 0xFF) << 24);
    }
}
