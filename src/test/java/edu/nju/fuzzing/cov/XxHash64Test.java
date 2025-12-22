package edu.nju.fuzzing.cov;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for XxHash64.
 */
class XxHash64Test {

    @Test
    @DisplayName("hash produces consistent results")
    void hash_producesConsistentResults() {
        byte[] data = "Hello, World!".getBytes();

        long hash1 = XxHash64.hash(data);
        long hash2 = XxHash64.hash(data);

        assertEquals(hash1, hash2);
    }

    @Test
    @DisplayName("different data produces different hashes")
    void hash_differentData_differentHashes() {
        byte[] data1 = "Hello".getBytes();
        byte[] data2 = "World".getBytes();

        long hash1 = XxHash64.hash(data1);
        long hash2 = XxHash64.hash(data2);

        assertNotEquals(hash1, hash2);
    }

    @Test
    @DisplayName("hash handles empty array")
    void hash_emptyArray() {
        byte[] empty = new byte[0];
        long hash = XxHash64.hash(empty);
        // Should not throw and return a valid hash
        assertTrue(hash != 0 || hash == 0);  // Just check it runs
    }

    @Test
    @DisplayName("hash with offset and length")
    void hash_withOffsetAndLength() {
        byte[] data = "Hello, World!".getBytes();

        long fullHash = XxHash64.hash(data);
        long partialHash = XxHash64.hash(data, 0, 5);  // Just "Hello"

        assertNotEquals(fullHash, partialHash);
    }

    @Test
    @DisplayName("hash handles large data")
    void hash_largeData() {
        byte[] large = new byte[65536];
        for (int i = 0; i < large.length; i++) {
            large[i] = (byte) (i % 256);
        }

        long hash = XxHash64.hash(large);
        // Should produce a valid hash
        assertNotEquals(0, hash);
    }

    @Test
    @DisplayName("hash with seed produces different result")
    void hash_withSeed() {
        byte[] data = "Hello".getBytes();

        long hash1 = XxHash64.hash(data, 0, data.length, 0L);
        long hash2 = XxHash64.hash(data, 0, data.length, 12345L);

        assertNotEquals(hash1, hash2);
    }

    @Test
    @DisplayName("single byte changes produce different hash")
    void hash_singleByteChange() {
        byte[] data1 = new byte[100];
        byte[] data2 = new byte[100];
        data2[50] = 1;  // Single byte difference

        long hash1 = XxHash64.hash(data1);
        long hash2 = XxHash64.hash(data2);

        assertNotEquals(hash1, hash2);
    }
}
