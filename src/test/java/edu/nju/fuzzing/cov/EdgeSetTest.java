package edu.nju.fuzzing.cov;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for EdgeSet.
 */
class EdgeSetTest {

    @Test
    @DisplayName("fromBitmap creates EdgeSet from bitmap")
    void fromBitmap_createsEdgeSet() {
        byte[] bitmap = new byte[100];
        bitmap[5] = 1;
        bitmap[10] = 2;
        bitmap[50] = (byte) 255;

        EdgeSet edges = EdgeSet.fromBitmap(bitmap);

        assertEquals(3, edges.size());
        assertTrue(edges.contains(5));
        assertTrue(edges.contains(10));
        assertTrue(edges.contains(50));
        assertFalse(edges.contains(0));
        assertFalse(edges.contains(99));
    }

    @Test
    @DisplayName("fromBitmap returns empty for all-zero bitmap")
    void fromBitmap_emptyForZeroBitmap() {
        byte[] bitmap = new byte[100];
        EdgeSet edges = EdgeSet.fromBitmap(bitmap);
        assertTrue(edges.isEmpty());
        assertEquals(0, edges.size());
    }

    @Test
    @DisplayName("of creates EdgeSet from indices")
    void of_createsEdgeSet() {
        EdgeSet edges = EdgeSet.of(3, 1, 4, 1, 5, 9, 2, 6);

        // Should be sorted and deduplicated
        assertEquals(7, edges.size());
        int[] array = edges.toArray();
        assertArrayEquals(new int[]{1, 2, 3, 4, 5, 6, 9}, array);
    }

    @Test
    @DisplayName("empty returns empty set")
    void empty_returnsEmptySet() {
        EdgeSet edges = EdgeSet.empty();
        assertTrue(edges.isEmpty());
        assertEquals(0, edges.size());
        assertFalse(edges.contains(0));
    }

    @Test
    @DisplayName("contains uses binary search")
    void contains_usesBinarySearch() {
        EdgeSet edges = EdgeSet.of(10, 20, 30, 40, 50);

        assertTrue(edges.contains(10));
        assertTrue(edges.contains(30));
        assertTrue(edges.contains(50));
        assertFalse(edges.contains(15));
        assertFalse(edges.contains(0));
        assertFalse(edges.contains(100));
    }

    @Test
    @DisplayName("intersect returns common edges")
    void intersect_returnsCommonEdges() {
        EdgeSet a = EdgeSet.of(1, 2, 3, 4, 5);
        EdgeSet b = EdgeSet.of(3, 4, 5, 6, 7);

        EdgeSet intersection = a.intersect(b);

        assertEquals(3, intersection.size());
        assertTrue(intersection.contains(3));
        assertTrue(intersection.contains(4));
        assertTrue(intersection.contains(5));
    }

    @Test
    @DisplayName("union returns all edges")
    void union_returnsAllEdges() {
        EdgeSet a = EdgeSet.of(1, 2, 3);
        EdgeSet b = EdgeSet.of(3, 4, 5);

        EdgeSet union = a.union(b);

        assertEquals(5, union.size());
        assertArrayEquals(new int[]{1, 2, 3, 4, 5}, union.toArray());
    }

    @Test
    @DisplayName("subtract returns difference")
    void subtract_returnsDifference() {
        EdgeSet a = EdgeSet.of(1, 2, 3, 4, 5);
        EdgeSet b = EdgeSet.of(2, 4);

        EdgeSet diff = a.subtract(b);

        assertEquals(3, diff.size());
        assertArrayEquals(new int[]{1, 3, 5}, diff.toArray());
    }

    @Test
    @DisplayName("toBitSet creates correct BitSet")
    void toBitSet_createsCorrectBitSet() {
        EdgeSet edges = EdgeSet.of(1, 5, 10);

        var bitSet = edges.toBitSet();

        assertTrue(bitSet.get(1));
        assertTrue(bitSet.get(5));
        assertTrue(bitSet.get(10));
        assertFalse(bitSet.get(0));
        assertFalse(bitSet.get(2));
    }

    @Test
    @DisplayName("stream allows streaming operations")
    void stream_allowsStreaming() {
        EdgeSet edges = EdgeSet.of(1, 2, 3, 4, 5);

        int sum = edges.stream().sum();

        assertEquals(15, sum);
    }

    @Test
    @DisplayName("iterator allows iteration")
    void iterator_allowsIteration() {
        EdgeSet edges = EdgeSet.of(1, 2, 3);
        int sum = 0;

        for (int edge : edges) {
            sum += edge;
        }

        assertEquals(6, sum);
    }

    @Test
    @DisplayName("equals and hashCode work correctly")
    void equalsAndHashCode() {
        EdgeSet a = EdgeSet.of(1, 2, 3);
        EdgeSet b = EdgeSet.of(3, 2, 1);  // Same edges, different order
        EdgeSet c = EdgeSet.of(1, 2, 4);

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
    }
}
