package edu.nju.fuzzing.cov;

import java.util.Arrays;
import java.util.BitSet;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.stream.IntStream;

/**
 * Efficient representation of a sparse set of edge indices.
 * Used to track which edges were hit during an execution.
 * 
 * This class provides both:
 * - Fast iteration (sorted array for small sets)
 * - Fast membership testing (BitSet for large sets)
 * 
 * Immutable after construction.
 */
public final class EdgeSet implements Iterable<Integer> {

    private static final EdgeSet EMPTY = new EdgeSet(new int[0]);

    private final int[] edges;  // Sorted array of edge indices

    private EdgeSet(int[] edges) {
        this.edges = edges;
    }

    /**
     * Creates an EdgeSet from a bitmap, extracting non-zero indices.
     *
     * @param bitmap the coverage bitmap
     * @return EdgeSet containing indices of non-zero bytes
     */
    public static EdgeSet fromBitmap(byte[] bitmap) {
        if (bitmap == null || bitmap.length == 0) {
            return EMPTY;
        }

        // Count non-zero first
        int count = 0;
        for (byte b : bitmap) {
            if (b != 0) count++;
        }

        if (count == 0) {
            return EMPTY;
        }

        // Collect indices
        int[] edges = new int[count];
        int idx = 0;
        for (int i = 0; i < bitmap.length; i++) {
            if (bitmap[i] != 0) {
                edges[idx++] = i;
            }
        }

        return new EdgeSet(edges);
    }

    /**
     * Creates an EdgeSet from explicit indices.
     * The indices will be sorted and deduplicated.
     *
     * @param indices the edge indices
     * @return EdgeSet containing the specified indices
     */
    public static EdgeSet of(int... indices) {
        if (indices == null || indices.length == 0) {
            return EMPTY;
        }

        // Sort and deduplicate
        int[] sorted = Arrays.copyOf(indices, indices.length);
        Arrays.sort(sorted);

        // Count unique
        int uniqueCount = 1;
        for (int i = 1; i < sorted.length; i++) {
            if (sorted[i] != sorted[i - 1]) {
                uniqueCount++;
            }
        }

        if (uniqueCount == sorted.length) {
            return new EdgeSet(sorted);
        }

        // Deduplicate
        int[] unique = new int[uniqueCount];
        unique[0] = sorted[0];
        int idx = 1;
        for (int i = 1; i < sorted.length; i++) {
            if (sorted[i] != sorted[i - 1]) {
                unique[idx++] = sorted[i];
            }
        }

        return new EdgeSet(unique);
    }

    /**
     * Returns an empty EdgeSet.
     */
    public static EdgeSet empty() {
        return EMPTY;
    }

    /**
     * Returns the number of edges in this set.
     */
    public int size() {
        return edges.length;
    }

    /**
     * Returns true if this set is empty.
     */
    public boolean isEmpty() {
        return edges.length == 0;
    }

    /**
     * Returns true if this set contains the specified edge index.
     * Uses binary search for O(log n) lookup.
     */
    public boolean contains(int edgeIndex) {
        return Arrays.binarySearch(edges, edgeIndex) >= 0;
    }

    /**
     * Returns the edge indices as an array.
     * The returned array is a copy; modifications won't affect this EdgeSet.
     */
    public int[] toArray() {
        return Arrays.copyOf(edges, edges.length);
    }

    /**
     * Returns a stream of edge indices.
     */
    public IntStream stream() {
        return Arrays.stream(edges);
    }

    /**
     * Returns the intersection with another EdgeSet.
     */
    public EdgeSet intersect(EdgeSet other) {
        if (this.isEmpty() || other.isEmpty()) {
            return EMPTY;
        }

        int[] result = new int[Math.min(this.edges.length, other.edges.length)];
        int i = 0, j = 0, k = 0;

        while (i < this.edges.length && j < other.edges.length) {
            if (this.edges[i] < other.edges[j]) {
                i++;
            } else if (this.edges[i] > other.edges[j]) {
                j++;
            } else {
                result[k++] = this.edges[i];
                i++;
                j++;
            }
        }

        return k == 0 ? EMPTY : new EdgeSet(Arrays.copyOf(result, k));
    }

    /**
     * Returns the union with another EdgeSet.
     */
    public EdgeSet union(EdgeSet other) {
        if (this.isEmpty()) return other;
        if (other.isEmpty()) return this;

        int[] result = new int[this.edges.length + other.edges.length];
        int i = 0, j = 0, k = 0;

        while (i < this.edges.length && j < other.edges.length) {
            if (this.edges[i] < other.edges[j]) {
                result[k++] = this.edges[i++];
            } else if (this.edges[i] > other.edges[j]) {
                result[k++] = other.edges[j++];
            } else {
                result[k++] = this.edges[i];
                i++;
                j++;
            }
        }

        while (i < this.edges.length) {
            result[k++] = this.edges[i++];
        }
        while (j < other.edges.length) {
            result[k++] = other.edges[j++];
        }

        return new EdgeSet(Arrays.copyOf(result, k));
    }

    /**
     * Returns edges in this set that are not in the other set (this - other).
     */
    public EdgeSet subtract(EdgeSet other) {
        if (this.isEmpty() || other.isEmpty()) {
            return this;
        }

        int[] result = new int[this.edges.length];
        int i = 0, j = 0, k = 0;

        while (i < this.edges.length && j < other.edges.length) {
            if (this.edges[i] < other.edges[j]) {
                result[k++] = this.edges[i++];
            } else if (this.edges[i] > other.edges[j]) {
                j++;
            } else {
                i++;
                j++;
            }
        }

        while (i < this.edges.length) {
            result[k++] = this.edges[i++];
        }

        return k == 0 ? EMPTY : new EdgeSet(Arrays.copyOf(result, k));
    }

    /**
     * Converts to a BitSet representation.
     * Useful for frequent membership testing.
     */
    public BitSet toBitSet() {
        BitSet bitSet = new BitSet();
        for (int edge : edges) {
            bitSet.set(edge);
        }
        return bitSet;
    }

    @Override
    public Iterator<Integer> iterator() {
        return new Iterator<>() {
            private int idx = 0;

            @Override
            public boolean hasNext() {
                return idx < edges.length;
            }

            @Override
            public Integer next() {
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                return edges[idx++];
            }
        };
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EdgeSet other)) return false;
        return Arrays.equals(edges, other.edges);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(edges);
    }

    @Override
    public String toString() {
        if (edges.length <= 10) {
            return "EdgeSet" + Arrays.toString(edges);
        }
        return "EdgeSet[size=" + edges.length + ", first10=" + 
               Arrays.toString(Arrays.copyOf(edges, 10)) + "...]";
    }
}
