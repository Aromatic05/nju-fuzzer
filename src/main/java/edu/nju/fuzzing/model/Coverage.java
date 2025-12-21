package edu.nju.fuzzing.model;

import java.util.concurrent.atomic.AtomicLong;

public record Coverage(
        long execId,
        long timestampMillis,
        int nonZeroBytes,
        int newBytes,
        boolean interesting
) {
    private static final AtomicLong EXEC_ID_COUNTER = new AtomicLong(0);

    public static Coverage empty(RunResult result) {
        return new Coverage(
                EXEC_ID_COUNTER.incrementAndGet(),
                System.currentTimeMillis(),
                0,
                0,
                false
        );
    }
}
