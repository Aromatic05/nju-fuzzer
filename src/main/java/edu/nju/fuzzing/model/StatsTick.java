package edu.nju.fuzzing.model;

public record StatsTick(
        long elapsedSec,
        long execsTotal,
        double execsPerSec,
        int queueSize,
        int crashes,
        int hangs
) {}

