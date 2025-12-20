package edu.nju.fuzzing.schedule;

import edu.nju.fuzzing.model.Seed;

import java.util.List;

public interface SeedPrioritizer {
    Seed pickNext(List<Seed> queue);
}

