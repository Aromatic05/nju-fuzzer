package edu.nju.fuzzing.schedule;

import edu.nju.fuzzing.model.Seed;

public interface PowerScheduler {
    int energyFor(Seed seed);
}

