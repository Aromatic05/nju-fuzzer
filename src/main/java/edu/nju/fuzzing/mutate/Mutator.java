package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.util.List;

public interface Mutator {
    List<Testcase> mutate(Seed seed, int energy);
}
