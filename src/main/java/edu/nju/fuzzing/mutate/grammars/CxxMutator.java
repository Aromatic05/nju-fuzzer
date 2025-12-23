package edu.nju.fuzzing.mutate.grammars;
import edu.nju.fuzzing.mutate.AbstractGrammarMutator;
import java.util.Arrays;

public class CxxMutator extends AbstractGrammarMutator {
    @Override
    protected void defineGrammar() {
        addRule("<start>", Arrays.asList("_Z<func><args>", "_Z3foo<type>", "_Z4mainv"));
        addRule("<func>", Arrays.asList("3bar", "4func", "1f"));
        addRule("<args>", Arrays.asList("i", "if", "v", "Pi"));
        addRule("<type>", Arrays.asList("i", "c", "d"));
    }
}