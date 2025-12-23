package edu.nju.fuzzing.mutate;
import java.util.Arrays;

public class JsonMutator extends AbstractGrammarMutator {
    @Override
    protected void defineGrammar() {
        addRule("<start>", Arrays.asList("{ <kv> }", "[ <val>, <val> ]"));
        addRule("<kv>", Arrays.asList("\"id\": <val>", "\"key\": \"str\""));
        addRule("<val>", Arrays.asList("123", "true", "null", "[]", "{}"));
    }
}