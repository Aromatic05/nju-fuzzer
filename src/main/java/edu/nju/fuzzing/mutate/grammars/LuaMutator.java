package edu.nju.fuzzing.mutate.grammars;
import edu.nju.fuzzing.mutate.AbstractGrammarMutator;
import java.util.Arrays;

public class LuaMutator extends AbstractGrammarMutator {
    @Override
    protected void defineGrammar() {
        addRule("<start>", Arrays.asList("function f() <stmt> end", "a=1; <stmt>"));
        addRule("<stmt>", Arrays.asList("print('ok')", "if 1==1 then return end"));
    }
}