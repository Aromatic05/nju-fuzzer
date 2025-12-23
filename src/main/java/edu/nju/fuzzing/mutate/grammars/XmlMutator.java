package edu.nju.fuzzing.mutate.grammars;
import edu.nju.fuzzing.mutate.AbstractGrammarMutator;
import java.util.Arrays;

public class XmlMutator extends AbstractGrammarMutator {
    @Override
    protected void defineGrammar() {
        addRule("<start>", Arrays.asList("<root><elem/></root>", "<root><elem><elem/></elem></root>"));
        addRule("<elem>", Arrays.asList("<tag prop='val'/>", "<tag>text</tag>"));
        addRule("<tag>", Arrays.asList("foo", "bar", "div"));
    }
}