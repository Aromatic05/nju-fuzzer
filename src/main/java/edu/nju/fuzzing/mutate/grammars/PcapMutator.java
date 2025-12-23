package edu.nju.fuzzing.mutate.grammars;
import edu.nju.fuzzing.mutate.AbstractGrammarMutator;
import java.util.Arrays;

public class PcapMutator extends AbstractGrammarMutator {
    @Override
    protected void defineGrammar() {
        // Global Header: Magic(D4 C3 B2 A1) ...
        String global = "\u00D4\u00C3\u00B2\u00A1\u0002\u0000\u0004\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0004\u0000\u0001\u0000\u0000\u0000";
        addRule("<start>", Arrays.asList(global + "<packet>"));
        addRule("<packet>", Arrays.asList("<p_hdr><p_data>", "<p_hdr><p_data><packet>"));
        addRule("<p_hdr>", Arrays.asList("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0010\u0000\u0000\u0000\u0010\u0000\u0000\u0000"));
        addRule("<p_data>", Arrays.asList("0123456789ABCDEF"));
    }
}