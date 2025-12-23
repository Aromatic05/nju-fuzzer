package edu.nju.fuzzing.mutate;
import java.util.Arrays;

public class ElfMutator extends AbstractGrammarMutator {
    @Override
    protected void defineGrammar() {
        // Magic: 0x7F 'E' 'L' 'F'
        String header = "\u007FELF\u0002\u0001\u0001\u0000";
        addRule("<start>", Arrays.asList(header + "<padding><type><machine>"));
        addRule("<padding>", Arrays.asList("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000"));
        addRule("<type>", Arrays.asList("\u0002\u0000", "\u0003\u0000"));
        addRule("<machine>", Arrays.asList("\u003E\u0000", "\u0003\u0000"));
    }
}