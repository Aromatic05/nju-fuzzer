package edu.nju.fuzzing.mutate.grammars;
import edu.nju.fuzzing.mutate.AbstractGrammarMutator;
import java.util.Arrays;

public class JpegMutator extends AbstractGrammarMutator {
    @Override
    protected void defineGrammar() {
        // SOI (FF D8) ... EOI (FF D9)
        addRule("<start>", Arrays.asList("\u00FF\u00D8<segments>\u00FF\u00D9"));
        addRule("<segments>", Arrays.asList("<dqt><sof>", "<app0><dqt>"));
        // APP0: FF E0
        addRule("<app0>", Arrays.asList("\u00FF\u00E0\u0000\u0010JFIF\u0000\u0001"));
        // DQT: FF DB
        addRule("<dqt>", Arrays.asList("\u00FF\u00DB\u0000\u0043\u0000<data64>"));
        // SOF: FF C0
        addRule("<sof>", Arrays.asList("\u00FF\u00C0\u0000\u0011\u0008<dim>"));
        addRule("<dim>", Arrays.asList("\u0000\u0064\u0000\u0064"));
        addRule("<data64>", Arrays.asList("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }
}