package edu.nju.fuzzing.mutate;
import java.util.Arrays;

public class PngMutator extends AbstractGrammarMutator {
    @Override
    protected void defineGrammar() {
        // Magic: 89 50 4E 47 0D 0A 1A 0A
        // 注意使用 \r\n 代替 \\u000D\\u000A 防止编译错误
        String magic = "\u0089PNG\r\n\u001A\n";
        addRule("<start>", Arrays.asList(magic + "<ihdr><iend>"));
        // IHDR Chunk
        addRule("<ihdr>", Arrays.asList("\u0000\u0000\u0000\rIHDR\u0000\u0000\u0000\u0010\u0000\u0000\u0000\u0010\u0008\u0002\u0000\u0000\u0000\u0000"));
        // IEND Chunk
        addRule("<iend>", Arrays.asList("\u0000\u0000\u0000\u0000IEND\u00AE\u0042\u0060\u0082"));
    }
}