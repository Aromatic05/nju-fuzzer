package edu.nju.fuzzing.exec;

import edu.nju.fuzzing.model.TargetSpec;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class CommandResolver {

    private CommandResolver() {}

    public static TargetCommand resolve(TargetSpec spec, Path inputFile) {
        if (spec == null) throw new IllegalArgumentException("spec is null");

        int atCount = 0;
        for (String s : spec.argvTemplate()) {
            if ("@@".equals(s)) atCount++;
        }

        if (atCount > 0) {
            if (inputFile == null) throw new IllegalArgumentException("inputFile is null for FILE mode");
            String inputPath = inputFile.toAbsolutePath().toString();

            List<String> argv = new ArrayList<>(spec.argvTemplate().size());
            for (String token : spec.argvTemplate()) {
                argv.add("@@".equals(token) ? inputPath : token);
            }
            return new TargetCommand(argv, InputMode.FILE, inputFile, spec.env());
        } else {
            // stdin 模式：不替换 argv，不要求 inputFile
            return new TargetCommand(List.copyOf(spec.argvTemplate()), InputMode.STDIN, null, spec.env());
        }
    }
}
