package edu.nju.fuzzing.cli;

import java.util.ArrayList;
import java.util.List;

public final class CmdLineTokenizer {

    private CmdLineTokenizer() {}

    public static List<String> tokenize(String cmdLine) {
        if (cmdLine == null) throw new IllegalArgumentException("cmdLine is null");
        cmdLine = cmdLine.trim();
        if (cmdLine.isEmpty()) throw new IllegalArgumentException("cmdLine is empty");

        List<String> tokens = new ArrayList<>();
        StringBuilder cur = new StringBuilder();

        boolean inSingle = false;
        boolean inDouble = false;

        for (int i = 0; i < cmdLine.length(); i++) {
            char c = cmdLine.charAt(i);

            if (c == '\'' && !inDouble) {
                inSingle = !inSingle;
                continue;
            }
            if (c == '"' && !inSingle) {
                inDouble = !inDouble;
                continue;
            }

            if (Character.isWhitespace(c) && !inSingle && !inDouble) {
                if (cur.length() > 0) {
                    tokens.add(cur.toString());
                    cur.setLength(0);
                }
                continue;
            }

            cur.append(c);
        }

        if (inSingle || inDouble) {
            throw new IllegalArgumentException("Unclosed quote in cmdLine: " + cmdLine);
        }

        if (cur.length() > 0) tokens.add(cur.toString());

        if (tokens.isEmpty()) throw new IllegalArgumentException("No tokens parsed from cmdLine");
        return tokens;
    }
}
