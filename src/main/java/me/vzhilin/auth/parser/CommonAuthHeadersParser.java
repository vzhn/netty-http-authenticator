/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Vladimir Zhilin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package me.vzhilin.auth.parser;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/** Common parser */
class CommonAuthHeadersParser {
    private final char[] chars;

    /** current symbol position */
    private int pos;

    /**
     * header parser
     * @param line header
     */
    CommonAuthHeadersParser(String line) {
        this.chars = line.toCharArray();
        this.pos = 0;
    }

    /**
     * @return current symbol position
     */
    protected int getPos() {
        return pos;
    }

    protected List<String> splitList(String list) {
        List<String> rs = new ArrayList<>(2);
        for (String part: list.split(",")) {
            rs.add(part.trim());
        }
        return rs;
    }

    protected String readQuotedString() throws ParseException {
        readWord("\"");
        StringBuilder word = new StringBuilder();
        while (hasNext() && ch() != '"') {
            word.append(readNext());
        }
        readWord("\"");
        return word.toString();
    }

    protected String readUnquotedString() throws ParseException {
        StringBuilder word = new StringBuilder();
        while (hasNext() && ch() != ',') {
            word.append(readNext());
        }

        return word.toString();
    }

    protected boolean readIfMatches(String word) throws ParseException {
        for (int i = 0; i < word.length(); i++) {
            if (pos + i >= chars.length){
                return false;
            }

            if (Character.toLowerCase(chars[pos + i]) != Character.toLowerCase(word.charAt(i))) {
                return false;
            }
        }

        pos += word.length();

        readWs();
        return true;
    }

    protected void readWord(String word) throws ParseException {
        if (!readIfMatches(word)) {
            throw new ParseException("expected: " + word, pos);
        }
    }

    protected void readWs() throws ParseException {
        while (hasNext() && (ch() == ' ' || ch() == '\r' || ch() == '\n')) {
            ++pos;
        }
    }

    protected char readNext() throws ParseException {
        if (hasNext()) {
            return chars[pos++];
        } else {
            throw new ParseException("EOL", pos);
        }
    }

    /**
     * @return current character
     * @throws ParseException parse error
     */
    protected char ch() throws ParseException {
        if (hasNext()) {
            return chars[pos];
        } else {
            throw new ParseException("Unexpected end of line", pos);
        }
    }

    protected boolean hasNext() {
        return pos < chars.length;
    }
}
