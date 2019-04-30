package me.vzhilin.auth.parser;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/** Common parser */
class CommonAuthHeadersParser {
    /** Строка */
    private final char[] chars;

    /** Текущий символ */
    private int pos;

    /**
     * Парсер
     * @param line строка
     */
    CommonAuthHeadersParser(String line) {
        this.chars = line.toCharArray();
        this.pos = 0;
    }

    /**
     * @return номер текущего символа
     */
    protected int getPos() {
        return pos;
    }

    /**
     * Разбираем список строк, разделенных запятыми
     * @param list список строк
     * @return отдельные строки
     */
    protected List<String> parseList(String list) {
        List<String> rs = new ArrayList<>(2);
        for (String part: list.split(",")) {
            rs.add(part.trim());
        }
        return rs;
    }

    /**
     * @return строка в кавычках
     * @throws ParseException ошибка
     */
    protected String readQuotedString() throws ParseException {
        readWord("\"");
        StringBuilder word = new StringBuilder();
        while (hasNext() && ch() != '"') {
            word.append(readNext());
        }
        readWord("\"");
        return word.toString();
    }

    /**
     * @return строка "не в кавычках"
     * @throws ParseException ошибка
     */
    protected String readUnquotedString() throws ParseException {
        StringBuilder word = new StringBuilder();
        while (hasNext() && ch() != ',') {
            word.append(readNext());
        }

        return word.toString();
    }

    /**
     * Считываем строку, если это возможно
     * @param word строка
     * @return true, если удалось считать строку
     * @throws ParseException ошибка
     */
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

    /**
     * Считываем строку
     * @param word строка
     * @throws ParseException ошибка
     */
    protected void readWord(String word) throws ParseException {
        if (!readIfMatches(word)) {
            throw new ParseException("expected: " + word, pos);
        }
    }

    /**
     * Считываем пробел
     * @throws ParseException ошибка
     */
    protected void readWs() throws ParseException {
        while (hasNext() && (ch() == ' ' || ch() == '\r' || ch() == '\n')) {
            ++pos;
        }
    }

    /**
     * Считываем следующий символ
     * @return следующий символ
     * @throws ParseException ошибка
     */
    protected char readNext() throws ParseException {
        if (hasNext()) {
            return chars[pos++];
        } else {
            throw new ParseException("EOL", pos);
        }
    }

    /**
     * @return текущий символ
     * @throws ParseException ошибка
     */
    protected char ch() throws ParseException {
        if (hasNext()) {
            return chars[pos];
        } else {
            throw new ParseException("Unexpected end of line", pos);
        }
    }

    /**
     * @return true, если есть следующий символ
     */
    protected boolean hasNext() {
        return pos < chars.length;
    }
}
