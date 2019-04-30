package me.vzhilin.auth.parser;

import java.text.ParseException;

/**
 * Парсер заголовка authorization
 */
public class AuthRequestParser extends CommonAuthHeadersParser {
    public AuthRequestParser(String line) {
        super(line);
    }

    /**
     * Парсим заголовок authorization
     * @return DigestRequest
     * @throws ParseException ошибка
     */
    public DigestRequest parseDigestRequest() throws ParseException {
        readWord("Digest");
        return readDigestResponse();
    }

    private DigestRequest readDigestResponse() throws ParseException {
        DigestRequest authRequest = new DigestRequest();

        do {
            if (readIfMatches("username")) {
                readWord("=");
                authRequest.setUsername(readQuotedString());
            } else
            if(readIfMatches("realm")) {
                readWord("=");
                authRequest.setRealm(readQuotedString());
            } else
            if (readIfMatches("nonce")) {
                readWord("=");
                authRequest.setNonce(readQuotedString());
            } else
            if (readIfMatches("nc")) {
                readWord("=");
                authRequest.setNc(readHex(8));
            } else
            if (readIfMatches("uri")) {
                readWord("=");
                authRequest.setUri(readQuotedString());
            } else
            if (readIfMatches("response")) {
                readWord("=");
                readWord("\"");
                authRequest.setResponse(readHex(32));
                readWord("\"");
            } else
            if (readIfMatches("algorithm")) {
                readWord("=");
                switch (readQuotedString()) {
                case "MD5":
                    authRequest.setAlgorithm(DigestAlgorithm.MD5);
                    break;
                case "MD5-sess":
                    authRequest.setAlgorithm(DigestAlgorithm.MD5_SESS);
                    break;
                case "SHA-512-256":
                    authRequest.setAlgorithm(DigestAlgorithm.SHA_512_256);
                    break;
                case "SHA-512-256-sess":
                    authRequest.setAlgorithm(DigestAlgorithm.SHA_512_256_SESS);
                    break;
                case "SHA-256":
                    authRequest.setAlgorithm(DigestAlgorithm.SHA_256);
                    break;
                case "SHA-256-sess":
                    authRequest.setAlgorithm(DigestAlgorithm.SHA_256_SESS);
                    break;
                default:
                    break;
                }
            } else
            if (readIfMatches("cnonce")) {
                readWord("=");
                authRequest.setCnonce(readQuotedString());
            } else
            if (readIfMatches("opaque")) {
                readWord("=");
                authRequest.setOpaque(readQuotedString());
            } else
            if (readIfMatches("qop")) {
                readWord("=");
                switch (readUnquotedString()) {
                case "auth":
                    authRequest.setQopOption(QopOptions.AUTH);
                    break;
                case "auth-int":
                    authRequest.setQopOption(QopOptions.AUTH_INT);
                    break;
                default:
                    break;
                }
            } else {
                throw new ParseException("unexpected input", getPos());
            }

            if (hasNext()) {
                readWord(",");
            }
        } while (hasNext());
        return authRequest;
    }

    private String readHex(int count) throws ParseException {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < count; i++) {
            if (!hasNext()) {
                throw new ParseException("EOL", getPos());
            }
            if (ch() >= '0' && ch() <= '9' || ch() >= 'a' && ch() <= 'f') {
                hex.append(readNext());
            } else {
                throw new ParseException("expected: hex string", getPos());
            }
        }
        return hex.toString();
    }

}
