package me.vzhilin.auth.parser;

import java.text.ParseException;

/**
 * www-authenticate header parser
 */
public final class ChallengeResponseParser extends CommonAuthHeadersParser {
    /**
     * www-authenticate header parser
     * @param line header contents
     */
    public ChallengeResponseParser(String line) {
        super(line);
    }

    /**
     * Парсим заголовки
     * @return DigestChallengeResponse
     * @throws ParseException ошибка
     */
    public ChallengeResponse parseChallenge() throws ParseException {
        ChallengeResponse challenge = new ChallengeResponse();
        if (readIfMatches("Digest")) {
            challenge.setAuthMethod(AuthMethod.DIGEST);
        } else
        if (readIfMatches("Basic")) {
            challenge.setAuthMethod(AuthMethod.BASIC);
        }
        return readDigestChallenge(challenge);
    }

    private ChallengeResponse readDigestChallenge(ChallengeResponse challenge) throws ParseException {
        do {
            if (readIfMatches("charset")) {
                readWord("=");
                challenge.setCharset(readQuotedString());
            } else
            if (readIfMatches("realm")) {
                readWord("=");
                challenge.setRealm(readQuotedString());
            } else
            if (readIfMatches("domain")) {
                readWord("=");
                challenge.setDomain(readQuotedString());
            } else
            if (readIfMatches("nonce")){
                readWord("=");
                challenge.setNonce(readQuotedString());
            } else
            if (readIfMatches("opaque")) {
                readWord("=");
                challenge.setOpaque(readQuotedString());
            } else
            if (readIfMatches("stale")) {
                readWord("=");
                String word = readUnquotedString();
                if (word.equalsIgnoreCase("true")) {
                    challenge.setStale(true);
                } else
                if (word.equalsIgnoreCase("false")) {
                    challenge.setStale(false);
                } else {
                    throw new ParseException("expected: true | false", getPos());
                }
            } else
            if (readIfMatches("algorithm")) {
                readWord("=");
                switch (readUnquotedString()) {
                case "MD5":
                    challenge.addAlgorithm(DigestAlgorithm.MD5);
                    break;
                case "MD5-sess":
                    challenge.addAlgorithm(DigestAlgorithm.MD5_SESS);
                    break;
                case "SHA-512-256":
                    challenge.addAlgorithm(DigestAlgorithm.SHA_512_256);
                    break;
                case "SHA-512-256-sess":
                    challenge.addAlgorithm(DigestAlgorithm.SHA_512_256_SESS);
                    break;
                case "SHA-256":
                    challenge.addAlgorithm(DigestAlgorithm.SHA_256);
                    break;
                case "SHA-256-sess":
                    challenge.addAlgorithm(DigestAlgorithm.SHA_256_SESS);
                    break;
                default:
                    break;
                }
            } else
            if (readIfMatches("qop")) {
                readWord("=");
                for (String option: parseList(readQuotedString())) {
                    switch (option) {
                    case "auth":
                        challenge.addQopOption(QopOptions.AUTH);
                        break;
                    case "auth-int":
                        challenge.addQopOption(QopOptions.AUTH_INT);
                        break;
                    default:
                        break;
                    }
                }
            } else
            if (readIfMatches("auth-param")) {
                readWord("=");
                challenge.setAuthParam(readQuotedString());
            } else {
                throw new ParseException("unexpected input", getPos());
            }
            if (hasNext()) {
                readWord(",");
            }
        } while (hasNext());
        return challenge;
    }
}
