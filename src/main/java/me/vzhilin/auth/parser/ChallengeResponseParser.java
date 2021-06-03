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
     * Parse headers
     * @return DigestChallengeResponse
     * @throws ParseException parse error
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
                challenge.setStale(word.equalsIgnoreCase("true") || word.equalsIgnoreCase("\"true\""));
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
                for (String option: splitList(readQuotedString())) {
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

        if (challenge.getAlgorithm() == null) {
            challenge.addAlgorithm(DigestAlgorithm.MD5);
        }

        return challenge;
    }
}
