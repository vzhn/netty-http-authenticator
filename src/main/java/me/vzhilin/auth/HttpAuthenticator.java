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
package me.vzhilin.auth;

import me.vzhilin.auth.parser.AuthMethod;
import me.vzhilin.auth.parser.ChallengeResponse;
import me.vzhilin.auth.parser.DigestAlgorithm;
import me.vzhilin.auth.parser.QopOptions;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.util.Set;

final class HttpAuthenticator {
    /** RNG for client nonce key generation */
    private final Random random = new Random();
    private final String username;
    private final String password;

    /** client nonce */
    private String cnonce;

    /** client nonce count */
    private int nonceCount;

    private QopOptions qop;
    private ChallengeResponse challenge;
    private DigestAlgorithm algorithm;

    HttpAuthenticator(String username, String password) {
        this.username = username;
        this.password = password;
        generateCnonce();
    }

    void challenge(ChallengeResponse challenge) {
        this.challenge = challenge;
        if (challenge.getAuthMethod() == AuthMethod.DIGEST) {
            this.qop = chooseQop(challenge);
            if (algorithm == null) {
                algorithm = DigestAlgorithm.MD5;
            }
            this.algorithm = this.challenge.getAlgorithm();

            if (challenge.isStale()) {
                generateCnonce();
            }
        }
    }
    String generateAuthHeader(String httpMethod, String uri) {
        switch (challenge.getAuthMethod()) {
            case BASIC:
                return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password)
                        .getBytes(StandardCharsets.ISO_8859_1));
            case DIGEST:
                Digester digester = new Digester();
                digester.setUsername(username);
                digester.setPassword(password);
                digester.setAlgorithm(challenge.getAlgorithm());
                digester.setRealm(challenge.getRealm());
                digester.setNonce(challenge.getNonce());
                digester.setNonceCount(++nonceCount);
                digester.setDigestUri(uri);
                digester.setQop(qop);
                digester.setCnonce(cnonce);
                digester.setMethod(httpMethod);
                String rsp = digester.response();

                StringBuilder sb = new StringBuilder("Digest ");
                if (username != null) sb.append("username=\"").append(username).append("\",");
                sb.append("realm=\"").append(challenge.getRealm()).append("\",");
                sb.append("nonce=\"").append(challenge.getNonce()).append("\",");
                if (challenge.getOpaque() != null) sb.append("opaque=\"").append(challenge.getOpaque()).append("\",");
                sb.append("uri=\"").append(uri).append("\",");
                if (algorithm != null) sb.append("algorithm=").append(algorithm).append(",");
                sb.append("response=\"").append(rsp).append("\",");
                sb.append("qop=").append(qop).append(",");
                sb.append("nc=").append(digester.getNonceCount()).append(",");
                sb.append("cnonce=\"").append(cnonce).append("\",");
                sb.setLength(sb.length() - 1);
                return sb.toString();
            default:
                throw new RuntimeException("unimplemented: " + challenge.getAuthMethod());
        }
    }

    /** generate new random client nonce */
    private void generateCnonce() {
        cnonce = new BigInteger(130, random).toString(16);
        nonceCount = 0;
    }

    private QopOptions chooseQop(ChallengeResponse challenge) {
        Set<QopOptions> options = challenge.getQopOptions();
        if (options.contains(QopOptions.AUTH)) {
            return QopOptions.AUTH;
        }

        if (options.contains(QopOptions.AUTH_INT)) {
            return QopOptions.AUTH_INT;
        }

        return null;
    }
}
