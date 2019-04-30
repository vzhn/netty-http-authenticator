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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;
import java.util.Set;

final class HttpAuthenticator {
    /** PRNG for client nonce key generation */
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

    void setCnonce(String cnonce) {
        this.cnonce = cnonce;
    }

    String generateAuthHeader(String httpMethod, String uri) {
        switch (challenge.getAuthMethod()) {
            case BASIC:
                return "Basic " + Base64.getEncoder().encodeToString((username + ":" + password)
                        .getBytes(StandardCharsets.ISO_8859_1));
            case DIGEST:
                DigestAlgorithm algorithm = challenge.getAlgorithm();
                StringBuilder sb = new StringBuilder("Digest ");
                String realm = challenge.getRealm();
                String nonce = challenge.getNonce();
                String opaque = challenge.getOpaque();
                String rsp = response(httpMethod, uri, "");
                String nc = String.format("%08x", nonceCount);
                if (username != null) sb.append("username=\"").append(username).append("\",");
                if (realm != null) sb.append("realm=\"").append(realm).append("\",");
                if (nonce != null) sb.append("nonce=\"").append(nonce).append("\",");
                if (opaque != null) sb.append("opaque=\"").append(opaque).append("\",");
                if (uri != null) sb.append("uri=\"").append(uri).append("\",");
                if (algorithm != null) sb.append("algorithm=").append(algorithm).append(",");
                if (rsp != null) sb.append("response=\"").append(rsp).append("\",");
                if (qop != null)  sb.append("qop=").append(qop).append(",");
                if (nc != null)  sb.append("nc=").append(nc).append(",");
                if (cnonce != null) sb.append("cnonce=\"").append(cnonce).append("\",");
                sb.setLength(sb.length() - 1);
                return sb.toString();
            default:
                throw new RuntimeException("unimplemented: " + challenge.getAuthMethod());
        }
    }

    /**
     * @return response
     */
    String response(String method, String digestUri, String entityBody) {
        String realm = challenge.getRealm();
        String nonce = challenge.getNonce();
        String nc = String.format("%08x", ++nonceCount);
        String ha1;
        if (!algorithm.isSess()) {
            ha1 = h(username +":"+ realm +":"+password, algorithm);
        } else {
            String local = h(username +":"+ realm +":"+password, algorithm);
            ha1 = h(local+":"+ nonce +":"+ cnonce, algorithm);
        }

        String ha2;
        if (qop == null || qop == QopOptions.AUTH) {
            ha2 = h(method+":"+ digestUri, algorithm);
        } else
        if (qop == QopOptions.AUTH_INT) {
            ha2 = h(method+":"+ digestUri +":"+ h(entityBody, algorithm), algorithm);
        } else {
            throw new RuntimeException();
        }

        String response;
        if (qop == null) {
            response = h(ha1+":"+nonce+":"+ha2, algorithm);
        } else {
            response = h(ha1+":"+nonce+":"+nc+":"+cnonce+":"+qop+":"+ha2, algorithm);
        }

        return response;
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

    private String h(String string, DigestAlgorithm algorithm) {
        MessageDigest instance;

        try {
            if (algorithm == DigestAlgorithm.MD5 || algorithm == DigestAlgorithm.MD5_SESS) {
                instance = MessageDigest.getInstance("MD5");
            } else
            if (algorithm == DigestAlgorithm.SHA_256 || algorithm == DigestAlgorithm.SHA_256_SESS) {
                instance = MessageDigest.getInstance("SHA-256");
            } else
            if (algorithm == DigestAlgorithm.SHA_512_256 || algorithm == DigestAlgorithm.SHA_512_256_SESS) {
                instance = MessageDigest.getInstance("SHA-512/256");
            } else {
                throw new RuntimeException("Unsupported: " + algorithm);
            }
            return bytesToHex(instance.digest(string.getBytes()));
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static String bytesToHex(final byte[] bytes) {
        final int numBytes = bytes.length;
        final char[] container = new char[numBytes * 2];

        for (int i = 0; i < numBytes; i++) {
            final int b = bytes[i] & 0xFF;
            container[i * 2] = Character.forDigit(b >>> 4, 0x10);
            container[i * 2 + 1] = Character.forDigit(b & 0xF, 0x10);
        }

        return new String(container);
    }
}
