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
package me.vzhilin.auth.digester;

import me.vzhilin.auth.parser.DigestAlgorithm;
import me.vzhilin.auth.parser.QopOptions;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

public class Digester {
    private final SecureRandom random = new SecureRandom();
    private DigestAlgorithm algorithm;
    private String nonce;
    private QopOptions qop;
    private int nonceCount;
    private String cnonce;

    public void setAlgorithm(DigestAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public boolean updateNonce(String nonce) {
        boolean b = !Objects.equals(this.nonce, nonce);
        this.nonce = nonce;
        return b;
    }

    public void setQop(QopOptions qop) {
        this.qop = qop;
    }

    public int getNonceCount() {
        return nonceCount;
    }

    public String getNonceCountAsString() {
        return String.format("%08x", nonceCount);
    }

    public void setCnonce(String cnonce) {
        this.cnonce = cnonce;
    }

    public String getCnonce() {
        return cnonce;
    }

    public QopOptions getQop() {
        return qop;
    }

    public DigestAlgorithm getAlgorithm() {
        return algorithm;
    }

    public String getNonce() {
        return nonce;
    }

    public void generateCnonce() {
        cnonce = new BigInteger(130, random).toString(16);
    }

    public void incNonceCount() {
        ++nonceCount;
    }

    public void resetNonceCount() {
        nonceCount = 1;
    }

    /**
     * @return response
     */
    public String response(Ha1 credentials, String uri, String method) {
        return response(credentials, uri, method, "");
    }

    public String response(Ha1 credentials, String uri, String method, String entityBody) {
        String ha1;
        if (!algorithm.isSess()) {
            ha1 = credentials.getHash(algorithm);
        } else {
            ha1 = h(credentials.getHash(algorithm)+":"+ nonce +":"+ cnonce, algorithm);
        }

        String ha2;
        if (qop == null || qop == QopOptions.AUTH) {
            ha2 = h(method+":"+ uri, algorithm);
        } else
        if (qop == QopOptions.AUTH_INT) {
            ha2 = h(method+":"+ uri +":"+ h(entityBody, algorithm), algorithm);
        } else {
            throw new RuntimeException();
        }

        String response;
        if (qop == null) {
            response = h(ha1+":"+nonce+":"+ha2, algorithm);
        } else {
            response = h(ha1+":"+nonce+":"+getNonceCountAsString()+":"+cnonce+":"+qop+":"+ha2, algorithm);
        }

        return response;
    }

    private String h(String string, DigestAlgorithm algorithm) {
        MessageDigest instance;

        try {
            if (algorithm == DigestAlgorithm.MD5 || algorithm == DigestAlgorithm.MD5_SESS || algorithm == null) {
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

    public void setNonceCount(int nonceCount) {
        this.nonceCount = nonceCount;
    }
}
