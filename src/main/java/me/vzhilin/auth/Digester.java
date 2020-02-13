package me.vzhilin.auth;

import me.vzhilin.auth.parser.DigestAlgorithm;
import me.vzhilin.auth.parser.QopOptions;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Digester {
    private String realm;
    private DigestAlgorithm algorithm;
    private String nonce;
    private String method;
    private String username;
    private String password;
    private String uri;
    private QopOptions qop;
    private String nonceCount;
    private String cnonce;
    private final String entityBody = "";

    /**
     * @return response
     */
    public String response() {
        String ha1;
        if (!algorithm.isSess()) {
            ha1 = h(username +":"+ realm +":"+password, algorithm);
        } else {
            String local = h(username +":"+ realm +":"+password, algorithm);
            ha1 = h(local+":"+ nonce +":"+ cnonce, algorithm);
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
            response = h(ha1+":"+nonce+":"+nonceCount+":"+cnonce+":"+qop+":"+ha2, algorithm);
        }

        return response;
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

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public void setAlgorithm(DigestAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setDigestUri(String uri) {
        this.uri = uri;
    }

    public void setQop(QopOptions qop) {
        this.qop = qop;
    }

    public void setNonceCount(String nonceCount) {
        this.nonceCount = nonceCount;
    }

    public void setNonceCount(int nonceCount) {
        setNonceCount(String.format("%08x", nonceCount));
    }

    public String getNonceCount() {
        return nonceCount;
    }

    public void setCnonce(String cnonce) {
        this.cnonce = cnonce;
    }
}
