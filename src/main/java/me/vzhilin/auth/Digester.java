package me.vzhilin.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import me.vzhilin.auth.parser.DigestAlgorithm;
import me.vzhilin.auth.parser.QopOptions;

/**
 * Вычисляет хэш
 */
public class Digester {
    /** qop */
    private QopOptions qop;

    /** algorithms */
    private DigestAlgorithm algorithm;

    /** HTTP method */
    private String method;

    /** username */
    private String username;

    /** realm */
    private String realm;

    /** password */
    private String password;

    /** digest uri*/
    private String digestUri;

    /** http entity body */
    private String entityBody;

    /** server nonce */
    private String nonce;

    /** client nonce */
    private String cnonce;

    /** client nonce count */
    private String nonceCount;

    /** userhash */
    private boolean userhash;

    /**
     * @param qop qop
     */
    public void setQop(QopOptions qop) {
        this.qop = qop;
    }

    /**
     * @param algorithm DigestAlgorithm
     */
    public void setAlgorithm(DigestAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * @param method http method
     */
    public void setMethod(String method) {
        this.method = method;
    }

    /**
     * @param entityBody entity body
     */
    void setEntityBody(String entityBody) {
        this.entityBody = entityBody;
    }

    /**
     * @param nonce server nonce
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    /**
     * @param nonceCount client nonce count
     */
    public void setNonceCount(String nonceCount) {
        this.nonceCount = nonceCount;
    }

    /**
     * @param cnonce client nonce
     */
    public void setCnonce(String cnonce) {
        this.cnonce = cnonce;
    }

    /**
     * @param username username
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * @param realm realm
     */
    public void setRealm(String realm) {
        this.realm = realm;
    }

    /**
     * @param digestUri digest Uri
     */
    public void setDigestUri(String digestUri) {
        this.digestUri = digestUri;
    }

    /**
     * @param password password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * @param userhash userhash
     */
    public void setUserhash(boolean userhash) {
        this.userhash = userhash;
    }

    /**
     * @return true, if username is hashed
     */
    public boolean isUserhash() {
        return userhash;
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

    /**
     * @return response
     */
    public String response() {
        if (algorithm == null) {
            algorithm = DigestAlgorithm.MD5;
        }

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
            response = h(ha1+":"+nonce+":"+nonceCount+":"+cnonce+":"+qop+":"+ha2, algorithm);
        }

        return response;
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
