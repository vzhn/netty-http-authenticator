package me.vzhilin.auth.digester;

import me.vzhilin.auth.parser.DigestAlgorithm;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Ha1 {
    private final String hash;
    private final DigestAlgorithm algorithm;
    private final String username;
    private final String realm;

    private Ha1(DigestAlgorithm algorithm, String username, String realm, String hash) {
        this.algorithm = algorithm;
        this.username = username;
        this.realm = realm;
        this.hash = hash;
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

    public String getHash(DigestAlgorithm algorithm) {
        // todo ensure that ...
        return hash;
    }

    public String getUsername() {
        return username;
    }

    public String getRealm() {
        return realm;
    }

    public DigestAlgorithm getAlgorithm() {
        return algorithm;
    }

    public static Ha1 preHashed(DigestAlgorithm algorithm, String username, String realm, String hash) {
        return new Ha1(algorithm, username, realm, hash);
    }

    public static Ha1 hash(DigestAlgorithm algorithm, String username, String realm, String password) {
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
            String hash = bytesToHex(instance.digest((username +":"+ realm +":"+password).getBytes()));

            return new Ha1(algorithm, username, realm, hash);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }
}
