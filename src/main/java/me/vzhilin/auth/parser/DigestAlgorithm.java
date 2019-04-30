package me.vzhilin.auth.parser;

/**
 * DigestAlgorithms
 */
public enum DigestAlgorithm {
    /** MD5 algorithm */
    MD5("MD5", false),

    /** MD5-sess algorithm */
    MD5_SESS("MD5-sess", true),

    /** SHA-512-256 algorithm */
    SHA_512_256("SHA-512-256", false),

    /** SHA-512-256-sess algorithm */
    SHA_512_256_SESS("SHA-512-256-sess", true),

    /** SHA-256 algorithm */
    SHA_256("SHA-256", false),

    /** SHA-256 algorithm */
    SHA_256_SESS("SHA-256-sess", true);

    private final boolean sess;
    private String name;

    DigestAlgorithm(String name, boolean sess) {
        this.name = name;
        this.sess = sess;
    }

    /**
     * @return true, if "sess"
     */
    public boolean isSess() {
        return sess;
    }

    @Override
    public String toString() {
        return name;
    }
}
