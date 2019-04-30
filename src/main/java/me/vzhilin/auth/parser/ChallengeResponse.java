package me.vzhilin.auth.parser;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.joining;

/**
 * The WWW-Authenticate Response Header
 */
public class ChallengeResponse {
    private AuthMethod method;
    private String realm;
    private String domain;
    private String nonce;
    private String opaque;
    private boolean stale;
    private String authParam;
    private DigestAlgorithm algorithms;
    private String charset;
    private Set<QopOptions> qopOptions = new HashSet<>(2);

    void setAuthMethod(AuthMethod method) {
        this.method = method;
    }

    void setRealm(String realm) {
        this.realm = realm;
    }

    void setDomain(String domain) {
        this.domain = domain;
    }

    void setNonce(String nonce) {
        this.nonce = nonce;
    }

    void setOpaque(String opaque) {
        this.opaque = opaque;
    }

    void setStale(boolean stale) {
        this.stale = stale;
    }

    void addQopOption(QopOptions option) {
        qopOptions.add(option);
    }

    void addAlgorithm(DigestAlgorithm algorithm) {
        algorithms = algorithm;
    }

    void setAuthParam(String authParam) {
        this.authParam = authParam;
    }

    public String getRealm() {
        return realm;
    }

    public String getDomain() {
        return domain;
    }

    public String getNonce() {
        return nonce;
    }

    public String getOpaque() {
        return opaque;
    }

    public boolean isStale() {
        return stale;
    }

    public String getAuthParam() {
        return authParam;
    }

    public Set<QopOptions> getQopOptions() {
        return qopOptions;
    }

    public DigestAlgorithm getAlgorithm() {
        return algorithms;
    }

    public boolean hasQop(QopOptions qop) {
        return qopOptions.contains(qop);
    }

    void setCharset(String charset) {
        this.charset = charset;
    }

    public String getCharset() {
        return charset;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(" ");

        if (realm != null) sb.append("realm=\"").append(realm).append("\",");
        if (domain != null) sb.append("domain=\"").append(domain).append("\",");
        if (nonce != null) sb.append("nonce=\"").append(nonce).append("\",");
        if (opaque != null) sb.append("opaque=\"").append(opaque).append("\",");
        if (stale) sb.append("stale=true,");
        if (!qopOptions.isEmpty()) {
            sb.append("qop=\"" + qopOptions.stream().map(Enum::toString).collect(joining(",")) + "\",");
        }

        if (algorithms != null) { sb.append("algorithm=").append(algorithms).append(","); }
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    /**
     * @return method
     */
    public AuthMethod getAuthMethod() {
        return method;
    }
}
