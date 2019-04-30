package me.vzhilin.auth.parser;

/**
 * Содержимое заголовка Authorization header
 */
public class DigestRequest {
    private String username;
    private String realm;
    private String nonce;
    private String nc;
    private String uri;
    private String response;
    private String cnonce;
    private String opaque;

    private DigestAlgorithm algorithms;
    private QopOptions qop;

    public void setUsername(String username) {
        this.username = username;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public void setNc(String nc) {
        this.nc = nc;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public void setResponse(String response) {
        this.response = response;
    }

    public void setAlgorithm(DigestAlgorithm am) {
        algorithms = am;
    }

    public void setCnonce(String cnonce) {
        this.cnonce = cnonce;
    }

    public void setOpaque(String opaque) {
        this.opaque = opaque;
    }

    public void setQopOption(QopOptions option) {
        qop = option;
    }

    public String getUsername() {
        return username;
    }

    public String getRealm() {
        return realm;
    }

    public String getNonce() {
        return nonce;
    }

    public String getNc() {
        return nc;
    }

    public String getUri() {
        return uri;
    }

    public String getResponse() {
        return response;
    }

    public String getCnonce() {
        return cnonce;
    }

    public String getOpaque() {
        return opaque;
    }

    public DigestAlgorithm getAlgorithms() {
        return algorithms;
    }

    public QopOptions getQop() {
        return qop;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Digest ");

        if (username != null) sb.append("username=\"" + username + "\",");
        if (realm != null) sb.append("realm=\"" + realm + "\",");
        if (nonce != null) sb.append("nonce=\"" + nonce + "\",");
        if (opaque != null) sb.append("opaque=\"" + opaque + "\",");
        if (uri != null) sb.append("uri=\"" + uri + "\",");
        if (algorithms != null) sb.append("algorithm=" + algorithms + ",");
        if (response != null) sb.append("response=\"" + response + "\",");
        if (qop != null)  sb.append("qop=" + qop + ",");
        if (nc != null)  sb.append("nc=" + nc + ",");
        if (cnonce != null) sb.append("cnonce=\"" + cnonce + "\",");

        sb.setLength(sb.length() - 1);
        return sb.toString();
    }
}
