package me.vzhilin.auth;

import me.vzhilin.auth.digester.Digester;
import me.vzhilin.auth.parser.QopOptions;

public class DigestAuthenticationHeader {
    private final String username;
    private final String realm;
    private final String nonce;
    private final String opaque;
    private final String uri;
    private final String algorithm;
    private final String response;
    private final String qop;
    private final String nc;
    private final String cnonce;

    public DigestAuthenticationHeader(String opaque, String uri, String username, String realm, String response, Digester digester) {
        this.realm = realm;
        this.username = username;
        this.response = response;
        this.nonce = digester.getNonce();
        this.uri = uri;
        this.opaque = opaque;
        this.algorithm = digester.getAlgorithm().toString();
        QopOptions qop = digester.getQop();
        this.qop = qop == null ? null : qop.toString();
        this.nc = digester.getNonceCountAsString();
        this.cnonce = digester.getCnonce();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Digest ");
        sb.append("username=\"").append(username).append("\",");
        sb.append("realm=\"").append(realm).append("\",");
        sb.append("nonce=\"").append(nonce).append("\",");
        if (opaque != null) sb.append("opaque=\"").append(opaque).append("\",");
        sb.append("uri=\"").append(uri).append("\",");
        if (algorithm != null) sb.append("algorithm=").append(algorithm).append(",");
        sb.append("response=\"").append(response).append("\",");
        if (qop != null) sb.append("qop=").append(qop).append(",");
        sb.append("nc=").append(nc).append(",");
        sb.append("cnonce=\"").append(cnonce).append("\",");
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }
}
