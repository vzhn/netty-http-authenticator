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
package me.vzhilin.auth.parser;

import java.util.HashSet;
import java.util.Set;

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

    public void setAuthMethod(AuthMethod method) {
        this.method = method;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    void setDomain(String domain) {
        this.domain = domain;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    void setOpaque(String opaque) {
        this.opaque = opaque;
    }

    void setStale(boolean stale) {
        this.stale = stale;
    }

    public void addQopOption(QopOptions option) {
        qopOptions.add(option);
    }

    public void addAlgorithm(DigestAlgorithm algorithm) {
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
            sb.append("qop=\"").append(qopOptions.stream().map(Enum::toString).collect(joining(","))).append("\",");
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
