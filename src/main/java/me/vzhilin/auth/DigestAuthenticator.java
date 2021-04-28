package me.vzhilin.auth;

import me.vzhilin.auth.digester.*;
import me.vzhilin.auth.parser.*;

import java.util.Set;

public class DigestAuthenticator {
    private final Ha1Supplier ha1Supplier;
    private Digester digester;
    private String opaque;
    private String realm;

    public DigestAuthenticator(Ha1Supplier ha1Supplier) {
        this.ha1Supplier = ha1Supplier;
        this.digester = new Digester();
    }

    public DigestAuthenticator(Ha1Supplier ha1Supplier, Digester digester) {
        this.ha1Supplier = ha1Supplier;
        this.digester = digester;
    }

    public DigestAuthenticator(String user, String pass) {
        this(user, pass, DigestAlgorithm.MD5);
    }

    public DigestAuthenticator(String user, String pass, DigestAlgorithm defaultAlgorithm) {
        this(new FallbackHa1Supplier((algorithm, realm) -> Ha1.hash(algorithm, user, realm, pass), defaultAlgorithm));
    }

    public synchronized void onResponseReceived(ChallengeResponse response, int httpStatus) {
        boolean cnonceChanged = digester.updateNonce(response.getNonce());
        if (httpStatus == 401 || response.isStale() || cnonceChanged) {
            digester.generateCnonce();
            digester.resetNonceCount();
        }

        digester.setAlgorithm(response.getAlgorithm());
        digester.setQop(chooseQop(response));

        this.opaque = response.getOpaque();
        this.realm = response.getRealm();
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

    public String authorizationHeader(String method, String uri) {
        return authorizationHeader(method, uri, "");
    }

    public synchronized String authorizationHeader(String method, String uri, String entityBody) {
        if (digester.getNonce() == null) {
            return null;
        }
        Ha1 ha1 = ha1Supplier.hash(digester.getAlgorithm(), realm);
        String response = digester.response(ha1, uri, method, entityBody);
        final String username = ha1.getUsername();
        final String realm = ha1.getRealm();
        final DigestAuthenticationHeader header = new DigestAuthenticationHeader(opaque, uri, username, realm, response, digester);
        final String headerValue = header.toString();
        digester.incNonceCount();
        return headerValue;
    }

    private static final class FallbackHa1Supplier implements Ha1Supplier {
        private final Ha1Supplier delegate;
        private final DigestAlgorithm defaultAlgorithm;

        public FallbackHa1Supplier(Ha1Supplier delegate, DigestAlgorithm defaultAlgorithm) {
            this.delegate = delegate;
            this.defaultAlgorithm = defaultAlgorithm;
        }

        @Override
        public Ha1 hash(DigestAlgorithm algorithm, String realm) {
            if (algorithm == null) {
                return delegate.hash(defaultAlgorithm, realm);
            } else {
                return delegate.hash(algorithm, realm);
            }
        }
    }
}
