package me.vzhilin.auth;

@FunctionalInterface
public interface DigestAuthenticatorProvider {
    DigestAuthenticator authenticatorFor(String host, int port, String resource);
}
