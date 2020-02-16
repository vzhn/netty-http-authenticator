package me.vzhilin.auth;

@FunctionalInterface
interface CredentialsProvider {
    Credentials getCredentials(String host, int port, String uri, String realm);
}
