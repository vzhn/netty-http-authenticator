package me.vzhilin.auth;

import me.vzhilin.auth.util.UriMatcher;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

public class PatternMatcherCredentialsProvider implements CredentialsProvider {
    private final LinkedHashMap<UriMatcher, Credentials> matchers = new LinkedHashMap<>();
    private final Credentials defaultCredentials;

    public PatternMatcherCredentialsProvider() {
        this(null);
    }

    public PatternMatcherCredentialsProvider(Credentials defaultCredentials) {
        this.defaultCredentials = defaultCredentials;
    }

    public void add(String pattern, String user, String password) {
        UriMatcher matcher = new UriMatcher(0);
        matcher.addURI("*", pattern, 0);
        matchers.put(matcher, new Credentials(user, password));
    }

    @Override
    public Credentials getCredentials(String host, int port, String uri, String realm) {
        URI u = URI.create("http://" + host + ":" + port + uri);
        return  matchers.entrySet()
                .stream()
                .filter(e -> e.getKey().match(u) >= 0)
                .map(Map.Entry::getValue).findAny().orElse(defaultCredentials);
    }
}
