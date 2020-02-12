package me.vzhilin.test;

import me.vzhilin.auth.DigestAuthenticator;
import me.vzhilin.auth.parser.ChallengeResponse;
import me.vzhilin.auth.parser.ChallengeResponseParser;
import me.vzhilin.demo.server.JettyDemoServer;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.junit.Assert;
import org.junit.Test;

import java.net.URI;

public final class DigestAuthenticatorTest extends Assert {
    @Test
    public void digestAuth() throws Exception {
        final JettyDemoServer demoServer = new JettyDemoServer("Realm");
        final String username = "user";
        final String password = "pass";
        final String role = "role";
        demoServer.addUser(username, password, role);
        demoServer.addConstraintMapping("/status", role);
        demoServer.start();

        CloseableHttpClient httpClient = HttpClients.createDefault();
        DigestAuthenticator authenticator = new DigestAuthenticator(username, password);

        URI uri = URI.create("http://127.0.0.1:8090/status");
        HttpGet request = new HttpGet(uri);
        CloseableHttpResponse firstResponse = httpClient.execute(request);
        EntityUtils.consume(firstResponse.getEntity());
        assertEquals("expected unathorized",401, firstResponse.getStatusLine().getStatusCode());

        final ChallengeResponse challenge = new ChallengeResponseParser(firstResponse.getFirstHeader("WWW-Authenticate").getValue()).parseChallenge();
        authenticator.onResponseReceived(challenge, firstResponse.getStatusLine().getStatusCode());

        request.setHeader("Authorization", authenticator.headerFor("GET", uri.getPath()).orElse(null));
        CloseableHttpResponse secondResponse = httpClient.execute(request);
        EntityUtils.consume(secondResponse.getEntity());
        assertEquals("expected authorized", 200, secondResponse.getStatusLine().getStatusCode());

        request.setHeader("Authorization", authenticator.headerFor("GET", uri.getPath()).orElse(null));
        CloseableHttpResponse thirdResponse = httpClient.execute(request);
        EntityUtils.consume(thirdResponse.getEntity());
        assertEquals("ensure that digester is working", 200, thirdResponse.getStatusLine().getStatusCode());
        demoServer.stop();
    }
}
