package me.vzhilin.auth;
//CS_OFF:IllegalThrows

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.util.Set;

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import me.vzhilin.auth.parser.AuthMethod;
import me.vzhilin.auth.parser.ChallengeResponse;
import me.vzhilin.auth.parser.ChallengeResponseParser;
import me.vzhilin.auth.parser.DigestAlgorithm;
import me.vzhilin.auth.parser.DigestRequest;
import me.vzhilin.auth.parser.QopOptions;

/**
 * Provides digest and basic authentication
 */
public class HttpClientAuthenticator extends ChannelDuplexHandler {
    private final String username;
    private final String password;
    private ChallengeResponse challenge;

    /** Random instance for generating client nonce */
    private final Random random;

    /** client nonce */
    private String cnonce;

    /** client nonce count */
    private int nonceCount;

    /** keep the client request */
    private FullHttpRequest request;

    private enum State {
        INIT,
        CHALLENGE_RESPONSE_SENT,
        COMPLETED_OK,
        COMPLETED_UNAUTHORIZED
    }

    private State state = State.INIT;

    /**
     * @param username
     * @param password
     */
    public HttpClientAuthenticator(String username, String password) {
        this.username = username;
        this.password = password;
        this.random = new Random();
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        nonceCount = 0;
        generateCnonce();

        super.channelActive(ctx);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        if (request != null) {
            request.release();
            request = null;
        }

        super.channelInactive(ctx);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof FullHttpResponse) {
            FullHttpResponse httpResponse = (FullHttpResponse) msg;
            HttpResponseStatus status = httpResponse.status();
            if (status.equals(HttpResponseStatus.OK)) {
                state = State.COMPLETED_OK;
                if (request != null) {
                    request.release();
                    request = null;
                }
            } else
            if (status.equals(HttpResponseStatus.UNAUTHORIZED)) {
                if (state == State.COMPLETED_OK || state == State.INIT) {
                    state = State.CHALLENGE_RESPONSE_SENT;
                    String authenticateHeader = httpResponse.headers().get(HttpHeaderNames.WWW_AUTHENTICATE);
                    challenge = new ChallengeResponseParser(authenticateHeader).parseChallenge();
                    if (challenge.getAuthMethod() == AuthMethod.DIGEST && challenge.isStale()) {
                        generateCnonce();
                    }
                    String method = request.method().name();
                    String uri = request.uri();
                    request.headers().add(HttpHeaderNames.AUTHORIZATION, generateAuthHeader(method, uri));
                    request.retain();
                    ctx.writeAndFlush(request);
                    httpResponse.release();
                    return;
                } else {
                    state = State.COMPLETED_UNAUTHORIZED;
                }
            }
        }
        super.channelRead(ctx, msg);
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (msg instanceof FullHttpRequest) {
            FullHttpRequest req = (FullHttpRequest) msg;
            if (state == State.COMPLETED_OK || state == State.CHALLENGE_RESPONSE_SENT) {
                String method = req.method().name();
                String uri = req.uri();
                req.headers().add(HttpHeaderNames.AUTHORIZATION, generateAuthHeader(method, uri));
            }
            // keep the client request
            // If server responds 401 Unauthorized, resend the request with authentication header
            if (this.request != null) {
                this.request.release();
            }
            this.request = (FullHttpRequest) msg;
            this.request.retain();
        }

        super.write(ctx, msg, promise);
    }

    private String generateAuthHeader(String httpMethod, String uri) {
        AuthMethod authMethod = challenge.getAuthMethod();
        if (authMethod == AuthMethod.DIGEST) {
            DigestAlgorithm algorithm = challenge.getAlgorithm();

            String nc = String.format("%08x", ++nonceCount);
            QopOptions qop = chooseQop();
            Digester digester = new Digester();
            digester.setAlgorithm(algorithm);
            digester.setQop(qop);
            digester.setUsername(username);
            digester.setPassword(password);
            digester.setNonceCount(nc);
            digester.setCnonce(cnonce);
            digester.setDigestUri(uri);
            digester.setMethod(httpMethod);
            digester.setNonce(challenge.getNonce());
            digester.setRealm(challenge.getRealm());
            DigestRequest authRequest = new DigestRequest();
            authRequest.setUsername(username);
            authRequest.setUri(uri);
            authRequest.setAlgorithm(algorithm);
            authRequest.setQopOption(qop);
            authRequest.setNc(nc);
            authRequest.setCnonce(cnonce);
            String response = digester.response();
            authRequest.setResponse(response);
            authRequest.setRealm(challenge.getRealm());
            authRequest.setNonce(challenge.getNonce());
            return authRequest.toString();
        } else {
            String value = Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.ISO_8859_1));
            return "Basic " + value;
        }
    }

    private QopOptions chooseQop() {
        Set<QopOptions> options = challenge.getQopOptions();
        if (options.contains(QopOptions.AUTH)) {
            return QopOptions.AUTH;
        }

        if (options.contains(QopOptions.AUTH_INT)) {
            return QopOptions.AUTH_INT;
        }

        return null;
    }

    /** generate new random client nonce */
    private void generateCnonce() {
        cnonce = new BigInteger(130, random).toString(16);
        nonceCount = 0;
    }
}
