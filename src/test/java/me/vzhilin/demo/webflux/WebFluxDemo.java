package me.vzhilin.demo.webflux;

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponse;
import me.vzhilin.auth.DigestAuthenticator;
import me.vzhilin.auth.parser.ChallengeResponse;
import me.vzhilin.auth.parser.ChallengeResponseParser;
import me.vzhilin.demo.server.JettyDemoServer;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.Connection;
import reactor.netty.http.client.HttpClient;
import reactor.netty.http.client.HttpClientRequest;

import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.function.BiConsumer;

public class WebFluxDemo {
    public static void main(String... argv) throws Exception {
        final JettyDemoServer demoServer = new JettyDemoServer("Realm");
        final String username = "user";
        final String password = "pass";
        final String role = "role";
        final String path = "/status";
        demoServer.addUser(username, password, role);
        demoServer.addConstraintMapping(path, role);
        demoServer.start();

        DigestAuthenticator auth = new DigestAuthenticator(username, password);

        HttpClient client = HttpClient.create().doOnRequest(new BiConsumer<HttpClientRequest, Connection>() {
            @Override
            public void accept(HttpClientRequest httpClientRequest, Connection connection) {
                connection.addHandler(new ChannelDuplexHandler() {
                    @Override
                    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
                        if (msg instanceof HttpRequest) {
                            HttpRequest request = (HttpRequest) msg;
                            String authorization = request.headers().get(HttpHeaderNames.AUTHORIZATION);
                            if (authorization == null) {
                                final Optional<String> maybeHeader = auth.headerFor(request.method().name(), request.uri());
                                maybeHeader.ifPresent((v) -> request.headers().set(HttpHeaderNames.AUTHORIZATION, v));
                            }
                        }
                        super.write(ctx, msg, promise);
                    }

                    @Override
                    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
                        if (msg instanceof HttpResponse) {
                            HttpResponse response = (HttpResponse) msg;
                            final String authenticateHeader = response.headers().get(HttpHeaderNames.WWW_AUTHENTICATE);
                            if (authenticateHeader != null) {
                                ChallengeResponse challengeResponse = new ChallengeResponseParser(authenticateHeader).parseChallenge();
                                auth.onResponseReceived(challengeResponse, response.status().code());
                            }
                        }
                        super.channelRead(ctx, msg);
                    }
                });
            }
        });

        final WebClient webClient = WebClient
            .builder()
            .clientConnector(new ReactorClientHttpConnector(client))
            .baseUrl("http://127.0.0.1:8090").build();

        CountDownLatch latch = new CountDownLatch(1);

        webClient
            .method(HttpMethod.GET)
            .uri(path)
            .retrieve()
            .onStatus(HttpStatus.UNAUTHORIZED::equals, clientResponse -> {
                webClient
                    .method(HttpMethod.GET)
                    .uri(path)
                    .retrieve()
                        .onStatus(HttpStatus.OK::equals, clientResponse1 -> {
                            latch.countDown();
                            return Mono.empty();
                        }).bodyToMono(String.class).subscribe(System.out::println); // dunno how it supposed to be working, never coded any reactive and spring-related stuff
                return Mono.empty();
            }).bodyToMono(String.class).subscribe(System.out::println);

        latch.await();
        demoServer.stop();
    }
}
