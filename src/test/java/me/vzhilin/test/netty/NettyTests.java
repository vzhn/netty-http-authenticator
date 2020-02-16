package me.vzhilin.test.netty;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import me.vzhilin.auth.DigestAuthenticator;
import me.vzhilin.auth.netty.DigestNettyHttpAuthenticator;
import me.vzhilin.auth.netty.TransparentDigestNettyHttpAuthenticator;
import me.vzhilin.demo.server.JettyDemoServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;

public class NettyTests {
    private final String realm = "Realm";
    private final String username = "user";
    private final String password = "pass";
    private final String role = "role";
    private final String path = "/status";
    private final String host = "127.0.0.1";

    private JettyDemoServer digestServer;

    @Before
    public void setUp() throws Exception {
        digestServer = new JettyDemoServer(realm);
        digestServer.addUser(username, password, role);
        digestServer.addConstraintMapping(path, role);
        digestServer.start();
    }

    @After
    public void tearDown() throws Exception {
        digestServer.stop();
    }

    @Test
    public void transparentAuthenticatorTest() throws Exception {
        DigestAuthenticator authenticator = new DigestAuthenticator(username, password);
        final NettyHttpClientHandler nettyHttpClientHandler = new NettyHttpClientHandler();

        NettyHttpClient nettyClient = new NettyHttpClient(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) throws Exception {
                ChannelPipeline p = ch.pipeline();
                p.addLast(new HttpClientCodec());
                p.addLast(new HttpContentDecompressor());
                p.addLast(new HttpObjectAggregator(2048));
                p.addLast(new TransparentDigestNettyHttpAuthenticator(authenticator));
                p.addLast(nettyHttpClientHandler);
            }
        });

        // Make the connection attempt.
        Channel ch = nettyClient.connect("127.0.0.1", 8090);
        CompletableFuture<Object> responseFuture = new CompletableFuture<>();
        nettyHttpClientHandler.setResponseFuture(responseFuture);

        ch.writeAndFlush(makeHttpRequest());
        HttpResponse response = (HttpResponse) responseFuture.get(5, TimeUnit.SECONDS);
        assertEquals(HttpResponseStatus.OK, response.status());

        nettyClient.stop();
    }

    @Test
    public void defaultAuthenticatorTest() throws Exception {
        DigestAuthenticator authenticator = new DigestAuthenticator(username, password);
        final NettyHttpClientHandler nettyHttpClientHandler = new NettyHttpClientHandler();

        NettyHttpClient nettyClient = new NettyHttpClient(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) throws Exception {
                ChannelPipeline p = ch.pipeline();
                p.addLast(new HttpClientCodec());
                p.addLast(new HttpContentDecompressor());
                p.addLast(new DigestNettyHttpAuthenticator(authenticator));
                p.addLast(nettyHttpClientHandler);
            }
        });

        // Make the connection attempt.
        Channel ch = nettyClient.connect(host, 8090);
        CompletableFuture<Object> responseFuture = new CompletableFuture<>();
        nettyHttpClientHandler.setResponseFuture(responseFuture);
        ch.writeAndFlush(makeHttpRequest());
        HttpResponse response = (HttpResponse) responseFuture.get(5, TimeUnit.SECONDS);
        assertEquals(HttpResponseStatus.UNAUTHORIZED, response.status());

        CompletableFuture<Object> nextResponseFuture = new CompletableFuture<>();
        nettyHttpClientHandler.setResponseFuture(nextResponseFuture);
        ch.writeAndFlush(makeHttpRequest());
        HttpResponse nextResponse = (HttpResponse) nextResponseFuture.get(5, TimeUnit.SECONDS);
        assertEquals(HttpResponseStatus.OK, nextResponse.status());

        nettyClient.stop();
    }

    private HttpRequest makeHttpRequest() {
        HttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, path);
        request.headers().set(HttpHeaderNames.HOST, "127.0.0.1");
        request.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
        return request;
    }

    private static final class NettyHttpClientHandler extends ChannelDuplexHandler {
        private volatile CompletableFuture<Object> responseFuture;

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            super.channelRead(ctx, msg);
            if (responseFuture != null && msg instanceof HttpResponse) {
                responseFuture.complete(msg);
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            super.exceptionCaught(ctx, cause);
            responseFuture.completeExceptionally(cause);
        }

        public void setResponseFuture(CompletableFuture<Object> responseFuture) {
            this.responseFuture = responseFuture;
        }
    }

    private final static class NettyHttpClient {
        private final Bootstrap b;
        private final NioEventLoopGroup group;

        public NettyHttpClient(ChannelInitializer<SocketChannel> handler) {
            group = new NioEventLoopGroup();
            b = new Bootstrap().group(group).channel(NioSocketChannel.class).handler(handler);
        }

        public void stop() {
            group.shutdownGracefully();
        }

        public Channel connect(String host, int port) throws InterruptedException {
            return b.connect(host, port).sync().channel();
        }
    }
}
