package me.vzhilin.test.netty;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import me.vzhilin.auth.DigestAuthenticator;
import me.vzhilin.auth.netty.NettyHttpAuthenticator;
import me.vzhilin.demo.client.NettyClientDemoHandler;

import java.net.URI;

public class NettyClient {
    static final String URL = System.getProperty("url", "http://127.0.0.1:8090/status");
    private final Bootstrap b;
    private DigestAuthenticator authenticator;
    private NioEventLoopGroup group;

    public NettyClient() {
        authenticator = new DigestAuthenticator("user", "pass");
        group = new NioEventLoopGroup(1);

        b = new Bootstrap();
        b.group(group)
            .channel(NioSocketChannel.class)
            .handler(getHandler(authenticator));
    }

    public void stop() {
        group.shutdownGracefully();
    }

    public static void main(String[] args) throws Exception {
        URI uri = new URI(URL);
        String host = uri.getHost() == null? "127.0.0.1" : uri.getHost();
        int port = uri.getPort();

        NettyClient client = new NettyClient();
        client.connectAndSend(uri, host, port); // the first one got 401
        client.connectAndSend(uri, host, port); // the second attempt succeeds
        client.stop();
    }

    private static ChannelInitializer<SocketChannel> getHandler(DigestAuthenticator authenticator) {
        return new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) throws Exception {
                ChannelPipeline p = ch.pipeline();
                p.addLast(new HttpClientCodec());
                p.addLast(new HttpContentDecompressor());
                p.addLast(new NettyHttpAuthenticator(authenticator));
                p.addLast(new NettyClientDemoHandler());
            }
        };
    }

    private void connectAndSend(URI uri, String host, int port) throws InterruptedException {
        // Make the connection attempt.
        Channel ch = b.connect(host, port).sync().channel();

        // Prepare the HTTP request.
        HttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1, HttpMethod.GET, uri.getRawPath());
        request.headers().set(HttpHeaderNames.HOST, host);
        request.headers().set(HttpHeaderNames.ACCEPT_ENCODING, HttpHeaderValues.GZIP);

        // Send the HTTP request.
        ch.writeAndFlush(request);

        // Wait for the server to close the connection.
        ch.closeFuture().sync();
    }
}
