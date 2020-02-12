/*
 * Copyright 2012 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package me.vzhilin.demo.client;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import me.vzhilin.auth.DigestAuthenticator;
import me.vzhilin.auth.netty.NettyHttpAuthenticator;

import java.net.URI;

public final class NettyClientDemo {
    static final String URL = System.getProperty("url", "http://127.0.0.1:8090/status");

    public static void main(String[] args) throws Exception {
        URI uri = new URI(URL);
        String host = uri.getHost() == null? "127.0.0.1" : uri.getHost();
        int port = uri.getPort();

        final DigestAuthenticator authenticator = new DigestAuthenticator("user", "pass");
        // Configure the client.
        EventLoopGroup group = new NioEventLoopGroup(1); // todo: avoid possible nonceCount race
        try {
            Bootstrap b = new Bootstrap();
            b.group(group)
             .channel(NioSocketChannel.class)
             .handler(new ChannelInitializer<SocketChannel>() {
                 @Override
                 protected void initChannel(SocketChannel ch) throws Exception {
                     ChannelPipeline p = ch.pipeline();
                     p.addLast(new HttpClientCodec());
                     p.addLast(new HttpContentDecompressor());
                     p.addLast(new NettyHttpAuthenticator(authenticator));
                     p.addLast(new NettyClientDemoHandler());
                 }
             });
            connectAndSend(uri, host, port, b); // the first one got 401
            connectAndSend(uri, host, port, b); // the second attempt succeeds

        } finally {
            // Shut down executor threads to exit.
            group.shutdownGracefully();
        }
    }

    private static void connectAndSend(URI uri, String host, int port, Bootstrap b) throws InterruptedException {
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