package me.vzhilin.auth.netty;

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class BasicNettyHttpAuthenticator extends ChannelDuplexHandler {
    private final String basicAuthHeader;

    public BasicNettyHttpAuthenticator(String username, String password) {
        this.basicAuthHeader =
            "Basic " + Base64.getEncoder()
                .encodeToString((username + ":" + password)
                .getBytes(StandardCharsets.ISO_8859_1));
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (msg instanceof HttpRequest) {
            ((HttpRequest) msg).headers().set(HttpHeaderNames.AUTHORIZATION, basicAuthHeader);
        }
        super.write(ctx, msg, promise);
    }
}
