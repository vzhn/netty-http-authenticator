/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Vladimir Zhilin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package me.vzhilin.auth.netty;

import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import me.vzhilin.auth.DigestAuthenticator;
import me.vzhilin.auth.parser.ChallengeResponseParser;

/**
 * transparent digest authentication
 * NOTE: works only with keep-alive connections!
 */
public class TransparentNettyHttpAuthenticator extends ChannelDuplexHandler {
    /** keep the client request */
    private FullHttpRequest request;
    private DigestAuthenticator authenticator;

    private enum State {
        INIT,
        CHALLENGE_RESPONSE_SENT,
        COMPLETED_OK,
        COMPLETED_UNAUTHORIZED
    }

    private State state = State.INIT;

    public TransparentNettyHttpAuthenticator(DigestAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        freeRequest();

        super.channelInactive(ctx);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        if (msg instanceof FullHttpResponse) {
            FullHttpResponse httpResponse = (FullHttpResponse) msg;
            HttpResponseStatus status = httpResponse.status();
            if (status.equals(HttpResponseStatus.OK)) {
                state = State.COMPLETED_OK;
                freeRequest();
            } else
            if (status.equals(HttpResponseStatus.UNAUTHORIZED)) {
                if (state == State.COMPLETED_OK || state == State.INIT) {
                    state = State.CHALLENGE_RESPONSE_SENT;
                    if (ctx.channel().isOpen()) {
                        String authenticateHeader = httpResponse.headers().get(HttpHeaderNames.WWW_AUTHENTICATE);
                        if (authenticateHeader != null) {
                            authenticator.onResponseReceived(new ChallengeResponseParser(authenticateHeader).parseChallenge(), status.code());
                        }
                        request.headers().set(HttpHeaderNames.AUTHORIZATION, authenticator.headerFor(request.method().name(), request.uri()));
                        request.retain();
                        ctx.writeAndFlush(request);
                    } else {
                        freeRequest();
                        state = State.INIT;
                    }

                    httpResponse.release();
                    return;
                } else {
                    state = State.COMPLETED_UNAUTHORIZED;
                }
            }
        }
        super.channelRead(ctx, msg);
    }

    private void freeRequest() {
        if (request != null) {
            request.release();
            request = null;
        }
    }

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        if (msg instanceof FullHttpRequest) {
            FullHttpRequest req = (FullHttpRequest) msg;
            if (state == State.COMPLETED_OK || state == State.CHALLENGE_RESPONSE_SENT) {
                String method = req.method().name();
                String uri = req.uri();

                req.headers().set(HttpHeaderNames.AUTHORIZATION, authenticator.headerFor(method, uri));
            }
            // keep the client request
            // When server responds 401 Unauthorized, resend the request with authentication header
            if (this.request != null) {
                this.request.release();
            }
            this.request = (FullHttpRequest) msg;
            this.request.retain();
        }

        super.write(ctx, msg, promise);
    }
}
