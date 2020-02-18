![Travis (.org)](https://img.shields.io/travis/vzhn/netty-http-authenticator?style=plastic)
![Maven Central](https://img.shields.io/maven-central/v/io.github.vzhn/netty-http-authenticator?style=plastic)

### BasicNetyHttpAuthenticator
`BasicNettyHttpAuthenticator` just appends the auth header to an every request.
```java
Bootstrap b = new Bootstrap();
b.group(group)
 .channel(NioSocketChannel.class)
 .handler(new ChannelInitializer<SocketChannel>() {
     @Override
     protected void initChannel(SocketChannel ch) {
         ChannelPipeline p = ch.pipeline();
         p.addLast(new HttpClientCodec());
         p.addLast(new HttpObjectAggregator(1048576));
         p.addLast(new BasicNettyHttpAuthenticator("scott", "tiger"));
         p.addLast(new HttpClientHandler());
     }
 });
```

### DigestNettyHttpAuthenticator
```java
DigestAuthenticator digestAuthenticator = new DigestAuthenticator("scott", "tiger");

Bootstrap b = new Bootstrap();
b.group(group)
 .channel(NioSocketChannel.class)
 .handler(new ChannelInitializer<SocketChannel>() {
     @Override
     protected void initChannel(SocketChannel ch) {
         ChannelPipeline p = ch.pipeline();
         p.addLast(new HttpClientCodec());
         p.addLast(new DigestNettyHttpAuthenticator(digestAuthenticator));
         p.addLast(new HttpClientHandler());
     }
 });

...
  ch.writeAndFlush(firstSequest); // the first request got 401 error
  ch.writeAndFlush(secondRequest); // the second will succeeded if credentinals are not wrong
```

### TransparentDigestNettyHttpAuthenticator
This is the tricky one. It works only with aggregated HTTP messages: `FullHttpRequest` and `FullHttpResponse` and keep-alive connection. 
The solution that fits for `RTSP`.

`TransparentDigestNettyHttpAuthenticator` must be initialized with `username` and `password` and placed in a channel pipeline between `HttpObjectAggregator` 
and handler that processes server responses, like this:

```java
DigestAuthenticator digestAuthenticator = new DigestAuthenticator("scott", "tiger");

Bootstrap b = new Bootstrap();
b.group(group)
 .channel(NioSocketChannel.class)
 .handler(new ChannelInitializer<SocketChannel>() {
     @Override
     protected void initChannel(SocketChannel ch) {
         ChannelPipeline p = ch.pipeline();
         p.addLast(new HttpClientCodec());
         p.addLast(new HttpObjectAggregator(1048576)); // NB! works only with aggregated request/response
         p.addLast(new TransparentDigestNettyHttpAuthenticator(authenticator));
         p.addLast(new HttpClientHandler());
     }
 });
..
  ch.writeAndFlush(request); // the first attempt will succeeded if credentinals are not wrong
```

##### How it works
`TransparentDigestNettyHttpAuthenticator` intercepts the client request, and remembers it
* If a server returns the `401 Unathorized` error,  authenticator resends the request with proper authorization header
* If a server returns `200 OK`, authenticator attaches the authorization header to all subsequent requests
* If a server returns the `401 Unathorized` error again, and `stale=false`, authenticator pass that *error* to client (bad credentials)
* If a server returns the `401 Unathorized error` and `stale=true`, authenticator generates a new client nonce and resend the request with new authorization header

Typical client-server exchange may look like this:

![Digest authenticator](digest-auth-sequence.png)


## Downloading from the Maven central repository
Add the following dependency section to your pom.xml:
```xml
<dependency>
    <groupId>io.github.vzhn</groupId>
    <artifactId>netty-http-authenticator</artifactId>
    <version>1.1</version>
</dependency>
```

## How to contribute
Make your changes, and submit a pull request. Contributions are welcome!

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
