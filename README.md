# SOCKS sockets

    [![Pub](https://img.shields.io/pub/v/socks_socket.svg)](https://pub.dev/packages/socks_socket)
    [![GitHub](https://img.shields.io/github/license/stackdump/socks_socket)](

SOCKS version 5 sockets for Dart and Flutter, *eg.* ElectrumX and/or Fulcrum over Tor via socket(s).

## Features

- Dart & Flutter 3.
- Support for SOCKS version 5 protocol.
- Supports ElectrumX and Fulcrum servers via socket(s).
- Async support for non-blocking network communication.
- Lightweight and minimal dependencies.
- Configurable connection timeouts (handshake and operation).
- Reconnection support without creating a new instance.
- Newline option for line-delimited protocols (ElectrumX).
- Connection state tracking (disconnected, connecting, connected, error).
- Typed exception hierarchy with SOCKS5 reply codes.
- Tor circuit isolation via `isolationToken`.
- Cancellation of in-flight connections via `cancel()`.

## Getting Started

See `socks_socket.dart` itself for properties and methods and the example for reference.

```dart
import 'package:socks_socket/socks.dart';

// Instantiate a socks socket at localhost and on the port selected by the tor service.
var socksSocket = await SOCKSSocket.create(
    proxyHost: InternetAddress.loopbackIPv4.address,
    proxyPort: Tor.instance.port,
    sslEnabled: true, // For SSL connections.
);

// Connect to the socks instantiated above.
await socksSocket.connect();

// Connect to bitcoin.stackwallet.com on port 50002 via socks socket.
//
// Note that this is an SSL example.
await socksSocket.connectTo('bitcoin.stackwallet.com', 50002);

// Send a server features command to the socket, see method for more specific usage example.
await socksSocket.sendServerFeaturesCommand();
```

`socks.dart` omits the `ConnectionState` alias for use alongside Flutter.

## Timeout Configuration

```dart
// Configure custom timeouts for slow networks like Tor.
var socksSocket = await SOCKSSocket.create(
    proxyHost: InternetAddress.loopbackIPv4.address,
    proxyPort: Tor.instance.port,
    sslEnabled: true,
    handshakeTimeout: Duration(seconds: 60),
    operationTimeout: Duration(seconds: 45),
);
```

## Circuit Isolation

```dart
// Use isolationToken to request a separate Tor circuit.
var socksSocket = await SOCKSSocket.create(
    proxyHost: InternetAddress.loopbackIPv4.address,
    proxyPort: Tor.instance.port,
    sslEnabled: true,
    isolationToken: 'wallet-btc-001',
);
await socksSocket.connect();
await socksSocket.connectTo('bitcoin.stackwallet.com', 50002);

// Reconnect with a different token; requires an earlier connectTo().
await socksSocket.reconnect(isolationToken: 'wallet-btc-002');
```

Tokens are sent as SOCKS5 credentials. A proxy selecting no-auth is rejected unless `requireIsolation: false`.

## Reconnection

```dart
// After a connection drops, reconnect to the same target.
await socksSocket.reconnect();

// Continue sending data on the restored connection.
await socksSocket.write('{"jsonrpc":"2.0","method":"server.ping","id":1}',
    newline: true);
```

After `cancel()` or `close()` during connect, `reconnect()` opens a new connection once a target is known. `reconnect()` closes the current connection first, which ends `inputStream`; a `close()` or `destroy()` while it is in progress cancels it, including one made from that stream's `onDone`. Peer close is noticed, and `state` updated, only while `inputStream` has a listener.

By default the connection closes once the peer closes its side. Pass `closeOnPeerEof: false` to `create()` to keep writing after a peer half-close until you call `close()`.

`destroy()` aborts a connection without draining output; pending writes fail, and a connect, TLS handshake or `reconnect()` in flight ends with `SocksCancelledException`. Use `close()` to drain accepted output before closing; it ends a connect or `reconnect()` in flight the same way.

## Migrating to 2.0.0

`SOCKSSocket.socket` has been removed. All transport operations now go through the wrapper so writes and teardown share the same lifecycle tracking.

| Previous operation | Replacement |
| --- | --- |
| `socks.socket.destroy()` | `socks.destroy()` |
| `socks.socket.close()` | `await socks.close()` |
| `socks.socket.add(bytes)` | `socks.outputStream.add(bytes)` |
| `socks.socket.addStream(source)` | `await socks.outputStream.addStream(source)` |
| Reading the underlying socket | `socks.inputStream` or `socks.listen(...)` |
| `SecureSocket.secure(socks.socket, ...)` | Set `sslEnabled: true` and, if needed, `securityContext` on `SOCKSSocket.create(...)` |

For an awaited binary write, use `await socks.outputStream.addStream(Stream.value(bytes))`. The output sink accepts one stream at a time. For text, use `await socks.write(text)`. To drain and finish the connection, use `await socks.close()`.

Built-in TLS starts during `connectTo()`, after the SOCKS handshake. Upgrading an established plaintext application session to TLS is not exposed by `SOCKSSocket`.

`SocksConnection.start` still returns a `ConnectionTask<Socket>` for `HttpClient.connectionFactory`; that separate API is unchanged.

## HttpClient Connections

`SocksConnection.start` returns a cancellable `ConnectionTask<Socket>` for `HttpClient.connectionFactory`; see `example/http/http_connection.dart`. Pass `tlsHost` for HTTPS. Requires Dart 3.5.
