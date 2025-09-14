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

## Getting Started

See `socks_socket.dart` itself for properties and methods and the example for reference.

```dart
import 'package:socks_socket/socks_socket.dart';

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

## Reconnection

```dart
// After a connection drops, reconnect to the same target.
await socksSocket.reconnect();

// Continue sending data on the restored connection.
await socksSocket.write('{"jsonrpc":"2.0","method":"server.ping","id":1}',
    newline: true);
```
