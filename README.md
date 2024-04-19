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
