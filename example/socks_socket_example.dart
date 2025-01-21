// This won't work in pure Dart because the Tor plugin requires Flutter.
//
// See the [Arti package](https://pub.dev/packages/arti) for a pure Dart implementation.

import 'dart:async';
import 'dart:io';

import 'package:socks_socket/socks_socket.dart';
import 'package:tor_ffi_plugin/tor_ffi_plugin.dart';

Future<void> main() async {
  // Instantiate a socks socket at localhost and on the port selected by the
  // tor service.
  var socksSocket = await SOCKSSocket.create(
    proxyHost: InternetAddress.loopbackIPv4.address,
    proxyPort: Tor.instance.port,
    // sslEnabled: true, // For SSL connections.
  );

  // Connect to the socks instantiated above.
  await socksSocket.connect();

  // Connect to bitcoincash.stackwallet.com on port 50001 via socks socket.
  await socksSocket.connectTo('bitcoincash.stackwallet.com', 50001);

  // Send a server features command to the connected socket, see method for
  // more specific usage example..
  await socksSocket.sendServerFeaturesCommand();
  await socksSocket.close();
}
