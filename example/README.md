# socks_socket example

A Flutter app that starts Tor in-process with `tor_ffi_plugin`, opens a
`SOCKSSocket` through it, and talks to an ElectrumX server over the proxy. It
also shows the same request through a general-purpose SOCKS5 client package
for comparison.

Run it with `flutter run` on a desktop or mobile target. The first start
downloads Tor's consensus, which can take a minute.

Two smaller, non-Flutter examples live beside it:

- `socks_socket_example.dart`: the socket API without the UI. It still needs
  Flutter for the Tor plugin; run it from a Flutter project, or point
  `proxyPort` at a Tor you run yourself.
- `http/http_connection.dart`: `SocksConnection.start` as an
  `HttpClient.connectionFactory`, runnable with plain Dart against any local
  SOCKS5 proxy. See the main README for the command.
