import 'dart:async';
import 'dart:io';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/mock_socks_server.dart';
import 'helpers/test_certificates.dart';
import 'helpers/tunnel_proxy.dart';

void main() {
  for (final tls in [false, true]) {
    test('preserves input before and between listeners (TLS=$tls)', () async {
      final certificates = TestCertificates.generate();
      late Stream<Socket> connections;
      late int port;
      if (tls) {
        final server = await SecureServerSocket.bind(
            InternetAddress.loopbackIPv4, 0, certificates.serverContext());
        connections = server;
        port = server.port;
        addTearDown(server.close);
      } else {
        final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
        connections = server;
        port = server.port;
        addTearDown(server.close);
      }
      final accepted = Completer<Socket>();
      connections.listen((peer) {
        addTearDown(peer.destroy);
        accepted.complete(peer);
      });
      final proxy = TunnelProxy(upstreamPort: port);
      await proxy.start();
      addTearDown(proxy.close);
      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: proxy.port,
        sslEnabled: tls,
        securityContext: certificates.clientContext(),
      );
      addTearDown(socket.close);
      await socket.connect();
      await socket.connectTo('localhost', 443);
      final peer = await accepted.future;
      peer.add([1]);
      await peer.flush();
      expect(await socket.inputStream.first, [1]);
      peer.add([2]);
      await peer.flush();
      expect(await socket.inputStream.first, [2]);
      final first = socket.inputStream.listen((_) {});
      final second = socket.inputStream.listen((_) {});
      await first.cancel();
      await second.cancel();
    });

    test(
        'a listener from before reconnect cannot pause the new connection '
        '(TLS=$tls)', () async {
      final certificates = TestCertificates.generate();
      final proxy = MockSocksServer()
        ..sslEnabled = tls
        ..securityContext = certificates.serverContext();
      await proxy.start();
      addTearDown(proxy.stop);
      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: proxy.port,
        sslEnabled: tls,
        securityContext: certificates.clientContext(),
      );
      addTearDown(() => socket.close().catchError((_) {}));
      await socket.connect();
      await socket.connectTo('localhost', 443);
      final stale = socket.inputStream.listen((_) {})..pause();
      await socket.reconnect();
      final reply = socket.inputStream.first;
      await stale.cancel();
      await socket.write('A');
      expect(await reply.timeout(const Duration(seconds: 2)), [65]);
    });
  }
}
