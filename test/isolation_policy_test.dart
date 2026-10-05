import 'dart:io';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/tunnel_proxy.dart';

void main() {
  test('adding an isolation token on reconnect also requires authentication',
      () async {
    final proxy = TunnelProxy(overrideMethod: 0);
    await proxy.start();
    addTearDown(proxy.close);
    final socket = await SOCKSSocket.create(
      proxyHost: InternetAddress.loopbackIPv4.address,
      proxyPort: proxy.port,
    );
    addTearDown(socket.close);
    await socket.connect();
    await socket.connectTo('example.invalid', 443);
    await expectLater(socket.reconnect(isolationToken: 'new-token'),
        throwsA(isA<SocksHandshakeException>()));
  });

  for (final fallback in [false, true]) {
    test('no-auth fallback must be explicit (opt-out=$fallback)', () async {
      final proxy = TunnelProxy(overrideMethod: 0);
      await proxy.start();
      addTearDown(proxy.close);
      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: proxy.port,
        isolationToken: 'token',
        requireIsolation: fallback ? false : null,
      );
      addTearDown(socket.close);
      if (fallback) {
        await socket.connect();
        await socket.connectTo('example.invalid', 443);
        expect(socket.state, ConnectionState.connected);
      } else {
        await expectLater(
            socket.connect(), throwsA(isA<SocksHandshakeException>()));
        expect(proxy.target, isNull);
      }
    });
  }
}
