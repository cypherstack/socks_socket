import 'dart:convert';
import 'dart:io';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/mock_socks_server.dart';
import 'helpers/test_certificates.dart';

void main() {
  test('legacy plain socket supports a caller-managed TLS upgrade', () async {
    final certificates = TestCertificates.generate();
    final proxy = MockSocksServer()
      ..sslEnabled = true
      ..securityContext = certificates.serverContext();
    await proxy.start();
    addTearDown(proxy.stop);
    final socket = await SOCKSSocket.create(
      proxyHost: InternetAddress.loopbackIPv4.address,
      proxyPort: proxy.port,
    );
    addTearDown(socket.close);
    await socket.connect();
    await socket.connectTo('localhost', 443);
    final secured = await SecureSocket.secure(socket.socket,
        host: 'localhost', context: certificates.clientContext());
    addTearDown(secured.destroy);
    final reply = secured.expand((b) => b).take(10).toList();
    secured.add(utf8.encode('manual TLS'));
    await secured.flush();
    expect(utf8.decode(await reply), 'manual TLS');
  });
}
