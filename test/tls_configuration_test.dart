import 'dart:convert';
import 'dart:io';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/mock_socks_server.dart';
import 'helpers/test_certificates.dart';

void main() {
  test('SOCKSSocket manages TLS with a custom security context', () async {
    final certificates = TestCertificates.generate();
    final proxy = MockSocksServer()
      ..sslEnabled = true
      ..securityContext = certificates.serverContext();
    await proxy.start();
    addTearDown(proxy.stop);
    final socket = await SOCKSSocket.create(
      proxyHost: InternetAddress.loopbackIPv4.address,
      proxyPort: proxy.port,
      sslEnabled: true,
      securityContext: certificates.clientContext(),
    );
    addTearDown(socket.close);
    await socket.connect();
    await socket.connectTo('localhost', 443);
    final reply = socket.inputStream.expand((b) => b).take(10).toList();
    await socket.write('custom TLS');
    expect(utf8.decode(await reply), 'custom TLS');
  });
}
