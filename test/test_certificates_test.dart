import 'dart:io';

import 'package:test/test.dart';

import 'helpers/test_certificates.dart';

void main() {
  test('generated server certificate is short-lived and CA-signed', () async {
    final certificates = TestCertificates.generate();
    final server = await SecureServerSocket.bind(
        InternetAddress.loopbackIPv4, 0, certificates.serverContext());
    addTearDown(server.close);
    server.listen((socket) => socket.destroy(), onError: (Object _) {});
    final socket = await SecureSocket.secure(
        await Socket.connect(InternetAddress.loopbackIPv4, server.port),
        host: 'localhost',
        context: certificates.clientContext());
    addTearDown(socket.destroy);
    socket.listen((_) {}, onError: (Object _) {});
    final certificate = socket.peerCertificate!;
    final now = DateTime.now();
    expect(certificate.subject, contains('localhost'));
    expect(certificate.issuer, isNot(certificate.subject));
    expect(certificate.startValidity.isBefore(now), isTrue);
    expect(certificate.endValidity.isAfter(now), isTrue);
    expect(certificate.endValidity.difference(certificate.startValidity),
        lessThanOrEqualTo(const Duration(days: 825)));
  });
}
