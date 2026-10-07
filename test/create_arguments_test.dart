import 'dart:async';
import 'dart:io';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/tunnel_peer.dart';

void main() {
  final host = InternetAddress.loopbackIPv4.address;

  test('create() rejects an empty proxy host', () async {
    await expectLater(SOCKSSocket.create(proxyHost: '', proxyPort: 1080),
        throwsArgumentError);
  });

  for (final port in [0, 65536]) {
    test('create() rejects proxy port $port', () async {
      await expectLater(SOCKSSocket.create(proxyHost: host, proxyPort: port),
          throwsArgumentError);
    });
  }

  test('create() rejects a non-positive handshake timeout', () async {
    await expectLater(
        SOCKSSocket.create(
            proxyHost: host, proxyPort: 1080, handshakeTimeout: Duration.zero),
        throwsArgumentError);
  });

  test('create() rejects a non-positive operation timeout', () async {
    await expectLater(
        SOCKSSocket.create(
            proxyHost: host,
            proxyPort: 1080,
            operationTimeout: const Duration(seconds: -1)),
        throwsArgumentError);
  });

  test('a sub-second handshake timeout is reported in milliseconds', () async {
    final server = await TunnelServer.start();
    server.holdGreeting = TunnelHold();
    final client = await server.createClient(
        handshakeTimeout: const Duration(milliseconds: 500));
    await expectLater(
        client.connect(),
        throwsA(isA<TimeoutException>()
            .having((e) => e.message, 'message', contains('500 ms'))));
  });
}
