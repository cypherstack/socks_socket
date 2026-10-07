import 'dart:async';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/tunnel_peer.dart';

final _destroyed = isA<SocksConnectionException>()
    .having((e) => e.message, 'message', contains('destroyed'));

void main() {
  for (final tls in [false, true]) {
    group('destroy() (TLS=$tls)', () {
      test('fails a pending outputStream write', () async {
        final (client, peer) = await connectTunnel(tls: tls);
        // The peer stops reading, so the write stays in flight.
        peer.input.pause();
        final uploading = client.outputStream
            .addStream(Stream.value(List.filled(8 * 1024 * 1024, 1)));
        final failed = expectLater(uploading, throwsA(_destroyed));
        await Future<void>.delayed(const Duration(milliseconds: 200));
        client.destroy();
        await failed.timeout(tunnelDeadline);
        expect(client.state, SocksSocketState.disconnected);
        await client.close().timeout(tunnelDeadline);
      });

      test('fails a pending write()', () async {
        final (client, peer) = await connectTunnel(tls: tls);
        peer.input.pause();
        final writing = client.write('A' * (8 * 1024 * 1024));
        final failed = expectLater(writing, throwsA(_destroyed));
        await Future<void>.delayed(const Duration(milliseconds: 200));
        client.destroy();
        await failed.timeout(tunnelDeadline);
      });

      test('rejects later writes', () async {
        final (client, _) = await connectTunnel(tls: tls);
        client.destroy();
        await expectLater(client.write('A'), throwsStateError);
        expect(() => client.outputStream.add([65]), throwsStateError);
        await client.close().timeout(tunnelDeadline);
      });

      test('ends inputStream', () async {
        final (client, _) = await connectTunnel(tls: tls);
        final input = client.inputStream.drain<void>();
        client.destroy();
        await input.timeout(tunnelDeadline);
      });

      test('may be called from the upload source\'s onCancel', () async {
        final (client, peer) = await connectTunnel(tls: tls);
        peer.input.pause();
        final source = StreamController<List<int>>(onCancel: client.destroy);
        source.add(List.filled(8 * 1024 * 1024, 1));
        final uploading = client.outputStream.addStream(source.stream);
        final failed =
            expectLater(uploading, throwsA(isA<SocksConnectionException>()));
        await Future<void>.delayed(const Duration(milliseconds: 200));
        client.destroy();
        await failed.timeout(tunnelDeadline);
        await client.close().timeout(tunnelDeadline);
      });
    });
  }
}
