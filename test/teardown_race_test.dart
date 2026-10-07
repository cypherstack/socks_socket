import 'dart:async';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/tunnel_peer.dart';

/// close() and destroy() racing a reconnect, a TLS handshake, or each other.
void main() {
  final teardowns = <String, Future<void> Function(SOCKSSocket)>{
    'destroy()': (client) async => client.destroy(),
    'close()': (client) => client.close(),
  };

  for (final tls in [false, true]) {
    for (final MapEntry(key: name, value: teardown) in teardowns.entries) {
      group('$name during reconnect (TLS=$tls)', () {
        test('right after it starts', () async {
          final server = await TunnelServer.start(tls: tls);
          final (client, peer) = await server.connect();
          final reconnecting = client.reconnect();
          final failed = expectLater(
              reconnecting, throwsA(isA<SocksCancelledException>()));
          final tearingDown = teardown(client);
          await failed.timeout(tunnelDeadline);
          await tearingDown.timeout(tunnelDeadline);
          expect(client.state, SocksSocketState.disconnected);
          await expectLater(client.write('A'), throwsStateError);
          await peer.done.future.timeout(tunnelDeadline);
          expect(server.connections, 1);
          await client.close().timeout(tunnelDeadline);
        });

        test('while the proxy answers the greeting', () async {
          final server = await TunnelServer.start(tls: tls);
          final (client, peer) = await server.connect();
          await client.write('before');
          await peer.firstChunk.future.timeout(tunnelDeadline);
          final hold = server.holdGreeting = TunnelHold();
          final reconnecting = client.reconnect();
          final failed = expectLater(
              reconnecting, throwsA(isA<SocksCancelledException>()));
          await hold.reached.future.timeout(tunnelDeadline);
          expect(server.connections, 2);
          final tearingDown = teardown(client);
          await failed.timeout(tunnelDeadline);
          await tearingDown.timeout(tunnelDeadline);
          expect(client.state, SocksSocketState.disconnected);
          hold.release.complete();
          // The abandoned handshake must not connect the socket after all.
          await Future<void>.delayed(const Duration(milliseconds: 200));
          expect(client.state, SocksSocketState.disconnected);
          await expectLater(client.write('after'), throwsStateError);
          await client.close().timeout(tunnelDeadline);
        });

        test('while the proxy TCP connect is pending', () async {
          final server = await TunnelServer.start(tls: tls);
          final (client, peer) = await server.connect(
              handshakeTimeout: const Duration(seconds: 2));
          if (!await server.stall()) {
            markTestSkipped('This host completes connects beyond the backlog');
            return;
          }
          final reconnecting = client.reconnect();
          final failed = expectLater(
              reconnecting, throwsA(isA<SocksCancelledException>()));
          await peer.done.future.timeout(tunnelDeadline);
          await Future<void>.delayed(const Duration(milliseconds: 100));
          final stopwatch = Stopwatch()..start();
          final tearingDown = teardown(client);
          await failed.timeout(tunnelDeadline);
          expect(stopwatch.elapsed, lessThan(const Duration(seconds: 1)));
          await tearingDown.timeout(tunnelDeadline);
          expect(client.state, SocksSocketState.disconnected);
          await expectLater(client.write('A'), throwsStateError);
          await client.close().timeout(tunnelDeadline);
        });

        test('from the old inputStream ending', () async {
          // reconnect() creates the connect task a few microtasks after the
          // old connection's close completes, and the old inputStream's done
          // event is delivered in that gap. A teardown from there finds no
          // task to cancel yet, so sweep a few microtasks after the event.
          const microtasks = 4;
          final server = await TunnelServer.start(tls: tls);
          final clients = [
            for (var i = 0; i < microtasks; i++)
              await server.connect(handshakeTimeout: const Duration(seconds: 2))
          ];
          if (!await server.stall()) {
            markTestSkipped('This host completes connects beyond the backlog');
            return;
          }
          for (var delay = 0; delay < microtasks; delay++) {
            final (client, _) = clients[delay];
            final stopwatch = Stopwatch();
            final tornDown = Completer<void>();
            client.inputStream.listen(null, onDone: () async {
              for (var i = 0; i < delay; i++) {
                await Future<void>.value();
              }
              stopwatch.start();
              tornDown.complete(teardown(client));
            });
            await expectLater(
                    client.reconnect(), throwsA(isA<SocksCancelledException>()))
                .timeout(tunnelDeadline);
            expect(stopwatch.elapsed, lessThan(const Duration(seconds: 1)),
                reason: 'teardown $delay microtasks after the old input ended');
            await tornDown.future.timeout(tunnelDeadline);
            expect(client.state, SocksSocketState.disconnected);
          }
        });
      });
    }

    test('reconnect() after cancel() connects again (TLS=$tls)', () async {
      final server = await TunnelServer.start(tls: tls);
      final hold = server.holdConnect = TunnelHold();
      final client = await server.createClient();
      await client.connect();
      final connecting = client.connectTo('localhost', 443);
      final failed =
          expectLater(connecting, throwsA(isA<SocksCancelledException>()));
      await hold.reached.future.timeout(tunnelDeadline);
      await client.cancel();
      await failed.timeout(tunnelDeadline);
      // The abandoned handshake stays parked; only new connections proceed.
      server.holdConnect = null;
      await client.reconnect().timeout(tunnelDeadline);
      expect(client.state, SocksSocketState.connected);
      final peer = await server.nextPeer();
      await client.write('again');
      await peer.firstChunk.future.timeout(tunnelDeadline);
      expect(peer.bytes.takeBytes(), 'again'.codeUnits);
    });

    test('reconnect() after destroy() connects again (TLS=$tls)', () async {
      final server = await TunnelServer.start(tls: tls);
      final (client, _) = await server.connect();
      client.destroy();
      await client.reconnect().timeout(tunnelDeadline);
      expect(client.state, SocksSocketState.connected);
      final peer = await server.nextPeer();
      await client.write('again');
      await peer.firstChunk.future.timeout(tunnelDeadline);
      expect(peer.bytes.takeBytes(), 'again'.codeUnits);
    });
  }

  test('a second reconnect() is rejected while one is in progress', () async {
    final server = await TunnelServer.start();
    final (client, _) = await server.connect();
    final reconnecting = client.reconnect();
    await expectLater(client.reconnect(), throwsStateError);
    await reconnecting.timeout(tunnelDeadline);
    expect(client.state, SocksSocketState.connected);
  });

  for (final MapEntry(key: name, value: teardown) in teardowns.entries) {
    test('$name ends a TLS handshake at once', () async {
      final server = await TunnelServer.start(tls: true);
      // Part of the server's reply sits in the TLS filter, so the SDK ignores
      // the destroyed transport and waits for the handshake deadline.
      final hold = server.holdTls = TunnelHold(after: 64);
      final client = await server.createClient(
          handshakeTimeout: const Duration(seconds: 5));
      await client.connect();
      final connecting = client.connectTo('localhost', 443);
      final failed =
          expectLater(connecting, throwsA(isA<SocksCancelledException>()));
      await hold.reached.future.timeout(tunnelDeadline);
      final stopwatch = Stopwatch()..start();
      final tearingDown = teardown(client);
      await failed.timeout(tunnelDeadline);
      expect(stopwatch.elapsed, lessThan(const Duration(seconds: 1)));
      await tearingDown.timeout(tunnelDeadline);
      expect(client.state, SocksSocketState.disconnected);
      hold.release.complete();
      await client.close().timeout(tunnelDeadline);
    });
  }

  for (final tls in [false, true]) {
    group('close() after destroy() (TLS=$tls)', () {
      final payload = List.filled(8 * 1024 * 1024, 1);

      test('completes when destroy() failed an explicit close in flight',
          () async {
        final (client, peer) = await connectTunnel(tls: tls);
        peer.input.pause();
        final uploading = client.outputStream.addStream(Stream.value(payload));
        final uploadFailed =
            expectLater(uploading, throwsA(isA<SocksConnectionException>()));
        await Future<void>.delayed(const Duration(milliseconds: 200));
        final closing = client.close();
        final closeFailed =
            expectLater(closing, throwsA(isA<SocksConnectionException>()));
        client.destroy();
        await Future.wait([uploadFailed, closeFailed]).timeout(tunnelDeadline);
        await client.close().timeout(tunnelDeadline);
        expect(client.state, SocksSocketState.disconnected);
      });

      test('completes when destroy() failed a peer-EOF close in flight',
          () async {
        final (client, peer) = await connectTunnel(tls: tls);
        final eof = client.inputStream.drain<void>();
        peer.input.pause();
        final uploading = client.outputStream.addStream(Stream.value(payload));
        final uploadFailed =
            expectLater(uploading, throwsA(isA<SocksConnectionException>()));
        await Future<void>.delayed(const Duration(milliseconds: 200));
        await peer.socket.close();
        await eof.timeout(tunnelDeadline);
        client.destroy();
        await uploadFailed.timeout(tunnelDeadline);
        await client.close().timeout(tunnelDeadline);
        expect(client.state, SocksSocketState.disconnected);
      });
    });
  }
}
