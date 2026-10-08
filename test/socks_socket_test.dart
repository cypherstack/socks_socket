import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:socks_socket/socks_socket.dart';
import 'package:socks_socket/src/connection_socket.dart';
import 'helpers/mock_socks_server.dart';
import 'helpers/test_certificates.dart';
import 'helpers/tunnel_proxy.dart';

/// Helper: create, connect, and connectTo in one call.
Future<SOCKSSocket> createAndConnect(
  MockSocksServer server, {
  bool ssl = false,
  bool allowBadCerts = false,
  SecurityContext? trust,
  Duration? handshakeTimeout,
}) async {
  final socket = await SOCKSSocket.create(
    proxyHost: InternetAddress.loopbackIPv4.address,
    proxyPort: server.port,
    sslEnabled: ssl,
    handshakeTimeout: handshakeTimeout ?? const Duration(seconds: 5),
    operationTimeout: const Duration(seconds: 5),
    allowBadCertificates: allowBadCerts,
    securityContext: trust,
  );
  await socket.connect();
  await socket.connectTo('localhost', 1234);
  return socket;
}

/// Collects [length] bytes through [SOCKSSocket.listen], however they arrive.
Future<List<int>> collect(SOCKSSocket socket, int length) {
  final completer = Completer<List<int>>();
  final received = <int>[];
  socket.listen((data) {
    received.addAll(data);
    if (received.length >= length && !completer.isCompleted) {
      completer.complete(received);
    }
  });
  return completer.future.timeout(const Duration(seconds: 5));
}

void main() {
  final certificates = TestCertificates.generate();

  for (final size in [3, 4096]) {
    test('preserves $size application bytes sent with the CONNECT reply',
        () async {
      final payload = List<int>.generate(size, (i) => i % 251);
      final proxy = TunnelProxy(initialData: payload);
      await proxy.start();
      addTearDown(proxy.close);
      final socket = await SOCKSSocket.create(
          proxyHost: '127.0.0.1', proxyPort: proxy.port);
      addTearDown(socket.close);
      await socket.connect();
      await socket.connectTo('example.invalid', 80);
      await proxy.replyFlushed.future;
      final laterData = [251, 252, 253];
      proxy.sockets.first.add(laterData);
      await proxy.sockets.first.flush();
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(
          await socket.inputStream
              .expand((b) => b)
              .take(size + laterData.length)
              .toList()
              .timeout(const Duration(seconds: 2)),
          [...payload, ...laterData]);
    });
  }

  for (final token in [null, 'circuit']) {
    test(
        'an inputStream listener attached before connecting sees only '
        'application data${token == null ? '' : ' (with isolation token)'}',
        () async {
      final payload = [7, 7, 7];
      final proxy = TunnelProxy(initialData: payload);
      await proxy.start();
      addTearDown(proxy.close);
      final socket = await SOCKSSocket.create(
          proxyHost: '127.0.0.1', proxyPort: proxy.port, isolationToken: token);
      addTearDown(socket.close);
      final received = <int>[];
      socket.inputStream.listen(received.addAll);
      await socket.connect();
      await socket.connectTo('example.invalid', 80);
      await proxy.replyFlushed.future;
      final laterData = [8, 9];
      proxy.sockets.first.add(laterData);
      await proxy.sockets.first.flush();
      final deadline = DateTime.now().add(const Duration(seconds: 2));
      while (received.length < payload.length + laterData.length &&
          DateTime.now().isBefore(deadline)) {
        await Future<void>.delayed(const Duration(milliseconds: 10));
      }
      expect(received, [...payload, ...laterData]);
    });
  }

  group('Happy path', () {
    late MockSocksServer server;

    setUp(() async {
      server = MockSocksServer();
      await server.start();
    });

    tearDown(() async {
      await server.stop();
    });

    test('connects through SOCKS5 proxy and reaches connected state', () async {
      final socket = await createAndConnect(server);
      try {
        expect(socket.state, ConnectionState.connected);
      } finally {
        await socket.close();
      }
    });

    test('sends data and receives echo response', () async {
      final socket = await createAndConnect(server);
      try {
        final received = collect(socket, utf8.encode('hello').length);

        await socket.write('hello');

        expect(await received, equals(utf8.encode('hello')));
      } finally {
        await socket.close();
      }
    });

    test('write with newline appends trailing newline', () async {
      final socket = await createAndConnect(server);
      try {
        final received = collect(socket, utf8.encode('test\n').length);

        await socket.write('test', newline: true);

        expect(await received, equals(utf8.encode('test\n')));
      } finally {
        await socket.close();
      }
    });

    test('write null is no-op', () async {
      final socket = await createAndConnect(server);
      try {
        // Should not throw.
        await socket.write(null);
      } finally {
        await socket.close();
      }
    });

    test('close transitions to disconnected state', () async {
      final socket = await createAndConnect(server);
      expect(socket.state, ConnectionState.connected);
      await socket.close();
      expect(socket.state, ConnectionState.disconnected);
    });

    test('ConnectionState starts as disconnected', () async {
      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );
      try {
        // After create() but before connect(), state is disconnected.
        expect(socket.state, ConnectionState.disconnected);
      } finally {
        await socket.close();
      }
    });
  });

  group('Fragmented responses', () {
    late MockSocksServer server;

    setUp(() async {
      server = MockSocksServer()..fragmentResponses = true;
      await server.start();
    });

    tearDown(() async {
      await server.stop();
    });

    test('handles SOCKS5 greeting and connect responses one byte at a time',
        () async {
      // Fragmented delivery needs a longer timeout.
      final socket = await createAndConnect(
        server,
        handshakeTimeout: const Duration(seconds: 10),
      );
      try {
        expect(socket.state, ConnectionState.connected);
      } finally {
        await socket.close();
      }
    });
  });

  group('Timeout behavior', () {
    late MockSocksServer server;

    setUp(() async {
      server = MockSocksServer();
    });

    tearDown(() async {
      await server.stop();
    });

    test('throws TimeoutException when proxy never responds to greeting',
        () async {
      server.hangOnGreeting = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(milliseconds: 200),
      );

      try {
        await expectLater(
          socket.connect(),
          throwsA(isA<TimeoutException>()),
        );
      } finally {
        try {
          await socket.close();
        } catch (_) {}
      }
    });

    test('throws when proxy drops connection immediately', () async {
      server.dropConnection = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(milliseconds: 500),
      );
      addTearDown(() => socket.close().catchError((_) {}));

      await expectLater(
          socket.connect(), throwsA(isA<SocksConnectionException>()));
      expect(socket.state, ConnectionState.error);
    });

    test('configurable handshakeTimeout is respected', () async {
      server.hangOnGreeting = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(milliseconds: 150),
      );

      final stopwatch = Stopwatch()..start();
      try {
        await socket.connect();
        fail('Should have thrown');
      } on TimeoutException {
        stopwatch.stop();
        // ~150ms expected.
        expect(stopwatch.elapsedMilliseconds, greaterThan(80));
        expect(stopwatch.elapsedMilliseconds, lessThan(1000));
      } finally {
        try {
          await socket.close();
        } catch (_) {}
      }
    });
  });

  group('SSL upgrade', () {
    late MockSocksServer server;
    late SecurityContext serverContext;

    setUp(() async {
      serverContext = certificates.serverContext();

      server = MockSocksServer()
        ..sslEnabled = true
        ..securityContext = serverContext;
      await server.start();
    });

    tearDown(() async {
      await server.stop();
    });

    test('connects and upgrades to SSL through SOCKS5 proxy', () async {
      final socket = await createAndConnect(
        server,
        ssl: true,
        allowBadCerts: true,
      );
      try {
        expect(socket.state, ConnectionState.connected);
      } finally {
        await socket.close();
      }
    });

    test('SSL echo works through SOCKS5 proxy', () async {
      final socket = await createAndConnect(
        server,
        ssl: true,
        trust: certificates.clientContext(),
      );
      try {
        final received = collect(socket, utf8.encode('ssl-hello').length);

        await socket.write('ssl-hello');

        expect(await received, equals(utf8.encode('ssl-hello')));
      } finally {
        await socket.close();
      }
    });
  });

  group('Error conditions', () {
    late MockSocksServer server;

    setUp(() async {
      server = MockSocksServer();
    });

    tearDown(() async {
      await server.stop();
    });

    test('throws on SOCKS5 proxy rejection', () async {
      server.rejectConnection = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );

      try {
        await socket.connect();
        await expectLater(
          socket.connectTo('localhost', 1234),
          throwsA(
            isA<SocksRequestException>().having(
              (e) => e.replyCode,
              'replyCode',
              SocksReplyCode.generalFailure,
            ),
          ),
        );
      } finally {
        try {
          await socket.close();
        } catch (_) {}
      }
    });

    test('throws on invalid SOCKS5 response', () async {
      server.sendInvalidResponse = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(milliseconds: 500),
      );

      try {
        await socket.connect();
        // 1-byte response never satisfies expected length; times out.
        await expectLater(
          socket.connectTo('localhost', 1234),
          throwsA(anything),
        );
      } finally {
        try {
          await socket.close();
        } catch (_) {}
      }
    });

    test('double close does not throw', () async {
      await server.start();

      final socket = await createAndConnect(server);
      await socket.close();
      // Second close should not throw.
      await socket.close();
    });

    test('write throws StateError when not connected', () async {
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );

      try {
        await expectLater(
          socket.write('test'),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('not connected'),
            ),
          ),
        );
      } finally {
        try {
          await socket.close();
        } catch (_) {}
      }
    });

    test('connectTo throws StateError when connect not called first', () async {
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );

      try {
        await expectLater(
          socket.connectTo('localhost', 1234),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('must call connect'),
            ),
          ),
        );
      } finally {
        try {
          await socket.close();
        } catch (_) {}
      }
    });
  });

  group('Reconnection', () {
    late MockSocksServer server;

    setUp(() async {
      server = MockSocksServer();
      await server.start();
    });

    tearDown(() async {
      await server.stop();
    });

    test('reconnect re-establishes connection after close', () async {
      final socket = await createAndConnect(server);
      try {
        expect(socket.state, ConnectionState.connected);
        await socket.close();
        expect(socket.state, ConnectionState.disconnected);

        await socket.reconnect();
        expect(socket.state, ConnectionState.connected);
      } finally {
        await socket.close();
      }
    });

    test('reconnect throws StateError if connectTo was never called', () async {
      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );

      try {
        await socket.connect();
        await expectLater(
          socket.reconnect(),
          throwsA(
            isA<StateError>().having(
              (e) => e.message,
              'message',
              contains('no target known'),
            ),
          ),
        );
      } finally {
        try {
          await socket.close();
        } catch (_) {}
      }
    });

    test('reconnect works from connected state', () async {
      final socket = await createAndConnect(server);
      try {
        expect(socket.state, ConnectionState.connected);
        await socket.reconnect();
        expect(socket.state, ConnectionState.connected);
      } finally {
        await socket.close();
      }
    });

    test('data can be sent after reconnect', () async {
      final socket = await createAndConnect(server);
      try {
        await socket.reconnect();

        final received = collect(socket, utf8.encode('hello').length);

        await socket.write('hello');

        expect(await received, equals(utf8.encode('hello')));
      } finally {
        await socket.close();
      }
    });
  });

  group('Typed exceptions', () {
    late MockSocksServer server;

    setUp(() {
      server = MockSocksServer();
    });

    tearDown(() async {
      await server.stop();
    });

    test('SocksRequestException thrown on connect rejection', () async {
      server.rejectConnection = true;
      server.replyCode = 0x05;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );

      await socket.connect();
      try {
        await expectLater(
          socket.connectTo('example.com', 8080),
          throwsA(
            isA<SocksRequestException>()
                .having((e) => e.replyCode, 'replyCode',
                    SocksReplyCode.connectionRefused)
                .having((e) => e.targetDomain, 'targetDomain', 'example.com')
                .having((e) => e.targetPort, 'targetPort', 8080)
                .having((e) => e.proxyHost, 'proxyHost',
                    InternetAddress.loopbackIPv4.address)
                .having((e) => e.message, 'message',
                    contains('SOCKS5 request failed')),
          ),
        );
      } finally {
        try {
          await socket.close();
        } catch (_) {}
      }
    });

    test('SocksRequestException is caught by catch (Exception e)', () async {
      server.rejectConnection = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );

      await socket.connect();
      var caughtByException = false;
      try {
        await socket.connectTo('example.com', 8080);
      } on Exception {
        caughtByException = true;
      } finally {
        try {
          await socket.close();
        } catch (_) {}
      }
      expect(caughtByException, isTrue,
          reason:
              'SocksRequestException must be caught by catch (Exception e)');
    });

    test('SocksConnectionException wraps stream errors', () {
      // SocksConnectionException is used to wrap non-SocksException errors
      // that surface through the response controller stream. Verify it can
      // be constructed and caught as an Exception.
      final error = SocksConnectionException(
        message: 'Connection closed before SOCKS5 response received '
            '(proxy: 127.0.0.1:9050).',
      );
      expect(error, isA<SocksException>());
      expect(error, isA<Exception>());
      expect(error.message,
          contains('Connection closed before SOCKS5 response received'));
    });

    test('SocksRequestException message contains proxy and target context',
        () async {
      server.rejectConnection = true;
      server.replyCode = 0x03;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );

      await socket.connect();
      try {
        await socket.connectTo('target.onion', 50001);
        fail('Should have thrown');
      } on SocksRequestException catch (e) {
        expect(
            e.message,
            contains(
                'proxy: ${InternetAddress.loopbackIPv4.address}:${server.port}'));
        expect(e.message, contains('target: target.onion:50001'));
        expect(e.message, contains('Network unreachable'));
        expect(e.replyCode, SocksReplyCode.networkUnreachable);
      } finally {
        try {
          await socket.close();
        } catch (_) {}
      }
    });

    test('SocksException subtypes have correct toString()', () {
      final handshake = SocksHandshakeException(
        proxyHost: '127.0.0.1',
        proxyPort: 9050,
        message: 'test handshake error',
      );
      expect(handshake.toString(), 'test handshake error');

      final request = SocksRequestException(
        replyCode: SocksReplyCode.hostUnreachable,
        proxyHost: '127.0.0.1',
        proxyPort: 9050,
        targetDomain: 'example.com',
        targetPort: 443,
        message: 'test request error',
      );
      expect(request.toString(), 'test request error');

      final connection =
          SocksConnectionException(message: 'test connection error');
      expect(connection.toString(), 'test connection error');

      final cancelled = SocksCancelledException(message: 'test cancelled');
      expect(cancelled.toString(), 'test cancelled');
    });
  });

  group('Reply code mapping', () {
    late MockSocksServer server;

    setUp(() {
      server = MockSocksServer();
    });

    tearDown(() async {
      await server.stop();
    });

    test('all 8 SOCKS5 reply codes map correctly via fromByte()', () {
      expect(SocksReplyCode.fromByte(0x01), SocksReplyCode.generalFailure);
      expect(
          SocksReplyCode.fromByte(0x02), SocksReplyCode.connectionNotAllowed);
      expect(SocksReplyCode.fromByte(0x03), SocksReplyCode.networkUnreachable);
      expect(SocksReplyCode.fromByte(0x04), SocksReplyCode.hostUnreachable);
      expect(SocksReplyCode.fromByte(0x05), SocksReplyCode.connectionRefused);
      expect(SocksReplyCode.fromByte(0x06), SocksReplyCode.ttlExpired);
      expect(SocksReplyCode.fromByte(0x07), SocksReplyCode.commandNotSupported);
      expect(SocksReplyCode.fromByte(0x08),
          SocksReplyCode.addressTypeNotSupported);
    });

    test('fromByte() returns null for unknown codes', () {
      expect(SocksReplyCode.fromByte(0x00), isNull);
      expect(SocksReplyCode.fromByte(0x09), isNull);
      expect(SocksReplyCode.fromByte(0xFF), isNull);
    });

    test('SocksReplyCode values have correct byte and description', () {
      expect(SocksReplyCode.values.length, 8);
      for (final code in SocksReplyCode.values) {
        expect(code.byte, greaterThanOrEqualTo(0x01));
        expect(code.byte, lessThanOrEqualTo(0x08));
        expect(code.description, isNotEmpty);
      }
    });

    test('all 8 reply codes produce correct SocksRequestException end-to-end',
        () async {
      final expectedCodes = {
        0x01: SocksReplyCode.generalFailure,
        0x02: SocksReplyCode.connectionNotAllowed,
        0x03: SocksReplyCode.networkUnreachable,
        0x04: SocksReplyCode.hostUnreachable,
        0x05: SocksReplyCode.connectionRefused,
        0x06: SocksReplyCode.ttlExpired,
        0x07: SocksReplyCode.commandNotSupported,
        0x08: SocksReplyCode.addressTypeNotSupported,
      };

      for (final entry in expectedCodes.entries) {
        server = MockSocksServer();
        server.rejectConnection = true;
        server.replyCode = entry.key;
        await server.start();

        final socket = await SOCKSSocket.create(
          proxyHost: InternetAddress.loopbackIPv4.address,
          proxyPort: server.port,
          handshakeTimeout: const Duration(seconds: 5),
        );

        await socket.connect();
        try {
          await socket.connectTo('test.onion', 50001);
          fail(
              'Should have thrown for reply code 0x${entry.key.toRadixString(16)}');
        } on SocksRequestException catch (e) {
          expect(e.replyCode, entry.value,
              reason: 'Reply code 0x${entry.key.toRadixString(16)} '
                  'should map to ${entry.value}');
          expect(e.message, contains(entry.value.description),
              reason: 'Message should contain description for '
                  '0x${entry.key.toRadixString(16)}');
        } finally {
          try {
            await socket.close();
          } catch (_) {}
          await server.stop();
        }
      }
    });
  });

  group('Circuit isolation', () {
    late MockSocksServer server;

    setUp(() async {
      server = MockSocksServer();
    });

    tearDown(() async {
      await server.stop();
    });

    test('connect with isolationToken performs auth handshake', () async {
      server.requireAuth = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        isolationToken: 'wallet-btc-001',
        handshakeTimeout: const Duration(seconds: 5),
      );
      await socket.connect();
      await socket.connectTo('target.onion', 50001);
      expect(socket.state, ConnectionState.connected);
      expect(server.lastUsername, 'wallet-btc-001');
      expect(server.lastPassword, 'wallet-btc-001');
      await socket.close();
    });

    test('connect without isolationToken uses no-auth greeting', () async {
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );
      await socket.connect();
      await socket.connectTo('target.onion', 50001);
      expect(socket.state, ConnectionState.connected);
      expect(server.lastUsername, isNull);
      expect(server.lastPassword, isNull);
      await socket.close();
    });

    test(
        'connect with token to no-auth server proceeds without sub-negotiation',
        () async {
      // Server selects no-auth even though client offers auth.
      server.requireAuth = false;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        isolationToken: 'some-token',
        requireIsolation: false,
        handshakeTimeout: const Duration(seconds: 5),
      );
      await socket.connect();
      await socket.connectTo('target.onion', 50001);
      expect(socket.state, ConnectionState.connected);
      expect(server.lastUsername, isNull);
      await socket.close();
    });

    test('auth rejection throws SocksHandshakeException from connect',
        () async {
      server.requireAuth = true;
      server.rejectAuth = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        isolationToken: 'rejected-token',
        handshakeTimeout: const Duration(seconds: 5),
      );
      await expectLater(
        socket.connect,
        throwsA(isA<SocksHandshakeException>().having(
          (e) => e.toString(),
          'message',
          contains('username/password auth rejected'),
        )),
      );
      await socket.close();
    });

    test('authentication receives a fresh handshake timeout', () async {
      server
        ..requireAuth = true
        ..responseDelay = const Duration(milliseconds: 150);
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        isolationToken: 'slow-auth',
        handshakeTimeout: const Duration(milliseconds: 250),
      );
      await socket.connect().timeout(const Duration(seconds: 2));
      expect(socket.state, ConnectionState.connecting);
      await socket.close();
    });

    test('reconnect with different isolationToken rotates circuit', () async {
      server.requireAuth = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        isolationToken: 'circuit-1',
        handshakeTimeout: const Duration(seconds: 5),
      );
      await socket.connect();
      await socket.connectTo('target.onion', 50001);
      expect(server.lastUsername, 'circuit-1');

      // Reconnect with a different token.
      await socket.reconnect(isolationToken: 'circuit-2');
      expect(server.lastUsername, 'circuit-2');
      expect(server.lastPassword, 'circuit-2');
      await socket.close();
    });

    test('requireIsolation offers only auth and rejects no-auth downgrade',
        () async {
      server.requireAuth = false;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        isolationToken: 'strict-token',
        requireIsolation: true,
        handshakeTimeout: const Duration(seconds: 5),
      );
      await expectLater(
        socket.connect,
        throwsA(isA<SocksHandshakeException>().having(
          (e) => e.toString(),
          'message',
          contains('isolation is required'),
        )),
      );
      expect(server.lastOfferedMethods, [0x02]);
      expect(server.lastUsername, isNull);
      expect(socket.state, ConnectionState.error);
      await socket.close();
    });

    test('requireIsolation connects when the proxy selects auth', () async {
      server.requireAuth = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        isolationToken: 'strict-token',
        requireIsolation: true,
        handshakeTimeout: const Duration(seconds: 5),
      );
      await socket.connect();
      await socket.connectTo('target.onion', 50001);
      expect(socket.state, ConnectionState.connected);
      expect(server.lastOfferedMethods, [0x02]);
      expect(server.lastUsername, 'strict-token');
      await socket.close();
    });

    test('requireIsolation without isolationToken throws ArgumentError',
        () async {
      await expectLater(
        () => SOCKSSocket.create(
          proxyHost: InternetAddress.loopbackIPv4.address,
          proxyPort: 1234,
          requireIsolation: true,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('isolationToken exceeding 255 UTF-8 bytes throws ArgumentError',
        () async {
      final longToken = 'a' * 256;
      await expectLater(
        () => SOCKSSocket.create(
          proxyHost: InternetAddress.loopbackIPv4.address,
          proxyPort: 1234,
          isolationToken: longToken,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('Cancellation', () {
    late MockSocksServer server;

    setUp(() async {
      server = MockSocksServer();
    });

    tearDown(() async {
      await server.stop();
    });

    test('cancel during connect throws SocksCancelledException', () async {
      server.hangOnGreeting = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );

      // Capture error so it doesn't leak.
      Object? caughtError;
      final connectFuture = socket.connect().catchError((e) {
        caughtError = e;
      });

      await Future.delayed(const Duration(milliseconds: 50));
      await socket.cancel();
      await connectFuture;

      expect(caughtError, isA<SocksCancelledException>());
      expect(socket.state, ConnectionState.disconnected);
    });

    for (final phase in ['connect', 'connectTo']) {
      test('close during $phase throws SocksCancelledException', () async {
        if (phase == 'connect') {
          server.hangOnGreeting = true;
        } else {
          server.hangOnConnect = true;
        }
        await server.start();

        final socket = await SOCKSSocket.create(
          proxyHost: InternetAddress.loopbackIPv4.address,
          proxyPort: server.port,
          handshakeTimeout: const Duration(seconds: 5),
        );
        if (phase == 'connectTo') await socket.connect();
        final pending = phase == 'connect'
            ? socket.connect()
            : socket.connectTo('example.com', 80);
        final failed =
            expectLater(pending, throwsA(isA<SocksCancelledException>()));

        await Future.delayed(const Duration(milliseconds: 50));
        await socket.close();
        await failed;
        expect(socket.state, ConnectionState.disconnected);
      });
    }

    test('cancel during connectTo throws SocksCancelledException', () async {
      server.hangOnConnect = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );

      await socket.connect();

      // Capture error so it doesn't leak.
      Object? caughtError;
      final connectToFuture =
          socket.connectTo('example.com', 80).catchError((e) {
        caughtError = e;
      });

      await Future.delayed(const Duration(milliseconds: 50));
      await socket.cancel();
      await connectToFuture;

      expect(caughtError, isA<SocksCancelledException>());
      expect(socket.state, ConnectionState.disconnected);
    });

    test('cancel after connected is silent no-op', () async {
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
      );
      await socket.connect();
      await socket.connectTo('example.com', 80);
      expect(socket.state, ConnectionState.connected);

      await socket.cancel(); // Should not throw or change state
      expect(socket.state, ConnectionState.connected);

      await socket.close();
    });

    test('cancel on disconnected socket is silent no-op', () async {
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
      );
      await socket.connect();
      await socket.connectTo('example.com', 80);
      await socket.close();
      expect(socket.state, ConnectionState.disconnected);

      await socket.cancel(); // Should not throw
      expect(socket.state, ConnectionState.disconnected);
    });

    test('state is disconnected after cancel during connect (resource cleanup)',
        () async {
      server.hangOnGreeting = true;
      await server.start();

      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 5),
      );

      final connectFuture = socket.connect().catchError((_) {});

      await Future.delayed(const Duration(milliseconds: 50));
      await socket.cancel();
      await connectFuture;

      expect(socket.state, ConnectionState.disconnected);
      await socket.cancel(); // Double cancel is safe.
      expect(socket.state, ConnectionState.disconnected);
    });
  });

  group('Protocol validation', () {
    Future<SOCKSSocket> open(TunnelProxy proxy, {String? token}) async {
      await proxy.start();
      addTearDown(proxy.close);
      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: proxy.port,
        isolationToken: token,
        handshakeTimeout: const Duration(seconds: 5),
      );
      addTearDown(() => socket.close().catchError((_) {}));
      return socket;
    }

    final handshakeFailure = throwsA(isA<SocksHandshakeException>());

    for (final (name, reply) in [
      ('wrong version', [4, 0]),
      ('trailing data', [5, 0, 0]),
    ]) {
      test('rejects greeting reply with $name', () async {
        final socket = await open(TunnelProxy(greetingReply: reply));
        await expectLater(socket.connect(), handshakeFailure);
        expect(socket.state, ConnectionState.error);
      });
    }

    test('rejects authentication reply with wrong version', () async {
      final socket =
          await open(TunnelProxy(authReply: [5, 0]), token: 'circuit');
      await expectLater(socket.connect(), handshakeFailure);
    });

    for (final (name, reply) in [
      ('wrong version', [4, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
      ('nonzero reserved byte', [5, 0, 1, 1, 0, 0, 0, 0, 0, 0]),
      ('unknown address type', [5, 0, 0, 2, 0, 0, 0, 0, 0, 0]),
      ('empty domain', [5, 0, 0, 3, 0, 0, 0]),
    ]) {
      test('rejects connect reply with $name promptly', () async {
        final socket = await open(TunnelProxy(connectReply: reply));
        await socket.connect();
        final stopwatch = Stopwatch()..start();
        await expectLater(
            socket.connectTo('example.com', 443), handshakeFailure);
        expect(stopwatch.elapsed, lessThan(const Duration(seconds: 2)));
        expect(socket.state, ConnectionState.error);
      });
    }

    test('rejected CONNECT ends inputStream for early and late listeners',
        () async {
      final socket = await open(TunnelProxy(replyCode: 5));
      final early = socket.inputStream.toList();
      await socket.connect();
      await expectLater(socket.connectTo('example.com', 443),
          throwsA(isA<SocksRequestException>()));
      await early.timeout(const Duration(seconds: 2));
      await socket.inputStream.toList().timeout(const Duration(seconds: 2));
      expect(socket.state, ConnectionState.error);
    });

    test('reports a short failure reply without waiting for the address',
        () async {
      final socket = await open(TunnelProxy(connectReply: [5, 4, 0, 1]));
      await socket.connect();
      await expectLater(
        socket.connectTo('example.com', 443),
        throwsA(isA<SocksRequestException>().having(
            (e) => e.replyCode, 'replyCode', SocksReplyCode.hostUnreachable)),
      );
    });

    test('sends the hostname for the proxy to resolve', () async {
      final proxy = TunnelProxy();
      final socket = await open(proxy);
      await socket.connect();
      await socket.connectTo('unresolvable.invalid', 8333);
      expect(proxy.targetType, 3);
      expect(proxy.target, 'unresolvable.invalid');
      expect(proxy.targetPort, 8333);
    });

    test('rejects destinations that do not fit the request', () async {
      final proxy = TunnelProxy();
      final socket = await open(proxy);
      await socket.connect();
      for (final domain in ['', 'a' * 256, 'unicode.é', 'has space', 'a\nb']) {
        await expectLater(
            socket.connectTo(domain, 443), throwsA(isA<ArgumentError>()));
      }
      for (final port in [0, 65536, -1]) {
        await expectLater(socket.connectTo('example.com', port),
            throwsA(isA<ArgumentError>()));
      }
      expect(socket.state, ConnectionState.connecting);
      await socket.connectTo('a' * 255, 443);
      expect(proxy.target, 'a' * 255);
    });

    test('reconnect rejects an oversized isolation token', () async {
      final proxy = TunnelProxy();
      final socket = await open(proxy, token: 'circuit-1');
      await socket.connect();
      await socket.connectTo('example.com', 443);
      await expectLater(socket.reconnect(isolationToken: 'b' * 256),
          throwsA(isA<ArgumentError>()));
      expect(socket.state, ConnectionState.connected);
      expect(proxy.connections, 1);
    });
  });

  group('Transport cleanup', () {
    for (final size in [1024, 65536, 2 * 1024 * 1024]) {
      test('SSL close delivers all $size bytes after write', () async {
        final server =
            await RawServerSocket.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(server.close);
        final received = Completer<List<int>>()..future.ignore();
        server.listen((raw) async {
          addTearDown(raw.close);
          try {
            final channel = RawChannel(raw);
            final greeting = await channel.read(2);
            await channel.read(greeting[1]);
            await channel.write([5, 0]);
            final request = await channel.read(5);
            await channel.read(request[4] + 2);
            await channel.write([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            final secure = await RawSecureSocket.secureServer(
                raw, certificates.serverContext(),
                subscription: channel.detach());
            addTearDown(secure.close);
            received.complete(await RawChannel(secure)
                .socket()
                .fold<List<int>>([], (bytes, chunk) => bytes..addAll(chunk)));
          } catch (error, stack) {
            received.completeError(error, stack);
          }
        });

        final socket = await SOCKSSocket.create(
          proxyHost: InternetAddress.loopbackIPv4.address,
          proxyPort: server.port,
          sslEnabled: true,
          securityContext: certificates.clientContext(),
        );
        addTearDown(socket.close);
        await socket.connect();
        await socket.connectTo('localhost', 443);
        final payload = List<int>.generate(size, (i) => 32 + i % 95);
        await socket.write(ascii.decode(payload));
        await socket.close();
        expect(await received.future.timeout(const Duration(seconds: 10)),
            payload);
      });
    }

    Future<(TunnelProxy, SOCKSSocket)> open(
      TunnelProxy proxy, {
      bool ssl = false,
      Duration handshakeTimeout = const Duration(seconds: 5),
    }) async {
      await proxy.start();
      addTearDown(proxy.close);
      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: proxy.port,
        sslEnabled: ssl,
        handshakeTimeout: handshakeTimeout,
      );
      addTearDown(() => socket.close().catchError((_) {}));
      return (proxy, socket);
    }

    test('stalled SSL handshake times out and closes the connection', () async {
      final (proxy, socket) = await open(TunnelProxy(),
          ssl: true, handshakeTimeout: const Duration(milliseconds: 200));
      await socket.connect();
      final stopwatch = Stopwatch()..start();
      await expectLater(
          socket.connectTo('localhost', 443), throwsA(isA<TimeoutException>()));
      expect(stopwatch.elapsed, lessThan(const Duration(seconds: 2)));
      expect((await proxy.applicationData.future).first, 22);
      expect(socket.state, ConnectionState.error);
      await proxy.disconnected.future.timeout(const Duration(seconds: 2));
    });

    test('cancel during SSL handshake closes the connection', () async {
      final (proxy, socket) = await open(TunnelProxy(), ssl: true);
      await socket.connect();
      final connecting = expectLater(socket.connectTo('localhost', 443),
          throwsA(isA<SocksCancelledException>()));
      await proxy.applicationData.future;
      await socket.cancel();
      await connecting.timeout(const Duration(seconds: 2));
      expect(socket.state, ConnectionState.disconnected);
      await proxy.disconnected.future.timeout(const Duration(seconds: 2));
    });

    test('handshake failure closes the connection without close()', () async {
      final (proxy, socket) = await open(TunnelProxy(stallAt: 0),
          handshakeTimeout: const Duration(milliseconds: 100));
      await expectLater(socket.connect(), throwsA(isA<TimeoutException>()));
      await proxy.disconnected.future.timeout(const Duration(seconds: 2));
      await socket.close();
    });

    test('proxy closing during the handshake fails without waiting', () async {
      final server = MockSocksServer()..dropConnection = true;
      await server.start();
      addTearDown(server.stop);
      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: server.port,
        handshakeTimeout: const Duration(seconds: 10),
      );
      final stopwatch = Stopwatch()..start();
      await expectLater(
          socket.connect(), throwsA(isA<SocksConnectionException>()));
      expect(stopwatch.elapsed, lessThan(const Duration(seconds: 2)));
      await socket.close();
    });

    test('remote close ends the input stream', () async {
      final upstream = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(upstream.close);
      upstream.listen((peer) => peer.close());
      final (_, socket) = await open(TunnelProxy(upstreamPort: upstream.port));
      await socket.connect();
      await socket.connectTo('example.com', 80);
      await socket.inputStream
          .drain<void>()
          .timeout(const Duration(seconds: 2));
    });

    test('SSL verifies the server against the supplied context', () async {
      final server = MockSocksServer()
        ..sslEnabled = true
        ..securityContext = certificates.serverContext();
      await server.start();
      addTearDown(server.stop);
      Future<SOCKSSocket> connect(String host, SecurityContext? trust) async {
        final socket = await SOCKSSocket.create(
          proxyHost: InternetAddress.loopbackIPv4.address,
          proxyPort: server.port,
          sslEnabled: true,
          securityContext: trust,
          handshakeTimeout: const Duration(seconds: 5),
        );
        addTearDown(() => socket.close().catchError((_) {}));
        await socket.connect();
        await socket.connectTo(host, 443);
        return socket;
      }

      final trust = certificates.clientContext();
      final socket = await connect('localhost', trust);
      final echoed = socket.inputStream.expand((b) => b).take(8).toList();
      await socket.write('verified');
      expect(utf8.decode(await echoed), 'verified');
      await expectLater(
          connect('localhost', null), throwsA(isA<HandshakeException>()));
      await expectLater(
          connect('wrong.invalid', trust), throwsA(isA<HandshakeException>()));
    });
  });
}
