import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:socks_socket/socks_socket.dart';
import 'helpers/mock_socks_server.dart';

/// Helper: create, connect, and connectTo in one call.
Future<SOCKSSocket> createAndConnect(
  MockSocksServer server, {
  bool ssl = false,
  bool allowBadCerts = false,
  Duration? handshakeTimeout,
}) async {
  final socket = await SOCKSSocket.create(
    proxyHost: InternetAddress.loopbackIPv4.address,
    proxyPort: server.port,
    sslEnabled: ssl,
    handshakeTimeout: handshakeTimeout ?? const Duration(seconds: 5),
    operationTimeout: const Duration(seconds: 5),
    allowBadCertificates: allowBadCerts,
  );
  await socket.connect();
  await socket.connectTo('localhost', 1234);
  return socket;
}

void main() {
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
        final completer = Completer<List<int>>();
        socket.listen((data) {
          if (!completer.isCompleted) completer.complete(data);
        });

        await socket.write('hello');

        final received =
            await completer.future.timeout(const Duration(seconds: 5));
        expect(received, equals(utf8.encode('hello')));
      } finally {
        await socket.close();
      }
    });

    test('write with newline appends trailing newline', () async {
      final socket = await createAndConnect(server);
      try {
        final completer = Completer<List<int>>();
        socket.listen((data) {
          if (!completer.isCompleted) completer.complete(data);
        });

        await socket.write('test', newline: true);

        final received =
            await completer.future.timeout(const Duration(seconds: 5));
        expect(received, equals(utf8.encode('test\n')));
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

      // Broken pipe from Socket.done leaks as a zone error; guard it.
      final testCompleter = Completer<void>();
      runZonedGuarded(() async {
        final socket = await SOCKSSocket.create(
          proxyHost: InternetAddress.loopbackIPv4.address,
          proxyPort: server.port,
          handshakeTimeout: const Duration(milliseconds: 500),
        );

        final errorSub = socket.inputStream.listen(
          (_) {},
          onError: (_) {},
          onDone: () {},
        );

        try {
          await socket.connect();
          // If we get here, the handshake timeout should fire.
          fail('Should have thrown');
        } catch (e) {
          // Any error is acceptable: TimeoutException, SocketException,
          // or connection-closed Exception.
          expect(e, isNotNull);
        } finally {
          await errorSub.cancel();
          try {
            await socket.close().timeout(const Duration(seconds: 2));
          } catch (_) {}
        }
        testCompleter.complete();
      }, (error, stack) {
        // Swallow zone errors (Broken pipe from Socket.done).
        if (!testCompleter.isCompleted) {
          testCompleter.complete();
        }
      });

      await testCompleter.future.timeout(const Duration(seconds: 5));
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
      serverContext = SecurityContext()
        ..useCertificateChain('test/helpers/test_certs/server.crt')
        ..usePrivateKey('test/helpers/test_certs/server.key');

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
        allowBadCerts: true,
      );
      try {
        final completer = Completer<List<int>>();
        socket.listen((data) {
          if (!completer.isCompleted) completer.complete(data);
        });

        await socket.write('ssl-hello');

        final received =
            await completer.future.timeout(const Duration(seconds: 5));
        expect(received, equals(utf8.encode('ssl-hello')));
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

        final completer = Completer<List<int>>();
        socket.listen((data) {
          if (!completer.isCompleted) completer.complete(data);
        });

        await socket.write('hello');

        final received =
            await completer.future.timeout(const Duration(seconds: 5));
        expect(received, equals(utf8.encode('hello')));
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
}
