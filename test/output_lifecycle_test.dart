import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:socks_socket/socks_socket.dart';
import 'package:socks_socket/src/connection_socket.dart';
import 'package:test/test.dart';

import 'helpers/mock_socks_server.dart';
import 'helpers/test_certificates.dart';
import 'helpers/tunnel_proxy.dart';

void main() {
  for (final tls in [false, true]) {
    group('ordered output (TLS=$tls)', () {
      late SOCKSSocket socket;
      late MockSocksServer proxy;
      setUp(() async {
        final certificates = TestCertificates.generate();
        proxy = MockSocksServer()
          ..sslEnabled = tls
          ..securityContext = certificates.serverContext();
        await proxy.start();
        addTearDown(proxy.stop);
        socket = await SOCKSSocket.create(
          proxyHost: InternetAddress.loopbackIPv4.address,
          proxyPort: proxy.port,
          sslEnabled: tls,
          securityContext: certificates.clientContext(),
        );
        addTearDown(() => socket.close().catchError((_) {}));
        await socket.connect();
        await socket.connectTo('localhost', 443);
      });

      test('overlapping writes and outputStream preserve byte order', () async {
        final reply = socket.inputStream.expand((b) => b).take(4).toList();
        final first = socket.write('A');
        final second = socket.write('B');
        socket.outputStream.add([67]);
        final last = socket.write('D');
        await Future.wait([first, second, last]);
        await socket.outputStream.close();
        expect(utf8.decode(await reply), 'ABCD');
      });

      test('close waits for accepted writes and rejects new writes', () async {
        proxy.echoApplicationData = false;
        final received = <int>[];
        final delivered = Completer<void>();
        proxy.onApplicationData = (bytes) {
          received.addAll(bytes);
          if (received.length == 65538) delivered.complete();
        };
        final first = socket.write('A' * 65536);
        final second = socket.write('B');
        socket.outputStream.add([67]);
        final closing = socket.close();
        await expectLater(socket.write('D'), throwsStateError);
        await Future.wait([first, second, closing, socket.close()]);
        await delivered.future.timeout(const Duration(seconds: 2),
            onTimeout: () {
          fail('Peer received ${received.length} of 65538 bytes');
        });
        expect(utf8.decode(received), '${'A' * 65536}BC');
        expect(socket.state, ConnectionState.disconnected);
      });

      test('close drains an accepted output source stream', () async {
        proxy.echoApplicationData = false;
        final received = <int>[];
        final delivered = Completer<void>();
        proxy.onApplicationData = (bytes) {
          received.addAll(bytes);
          if (received.length == 2) delivered.complete();
        };
        final source = StreamController<List<int>>();
        final uploading = socket.outputStream.addStream(source.stream);
        source.add([65]);
        final closing = socket.close();
        source.add([66]);
        await source.close();
        await Future.wait([uploading, closing]);
        await delivered.future.timeout(const Duration(seconds: 2),
            onTimeout: () => fail('Peer received $received'));
        expect(received, [65, 66]);
      });

      test('output source errors are observable through done', () async {
        final error = StateError('upload failed');
        final done =
            expectLater(socket.outputStream.done, throwsA(same(error)));
        socket.outputStream.addError(error);
        await done;
        expect(socket.state, ConnectionState.error);
      });
    });
  }

  test('output before connect is rejected without touching the socket',
      () async {
    final proxy = MockSocksServer();
    await proxy.start();
    addTearDown(proxy.stop);
    final socket = await SOCKSSocket.create(
      proxyHost: InternetAddress.loopbackIPv4.address,
      proxyPort: proxy.port,
    );
    addTearDown(() => socket.close().catchError((_) {}));
    expect(() => socket.outputStream.add([65]), throwsStateError);
    await expectLater(
        socket.outputStream.addStream(Stream.value([65])), throwsStateError);
    expect(socket.state, ConnectionState.disconnected);
    await socket.connect();
    await socket.connectTo('localhost', 443);
    final reply = socket.inputStream.expand((b) => b).take(2).toList();
    socket.outputStream.add([66]);
    await socket.write('C');
    expect(utf8.decode(await reply), 'BC');
    await socket.outputStream.close();
  });

  test('output during the handshake does not abort it', () async {
    final proxy = MockSocksServer()
      ..responseDelay = const Duration(milliseconds: 100);
    await proxy.start();
    addTearDown(proxy.stop);
    final socket = await SOCKSSocket.create(
      proxyHost: InternetAddress.loopbackIPv4.address,
      proxyPort: proxy.port,
    );
    addTearDown(() => socket.close().catchError((_) {}));
    final connecting = socket.connect();
    expect(() => socket.outputStream.add([65]), throwsStateError);
    await connecting;
    await socket.connectTo('localhost', 443);
    expect(socket.state, ConnectionState.connected);
  });

  for (final tls in [false, true]) {
    test('a transport error fails the output sink (TLS=$tls)', () async {
      final certificates = TestCertificates.generate();
      final accepted = Completer<void>();
      late int port;
      void serve(Socket peer) {
        addTearDown(peer.destroy);
        peer.listen((_) {}, onError: (_) {});
        accepted.complete();
      }

      if (tls) {
        final server = await SecureServerSocket.bind(
            InternetAddress.loopbackIPv4, 0, certificates.serverContext());
        server.listen(serve, onError: (_) {});
        port = server.port;
        addTearDown(server.close);
      } else {
        final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
        server.listen(serve);
        port = server.port;
        addTearDown(server.close);
      }
      final proxy = TunnelProxy(upstreamPort: port);
      await proxy.start();
      addTearDown(proxy.close);
      final socket = await SOCKSSocket.create(
        proxyHost: InternetAddress.loopbackIPv4.address,
        proxyPort: proxy.port,
        sslEnabled: tls,
        securityContext: certificates.clientContext(),
      );
      addTearDown(() => socket.close().catchError((_) {}));
      await socket.connect();
      await socket.connectTo('localhost', 443);
      await accepted.future;
      final input = Completer<void>();
      socket.inputStream
          .listen((_) {}, onError: (_) {}, onDone: input.complete);
      final done = expectLater(
          socket.outputStream.done, throwsA(isA<SocksConnectionException>()));
      // Linux SO_LINGER {on=1, seconds=0} requests a TCP reset on close.
      proxy.sockets.first.setRawOption(RawSocketOption(
          1, 13, Uint8List.view(Int32List.fromList([1, 0]).buffer)));
      proxy.sockets.first.destroy();
      await Future.wait([input.future, done]);
      expect(socket.state, ConnectionState.error);
      await expectLater(socket.outputStream.close(),
          throwsA(isA<SocksConnectionException>()));
    }, testOn: 'linux');
  }

  test('an output sink first used after a transport error reports it',
      () async {
    final proxy = TunnelProxy();
    await proxy.start();
    addTearDown(proxy.close);
    final socket = await SOCKSSocket.create(
      proxyHost: InternetAddress.loopbackIPv4.address,
      proxyPort: proxy.port,
    );
    addTearDown(() => socket.close().catchError((_) {}));
    await socket.connect();
    await socket.connectTo('localhost', 443);
    final input = Completer<void>();
    socket.inputStream.listen((_) {}, onError: (_) {}, onDone: input.complete);
    // Linux SO_LINGER {on=1, seconds=0} requests a TCP reset on close.
    proxy.sockets.first.setRawOption(RawSocketOption(
        1, 13, Uint8List.view(Int32List.fromList([1, 0]).buffer)));
    proxy.sockets.first.destroy();
    await input.future;
    expect(socket.state, ConnectionState.error);
    await expectLater(
        socket.outputStream.close(), throwsA(isA<SocksConnectionException>()));
  }, testOn: 'linux');

  test('a write to a dropped TLS connection throws SocksConnectionException',
      () async {
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
    addTearDown(() => socket.close().catchError((_) {}));
    await socket.connect();
    await socket.connectTo('localhost', 443);
    proxy.disconnectAllClients();
    final deadline = DateTime.now().add(const Duration(seconds: 5));
    while (true) {
      try {
        await socket.write('A');
      } catch (error) {
        expect(error, isA<SocksConnectionException>());
        break;
      }
      if (DateTime.now().isAfter(deadline)) fail('write kept succeeding');
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    expect(socket.state, ConnectionState.error);
    await expectLater(socket.write('B'), throwsStateError);
  });

  test('a write failing after reconnect does not affect the new connection',
      () async {
    final certificates = TestCertificates.generate();
    final server = await RawServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(server.close);
    var connections = 0;
    server.listen((raw) async {
      final first = connections++ == 0;
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
        final peer = RawChannel(secure).socket();
        if (!first) peer.listen(peer.add, onError: (_) {});
      } catch (_) {}
    });
    final socket = await SOCKSSocket.create(
      proxyHost: InternetAddress.loopbackIPv4.address,
      proxyPort: server.port,
      sslEnabled: true,
      securityContext: certificates.clientContext(),
      operationTimeout: const Duration(seconds: 1),
    );
    addTearDown(() => socket.close().catchError((_) {}));
    await socket.connect();
    await socket.connectTo('localhost', 443);
    final stuck = expectLater(
        socket.write('X' * (8 * 1024 * 1024)), throwsA(isA<Exception>()));
    await Future<void>.delayed(const Duration(milliseconds: 50));
    socket.outputStream.addError(StateError('abort'));
    await socket.reconnect();
    await stuck;
    expect(socket.state, ConnectionState.connected);
    final reply = socket.inputStream.first;
    await socket.write('A');
    expect(await reply.timeout(const Duration(seconds: 2)), [65]);
  });

  test('a flush timeout aborts the connection and pending writes', () async {
    final server = await RawServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(server.close);
    server.listen((peer) {
      addTearDown(peer.close);
      peer.writeEventsEnabled = false;
      var phase = 0;
      final buffer = <int>[];
      peer.listen((event) {
        if (event != RawSocketEvent.read) return;
        final bytes = peer.read();
        if (bytes == null) return;
        buffer.addAll(bytes);
        if (phase == 0 && buffer.length >= 3) {
          buffer.clear();
          peer.write([5, 0]);
          phase = 1;
        } else if (phase == 1 && buffer.length >= 5 + buffer[4] + 2) {
          peer.write([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
          peer.readEventsEnabled = false;
          phase = 2;
        }
      }, onError: (_) {});
    });
    final socket = await SOCKSSocket.create(
      proxyHost: InternetAddress.loopbackIPv4.address,
      proxyPort: server.port,
      operationTimeout: const Duration(milliseconds: 100),
    );
    addTearDown(socket.close);
    await socket.connect();
    await socket.connectTo('localhost', 443);
    final inputDone = socket.inputStream.drain<void>();
    final blocked = expectLater(socket.write('X' * (32 * 1024 * 1024)),
        throwsA(isA<TimeoutException>()));
    final queued =
        expectLater(socket.write('Y'), throwsA(isA<TimeoutException>()));
    await Future.wait([blocked, queued]);
    await inputDone;
    expect(socket.state, ConnectionState.error);
    await expectLater(socket.write('Z'), throwsStateError);
  });
}
