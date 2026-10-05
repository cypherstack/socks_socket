import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:socks_socket/socks_connection.dart';
import 'package:test/test.dart';
import 'helpers/test_certificates.dart';
import 'helpers/tunnel_proxy.dart';

ConnectionTask<Socket> connect(TunnelProxy proxy,
        {String host = 'unresolvable.invalid',
        String? tlsHost,
        SecurityContext? context,
        SocksCredentials? credentials,
        List<String>? supportedProtocols,
        Duration timeout = const Duration(seconds: 3)}) =>
    SocksConnection.start(
        proxyHost: InternetAddress.loopbackIPv4,
        proxyPort: proxy.port,
        targetHost: host,
        targetPort: 443,
        tlsHost: tlsHost,
        securityContext: context,
        credentials: credentials,
        supportedProtocols: supportedProtocols,
        timeout: timeout);

void main() {
  final certificates = TestCertificates.generate();
  for (final host in ['unresolvable.invalid', '8.8.8.8', '2001:db8::1']) {
    for (final bound in [1, 3, 4]) {
      test('preserves buffered data for $host, bound type $bound', () async {
        final proxy = TunnelProxy(
            boundAddressType: bound, initialData: ascii.encode('hello'));
        await proxy.start();
        addTearDown(proxy.close);
        final socket = await connect(proxy, host: host).socket;
        addTearDown(socket.destroy);
        expect(ascii.decode(await socket.expand((b) => b).take(5).toList()),
            'hello');
        expect(proxy.target, host);
        expect(
            proxy.targetType,
            host == '8.8.8.8'
                ? 1
                : host.contains(':')
                    ? 4
                    : 3);
      });
    }
  }
  test('fragmented greeting, CONNECT and authentication', () async {
    final proxy = TunnelProxy(fragmented: true, initialData: [42]);
    await proxy.start();
    addTearDown(proxy.close);
    final socket = await connect(proxy,
            credentials: SocksCredentials.isolation('private-token'))
        .socket;
    addTearDown(socket.destroy);
    expect(await socket.first, [42]);
    expect(proxy.username, 'private-token');
    expect(proxy.password, 'private-token');
  });
  for (final phase in [0, 1, 2]) {
    test('cancel closes peer during phase $phase', () async {
      final proxy = TunnelProxy(stallAt: phase);
      await proxy.start();
      addTearDown(proxy.close);
      final task = connect(proxy,
          credentials: phase == 2 ? SocksCredentials.isolation('token') : null);
      final failed = expectLater(
          task.socket,
          throwsA(isA<SocksConnectException>()
              .having((e) => e.code, 'code', SocksConnectError.cancelled)));
      await switch (phase) {
        0 => proxy.greetingSeen.future,
        1 => proxy.connected.future,
        _ => proxy.authenticationSeen.future,
      };
      task.cancel();
      task.cancel();
      await failed;
      await proxy.disconnected.future.timeout(const Duration(seconds: 2));
    });
  }
  test('immediate cancellation returns no socket', () async {
    final proxy = TunnelProxy();
    await proxy.start();
    addTearDown(proxy.close);
    final task = connect(proxy);
    final failed =
        expectLater(task.socket, throwsA(isA<SocksConnectException>()));
    task.cancel();
    await failed;
  });
  test('cancellation after delivery closes the owned connection', () async {
    final proxy = TunnelProxy();
    await proxy.start();
    addTearDown(proxy.close);
    final task = connect(proxy);
    final socket = await task.socket;
    addTearDown(socket.destroy);
    final closed = socket.drain<void>();
    task.cancel();
    task.cancel();
    await closed.timeout(const Duration(seconds: 2));
    await proxy.disconnected.future.timeout(const Duration(seconds: 2));
  });
  test('deadline closes stalled handshake', () async {
    final proxy = TunnelProxy(stallAt: 0);
    await proxy.start();
    addTearDown(proxy.close);
    await expectLater(
        connect(proxy, timeout: const Duration(milliseconds: 80)).socket,
        throwsA(isA<SocksConnectException>()
            .having((e) => e.code, 'code', SocksConnectError.timedOut)));
    await proxy.disconnected.future.timeout(const Duration(seconds: 2));
  });
  test('proxy rejection preserves reply code', () async {
    final proxy = TunnelProxy(replyCode: 5);
    await proxy.start();
    addTearDown(proxy.close);
    await expectLater(
        connect(proxy).socket,
        throwsA(isA<SocksConnectException>()
            .having((e) => e.replyCode, 'replyCode', 5)
            .having(
                (e) => e.reply, 'reply', SocksReplyCode.connectionRefused)));
    await proxy.disconnected.future.timeout(const Duration(seconds: 2));
  });
  test('no acceptable authentication method is reported as rejected', () async {
    final proxy = TunnelProxy(greetingReply: [5, 0xFF]);
    await proxy.start();
    addTearDown(proxy.close);
    await expectLater(
        connect(proxy, credentials: SocksCredentials.isolation('token')).socket,
        throwsA(isA<SocksConnectException>()
            .having((e) => e.code, 'code', SocksConnectError.rejected)
            .having((e) => e.replyCode, 'replyCode', isNull)));
    expect(proxy.target, isNull);
    await proxy.disconnected.future.timeout(const Duration(seconds: 2));
  });
  for (final cancel in [true, false]) {
    test('${cancel ? 'cancel' : 'deadline'} closes a stalled TLS handshake',
        () async {
      final proxy = TunnelProxy();
      await proxy.start();
      addTearDown(proxy.close);
      final task = connect(proxy,
          tlsHost: 'localhost', timeout: const Duration(milliseconds: 180));
      final failed =
          expectLater(task.socket, throwsA(isA<SocksConnectException>()));
      await proxy.connected.future;
      expect((await proxy.applicationData.future).first, 22);
      if (cancel) task.cancel();
      await failed;
      await proxy.disconnected.future.timeout(const Duration(seconds: 2));
    });
  }
  for (final tls in [false, true]) {
    test(
        'HttpClient consumes a ${tls ? 'TLS' : 'plain'} response through SOCKS',
        () async {
      final serverContext = certificates.serverContext();
      final server = tls
          ? await HttpServer.bindSecure(
              InternetAddress.loopbackIPv4, 0, serverContext)
          : await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      server.listen((request) {
        request.response.write('response through proxy');
        request.response.close();
      });
      final proxy = TunnelProxy(upstreamPort: server.port, fragmented: true);
      await proxy.start();
      addTearDown(proxy.close);
      final trust = certificates.clientContext();
      final client = HttpClient();
      addTearDown(() => client.close(force: true));
      client.connectionFactory = (uri, _, __) async =>
          connect(proxy, tlsHost: tls ? 'localhost' : null, context: trust);
      final request = await client.getUrl(
          Uri.parse('${tls ? 'https' : 'http'}://unresolvable.invalid/'));
      expect(await (await request.close()).transform(utf8.decoder).join(),
          'response through proxy');
      expect(proxy.target, 'unresolvable.invalid');
    });
  }
  for (final protocols in [null, 'custom/1']) {
    test('ClientHello ${protocols == null ? 'omits' : 'carries'} ALPN',
        () async {
      final upstream = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(upstream.close);
      final hello = Completer<List<int>>();
      upstream.listen((peer) {
        addTearDown(peer.destroy);
        final record = <int>[];
        peer.listen((bytes) {
          record.addAll(bytes);
          if (record.length >= 5 &&
              record.length >= 5 + (record[3] << 8 | record[4]) &&
              !hello.isCompleted) {
            hello.complete(record);
          }
        }, onError: (Object _) {});
      });
      final proxy = TunnelProxy(upstreamPort: upstream.port);
      await proxy.start();
      addTearDown(proxy.close);
      final task = connect(proxy,
          tlsHost: 'localhost',
          timeout: const Duration(seconds: 2),
          supportedProtocols: protocols == null ? null : [protocols]);
      final failed =
          expectLater(task.socket, throwsA(isA<SocksConnectException>()));
      final extensions = clientHelloExtensions(await hello.future);
      task.cancel();
      await failed;
      const alpn = 16;
      if (protocols == null) {
        expect(extensions.keys, isNot(contains(alpn)));
      } else {
        // protocol_name_list: 2-byte length, then 1-byte length-prefixed names.
        expect(extensions[alpn], [
          0,
          protocols.length + 1,
          protocols.length,
          ...ascii.encode(protocols)
        ]);
      }
    });
  }
  for (final wrongName in [false, true]) {
    test('rejects ${wrongName ? 'wrong TLS name' : 'untrusted certificate'}',
        () async {
      final context = certificates.serverContext();
      final server =
          await HttpServer.bindSecure(InternetAddress.loopbackIPv4, 0, context);
      server.listen((r) => r.response.close(), onError: (Object _) {});
      addTearDown(() => server.close(force: true));
      final proxy = TunnelProxy(upstreamPort: server.port);
      await proxy.start();
      addTearDown(proxy.close);
      final trust = wrongName
          ? certificates.clientContext()
          : SecurityContext(withTrustedRoots: false);
      await expectLater(
          connect(proxy,
                  tlsHost: wrongName ? 'wrong.invalid' : 'localhost',
                  context: trust)
              .socket,
          throwsA(isA<HandshakeException>()));
      await proxy.disconnected.future.timeout(const Duration(seconds: 2));
    });
  }
  test('renegotiate is unsupported on the TLS socket', () async {
    final server = await SecureServerSocket.bind(
        InternetAddress.loopbackIPv4, 0, certificates.serverContext());
    final accepted = <Socket>[];
    server.listen(accepted.add, onError: (Object _) {});
    addTearDown(() async {
      for (final socket in accepted) {
        socket.destroy();
      }
      await server.close();
    });
    final proxy = TunnelProxy(upstreamPort: server.port);
    await proxy.start();
    addTearDown(proxy.close);
    final socket = await connect(proxy,
            tlsHost: 'localhost', context: certificates.clientContext())
        .socket;
    addTearDown(socket.destroy);
    expect(socket, isA<SecureSocket>());
    expect(
        // ignore: deprecated_member_use
        () => (socket as SecureSocket).renegotiate(),
        throwsUnsupportedError);
  });
}

/// Extension bodies of a TLS ClientHello record, keyed by extension type.
Map<int, List<int>> clientHelloExtensions(List<int> record) {
  expect(record.take(1), [22], reason: 'handshake record');
  expect(record[5], 1, reason: 'ClientHello');
  var offset = 5 + 4 + 2 + 32;
  int u16(int at) => record[at] << 8 | record[at + 1];
  offset += 1 + record[offset]; // session_id
  offset += 2 + u16(offset); // cipher_suites
  offset += 1 + record[offset]; // compression_methods
  final end = offset + 2 + u16(offset);
  offset += 2;
  final extensions = <int, List<int>>{};
  while (offset < end) {
    final length = u16(offset + 2);
    extensions[u16(offset)] = record.sublist(offset + 4, offset + 4 + length);
    offset += 4 + length;
  }
  expect(offset, end, reason: 'extension lengths');
  return extensions;
}
