import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:socks_socket/socks_connection.dart';
import 'package:test/test.dart';
import 'helpers/tunnel_proxy.dart';

void main() {
  test('cancelling input preserves the write side', () async {
    final proxy = TunnelProxy(initialData: [42]);
    await proxy.start();
    addTearDown(proxy.close);
    final socket = await SocksConnection.start(
            proxyHost: InternetAddress.loopbackIPv4,
            proxyPort: proxy.port,
            targetHost: 'example.invalid',
            targetPort: 80)
        .socket;
    addTearDown(socket.destroy);
    expect(await socket.first, [42]);
    socket.add([99]);
    await socket.flush();
    expect(
        await proxy.applicationData.future.timeout(const Duration(seconds: 2)),
        [99]);
  });

  test('upload stream errors close transport and retain the original error',
      () async {
    final proxy = TunnelProxy();
    await proxy.start();
    addTearDown(proxy.close);
    final socket = await SocksConnection.start(
            proxyHost: InternetAddress.loopbackIPv4,
            proxyPort: proxy.port,
            targetHost: 'example.invalid',
            targetPort: 80)
        .socket;
    addTearDown(socket.destroy);
    final error = StateError('upload failed');
    final stack = StackTrace.current;
    await expectLater(socket.addStream(Stream<List<int>>.error(error, stack)),
        throwsA(same(error)));
    await proxy.disconnected.future.timeout(const Duration(seconds: 2));
  });

  test('required isolation never accepts a no-auth downgrade', () async {
    final proxy = TunnelProxy(overrideMethod: 0);
    await proxy.start();
    addTearDown(proxy.close);
    final task = SocksConnection.start(
        proxyHost: InternetAddress.loopbackIPv4,
        proxyPort: proxy.port,
        targetHost: 'example.invalid',
        targetPort: 443,
        credentials: SocksCredentials.isolation('token'));
    await expectLater(
        task.socket,
        throwsA(isA<SocksConnectException>()
            .having((e) => e.code, 'code', SocksConnectError.protocol)));
    expect(proxy.target, isNull);
    await proxy.disconnected.future.timeout(const Duration(seconds: 2));
  });
  test('invalid reply address type fails and closes transport', () async {
    final proxy = TunnelProxy(boundAddressType: 2);
    await proxy.start();
    addTearDown(proxy.close);
    await expectLater(
        SocksConnection.start(
                proxyHost: InternetAddress.loopbackIPv4,
                proxyPort: proxy.port,
                targetHost: 'example.invalid',
                targetPort: 443)
            .socket,
        throwsA(isA<SocksConnectException>()));
    await proxy.disconnected.future.timeout(const Duration(seconds: 2));
  });
  test('large bidirectional HTTP transfer handles socket backpressure',
      () async {
    final payload = List<int>.generate(2 * 1024 * 1024, (i) => i % 251);
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    server.listen((request) async {
      final received =
          await request.fold<List<int>>([], (b, c) => b..addAll(c));
      expect(received, payload);
      request.response.contentLength = received.length;
      request.response.add(received);
      await request.response.close();
    });
    final proxy = TunnelProxy(upstreamPort: server.port);
    await proxy.start();
    addTearDown(proxy.close);
    final client = HttpClient();
    addTearDown(() => client.close(force: true));
    client.connectionFactory = (uri, _, __) async => SocksConnection.start(
        proxyHost: InternetAddress.loopbackIPv4,
        proxyPort: proxy.port,
        targetHost: uri.host,
        targetPort: uri.port);
    final request = await client.postUrl(Uri.parse('http://example.invalid/'));
    request.contentLength = payload.length;
    await request.addStream(Stream.fromIterable([
      for (var i = 0; i < payload.length; i += 16384)
        payload.sublist(i, i + 16384)
    ]));
    final response = await request.close();
    expect(await response.fold<List<int>>([], (b, c) => b..addAll(c)), payload);
  });
  test('invalid inputs are rejected before connecting', () {
    for (final target in [
      '',
      'unicode.é',
      'has space',
      'https://example.org',
      'a' * 256
    ]) {
      expect(
          () => SocksConnection.start(
              proxyHost: InternetAddress.loopbackIPv4,
              proxyPort: 9050,
              targetHost: target,
              targetPort: 443),
          throwsArgumentError);
    }
    expect(() => SocksCredentials('', 'p'), throwsArgumentError);
    expect(() => SocksCredentials.isolation(utf8.decode(List.filled(256, 97))),
        throwsArgumentError);
  });
  test('destroy during an active write does not throw and releases the writer',
      () async {
    final proxy = TunnelProxy();
    await proxy.start();
    addTearDown(proxy.close);
    final socket = await SocksConnection.start(
            proxyHost: InternetAddress.loopbackIPv4,
            proxyPort: proxy.port,
            targetHost: 'example.invalid',
            targetPort: 80)
        .socket;
    final source = StreamController<List<int>>();
    addTearDown(source.close);
    final writing = socket.addStream(source.stream);
    source.add([1, 2, 3]);
    await proxy.applicationData.future;
    socket.destroy();
    await expectLater(writing, throwsA(isA<SocketException>()));
    expect(source.hasListener, isFalse);
    await proxy.disconnected.future.timeout(const Duration(seconds: 2));
  });
  test('HttpClient force close during an upload does not throw', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    final requestSeen = Completer<void>();
    server.listen((request) {
      if (!requestSeen.isCompleted) requestSeen.complete();
      request.listen((_) {}, onError: (Object _) {});
    });
    final proxy = TunnelProxy(upstreamPort: server.port);
    await proxy.start();
    addTearDown(proxy.close);
    final client = HttpClient()
      ..connectionFactory = (uri, _, __) async => SocksConnection.start(
          proxyHost: InternetAddress.loopbackIPv4,
          proxyPort: proxy.port,
          targetHost: uri.host,
          targetPort: uri.port);
    final request = await client.postUrl(Uri.parse('http://example.invalid/'));
    request.contentLength = 1 << 20;
    final body = StreamController<List<int>>();
    addTearDown(body.close);
    final upload = request.addStream(body.stream);
    upload.ignore();
    body.add(List<int>.filled(1024, 1));
    await requestSeen.future.timeout(const Duration(seconds: 2));
    client.close(force: true);
    await proxy.disconnected.future.timeout(const Duration(seconds: 2));
  });
  test('cancelling an unobserved task reports no unhandled error', () async {
    final proxy = TunnelProxy(stallAt: 0);
    await proxy.start();
    addTearDown(proxy.close);
    final task = SocksConnection.start(
        proxyHost: InternetAddress.loopbackIPv4,
        proxyPort: proxy.port,
        targetHost: 'example.invalid',
        targetPort: 80);
    await proxy.greetingSeen.future;
    task.cancel();
    await proxy.disconnected.future.timeout(const Duration(seconds: 2));
    await expectLater(task.socket, throwsA(isA<SocksConnectException>()));
  });
  test('peer half-close keeps the write side open', () async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(server.close);
    final received = Completer<List<int>>();
    server.listen((peer) {
      peer.listen((bytes) {
        if (!received.isCompleted) received.complete(bytes);
      });
      peer.add([1, 2, 3]);
      peer.close();
    });
    final proxy = TunnelProxy(upstreamPort: server.port);
    await proxy.start();
    addTearDown(proxy.close);
    final socket = await SocksConnection.start(
            proxyHost: InternetAddress.loopbackIPv4,
            proxyPort: proxy.port,
            targetHost: 'example.invalid',
            targetPort: 80)
        .socket;
    addTearDown(socket.destroy);
    expect(await socket.expand((b) => b).toList(), [1, 2, 3]);
    socket.add([4]);
    await socket.close();
    expect(await received.future.timeout(const Duration(seconds: 2)), [4]);
  });
}
