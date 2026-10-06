import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/tunnel_proxy.dart';

void main() {
  late TunnelProxy proxy;
  late SOCKSSocket socket;
  setUp(() async {
    proxy = TunnelProxy();
    await proxy.start();
    addTearDown(proxy.close);
    socket = await SOCKSSocket.create(
      proxyHost: InternetAddress.loopbackIPv4.address,
      proxyPort: proxy.port,
    );
    addTearDown(() => socket.close().catchError((_) {}));
  });

  test('rejects overlapping greetings without disturbing the first', () async {
    final greeting = socket.connect();
    final second = expectLater(socket.connect(), throwsStateError);
    final early =
        expectLater(socket.connectTo('localhost', 80), throwsStateError);
    await Future.wait([second, early, greeting]);
    await socket.connectTo('localhost', 80);
    expect(socket.state, ConnectionState.connected);
  });

  test('rejects repeated negotiation before sending application bytes',
      () async {
    await socket.connect();
    final connecting = socket.connectTo('localhost', 80);
    await expectLater(socket.connectTo('other.test', 80), throwsStateError);
    await connecting;
    await expectLater(socket.connect(), throwsStateError);
    await socket.write('application');
    expect(await proxy.applicationData.future, 'application'.codeUnits);
  });

  test('rejects negotiation while reconnect() is in progress', () async {
    await socket.connect();
    await socket.connectTo('localhost', 80);
    final reconnecting = socket.reconnect();
    final attempts = <Future<void>>[];
    var reconnected = false;
    void interrupt() {
      if (reconnected) return;
      attempts
        ..add(expectLater(socket.connect(), throwsStateError))
        ..add(expectLater(socket.connectTo('localhost', 80), throwsStateError));
      Timer.run(interrupt);
    }

    interrupt();
    await reconnecting;
    reconnected = true;
    await Future.wait(attempts);
    expect(socket.state, ConnectionState.connected);
  });

  test('cancellation between phases has the cancellation exception', () async {
    await socket.connect();
    await socket.cancel();
    await expectLater(socket.connectTo('localhost', 80),
        throwsA(isA<SocksCancelledException>()));
    expect(socket.state, ConnectionState.disconnected);
  });

  test('peer EOF updates state before completing input', () async {
    await socket.connect();
    await socket.connectTo('localhost', 80);
    final done = socket.inputStream.drain<void>();
    proxy.sockets.first.destroy();
    await done;
    expect(socket.state, ConnectionState.disconnected);
    await expectLater(socket.write('late'), throwsStateError);
  });

  test('peer EOF still delivers accepted writes', () async {
    const size = 1024 * 1024;
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(server.close);
    final received = Completer<int>();
    server.listen((peer) {
      addTearDown(peer.destroy);
      // Linux SO_RCVBUF: keep the upload queued in the sender.
      peer.setRawOption(RawSocketOption.fromInt(1, 8, 65536));
      final buffer = <int>[];
      var tunnel = false;
      var count = 0;
      late StreamSubscription<List<int>> input;
      input = peer.listen((bytes) async {
        if (tunnel) {
          count += bytes.length;
          return;
        }
        buffer.addAll(bytes);
        if (buffer.length == 3) {
          peer.add([5, 0]);
        } else if (buffer.length > 8 && buffer.length == 10 + buffer[7]) {
          tunnel = true;
          input.pause();
          peer.add([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
          await peer.close();
          await Future<void>.delayed(const Duration(milliseconds: 200));
          input.resume();
        }
      }, onDone: () => received.complete(count));
    });
    final uploader = await SOCKSSocket.create(
      proxyHost: InternetAddress.loopbackIPv4.address,
      proxyPort: server.port,
    );
    addTearDown(() => uploader.close().catchError((_) {}));
    await uploader.connect();
    await uploader.connectTo('localhost', 80);
    // Linux SO_SNDBUF.
    uploader.socket.setRawOption(RawSocketOption.fromInt(1, 7, 65536));
    final input = uploader.inputStream.drain<void>();
    await uploader.write('A' * size);
    await input;
    expect(await received.future.timeout(const Duration(seconds: 5)), size);
    expect(uploader.state, ConnectionState.disconnected);
  }, testOn: 'linux');

  test('peer reset marks the connection failed', () async {
    await socket.connect();
    await socket.connectTo('localhost', 80);
    final errors = <Object>[];
    final done = Completer<void>();
    socket.inputStream
        .listen((_) {}, onError: errors.add, onDone: done.complete);
    // Linux SO_LINGER {on=1, seconds=0} requests a TCP reset on close.
    proxy.sockets.first.setRawOption(RawSocketOption(
        1, 13, Uint8List.view(Int32List.fromList([1, 0]).buffer)));
    proxy.sockets.first.destroy();
    await done.future;
    expect(errors, contains(isA<SocksConnectionException>()));
    expect(socket.state, ConnectionState.error);
  }, testOn: 'linux');

  test('TCP reconnect failure closes the replacement streams', () async {
    await socket.connect();
    await socket.connectTo('localhost', 80);
    await proxy.server.close();
    await expectLater(socket.reconnect(), throwsA(isA<SocketException>()));
    await socket.inputStream.drain<void>().timeout(const Duration(seconds: 1));
    expect(socket.state, ConnectionState.error);
  });
}
