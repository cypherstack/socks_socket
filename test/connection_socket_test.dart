import 'dart:async';
import 'dart:io';

import 'package:socks_socket/src/connection_socket.dart';
import 'package:test/test.dart';

class _PendingWriteSocket extends Stream<RawSocketEvent> implements RawSocket {
  final events = StreamController<RawSocketEvent>();
  final writeStarted = Completer<void>();
  bool pendingWrite = false;
  bool closedWithPendingWrite = false;

  @override
  bool readEventsEnabled = false;
  @override
  bool writeEventsEnabled = false;

  @override
  StreamSubscription<RawSocketEvent> listen(
    void Function(RawSocketEvent)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) =>
      events.stream.listen(onData,
          onError: onError, onDone: onDone, cancelOnError: cancelOnError);

  @override
  int write(List<int> buffer, [int offset = 0, int? count]) {
    pendingWrite = true;
    writeStarted.complete();
    return count ?? buffer.length - offset;
  }

  void completeWrite() {
    pendingWrite = false;
    if (writeEventsEnabled) events.add(RawSocketEvent.write);
  }

  @override
  void shutdown(SocketDirection direction) {
    closedWithPendingWrite |= pendingWrite;
  }

  @override
  Future<RawSocket> close() async {
    closedWithPendingWrite |= pendingWrite;
    events.close();
    return this;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  test('flush followed by close delivers the complete TCP payload', () async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(server.close);
    final received = Completer<List<int>>();
    server.listen((peer) {
      addTearDown(peer.destroy);
      received.complete(peer.expand((chunk) => chunk).toList());
    });
    final raw =
        await RawSocket.connect(InternetAddress.loopbackIPv4, server.port);
    final socket = RawChannel(raw).socket();
    addTearDown(socket.destroy);
    final payload = List<int>.generate(2 * 1024 * 1024, (i) => i % 251);
    socket.add(payload);
    await socket.flush();
    await socket.close();
    socket.destroy();
    expect(await received.future.timeout(const Duration(seconds: 10)), payload);
  });

  test('flush waits for an accepted write to complete before close', () async {
    final raw = _PendingWriteSocket();
    final socket = RawChannel(raw).socket();
    addTearDown(socket.destroy);
    socket.add([1, 2, 3]);
    var flushed = false;
    final flush = socket.flush().then((_) => flushed = true);
    await raw.writeStarted.future;
    await Future<void>.delayed(Duration.zero);
    expect(flushed, isFalse);
    raw.completeWrite();
    await flush.timeout(const Duration(seconds: 2));
    await socket.close();
    socket.destroy();
    expect(raw.closedWithPendingWrite, isFalse);
  });

  test('destroy releases a writer awaiting send completion', () async {
    final raw = _PendingWriteSocket();
    final socket = RawChannel(raw).socket();
    addTearDown(socket.destroy);
    socket.add([1, 2, 3]);
    final flushed =
        expectLater(socket.flush(), throwsA(isA<SocketException>()));
    await raw.writeStarted.future;
    socket.destroy();
    await flushed.timeout(const Duration(seconds: 2));
  });
}
