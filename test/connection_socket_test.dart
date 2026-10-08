import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:socks_socket/src/connection_socket.dart';
import 'package:test/test.dart';

class _PendingWriteSocket extends Stream<RawSocketEvent> implements RawSocket {
  final events = StreamController<RawSocketEvent>();
  final writeStarted = Completer<void>();
  bool pendingWrite = false;
  bool closedWithPendingWrite = false;
  bool closed = false;
  final shutdowns = <SocketDirection>[];

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
    shutdowns.add(direction);
    closedWithPendingWrite |= pendingWrite;
  }

  @override
  Future<RawSocket> close() async {
    closed = true;
    closedWithPendingWrite |= pendingWrite;
    events.close();
    return this;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FakeRawSocketConnectTask implements RawSocketConnectTask {
  final Completer<RawSocket> result;
  bool cancelled = false;

  _FakeRawSocketConnectTask(this.result);

  @override
  Future<RawSocket> get socket => result.future;

  @override
  void cancel() {
    cancelled = true;
    if (!result.isCompleted) {
      result.completeError(const SocketException('cancelled'));
    }
  }
}

/// A socket that fails its next read or write synchronously: dart:io delivers
/// the error through the event stream and closes the socket before the call
/// returns, so no event follows. A plain socket reports a read failure this
/// way, which is how macOS surfaces a reset peer, and a secure socket reports
/// a write after the connection closed this way.
class _ResetSocket extends Stream<RawSocketEvent> implements RawSocket {
  final events = StreamController<RawSocketEvent>(sync: true);
  var reads = 0;

  @override
  bool writeEventsEnabled = false;
  bool _readEventsEnabled = false;

  @override
  bool get readEventsEnabled => _readEventsEnabled;

  @override
  set readEventsEnabled(bool enabled) {
    _readEventsEnabled = enabled;
    if (enabled) {
      scheduleMicrotask(() {
        if (_readEventsEnabled && events.hasListener) {
          events.add(RawSocketEvent.read);
        }
      });
    }
  }

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
  Uint8List? read([int? len]) {
    // Nothing to read the first time; the reset arrives with the read event.
    if (reads++ == 0) return null;
    _reset('Read failed');
    return null;
  }

  @override
  int write(List<int> buffer, [int offset = 0, int? count]) {
    _reset('Write failed');
    return 0;
  }

  void _reset(String what) {
    events.addError(SocketException('$what: Connection reset by peer'));
    scheduleMicrotask(() {
      if (events.hasListener) events.add(RawSocketEvent.closed);
      events.close();
    });
  }

  @override
  Future<RawSocket> close() async => this;

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  for (final inputFirst in [true, false]) {
    test(
        'channel closes after both directions close (${inputFirst ? 'input' : 'output'} first)',
        () async {
      final raw = _PendingWriteSocket();
      final socket = RawChannel(raw).socket();
      final input = socket.listen((_) {});

      if (inputFirst) {
        await input.cancel();
        expect(raw.shutdowns, [SocketDirection.receive]);
        expect(raw.closed, isFalse);
        await socket.close();
      } else {
        await socket.close();
        expect(raw.shutdowns, [SocketDirection.send]);
        expect(raw.closed, isFalse);
        await input.cancel();
      }

      expect(raw.shutdowns,
          containsAll([SocketDirection.receive, SocketDirection.send]));
      expect(raw.closed, isTrue);
    });
  }

  for (final delayedStart in [false, true]) {
    test(
        'cancellable connect cancels ${delayedStart ? 'before' : 'after'} the task is created',
        () async {
      final start = Completer<void>();
      final socket = Completer<RawSocket>();
      socket.future.ignore();
      final task = _FakeRawSocketConnectTask(socket);
      final connector = CancellableRawSocketConnect((_, __) async {
        if (delayedStart) await start.future;
        return task;
      });
      final connecting = connector.connect(InternetAddress.loopbackIPv4.address,
          1080, const Duration(seconds: 2));
      final failed = expectLater(connecting, throwsA(isA<SocketException>()));
      if (!delayedStart) await Future<void>.value();
      connector.cancel();
      if (delayedStart) start.complete();
      await failed.timeout(const Duration(seconds: 1));
      expect(task.cancelled, isTrue);
    });
  }

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

  test('a read fails at once when the socket reports a reset synchronously',
      () async {
    final raw = _ResetSocket();
    final channel = RawChannel(raw);
    await expectLater(
        channel.read(2).timeout(const Duration(seconds: 2)),
        throwsA(isA<SocketException>()
            .having((e) => e.message, 'message', contains('reset'))));
    expect(raw.reads, 2);
    expect(channel.isClosed, isTrue);
  });

  test('a write fails at once when the socket reports a reset synchronously',
      () async {
    final raw = _ResetSocket();
    final channel = RawChannel(raw);
    await expectLater(
        channel.write([1, 2, 3]).timeout(const Duration(seconds: 2)),
        throwsA(isA<SocketException>()
            .having((e) => e.message, 'message', contains('reset'))));
    expect(channel.isClosed, isTrue);
  });
}
