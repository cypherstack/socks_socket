import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

class TunnelProxy {
  final int? upstreamPort;
  final bool fragmented;
  final int? stallAt;
  final List<int> initialData;
  final int replyCode;
  final int? overrideMethod;
  final applicationData = Completer<List<int>>();
  final int boundAddressType;
  final List<int>? greetingReply;
  final List<int>? authReply;
  final List<int>? connectReply;
  late ServerSocket server;
  final sockets = <Socket>[];
  final connected = Completer<void>();
  final replyFlushed = Completer<void>();
  final disconnected = Completer<void>();
  final greetingSeen = Completer<void>();
  final authenticationSeen = Completer<void>();
  String? target;
  int? targetPort;
  int? targetType;
  String? username;
  String? password;
  int connections = 0;
  TunnelProxy(
      {this.upstreamPort,
      this.fragmented = false,
      this.stallAt,
      this.initialData = const [],
      this.replyCode = 0,
      this.overrideMethod,
      this.boundAddressType = 1,
      this.greetingReply,
      this.authReply,
      this.connectReply});

  int get port => server.port;
  Future<void> start() async {
    server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((client) {
      connections++;
      sockets.add(client);
      _serve(client);
    });
  }

  Future<void> _serve(Socket client) async {
    final buffer = <int>[];
    Completer<void>? changed;
    Socket? upstream;
    var closed = false;
    var connectedPhase = false;
    client.listen(
        (bytes) {
          if (connectedPhase && !applicationData.isCompleted) {
            applicationData.complete(bytes);
          }
          if (upstream != null) {
            upstream.add(bytes);
          } else {
            buffer.addAll(bytes);
            changed?.complete();
            changed = null;
          }
        },
        onError: (Object _) {},
        onDone: () {
          closed = true;
          changed?.complete();
          changed = null;
          upstream?.destroy();
          if (!disconnected.isCompleted) disconnected.complete();
        });
    Future<List<int>> read(int size) async {
      while (buffer.length < size) {
        if (closed) throw StateError('closed');
        changed = Completer<void>();
        await changed!.future;
      }
      final value = buffer.sublist(0, size);
      buffer.removeRange(0, size);
      return value;
    }

    Future<void> send(List<int> bytes) async {
      if (fragmented) {
        for (final byte in bytes) {
          client.add([byte]);
          await client.flush();
          await Future<void>.delayed(const Duration(milliseconds: 1));
        }
      } else {
        client.add(bytes);
        await client.flush();
      }
    }

    try {
      final head = await read(2);
      final methods = await read(head[1]);
      if (!greetingSeen.isCompleted) greetingSeen.complete();
      if (stallAt == 0) return;
      final method = overrideMethod ?? (methods.contains(2) ? 2 : 0);
      await send(greetingReply ?? [5, method]);
      if (method == 2) {
        final auth = await read(2);
        username = utf8.decode(await read(auth[1]));
        password = utf8.decode(await read((await read(1)).single));
        if (!authenticationSeen.isCompleted) authenticationSeen.complete();
        if (stallAt == 2) return;
        await send(authReply ?? [1, 0]);
      }
      final connect = await read(4);
      targetType = connect[3];
      if (targetType == 3) {
        target = ascii.decode(await read((await read(1)).single));
      } else {
        target = InternetAddress.fromRawAddress(
                Uint8List.fromList(await read(targetType == 1 ? 4 : 16)))
            .address;
      }
      final portBytes = await read(2);
      targetPort = portBytes[0] * 256 + portBytes[1];
      if (!connected.isCompleted) connected.complete();
      if (stallAt == 1) return;
      if (upstreamPort != null) {
        upstream =
            await Socket.connect(InternetAddress.loopbackIPv4, upstreamPort!);
        sockets.add(upstream);
      }
      final bound = switch (boundAddressType) {
        1 => [127, 0, 0, 1],
        4 => List<int>.filled(16, 0),
        3 => [4, ...ascii.encode('test')],
        _ => <int>[],
      };
      connectedPhase = true;
      await send(connectReply ??
          [5, replyCode, 0, boundAddressType, ...bound, 0, 0, ...initialData]);
      if (!replyFlushed.isCompleted) replyFlushed.complete();
      upstream?.listen(client.add,
          onError: (Object _) {}, onDone: client.close);
      if (upstream != null && buffer.isNotEmpty) {
        upstream.add(buffer.toList());
        buffer.clear();
      }
    } catch (_) {
      client.destroy();
    }
  }

  Future<void> close() async {
    for (final socket in sockets) {
      socket.destroy();
    }
    await server.close();
  }
}
