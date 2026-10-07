import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:socks_socket/socks_socket.dart';
import 'package:socks_socket/src/connection_socket.dart';
import 'package:test/test.dart';

import 'test_certificates.dart';

const tunnelDeadline = Duration(seconds: 5);

class TunnelPeer {
  final Socket socket;
  final bytes = BytesBuilder(copy: false);
  final firstChunk = Completer<void>();
  final done = Completer<void>();
  late final StreamSubscription<List<int>> input;

  TunnelPeer(this.socket) {
    input = socket.listen((chunk) {
      bytes.add(chunk);
      if (!firstChunk.isCompleted) firstChunk.complete();
    }, onError: (Object error, StackTrace stack) {
      done.completeError(error, stack);
    }, onDone: () {
      if (!done.isCompleted) done.complete();
    });
    done.future.ignore();
  }
}

/// A point where [TunnelServer] waits until the test lets it go on.
class TunnelHold {
  final reached = Completer<void>();
  final release = Completer<void>();

  /// For [TunnelServer.holdTls]: how many bytes of the server's handshake
  /// reply reach the client before the hold.
  final int after;

  TunnelHold({this.after = 0});

  Future<void> _wait() {
    if (!reached.isCompleted) reached.complete();
    return release.future;
  }
}

/// A SOCKS5 server that accepts every CONNECT and hands back the tunnel end.
class TunnelServer {
  final RawServerSocket _server;
  final TestCertificates? certificates;
  final _peers = StreamController<TunnelPeer>();
  late final _accepted = StreamIterator(_peers.stream);
  late final StreamSubscription<RawSocket> _accepting;
  late final int port = _server.port;
  RawServerSocket? _blocked;
  final _fillers = <ConnectionTask<Socket>>[];
  int connections = 0;

  /// Delays the greeting reply, so a client stays in connect().
  TunnelHold? holdGreeting;

  /// Delays the CONNECT reply, so a client stays in connectTo().
  TunnelHold? holdConnect;

  /// Stalls the TLS handshake after [TunnelHold.after] bytes of the server's
  /// reply, so a client stays in connectTo() after the SOCKS reply.
  TunnelHold? holdTls;

  TunnelServer._(this._server, this.certificates) {
    _accepting = _server.listen(_serve);
  }

  bool get tls => certificates != null;

  static Future<TunnelServer> start({bool tls = false}) async {
    final raw = await RawServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final server =
        TunnelServer._(raw, tls ? TestCertificates.generate() : null);
    addTearDown(server.close);
    return server;
  }

  Future<void> _serve(RawSocket raw) async {
    connections++;
    addTearDown(raw.close);
    try {
      final channel = RawChannel(raw);
      final greeting = await channel.read(2);
      await channel.read(greeting[1]);
      await holdGreeting?._wait();
      await channel.write([5, 0]);
      final request = await channel.read(5);
      await channel.read(request[4] + 2);
      await holdConnect?._wait();
      await channel.write([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]);
      final Socket transport;
      final hold = holdTls;
      if (hold != null) {
        transport = await _stalledTls(channel, hold);
      } else if (tls) {
        final secured = await RawSecureSocket.secureServer(
          raw,
          certificates!.serverContext(),
          subscription: channel.detach(),
        );
        transport = RawChannel(secured).socket();
      } else {
        transport = channel.socket();
      }
      addTearDown(transport.destroy);
      _peers.add(TunnelPeer(transport));
    } catch (_) {
      // The client gave up on this connection; nextPeer() times out if a
      // test expected it.
      raw.close();
    }
  }

  /// Relays the TLS handshake through a local server and withholds its reply
  /// after [TunnelHold.after] bytes until the hold is released.
  Future<Socket> _stalledTls(RawChannel channel, TunnelHold hold) async {
    final backend = await SecureServerSocket.bind(
        InternetAddress.loopbackIPv4, 0, certificates!.serverContext());
    addTearDown(backend.close);
    final accepted = backend.first;
    accepted.ignore();
    final front = channel.socket();
    final upstream =
        await Socket.connect(InternetAddress.loopbackIPv4, backend.port);
    addTearDown(upstream.destroy);
    front.listen(upstream.add,
        onError: (Object _) => upstream.destroy(), onDone: upstream.destroy);
    var forwarded = 0;
    late final StreamSubscription<List<int>> reply;
    reply = upstream.listen((chunk) async {
      final held = hold.reached.isCompleted;
      final keep = held ? chunk.length : hold.after - forwarded;
      if (keep > 0) front.add(chunk.sublist(0, keep));
      forwarded += keep;
      if (held) return;
      reply.pause();
      await hold._wait();
      if (keep < chunk.length) front.add(chunk.sublist(keep));
      reply.resume();
    }, onError: (Object _) => front.destroy(), onDone: front.destroy);
    return accepted;
  }

  /// Replaces the listener with one that never accepts and fills its
  /// backlog, so a later TCP connect to [port] stays pending. Returns false
  /// when this host completes such connects anyway.
  Future<bool> stall() async {
    await _accepting.cancel();
    await _server.close();
    try {
      _blocked = await RawServerSocket.bind(InternetAddress.loopbackIPv4, port,
          backlog: 1);
    } on SocketException {
      return false;
    }
    for (var i = 0; i < 4; i++) {
      final task =
          await Socket.startConnect(InternetAddress.loopbackIPv4, port);
      _fillers.add(task);
      final connected = task.socket
          .then((_) => true, onError: (Object _) => false)
          .timeout(const Duration(milliseconds: 300), onTimeout: () => false);
      if (!await connected) return true;
    }
    return false;
  }

  /// The next tunnel the server completed.
  Future<TunnelPeer> nextPeer() async {
    if (!await _accepted.moveNext().timeout(tunnelDeadline)) {
      throw StateError('Tunnel server closed');
    }
    return _accepted.current;
  }

  Future<SOCKSSocket> createClient({
    Duration handshakeTimeout = const Duration(seconds: 30),
    Duration operationTimeout = tunnelDeadline,
  }) async {
    final client = await SOCKSSocket.create(
      proxyHost: InternetAddress.loopbackIPv4.address,
      proxyPort: port,
      sslEnabled: tls,
      securityContext: certificates?.clientContext(),
      handshakeTimeout: handshakeTimeout,
      operationTimeout: operationTimeout,
    );
    addTearDown(() => client.close().catchError((_) {}));
    return client;
  }

  /// A connected client and its tunnel end.
  Future<(SOCKSSocket, TunnelPeer)> connect({
    Duration handshakeTimeout = const Duration(seconds: 30),
    Duration operationTimeout = tunnelDeadline,
  }) async {
    final client = await createClient(
      handshakeTimeout: handshakeTimeout,
      operationTimeout: operationTimeout,
    );
    await client.connect();
    await client.connectTo('localhost', 443);
    return (client, await nextPeer());
  }

  Future<void> close() async {
    for (final hold in [holdGreeting, holdConnect, holdTls]) {
      if (hold != null && !hold.release.isCompleted) hold.release.complete();
    }
    for (final filler in _fillers) {
      filler.cancel();
      filler.socket.then((s) => s.destroy(), onError: (Object _) {});
    }
    await _server.close();
    await _blocked?.close();
    await _accepted.cancel();
    // Without a listener the controller's close() would never complete.
    _peers.close().ignore();
  }
}

Future<(SOCKSSocket, TunnelPeer)> connectTunnel({
  bool tls = false,
  Duration operationTimeout = tunnelDeadline,
}) async {
  final server = await TunnelServer.start(tls: tls);
  return server.connect(
    operationTimeout: operationTimeout,
  );
}
