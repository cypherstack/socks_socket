import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'src/connection_socket.dart';
import 'src/reply_code.dart';
import 'src/socks_protocol.dart';

export 'socks_connection.dart';
export 'src/reply_code.dart';

/// Base exception for SOCKS5 errors. Sealed; catch subtypes or [Exception].
sealed class SocksException implements Exception {
  final String message;

  const SocksException(this.message);

  @override
  String toString() => message;
}

/// Thrown when the SOCKS5 greeting/authentication handshake fails.
class SocksHandshakeException extends SocksException {
  final String proxyHost;

  final int proxyPort;

  SocksHandshakeException({
    required this.proxyHost,
    required this.proxyPort,
    required String message,
  }) : super(message);
}

/// Thrown when a SOCKS5 connect request is rejected.
class SocksRequestException extends SocksException {
  final SocksReplyCode? replyCode;

  final String proxyHost;

  final int proxyPort;

  final String targetDomain;

  final int targetPort;

  SocksRequestException({
    required this.replyCode,
    required this.proxyHost,
    required this.proxyPort,
    required this.targetDomain,
    required this.targetPort,
    required String message,
  }) : super(message);
}

/// Thrown on transport-level connection errors.
class SocksConnectionException extends SocksException {
  SocksConnectionException({required String message}) : super(message);
}

/// Thrown when a connection is cancelled via [SOCKSSocket.cancel].
class SocksCancelledException extends SocksException {
  SocksCancelledException({required String message}) : super(message);
}

/// Connection state of a [SOCKSSocket].
enum SocksSocketState {
  disconnected,
  connecting,
  connected,
  error,
}

typedef ConnectionState = SocksSocketState;

/// Where a [SOCKSSocket] is in its life. [SOCKSSocket.state] is derived from it.
enum _Phase {
  /// A TCP connection to the proxy is open; [SOCKSSocket.connect] may run.
  idle,

  /// [SOCKSSocket.connect] is negotiating the greeting.
  greeting,

  /// The greeting succeeded; [SOCKSSocket.connectTo] may run.
  greeted,

  /// [SOCKSSocket.connectTo] is requesting the target, then negotiating TLS.
  requesting,
  connected,

  /// [SOCKSSocket.close] is draining accepted output.
  closing,

  /// [SOCKSSocket.cancel] ended a connect; [SOCKSSocket.reconnect] may run.
  cancelled,

  /// Closed or destroyed; [SOCKSSocket.reconnect] may run.
  closed,

  /// The handshake or the transport failed; [SOCKSSocket.reconnect] may run.
  failed,
}

/// A SOCKS5 socket.
///
/// Usage:
/// ```dart
/// final socks = await SOCKSSocket.create(
///   proxyHost: InternetAddress.loopbackIPv4.address,
///   proxyPort: tor.port,
///   // sslEnabled: true, // Negotiate TLS with the target after CONNECT.
/// );
/// await socks.connect();
/// await socks.connectTo('bitcoincash.stackwallet.com', 50001);
/// await socks.sendServerFeaturesCommand();
/// await socks.close();
/// ```
///
/// See also:
/// - SOCKS5 protocol(https://www.ietf.org/rfc/rfc1928.txt)
class SOCKSSocket {
  /// The host of the SOCKS5 proxy server.
  final String proxyHost;

  /// The port of the SOCKS5 proxy server.
  final int proxyPort;

  /// Whether [connectTo] negotiates TLS with the target.
  final bool sslEnabled;

  /// Timeout for the TCP connect, each handshake step, and the TLS upgrade.
  final Duration _handshakeTimeout;

  /// Timeout for flushing a write, and for draining output in [close].
  final Duration _operationTimeout;

  /// Accept bad certificates (testing only).
  final bool _allowBadCertificates;

  final SecurityContext? _securityContext;

  final bool? _requireIsolation;

  final bool _closeOnPeerEof;

  /// Tor circuit isolation token (RFC 1929 username/password auth).
  String? _isolationToken;

  /// Target of the last [connectTo], for [reconnect].
  String? _targetDomain;
  int? _targetPort;

  _Phase _phase = _Phase.idle;

  /// The connection to the proxy: a raw TCP channel until [connectTo] has
  /// negotiated TLS, then the TLS channel.
  RawChannel? _channel;

  /// [_channel] as a [Socket], once connected.
  Socket? _transport;

  /// Reads [_transport] into [_input]; paused while [_input] has no listener.
  StreamSubscription<List<int>>? _subscription;

  /// The proxy TCP connect in flight, so [close] and [destroy] can end it.
  ConnectionTask<RawSocket>? _connectTask;

  /// Ends the handshake in flight; see [_signalCancel].
  Completer<Never>? _cancel;

  late StreamController<List<int>> _input = _newInput();

  _SocketOutputSink? _outputSink;
  Future<void> _writeTail = Future<void>.value();
  Object? _writeFailure;
  StackTrace? _writeFailureStack;

  Future<void>? _closeFuture;

  /// Set by [close] and [destroy]; a [reconnect] in flight stops at its next
  /// step instead of opening a connection the caller has already given up.
  bool _closeRequested = false;
  bool _reconnecting = false;

  SOCKSSocket._(
      this.proxyHost,
      this.proxyPort,
      this.sslEnabled,
      this._isolationToken,
      this._handshakeTimeout,
      this._operationTimeout,
      this._allowBadCertificates,
      this._securityContext,
      this._requireIsolation,
      this._closeOnPeerEof);

  /// Creates a SOCKS5 socket to the specified [proxyHost] and [proxyPort].
  ///
  /// By default the connection closes once the peer closes its side. With
  /// [closeOnPeerEof] false, peer EOF only ends [inputStream]: the socket stays
  /// [SocksSocketState.connected] and keeps writing until [close].
  static Future<SOCKSSocket> create({
    required String proxyHost,
    required int proxyPort,
    bool sslEnabled = false,
    String? isolationToken,
    Duration handshakeTimeout = const Duration(seconds: 30),
    Duration operationTimeout = const Duration(seconds: 30),
    bool allowBadCertificates = false,
    SecurityContext? securityContext,
    bool? requireIsolation,
    bool closeOnPeerEof = true,
  }) async {
    _checkIsolationToken(isolationToken);
    if (requireIsolation == true && isolationToken == null) {
      throw ArgumentError(
        'requireIsolation needs an isolationToken.',
        'requireIsolation',
      );
    }
    final instance = SOCKSSocket._(
        proxyHost,
        proxyPort,
        sslEnabled,
        isolationToken,
        handshakeTimeout,
        operationTimeout,
        allowBadCertificates,
        securityContext,
        requireIsolation,
        closeOnPeerEof);
    await instance._init();
    return instance;
  }

  static void _checkIsolationToken(String? token) {
    if (token != null) encodeSocksCredentials(token, token);
  }

  /// Current connection state.
  ///
  /// Peer close or failure is noticed only while [inputStream] has a listener;
  /// until then a [write] to a dead peer may appear to succeed. With
  /// `closeOnPeerEof: false`, peer close leaves the state unchanged.
  SocksSocketState get state => switch (_phase) {
        _Phase.idle ||
        _Phase.closing ||
        _Phase.cancelled ||
        _Phase.closed =>
          SocksSocketState.disconnected,
        _Phase.greeting ||
        _Phase.greeted ||
        _Phase.requesting =>
          SocksSocketState.connecting,
        _Phase.connected => SocksSocketState.connected,
        _Phase.failed => SocksSocketState.error,
      };

  bool get _connecting =>
      _phase == _Phase.greeting ||
      _phase == _Phase.greeted ||
      _phase == _Phase.requesting;

  /// Whether [close], [cancel] or [destroy] has given the connection up.
  bool get _givenUp =>
      _phase == _Phase.closing ||
      _phase == _Phase.cancelled ||
      _phase == _Phase.closed;

  /// Data from the target, as List<int>.
  ///
  /// Reads pause while there is no listener; earlier data is kept.
  Stream<List<int>> get inputStream => _input.stream;

  /// The controller behind [inputStream].
  StreamController<List<int>> get responseController => _input;

  /// The subscription that feeds [inputStream], once connected.
  StreamSubscription<List<int>>? get subscription => _subscription;

  StreamSink<List<int>> get outputStream => _outputSink ??= _newOutputSink();

  StreamController<List<int>> _newInput() {
    late final StreamController<List<int>> input;
    input = StreamController<List<int>>.broadcast(
      onListen: () {
        if (identical(input, _input)) _subscription?.resume();
      },
      onCancel: () {
        if (identical(input, _input)) _subscription?.pause();
      },
    );
    return input;
  }

  _SocketOutputSink _newOutputSink() {
    late final _SocketOutputSink sink;
    sink = _SocketOutputSink(_queueSinkWrite, (error, stack) {
      if (identical(sink, _outputSink)) _fail(error, stack, _Phase.failed);
    });
    if (_writeFailure != null) {
      sink._stop(_writeFailure!, _writeFailureStack!);
    } else if (_phase == _Phase.closing || _phase == _Phase.closed) {
      sink.close().ignore();
    }
    return sink;
  }

  // ---------------------------------------------------------------------------
  // Connecting.

  /// Opens the TCP connection to the proxy.
  Future<void> _init() async {
    final task =
        _connectTask = await RawSocket.startConnect(proxyHost, proxyPort);
    // A close() or destroy() while the task was being created found nothing
    // to cancel yet.
    if (_closeRequested) task.cancel();
    final RawSocket raw;
    try {
      raw = await task.socket.timeout(_handshakeTimeout, onTimeout: () {
        task.cancel();
        throw SocketException(
            'Connection timed out, host: $proxyHost, port: $proxyPort');
      });
    } finally {
      _connectTask = null;
    }
    _channel = RawChannel(raw);
    _cancel = Completer<Never>()..future.ignore();
  }

  /// Negotiates the SOCKS5 greeting with the proxy.
  Future<void> connect() async {
    _checkNotReconnecting();
    return _connect();
  }

  Future<void> _connect() async {
    if (_phase != _Phase.idle) {
      throw StateError(
          'Cannot connect: use reconnect() for another connection');
    }
    _phase = _Phase.greeting;
    final channel = _channel!;
    try {
      await _handshake(() => negotiateSocks(
            write: channel.write,
            read: (count) => _readReply(channel, count),
            credentials: _isolationToken == null
                ? null
                : encodeSocksCredentials(_isolationToken!, _isolationToken!),
            allowNoAuthFallback:
                !(_requireIsolation ?? _isolationToken != null),
          ));
      _phase = _Phase.greeted;
    } catch (error) {
      throw _handshakeFailed(error, 'SOCKS5 handshake failed: ');
    }
  }

  /// Asks the proxy to connect to [domain]:[port], then negotiates TLS with
  /// the target if [sslEnabled].
  Future<void> connectTo(String domain, int port) async {
    _checkNotReconnecting();
    return _connectTo(domain, port);
  }

  void _checkNotReconnecting() {
    if (_reconnecting) throw StateError('Reconnect is already in progress');
  }

  Future<void> _connectTo(String domain, int port) async {
    if (_phase == _Phase.cancelled) {
      throw SocksCancelledException(message: 'SOCKS5 connection cancelled.');
    }
    if (_phase != _Phase.greeted) {
      throw StateError(
          'Cannot connectTo: must call connect() and await it before one connectTo()');
    }
    final request = encodeSocksDestination(domain, port);
    _phase = _Phase.requesting;
    _targetDomain = domain;
    _targetPort = port;
    final channel = _channel!;
    try {
      await _handshake(() async {
        await channel.write(request);
        checkSocksConnectReply(await _readConnectReply(channel));
      });
      if (sslEnabled) {
        final upgrade = RawSecureSocket.secure(
          channel.raw,
          subscription: channel.detach(),
          host: domain,
          context: _securityContext,
          onBadCertificate: _allowBadCertificates ? (_) => true : null,
        );
        try {
          _channel = RawChannel(await _handshake(() => upgrade));
        } catch (_) {
          // The upgrade may still succeed after a timeout or cancellation.
          upgrade.then<void>((s) => s.close(), onError: (_) {});
          rethrow;
        }
      }
    } catch (error) {
      throw _handshakeFailed(error, '', domain: domain, port: port);
    }
    final transport = _transport = _channel!.socket();
    _subscription = transport.listen(
      _input.add,
      onError: (Object e, StackTrace stack) {
        final error = e is SocksException
            ? e
            : SocksConnectionException(message: 'SOCKS5 connection error: $e');
        if (!_input.isClosed) _input.addError(error);
        if (_phase == _Phase.connected) _fail(error, stack, _Phase.failed);
      },
      onDone: () {
        if (_phase == _Phase.connected && _closeOnPeerEof) {
          _ensureClosed().ignore();
        }
        if (!_input.isClosed) _input.close();
      },
    );
    _phase = _Phase.connected;
    _cancel = null;
    if (!_input.hasListener) _subscription!.pause();
  }

  /// Runs one handshake [step] against the handshake deadline and the cancel
  /// signal. A cancellation that lands as the step completes still wins.
  Future<T> _handshake<T>(Future<T> Function() step) async {
    final cancel = _cancel!;
    final result = await Future.any<T>([step(), cancel.future]).timeout(
      _handshakeTimeout,
      onTimeout: () => throw TimeoutException('SOCKS5 handshake timed out '
          'after ${_handshakeTimeout.inSeconds} seconds.'),
    );
    if (cancel.isCompleted) await cancel.future;
    return result;
  }

  /// Reads a fixed-size greeting or authentication reply. Bytes beyond it
  /// have no place in the protocol here, so they fail the handshake.
  Future<List<int>> _readReply(RawChannel channel, int count) async {
    final reply = await channel.read(count);
    if (channel.raw.available() > 0) {
      throw const SocksProtocolFailure('reply has unexpected trailing data');
    }
    return reply;
  }

  /// Reads the variable-length CONNECT reply. Bytes after it belong to the
  /// target and stay in the socket for [inputStream].
  Future<List<int>> _readConnectReply(RawChannel channel) async {
    final reply = <int>[...await channel.read(4)];
    var length = socksConnectReplyLength(reply);
    if (length == null) {
      reply.addAll(await channel.read(1));
      length = socksConnectReplyLength(reply);
    }
    if (length != null && length > reply.length) {
      reply.addAll(await channel.read(length - reply.length));
    }
    return reply;
  }

  /// Tears down after a failed handshake step and maps [error] to what the
  /// caller sees. Cancellation, [close] and [destroy] report as such.
  Object _handshakeFailed(Object error, String prefix,
      {String? domain, int? port}) {
    _cancel = null;
    if (error is SocksCancelledException) return error;
    if (_phase == _Phase.cancelled) {
      return SocksCancelledException(message: 'SOCKS5 connection cancelled.');
    }
    if (_givenUp) return _closedBeforeConnected();
    _abandon(_Phase.failed);
    if (error is SocksProtocolFailure) {
      final replyCode = error.replyCode;
      if (replyCode != null) {
        final reply = SocksReplyCode.fromByte(replyCode);
        return SocksRequestException(
          replyCode: reply,
          proxyHost: proxyHost,
          proxyPort: proxyPort,
          targetDomain: domain!,
          targetPort: port!,
          message: 'SOCKS5 request failed (proxy: $proxyHost:$proxyPort, '
              'target: $domain:$port, reply: '
              '${reply?.description ?? "unknown (0x${replyCode.toRadixString(16).padLeft(2, '0')})"})',
        );
      }
      return SocksHandshakeException(
          proxyHost: proxyHost,
          proxyPort: proxyPort,
          message: '$prefix${error.message}');
    }
    if (error is SocketException) {
      return SocksConnectionException(
          message: 'Connection closed before SOCKS5 response received '
              '(proxy: $proxyHost:$proxyPort): ${error.message}');
    }
    return error;
  }

  SocksCancelledException _closedBeforeConnected() => SocksCancelledException(
      message: 'SOCKS5 connection closed before it was established.');

  // ---------------------------------------------------------------------------
  // Writing.

  /// Writes [object] to the socket. If [newline] is true, appends '\n'.
  Future<void> write(Object? object, {bool newline = false}) async {
    if (object == null) return;
    final data = utf8.encode(object.toString());
    await _queueWrite(newline ? [...data, 0x0A] : data);
  }

  /// close() rejects new sink operations, but an addStream it accepted still
  /// feeds chunks while output drains.
  Future<void> _queueSinkWrite(List<int> data) =>
      _queueWrite(data, draining: _phase == _Phase.closing);

  /// Throws synchronously when not writable, so a bound stream ends with the
  /// [StateError] instead of failing the connection.
  Future<void> _queueWrite(List<int> data, {bool draining = false}) {
    if (!(_phase == _Phase.connected || draining)) {
      throw StateError('Cannot write: socket is not connected (state: $state)');
    }
    final transport = _transport!;
    final bytes = List<int>.of(data);
    final writing = _writeTail.then((_) async {
      if (_writeFailure != null) {
        Error.throwWithStackTrace(_writeFailure!, _writeFailureStack!);
      }
      try {
        transport.add(bytes);
        await transport.flush().timeout(_operationTimeout);
        // A transport destroyed mid-flush can still complete the flush.
        if (_writeFailure != null) {
          Error.throwWithStackTrace(_writeFailure!, _writeFailureStack!);
        }
      } catch (e, stack) {
        // A failure that already ended the connection, such as destroy(),
        // is the cause; report it rather than the transport's symptom.
        if (_writeFailure != null) {
          Error.throwWithStackTrace(_writeFailure!, _writeFailureStack!);
        }
        final error = e is SocksException || e is TimeoutException
            ? e
            : SocksConnectionException(message: 'SOCKS5 write failed: $e');
        if (identical(transport, _transport)) {
          _fail(error, stack, _Phase.failed);
        }
        Error.throwWithStackTrace(error, stack);
      }
    });
    _writeTail =
        writing.then<void>((_) {}, onError: (Object _, StackTrace __) {});
    return writing;
  }

  // ---------------------------------------------------------------------------
  // Ending.

  /// Drains accepted output, then closes the connection.
  ///
  /// Rethrows a write failure that already ended the connection. A [close]
  /// or [destroy] while [reconnect] is in progress cancels the reconnect.
  Future<void> close() {
    _closeRequested = true;
    return _ensureClosed();
  }

  Future<void> _ensureClosed() => _closeFuture ??= _close();

  /// Tears the connection down at once, without draining output.
  ///
  /// Writes not yet delivered, through [write] or [outputStream], fail with a
  /// [SocksConnectionException], and [inputStream] ends. A connect or
  /// [reconnect] in flight fails with [SocksCancelledException]. A later
  /// [close] completes normally.
  void destroy() {
    _closeRequested = true;
    _signalCancel(
      SocksCancelledException(message: 'SOCKS5 connection destroyed.'),
    );
    _fail(
      SocksConnectionException(message: 'SOCKS5 connection destroyed'),
      StackTrace.current,
      _Phase.closed,
    );
    // A close already draining fails once its writes do; keep its outcome for
    // the caller that started it, but let a later close() complete normally.
    _closeFuture = (_closeFuture ?? _close()).catchError((Object _) {});
  }

  /// Cancels an in-flight connect operation. No-op if not connecting.
  /// Once a target is known, [reconnect] opens a new connection; to end a
  /// reconnect in progress, use [close] or [destroy].
  Future<void> cancel() async {
    if (!_connecting) return;
    _signalCancel(
      SocksCancelledException(message: 'SOCKS5 connection cancelled.'),
    );
    _abandon(_Phase.cancelled);
    _outputSink?.close().ignore();
  }

  /// Ends a connect in flight. The TLS handshake cannot notice a destroyed
  /// transport on its own, so it waits for this or for its deadline.
  void _signalCancel(SocksCancelledException error) {
    _connectTask?.cancel();
    final cancel = _cancel;
    if (cancel != null && !cancel.isCompleted) cancel.completeError(error);
  }

  /// Records a failure, fails pending output, and tears down into [phase].
  void _fail(Object error, StackTrace stack, _Phase phase) {
    _writeFailure ??= error;
    _writeFailureStack ??= stack;
    _outputSink?._stop(error, stack);
    _abandon(phase);
  }

  /// Destroys the transport and ends [inputStream] without draining; a paused
  /// input subscription would never see done otherwise. A closed socket stays
  /// closed: failures its teardown provokes are not news.
  void _abandon(_Phase phase) {
    if (_phase != _Phase.closed) _phase = phase;
    _channel?.destroy();
    if (!_input.isClosed) _input.close();
  }

  Future<void> _close() async {
    _signalCancel(_closedBeforeConnected());
    _phase = switch (_phase) {
      _Phase.connected => _Phase.closing,
      _Phase.failed => _Phase.failed,
      _ => _Phase.closed,
    };
    final channel = _channel;
    final transport = _transport;
    var flushed = false;
    try {
      await _outputSink?.close().timeout(_operationTimeout);
      await _writeTail;
      if (transport != null &&
          channel != null &&
          !channel.isClosed &&
          _writeFailure == null) {
        await transport.flush().timeout(_operationTimeout);
        flushed = true;
      }
    } catch (error, stack) {
      _outputSink?._stop(error, stack);
      rethrow;
    } finally {
      _phase = _Phase.closed;
      if (flushed) {
        await transport!.close().then<void>((_) {}, onError: (_) {});
      }
      await _subscription?.cancel();
      channel?.destroy();
      if (!_input.isClosed) _input.close();
    }
  }

  /// Reconnects to the previously connected target.
  ///
  /// Closes the current connection first, which ends [inputStream]. A [close]
  /// or [destroy] while the reconnect is in progress cancels it with
  /// [SocksCancelledException], including one made from that stream's onDone.
  ///
  /// Throws [StateError] if [connectTo] was never called.
  Future<void> reconnect({String? isolationToken}) async {
    if (_reconnecting) throw StateError('Reconnect is already in progress');
    _reconnecting = true;
    try {
      await _reconnect(isolationToken);
    } finally {
      _reconnecting = false;
    }
  }

  Future<void> _reconnect(String? isolationToken) async {
    if (_targetDomain == null || _targetPort == null) {
      throw StateError('Cannot reconnect: no target known. '
          'Call connectTo() before reconnect().');
    }
    _checkIsolationToken(isolationToken);
    if (isolationToken != null) _isolationToken = isolationToken;

    _closeRequested = false;
    try {
      await _ensureClosed();
    } catch (_) {
      // Connection may already be broken.
    }
    _checkReconnectAborted();

    // Broadcast controllers can't be reused after close.
    _input = _newInput();
    _transport = null;
    _subscription = null;
    _outputSink = null;
    _writeTail = Future<void>.value();
    _writeFailure = null;
    _writeFailureStack = null;
    _closeFuture = null;
    _phase = _Phase.idle;

    try {
      await _init();
      _checkReconnectAborted();
      await _connect();
      _checkReconnectAborted();
      await _connectTo(_targetDomain!, _targetPort!);
      _checkReconnectAborted();
    } catch (error) {
      final cancelled = error is SocksCancelledException || _closeRequested;
      _abandon(cancelled ? _Phase.closed : _Phase.failed);
      // A cancelled TCP connect fails with a SocketException.
      if (cancelled && error is! SocksCancelledException) {
        throw _reconnectCancelled();
      }
      rethrow;
    }
  }

  void _checkReconnectAborted() {
    if (_closeRequested) throw _reconnectCancelled();
  }

  SocksCancelledException _reconnectCancelled() => SocksCancelledException(
      message: 'SOCKS5 reconnect cancelled: the connection was closed.');

  StreamSubscription<List<int>> listen(
    void Function(List<int> data)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) =>
      _input.stream.listen(
        onData,
        onError: onError,
        onDone: onDone,
        cancelOnError: cancelOnError,
      );

  /// Sends the server.features command to the proxy server.
  ///
  /// This demos how to send the server.features command.  Use as an example
  /// for sending other commands.
  Future<void> sendServerFeaturesCommand() async {
    const String command =
        '{"jsonrpc":"2.0","id":"0","method":"server.features","params":[]}';
    await write(command, newline: true);
  }
}

class _SocketOutputSink implements StreamSink<List<int>> {
  final Future<void> Function(List<int>) _write;
  final void Function(Object, StackTrace) _onError;
  final _done = Completer<void>();
  Future<void> _last = Future<void>.value();
  bool _closed = false;
  StreamSubscription<List<int>>? _source;
  Completer<void>? _streamDone;

  _SocketOutputSink(this._write, this._onError) {
    _done.future.ignore();
  }

  @override
  Future<void> get done => _done.future;

  void _checkOpen() {
    if (_closed) throw StateError('Output sink is closed');
    if (_source != null) throw StateError('Output sink is bound to a stream');
  }

  void _stop(Object error, StackTrace stack) {
    _closed = true;
    _endStream(error, stack);
    if (!_done.isCompleted) _done.completeError(error, stack);
  }

  void _endStream([Object? error, StackTrace? stack]) {
    final completed = _streamDone;
    final source = _source;
    _source = null;
    _streamDone = null;
    // The source's onCancel may call destroy(), which ends up back here.
    source?.cancel();
    if (completed == null) return;
    if (error == null) {
      completed.complete();
    } else {
      completed.completeError(error, stack);
    }
  }

  void _failed(Object error, StackTrace stack) {
    _stop(error, stack);
    _onError(error, stack);
  }

  @override
  void add(List<int> data) {
    _checkOpen();
    _last = _write(data);
    _last.then<void>((_) {}, onError: _failed);
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {
    _checkOpen();
    _failed(error, stackTrace ?? StackTrace.current);
  }

  @override
  Future<void> addStream(Stream<List<int>> stream) {
    _checkOpen();
    final completed = _streamDone = Completer<void>();
    final source = _source = stream.listen(null, cancelOnError: true);
    source
      ..onData((List<int> data) {
        source.pause();
        try {
          _last = _write(data);
        } on StateError catch (error, stack) {
          _endStream(error, stack);
          return;
        }
        _last.then<void>((_) {
          if (identical(_source, source)) source.resume();
        }, onError: _failed);
      })
      ..onError(_failed)
      ..onDone(() => _endStream());
    return completed.future;
  }

  @override
  Future<void> close() {
    if (_closed) return done;
    _closed = true;
    final draining = _streamDone?.future ?? _last;
    draining.then<void>((_) {
      if (!_done.isCompleted) _done.complete();
    }, onError: _failed);
    return done;
  }
}
