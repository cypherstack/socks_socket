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

/// A SOCKS5 socket.
///
/// A Dart 3 Socket wrapper that implements the SOCKS5 protocol.  Now with SSL!
///
/// Properties:
///  - [proxyHost]: The host of the SOCKS5 proxy server.
///  - [proxyPort]: The port of the SOCKS5 proxy server.
///  - [_socksSocket]: The underlying Socket that connects to the SOCKS5 proxy
///  server.
///  - [_responseController]: A StreamController that listens to the
///  [_socksSocket] and broadcasts the response.
///
/// Methods:
/// - connect: Connects to the SOCKS5 proxy server.
/// - connectTo: Connects to the specified [domain] and [port] through the
/// SOCKS5 proxy server.
/// - write: Converts [object] to a String by invoking [Object.toString] and
/// sends the encoding of the result to the socket.
/// - sendServerFeaturesCommand: Sends the server.features command to the
/// proxy server.
/// - close: Closes the connection to the Tor proxy.
///
/// Usage:
/// ```dart
/// // Instantiate a socks socket at localhost and on the port selected by the
/// // tor service.
/// var socksSocket = await SOCKSSocket.create(
///  proxyHost: InternetAddress.loopbackIPv4.address,
///  proxyPort: tor.port,
///  // sslEnabled: true, // For SSL connections.
///  );
///
/// // Connect to the socks instantiated above.
/// await socksSocket.connect();
///
/// // Connect to bitcoincash.stackwallet.com on port 50001 via socks socket.
/// await socksSocket.connectTo(
/// 'bitcoincash.stackwallet.com', 50001);
///
/// // Send a server features command to the connected socket, see method for
/// // more specific usage example..
/// await socksSocket.sendServerFeaturesCommand();
/// await socksSocket.close();
/// ```
///
/// See also:
/// - SOCKS5 protocol(https://www.ietf.org/rfc/rfc1928.txt)
class SOCKSSocket {
  /// The host of the SOCKS5 proxy server.
  final String proxyHost;

  /// The port of the SOCKS5 proxy server.
  final int proxyPort;

  /// The underlying Socket that connects to the SOCKS5 proxy server.
  late Socket _socksSocket;

  /// Getter for the underlying Socket that connects to the SOCKS5 proxy server.
  ///
  /// To abort the connection, call [destroy] rather than `socket.destroy()`:
  /// dart:io completes a pending flush on a destroyed [Socket] normally, so
  /// writes cut short that way would be reported as sent.
  Socket get socket => sslEnabled ? _secureSocksSocket : _socksSocket;

  /// A wrapper around the _socksSocket that enables SSL connections.
  late Socket _secureSocksSocket;

  bool _nativeSocketOpen = false;
  bool _nativeSocketNeedsDestroy = false;

  RawChannel? _channel;

  RawChannel? _secureChannel;

  /// A StreamController that listens to the _socksSocket and broadcasts.
  late StreamController<List<int>> _responseController =
      _newResponseController();

  /// Bumped on teardown so a replaced connection's callbacks are ignored.
  int _generation = 0;

  StreamController<List<int>> _newResponseController() {
    final generation = _generation;
    return StreamController<List<int>>.broadcast(
      onListen: () {
        if (generation == _generation) _resumeApplicationInput();
      },
      onCancel: () {
        if (generation == _generation) _pauseApplicationInput();
      },
    );
  }

  List<int>? _pendingApplicationData;
  bool _applicationInputPaused = false;

  /// Broadcast: each handshake step listens and cancels in turn.
  StreamController<List<int>>? _handshakeResponses;

  bool get _handshaking => _state != SocksSocketState.connected;

  void _resumeApplicationInput() {
    if (_state != SocksSocketState.connected ||
        !responseController.hasListener) {
      return;
    }
    final pending = _pendingApplicationData;
    _pendingApplicationData = null;
    if (pending != null && pending.isNotEmpty) {
      _responseController.add(pending);
    }
    if (_applicationInputPaused) {
      _applicationInputPaused = false;
      _subscription?.resume();
    }
  }

  void _pauseApplicationInput() {
    if (_state == SocksSocketState.connected) _pauseInput();
  }

  void _pauseInput() {
    if (!_applicationInputPaused) {
      _applicationInputPaused = true;
      _subscription?.pause();
    }
  }

  /// A StreamController that listens to the _secureSocksSocket and broadcasts.
  late StreamController<List<int>> _secureResponseController =
      _newResponseController();

  /// Getter for the StreamController that listens to the _socksSocket and
  /// broadcasts, or the _secureSocksSocket and broadcasts if SSL is enabled.
  StreamController<List<int>> get responseController =>
      sslEnabled ? _secureResponseController : _responseController;

  /// A StreamSubscription that listens to the _socksSocket or the
  /// _secureSocksSocket if SSL is enabled.
  StreamSubscription<List<int>>? _subscription;

  /// Getter for the StreamSubscription that listens to the _socksSocket or the
  /// _secureSocksSocket if SSL is enabled.
  StreamSubscription<List<int>>? get subscription => _subscription;

  /// Is SSL enabled?
  final bool sslEnabled;

  /// Current connection state.
  SocksSocketState _state = SocksSocketState.disconnected;

  /// Peer close or failure is noticed only while [inputStream] has a listener;
  /// until then a [write] to a dead peer may appear to succeed. With
  /// `closeOnPeerEof: false`, peer close leaves the state unchanged.
  SocksSocketState get state => _state;

  /// Target domain for [reconnect].
  String? _targetDomain;

  /// Target port for [reconnect].
  int? _targetPort;

  /// Timeout for SOCKS5 handshake and TCP connect.
  final Duration _handshakeTimeout;

  /// Timeout for socket flush after [write].
  final Duration _operationTimeout;

  static const int _maxHandshakeBuffer = 1024;

  _SocketOutputSink? _outputSink;
  Future<void> _writeTail = Future<void>.value();
  Object? _writeFailure;
  StackTrace? _writeFailureStack;
  Future<void>? _closeFuture;
  bool _closing = false;

  /// Set by [close] and [destroy]; a [reconnect] in flight stops at its next
  /// step instead of opening a connection the caller has already given up.
  bool _closeRequested = false;
  bool _peerReadClosed = false;

  /// Accept bad certificates (testing only).
  final bool _allowBadCertificates;

  final SecurityContext? _securityContext;

  /// Cancel signal for in-flight operations.
  Completer<Never>? _cancelCompleter;

  /// The proxy TCP connect in flight, so [close] and [destroy] can end it.
  ConnectionTask<Object>? _connectTask;
  bool _cancelled = false;
  bool _greetingStarted = false;
  bool _greetingComplete = false;
  bool _requestStarted = false;
  bool _reconnecting = false;

  /// Tor circuit isolation token (RFC 1929 username/password auth).
  String? _isolationToken;

  final bool? _requireIsolation;

  final bool _closeOnPeerEof;

  /// Private constructor.
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

  /// Provides a stream of data as List<int>.
  ///
  /// Reads pause while there is no listener; earlier data is kept.
  Stream<List<int>> get inputStream => sslEnabled
      ? _secureResponseController.stream
      : _responseController.stream;

  StreamSink<List<int>> get outputStream => _outputSink ??= _newOutputSink();

  _SocketOutputSink _newOutputSink() {
    final generation = _generation;
    final sink = _SocketOutputSink(_queueSinkWrite, (error, stack) {
      if (generation == _generation) _failWrites(error, stack);
    });
    if (_writeFailure != null) {
      sink._stop(_writeFailure!, _writeFailureStack!);
    } else if (_closing) {
      sink.close().ignore();
    }
    return sink;
  }

  Future<void> _queueSinkWrite(List<int> data) {
    if (!_canQueueWrite(allowClosing: true)) {
      throw StateError(
          'Cannot write: socket is not connected (state: $_state)');
    }
    return _queueWrite(data, allowClosing: true);
  }

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

    // Create a SOCKS socket instance.
    var instance = SOCKSSocket._(
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

    // Initialize the SOCKS socket.
    await instance._init();

    // Return the SOCKS socket instance.
    return instance;
  }

  /// Deprecated. Does not await _init(); use [SOCKSSocket.create].
  @Deprecated('Use SOCKSSocket.create() instead')
  SOCKSSocket({
    required this.proxyHost,
    required this.proxyPort,
    required this.sslEnabled,
  })  : _isolationToken = null,
        _handshakeTimeout = const Duration(seconds: 30),
        _operationTimeout = const Duration(seconds: 30),
        _allowBadCertificates = false,
        _securityContext = null,
        _requireIsolation = null,
        _closeOnPeerEof = true {
    _init();
  }

  /// Initializes the SOCKS socket.
  ///
  /// This method is a private method that is called by the constructor.
  ///
  /// Returns:
  ///   A Future that resolves to void.
  Future<void> _init() async {
    // Connect to the SOCKS proxy server.
    _applicationInputPaused = false;
    _cancelled = false;
    _greetingStarted = false;
    _greetingComplete = false;
    _requestStarted = false;
    _peerReadClosed = false;
    if (sslEnabled) {
      final raw = await _connectProxy(RawSocket.startConnect);
      _channel = RawChannel(raw);
      _socksSocket = _channel!.socket();
    } else {
      // Keep a native Socket so callers can use SecureSocket.secure(socket).
      _socksSocket = await _connectProxy(Socket.startConnect);
      _nativeSocketOpen = true;
      _nativeSocketNeedsDestroy = true;
      _socksSocket.done.then<void>((_) {
        _nativeSocketOpen = false;
      }, onError: (Object _) {
        _nativeSocketOpen = false;
      });
    }
    _secureChannel = null;
    final responses = _responseController;
    final handshake = _handshakeResponses = StreamController.broadcast();

    // Listen to the socket.
    _subscription = _socksSocket.listen(
      (data) {
        (_handshaking ? handshake : _responseController).add(data);
      },
      onError: (Object e, StackTrace stack) {
        final error = e is SocksException
            ? e
            : SocksConnectionException(
                message: 'SOCKS5 connection error: $e',
              );
        if (_handshaking && !handshake.isClosed) handshake.addError(error);
        if (!responses.isClosed) responses.addError(error);
        if (_state == SocksSocketState.connected) _failWrites(error, stack);
      },
      onDone: () {
        // Close the response controller when the socket is closed.
        if (!handshake.isClosed) handshake.close();
        if (!_sslUpgraded) {
          if (_state == SocksSocketState.connected) _peerClosed();
          if (!responses.isClosed) responses.close();
        }
      },
    );
  }

  Future<T> _connectProxy<T extends Object>(
      Future<ConnectionTask<T>> Function(String host, int port) start) async {
    final task = _connectTask = await start(proxyHost, proxyPort);
    // A close() or destroy() while the task was being created found
    // nothing to cancel yet.
    if (_closeRequested) task.cancel();
    try {
      return await task.socket.timeout(_handshakeTimeout, onTimeout: () {
        task.cancel();
        throw SocketException(
            'Connection timed out, host: $proxyHost, port: $proxyPort');
      });
    } finally {
      _connectTask = null;
    }
  }

  /// The peer stopped sending; writes already accepted are still delivered.
  void _peerClosed() {
    _peerReadClosed = true;
    if (!_closeOnPeerEof) return;
    _state = SocksSocketState.disconnected;
    _ensureClosed().ignore();
  }

  void _destroyTransport() {
    // After the TLS upgrade the secure channel owns and drains the raw socket.
    (_secureChannel ?? _channel)?.destroy();
    // Sink completion does not cancel a paused addStream source after a reset.
    // Destroy every native transport we own, even when its done has completed.
    if (_nativeSocketNeedsDestroy) {
      _nativeSocketNeedsDestroy = false;
      _nativeSocketOpen = false;
      _socksSocket.destroy();
    }
  }

  /// Closes controllers directly; a paused input subscription never sees done.
  void _abandonConnection() {
    _destroyTransport();
    if (!_responseController.isClosed) _responseController.close();
    if (!_secureResponseController.isClosed) {
      _secureResponseController.close();
    }
  }

  /// Accumulates [expectedLength] bytes from the response stream.
  Future<List<int>> _waitForResponse(int expectedLength) =>
      _waitForReply((_) => expectedLength, allowTrailing: false);

  /// Accumulates a variable-length SOCKS5 connect response.
  Future<List<int>> _waitForConnectResponse() =>
      _waitForReply(socksConnectReplyLength, allowTrailing: true);

  Future<List<int>> _waitForReply(
    int? Function(List<int> buffer) lengthOf, {
    required bool allowTrailing,
  }) {
    final completer = Completer<List<int>>();
    final buffer = <int>[];
    late final StreamSubscription<List<int>> sub;

    void fail(String reason) {
      sub.cancel();
      if (!completer.isCompleted) {
        completer.completeError(
          SocksHandshakeException(
            proxyHost: proxyHost,
            proxyPort: proxyPort,
            message: 'SOCKS5 $reason (proxy: $proxyHost:$proxyPort).',
          ),
        );
      }
    }

    sub = _handshakeResponses!.stream.listen(
      (data) {
        buffer.addAll(data);
        final expectedLength = lengthOf(buffer);
        if (buffer.length >= _maxHandshakeBuffer &&
            (expectedLength == null || buffer.length < expectedLength)) {
          fail('handshake buffer overflow');
          return;
        }
        if (expectedLength == null || buffer.length < expectedLength) return;
        if (expectedLength < 0) {
          fail('reply is malformed');
        } else if (!allowTrailing && buffer.length > expectedLength) {
          fail('reply has unexpected trailing data');
        } else {
          sub.cancel();
          if (!completer.isCompleted) {
            if (allowTrailing && expectedLength > 0 && !sslEnabled) {
              _pendingApplicationData = buffer.sublist(expectedLength);
              _pauseInput();
            }
            completer.complete(buffer.sublist(0, expectedLength));
          }
        }
      },
      onError: (e) {
        sub.cancel();
        if (!completer.isCompleted) {
          completer.completeError(e);
        }
      },
      onDone: () {
        if (!completer.isCompleted) {
          completer.completeError(
            SocksConnectionException(
              message: 'Connection closed before SOCKS5 response received '
                  '(proxy: $proxyHost:$proxyPort).',
            ),
          );
        }
      },
    );

    final dataFuture = completer.future.timeout(
      _handshakeTimeout,
      onTimeout: () {
        sub.cancel();
        throw TimeoutException('SOCKS5 handshake timed out after '
            '${_handshakeTimeout.inSeconds} seconds.');
      },
    );

    final cancel = _cancelCompleter;
    if (cancel != null) {
      return Future.any<List<int>>([dataFuture, cancel.future]);
    }
    return dataFuture;
  }

  static void _checkIsolationToken(String? token) {
    if (token != null) encodeSocksCredentials(token, token);
  }

  Future<void> _writeHandshake(List<int> bytes) async =>
      _socksSocket.add(bytes);

  /// Connects to the SOCKS socket.
  ///
  /// Returns:
  ///  A Future that resolves to void.
  Future<void> connect() async {
    _checkNotReconnecting();
    return _connect();
  }

  Future<void> _connect() async {
    if (_greetingStarted ||
        _closing ||
        _state != SocksSocketState.disconnected) {
      throw StateError(
          'Cannot connect: use reconnect() for another connection');
    }
    _greetingStarted = true;
    _cancelCompleter = Completer<Never>()..future.ignore();
    _state = SocksSocketState.connecting;
    try {
      await negotiateSocks(
        write: _writeHandshake,
        read: _waitForResponse,
        credentials: _isolationToken == null
            ? null
            : encodeSocksCredentials(_isolationToken!, _isolationToken!),
        allowNoAuthFallback: !(_requireIsolation ?? _isolationToken != null),
      );
      if (_cancelled) {
        throw SocksCancelledException(message: 'SOCKS5 connection cancelled.');
      }
      _greetingComplete = true;
    } on SocksProtocolFailure catch (error) {
      _cancelCompleter = null;
      if (_closing) throw _closedBeforeConnected();
      _state = SocksSocketState.error;
      _abandonConnection();
      throw SocksHandshakeException(
          proxyHost: proxyHost,
          proxyPort: proxyPort,
          message: 'SOCKS5 handshake failed: ${error.message}');
    } catch (e) {
      _cancelCompleter = null;
      if (e is SocksCancelledException) rethrow;
      if (_closing) throw _closedBeforeConnected();
      _state = SocksSocketState.error;
      _abandonConnection();
      rethrow;
    }
  }

  SocksCancelledException _closedBeforeConnected() => SocksCancelledException(
      message: 'SOCKS5 connection closed before it was established.');

  /// Connects to the specified [domain] and [port] through the SOCKS socket.
  ///
  /// Parameters:
  /// - [domain]: The domain to connect to.
  /// - [port]: The port to connect to.
  ///
  /// Returns:
  ///   A Future that resolves to void.
  Future<void> connectTo(String domain, int port) async {
    _checkNotReconnecting();
    return _connectTo(domain, port);
  }

  void _checkNotReconnecting() {
    if (_reconnecting) throw StateError('Reconnect is already in progress');
  }

  Future<void> _connectTo(String domain, int port) async {
    if (_cancelled) {
      throw SocksCancelledException(message: 'SOCKS5 connection cancelled.');
    }
    if (_state != SocksSocketState.connecting ||
        !_greetingComplete ||
        _requestStarted ||
        _closing) {
      throw StateError(
          'Cannot connectTo: must call connect() and await it before one connectTo()');
    }

    final request = encodeSocksDestination(domain, port);

    _requestStarted = true;
    _targetDomain = domain;
    _targetPort = port;

    try {
      _socksSocket.add(request);
      final response = await _waitForConnectResponse();
      try {
        checkSocksConnectReply(response);
      } on SocksProtocolFailure catch (error) {
        if (error.replyCode != null) {
          final replyCode = SocksReplyCode.fromByte(error.replyCode!);
          throw SocksRequestException(
            replyCode: replyCode,
            proxyHost: proxyHost,
            proxyPort: proxyPort,
            targetDomain: domain,
            targetPort: port,
            message: 'SOCKS5 request failed (proxy: $proxyHost:$proxyPort, '
                'target: $domain:$port, reply: '
                '${replyCode?.description ?? "unknown (0x${error.replyCode!.toRadixString(16).padLeft(2, '0')})"})',
          );
        }
        throw SocksHandshakeException(
            proxyHost: proxyHost, proxyPort: proxyPort, message: error.message);
      }

      // Upgrade to SSL if needed.
      if (sslEnabled) {
        final channel = _channel!;
        final deadline = Completer<RawSecureSocket>()..future.ignore();
        final timer = Timer(_handshakeTimeout, () {
          channel.destroy();
          deadline.completeError(
              TimeoutException('SOCKS5 SSL handshake timed out after '
                  '${_handshakeTimeout.inSeconds} seconds.'));
        });
        final handshake = RawSecureSocket.secure(
          channel.raw,
          subscription: channel.detach(),
          host: domain,
          context: _securityContext,
          onBadCertificate: _allowBadCertificates ? (_) => true : null,
        );
        try {
          // Upgrade to SSL.
          final secured = await Future.any<RawSecureSocket>([
            handshake,
            deadline.future,
            if (_cancelCompleter != null) _cancelCompleter!.future,
          ]);
          final secureChannel = _secureChannel = RawChannel(secured);
          _secureSocksSocket = secureChannel.socket();
          _sslUpgraded = true;
          final responses = _secureResponseController;

          // Listen to the secure socket.
          _subscription = _secureSocksSocket.listen(
            (data) {
              // Add the data to the response controller.
              responses.add(data);
            },
            onError: (Object e, StackTrace stack) {
              final error = e is SocksException
                  ? e
                  : SocksConnectionException(
                      message: 'SOCKS5 connection error: $e',
                    );
              if (!responses.isClosed) responses.addError(error);
              if (_state == SocksSocketState.connected) {
                _failWrites(error, stack);
              }
            },
            onDone: () {
              if (_state == SocksSocketState.connected) _peerClosed();
              if (!responses.isClosed) responses.close();
            },
          );
          _pauseInput();
        } catch (e) {
          handshake.then<void>((s) => s.close(), onError: (_) {});
          if (_cancelCompleter?.isCompleted == true) {
            throw SocksCancelledException(
              message: 'SOCKS5 connection cancelled during SSL upgrade.',
            );
          }
          rethrow;
        } finally {
          timer.cancel();
        }
      }

      // Check if cancelled between handshake completion and state transition.
      if (_cancelCompleter?.isCompleted == true) {
        throw SocksCancelledException(
          message: 'SOCKS5 connection cancelled.',
        );
      }

      _state = SocksSocketState.connected;
      _cancelCompleter = null;
      _resumeApplicationInput();
    } catch (e) {
      _cancelCompleter = null;
      if (e is SocksCancelledException) rethrow;
      if (_closing) throw _closedBeforeConnected();
      _state = SocksSocketState.error;
      _abandonConnection();
      rethrow;
    }
  }

  /// Writes [object] to the socket. If [newline] is true, appends '\n'.
  Future<void> write(Object? object, {bool newline = false}) async {
    if (object == null) return;
    final data = utf8.encode(object.toString());
    await _queueWrite(newline ? [...data, 0x0A] : data);
  }

  bool _canQueueWrite({bool allowClosing = false}) {
    if (_closing && !allowClosing) return false;
    // close() rejects new sink operations, but an already accepted addStream
    // still feeds chunks after read-side EOF until it finishes or times out.
    return _state == SocksSocketState.connected ||
        (allowClosing &&
            _closing &&
            _peerReadClosed &&
            _state == SocksSocketState.disconnected);
  }

  Future<void> _queueWrite(List<int> data, {bool allowClosing = false}) {
    if (!_canQueueWrite(allowClosing: allowClosing)) {
      return Future<void>.error(
          StateError('Cannot write: socket is not connected (state: $_state)'));
    }
    final bytes = List<int>.of(data);
    final generation = _generation;
    final writing = _writeTail.then((_) async {
      if (_writeFailure != null) {
        Error.throwWithStackTrace(_writeFailure!, _writeFailureStack!);
      }
      try {
        socket.add(bytes);
        await socket.flush().timeout(_operationTimeout);
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
        if (generation == _generation) _failWrites(error, stack);
        Error.throwWithStackTrace(error, stack);
      }
    });
    _writeTail =
        writing.then<void>((_) {}, onError: (Object _, StackTrace __) {});
    return writing;
  }

  void _failWrites(Object error, StackTrace stack) {
    _writeFailure ??= error;
    _writeFailureStack ??= stack;
    _state = SocksSocketState.error;
    _outputSink?._stop(error, stack);
    _abandonConnection();
  }

  /// Whether SSL upgrade consumed the raw socket.
  bool _sslUpgraded = false;

  /// Closes the connection to the Tor proxy.
  ///
  /// Returns:
  ///  A Future that resolves to void.
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
    _failWrites(
      SocksConnectionException(message: 'SOCKS5 connection destroyed'),
      StackTrace.current,
    );
    _state = SocksSocketState.disconnected;
    // A close already draining fails once its writes do; keep its outcome for
    // the caller that started it, but let a later close() complete normally.
    _closeFuture = (_closeFuture ?? _close()).catchError((Object _) {});
  }

  Future<void> _flushBeforeClose(Socket transport) async {
    final elapsed = Stopwatch()..start();
    while (true) {
      final remaining = _operationTimeout - elapsed.elapsed;
      if (remaining <= Duration.zero) {
        throw TimeoutException(
            'SOCKS5 output did not drain before close', _operationTimeout);
      }
      final Future flushing;
      try {
        flushing = transport.flush();
      } on StateError {
        // The public native socket may have an active flush/addStream outside
        // _writeTail. IOSink rejects another flush synchronously while bound,
        // and exposes no future for that operation. Keep its transport alive
        // and retry within one deadline; wrapping it would break manual TLS.
        const interval = Duration(milliseconds: 10);
        await Future<void>.delayed(remaining < interval ? remaining : interval);
        continue;
      }
      // Async failures belong to the flush itself and must not be retried.
      await flushing.timeout(remaining);
      return;
    }
  }

  /// Ends a connect in flight. The TLS handshake cannot notice a destroyed
  /// transport on its own, so it waits for this or for its deadline.
  void _signalCancel(SocksCancelledException error) {
    _connectTask?.cancel();
    final cancel = _cancelCompleter;
    if (cancel != null && !cancel.isCompleted) cancel.completeError(error);
  }

  Future<void> _close() async {
    _closing = true;
    _signalCancel(_closedBeforeConnected());
    final upgraded = sslEnabled && _sslUpgraded;
    final channel = upgraded ? _secureChannel : _channel;
    var flushed = false;
    // Ensure all data is sent before closing.
    try {
      await _outputSink?.close().timeout(_operationTimeout);
      await _writeTail;
      final open = _nativeSocketOpen || (channel != null && !channel.isClosed);
      if (open && _writeFailure == null) {
        await _flushBeforeClose(upgraded ? _secureSocksSocket : _socksSocket);
        flushed = true;
      }
    } catch (error, stack) {
      _outputSink?._stop(error, stack);
      rethrow;
    } finally {
      _generation++;
      _state = SocksSocketState.disconnected;
      if (flushed) {
        await (upgraded ? _secureSocksSocket : _socksSocket)
            .close()
            .then<void>((_) {}, onError: (_) {});
      }
      await _subscription?.cancel();
      _destroyTransport();
      _closeHandshakeResponses();
      if (!_secureResponseController.isClosed) {
        _secureResponseController.close();
      }
      if (!_responseController.isClosed) {
        _responseController.close();
      }
      _sslUpgraded = false;
    }
  }

  /// Cancels an in-flight connect operation. No-op if not connecting.
  /// Once a target is known, [reconnect] opens a new connection; to end a
  /// reconnect in progress, use [close] or [destroy].
  Future<void> cancel() async {
    if (_state != SocksSocketState.connecting) return;

    final c = _cancelCompleter;
    if (c == null || c.isCompleted) return;

    _cancelled = true;
    _state = SocksSocketState.disconnected;
    c.completeError(
      SocksCancelledException(
        message: 'SOCKS5 connection cancelled.',
      ),
    );

    // Destroy socket to force pending operations to fail.
    _destroyTransport();

    await _subscription?.cancel();
    _outputSink?.close().ignore();
    _closeHandshakeResponses();
    if (!_responseController.isClosed) _responseController.close();
    if (!_secureResponseController.isClosed) {
      _secureResponseController.close();
    }

    _state = SocksSocketState.disconnected;
  }

  void _closeHandshakeResponses() {
    final handshake = _handshakeResponses;
    if (handshake != null && !handshake.isClosed) handshake.close();
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
    if (isolationToken != null) {
      _isolationToken = isolationToken;
    }

    _closeRequested = false;
    try {
      await _ensureClosed();
    } catch (_) {
      // Connection may already be broken.
    }
    _checkReconnectAborted();

    // Broadcast controllers can't be reused after close.
    _pendingApplicationData = null;
    _responseController = _newResponseController();
    _secureResponseController = _newResponseController();
    _outputSink = null;
    _writeTail = Future<void>.value();
    _writeFailure = null;
    _writeFailureStack = null;
    _closeFuture = null;
    _closing = false;

    try {
      await _init();
      _checkReconnectAborted();
      await _connect();
      _checkReconnectAborted();
      await _connectTo(_targetDomain!, _targetPort!);
      _checkReconnectAborted();
    } catch (error) {
      final cancelled = error is SocksCancelledException || _closeRequested;
      _state =
          cancelled ? SocksSocketState.disconnected : SocksSocketState.error;
      _abandonConnection();
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
  }) {
    return sslEnabled
        ? _secureResponseController.stream.listen(
            onData,
            onError: onError,
            onDone: onDone,
            cancelOnError: cancelOnError,
          )
        : _responseController.stream.listen(
            onData,
            onError: onError,
            onDone: onDone,
            cancelOnError: cancelOnError,
          );
  }

  /// Sends the server.features command to the proxy server.
  ///
  /// This demos how to send the server.features command.  Use as an example
  /// for sending other commands.
  ///
  /// Returns:
  ///   A Future that resolves to void.
  Future<void> sendServerFeaturesCommand() async {
    // The server.features command.
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
