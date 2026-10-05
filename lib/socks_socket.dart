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
enum ConnectionState {
  disconnected,
  connecting,
  connected,
  error,
}

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
  Socket get socket => sslEnabled ? _secureSocksSocket : _socksSocket;

  /// A wrapper around the _socksSocket that enables SSL connections.
  late Socket _secureSocksSocket;

  bool _nativeSocketOpen = false;

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

  bool get _handshaking => _state != ConnectionState.connected;

  void _resumeApplicationInput() {
    if (_state != ConnectionState.connected ||
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
    if (_state == ConnectionState.connected) _pauseInput();
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
  ConnectionState _state = ConnectionState.disconnected;

  /// Peer close or failure is noticed only while [inputStream] has a listener;
  /// until then a [write] to a dead peer may appear to succeed.
  ConnectionState get state => _state;

  /// Target domain for [reconnect].
  String? _targetDomain;

  /// Target port for [reconnect].
  int? _targetPort;

  /// Timeout for SOCKS5 handshake and TCP connect.
  final Duration _handshakeTimeout;

  /// Timeout for socket flush after [write].
  final Duration _operationTimeout;

  static const int _maxHandshakeBuffer = 1024;

  /// Cached output stream controller.
  StreamController<List<int>>? _outputController;

  /// Accept bad certificates (testing only).
  final bool _allowBadCertificates;

  final SecurityContext? _securityContext;

  /// Cancel signal for in-flight operations.
  Completer<Never>? _cancelCompleter;
  bool _cancelled = false;
  bool _greetingStarted = false;
  bool _greetingComplete = false;
  bool _requestStarted = false;
  bool _reconnecting = false;

  /// Tor circuit isolation token (RFC 1929 username/password auth).
  String? _isolationToken;

  final bool? _requireIsolation;

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
      this._requireIsolation);

  /// Provides a stream of data as List<int>.
  ///
  /// Reads pause while there is no listener; earlier data is kept.
  Stream<List<int>> get inputStream => sslEnabled
      ? _secureResponseController.stream
      : _responseController.stream;

  /// Provides a StreamSink compatible with List<int> for sending data.
  StreamSink<List<int>> get outputStream {
    _outputController ??= StreamController<List<int>>()
      ..stream.listen((data) {
        if (sslEnabled) {
          _secureSocksSocket.add(data);
        } else {
          _socksSocket.add(data);
        }
      });
    return _outputController!.sink;
  }

  /// Creates a SOCKS5 socket to the specified [proxyHost] and [proxyPort].
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
        requireIsolation);

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
        _requireIsolation = null {
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
    if (sslEnabled) {
      final raw = await RawSocket.connect(
        proxyHost,
        proxyPort,
        timeout: _handshakeTimeout,
      );
      _channel = RawChannel(raw);
      _socksSocket = _channel!.socket();
    } else {
      // Keep a native Socket so callers can use SecureSocket.secure(socket).
      _socksSocket = await Socket.connect(
        proxyHost,
        proxyPort,
        timeout: _handshakeTimeout,
      );
      _nativeSocketOpen = true;
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
      onError: (e) {
        final error = e is SocksException
            ? e
            : SocksConnectionException(
                message: 'SOCKS5 connection error: $e',
              );
        if (_handshaking && !handshake.isClosed) handshake.addError(error);
        if (!responses.isClosed) responses.addError(error);
        if (_state == ConnectionState.connected) {
          _state = ConnectionState.error;
          _abandonConnection();
        }
      },
      onDone: () {
        // Close the response controller when the socket is closed.
        if (!handshake.isClosed) handshake.close();
        if (!_sslUpgraded) {
          if (_state == ConnectionState.connected) {
            _state = ConnectionState.disconnected;
            _destroyTransport();
          }
          if (!responses.isClosed) responses.close();
        }
      },
    );
  }

  void _destroyTransport() {
    // After the TLS upgrade the secure channel owns and drains the raw socket.
    (_secureChannel ?? _channel)?.destroy();
    if (_nativeSocketOpen) {
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
    if (_greetingStarted || _state != ConnectionState.disconnected) {
      throw StateError(
          'Cannot connect: use reconnect() for another connection');
    }
    _greetingStarted = true;
    _cancelCompleter = Completer<Never>()..future.ignore();
    _state = ConnectionState.connecting;
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
      _state = ConnectionState.error;
      _abandonConnection();
      _cancelCompleter = null;
      throw SocksHandshakeException(
          proxyHost: proxyHost,
          proxyPort: proxyPort,
          message: 'SOCKS5 handshake failed: ${error.message}');
    } catch (e) {
      if (e is! SocksCancelledException) {
        _state = ConnectionState.error;
        _abandonConnection();
      }
      _cancelCompleter = null;
      rethrow;
    }
  }

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
    if (_state != ConnectionState.connecting ||
        !_greetingComplete ||
        _requestStarted) {
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
            onError: (e) {
              if (!responses.isClosed) {
                responses.addError(
                  e is SocksException
                      ? e
                      : SocksConnectionException(
                          message: 'SOCKS5 connection error: $e',
                        ),
                );
              }
              if (_state == ConnectionState.connected) {
                _state = ConnectionState.error;
                _abandonConnection();
              }
            },
            onDone: () {
              if (_state == ConnectionState.connected) {
                _state = ConnectionState.disconnected;
                _destroyTransport();
              }
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

      _state = ConnectionState.connected;
      _cancelCompleter = null;
      _resumeApplicationInput();
    } catch (e) {
      if (e is! SocksCancelledException) {
        _state = ConnectionState.error;
        _abandonConnection();
      }
      _cancelCompleter = null;
      rethrow;
    }
  }

  /// Writes [object] to the socket. If [newline] is true, appends '\n'.
  Future<void> write(Object? object, {bool newline = false}) async {
    // Don't write null.
    if (object == null) return;

    if (_state != ConnectionState.connected) {
      throw StateError(
          'Cannot write: socket is not connected (state: $_state)');
    }

    // Write the data to the socket.
    List<int> data = utf8.encode(object.toString());
    if (newline) {
      data = [...data, 0x0A]; // Append \n byte.
    }
    if (sslEnabled) {
      _secureSocksSocket.add(data);
      await _secureSocksSocket.flush().timeout(_operationTimeout);
    } else {
      _socksSocket.add(data);
      await _socksSocket.flush().timeout(_operationTimeout);
    }
  }

  /// Whether SSL upgrade consumed the raw socket.
  bool _sslUpgraded = false;

  /// Closes the connection to the Tor proxy.
  ///
  /// Returns:
  ///  A Future that resolves to void.
  Future<void> close() async {
    _state = ConnectionState.disconnected;
    final upgraded = sslEnabled && _sslUpgraded;
    final channel = upgraded ? _secureChannel : _channel;
    final open = _nativeSocketOpen || (channel != null && !channel.isClosed);
    var flushed = false;
    // Ensure all data is sent before closing.
    try {
      if (open) {
        await (upgraded ? _secureSocksSocket : _socksSocket)
            .flush()
            .timeout(_operationTimeout);
        flushed = true;
      }
    } finally {
      _generation++;
      _outputController?.close();
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
  /// The instance cannot be reused afterwards; create a new socket.
  Future<void> cancel() async {
    if (_state != ConnectionState.connecting) return;

    final c = _cancelCompleter;
    if (c == null || c.isCompleted) return;

    _cancelled = true;
    _state = ConnectionState.disconnected;
    c.completeError(
      SocksCancelledException(
        message: 'SOCKS5 connection cancelled.',
      ),
    );

    // Destroy socket to force pending operations to fail.
    _destroyTransport();

    await _subscription?.cancel();
    _outputController?.close();
    _closeHandshakeResponses();
    if (!_responseController.isClosed) _responseController.close();
    if (!_secureResponseController.isClosed) {
      _secureResponseController.close();
    }

    _state = ConnectionState.disconnected;
  }

  void _closeHandshakeResponses() {
    final handshake = _handshakeResponses;
    if (handshake != null && !handshake.isClosed) handshake.close();
  }

  /// Reconnects to the previously connected target.
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

    try {
      await close();
    } catch (_) {
      // Connection may already be broken.
    }

    // Broadcast controllers can't be reused after close.
    _pendingApplicationData = null;
    _responseController = _newResponseController();
    _secureResponseController = _newResponseController();
    _outputController = null;

    try {
      await _init();
      await _connect();
      await _connectTo(_targetDomain!, _targetPort!);
    } catch (error) {
      _state = error is SocksCancelledException
          ? ConnectionState.disconnected
          : ConnectionState.error;
      _abandonConnection();
      rethrow;
    }
  }

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

    if (!sslEnabled) {
      // Send the command to the proxy server.
      _socksSocket.writeln(command);

      // Wait for the response from the proxy server.
      // var responseData = await _responseController.stream.first;
      // if (kDebugMode) {
      //   print("responseData: ${utf8.decode(responseData)}");
      // }
    } else {
      // Send the command to the proxy server.
      _secureSocksSocket.writeln(command);

      // Wait for the response from the proxy server.
      // var responseData = await _secureResponseController.stream.first;
      // if (kDebugMode) {
      //   print("secure responseData: ${utf8.decode(responseData)}");
      // }
    }

    return;
  }
}
