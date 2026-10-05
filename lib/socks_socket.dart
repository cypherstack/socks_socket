import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'src/reply_code.dart';

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

  /// A StreamController that listens to the _socksSocket and broadcasts.
  StreamController<List<int>> _responseController =
      StreamController.broadcast();

  /// A StreamController that listens to the _secureSocksSocket and broadcasts.
  StreamController<List<int>> _secureResponseController =
      StreamController.broadcast();

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

  /// Cancel signal for in-flight operations.
  Completer<Never>? _cancelCompleter;

  /// Whether SSL upgrade is in progress.
  bool _sslUpgrading = false;

  /// Tor circuit isolation token (RFC 1929 username/password auth).
  String? _isolationToken;

  /// Private constructor.
  SOCKSSocket._(
      this.proxyHost,
      this.proxyPort,
      this.sslEnabled,
      this._isolationToken,
      this._handshakeTimeout,
      this._operationTimeout,
      this._allowBadCertificates);

  /// Provides a stream of data as List<int>.
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
  }) async {
    // RFC 1929 ULEN/PLEN max 255 bytes.
    if (isolationToken != null && utf8.encode(isolationToken).length > 255) {
      throw ArgumentError.value(
        isolationToken,
        'isolationToken',
        'Token UTF-8 encoding exceeds 255 bytes (RFC 1929 limit).',
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
        allowBadCertificates);

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
        _allowBadCertificates = false {
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
    _socksSocket = await Socket.connect(
      proxyHost,
      proxyPort,
      timeout: _handshakeTimeout,
    );

    // Listen to the socket.
    _subscription = _socksSocket.listen(
      (data) {
        // Add the data to the response controller.
        _responseController.add(data);
      },
      onError: (e) {
        _responseController.addError(
          e is SocksException
              ? e
              : SocksConnectionException(
                  message: 'SOCKS5 connection error: $e',
                ),
        );
      },
      onDone: () {
        // Close the response controller when the socket is closed.
        // _responseController.close();
      },
    );
  }

  /// Accumulates [expectedLength] bytes from the response stream.
  Future<List<int>> _waitForResponse(int expectedLength) {
    final completer = Completer<List<int>>();
    final buffer = <int>[];
    late final StreamSubscription<List<int>> sub;

    sub = _responseController.stream.listen(
      (data) {
        buffer.addAll(data);
        if (buffer.length >= _maxHandshakeBuffer) {
          sub.cancel();
          if (!completer.isCompleted) {
            completer.completeError(
              SocksHandshakeException(
                proxyHost: proxyHost,
                proxyPort: proxyPort,
                message: 'SOCKS5 handshake buffer overflow '
                    '(proxy: $proxyHost:$proxyPort, '
                    '${buffer.length} bytes received).',
              ),
            );
          }
          return;
        }
        if (buffer.length >= expectedLength) {
          sub.cancel();
          if (!completer.isCompleted) {
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

  /// Accumulates a variable-length SOCKS5 connect response.
  Future<List<int>> _waitForConnectResponse() {
    final completer = Completer<List<int>>();
    final buffer = <int>[];
    late final StreamSubscription<List<int>> sub;

    sub = _responseController.stream.listen(
      (data) {
        buffer.addAll(data);
        if (buffer.length >= _maxHandshakeBuffer) {
          sub.cancel();
          if (!completer.isCompleted) {
            completer.completeError(
              SocksHandshakeException(
                proxyHost: proxyHost,
                proxyPort: proxyPort,
                message: 'SOCKS5 handshake buffer overflow '
                    '(proxy: $proxyHost:$proxyPort, '
                    '${buffer.length} bytes received).',
              ),
            );
          }
          return;
        }
        if (buffer.length >= 5) {
          final expectedLength = _calcConnectResponseLength(buffer);
          if (expectedLength != null && buffer.length >= expectedLength) {
            sub.cancel();
            if (!completer.isCompleted) {
              completer.complete(buffer.sublist(0, expectedLength));
            }
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

  /// Expected response length by ATYP, or null if undetermined.
  static int? _calcConnectResponseLength(List<int> buf) {
    if (buf.length < 4) return null;
    switch (buf[3]) {
      case 0x01:
        return 10; // IPv4: 4 header + 4 addr + 2 port
      case 0x03:
        return buf.length >= 5
            ? 4 + 1 + buf[4] + 2 // Domain: 4 header + 1 len + domain + 2 port
            : null;
      case 0x04:
        return 22; // IPv6: 4 header + 16 addr + 2 port
      default:
        return null;
    }
  }

  /// Connects to the SOCKS socket.
  ///
  /// Returns:
  ///  A Future that resolves to void.
  Future<void> connect() async {
    _cancelCompleter = Completer<Never>();
    _state = ConnectionState.connecting;
    try {
      // Greeting and method selection.
      if (_isolationToken != null) {
        // Offer both no-auth (0x00) and username/password (0x02).
        _socksSocket.add([0x05, 0x02, 0x00, 0x02]);
      } else {
        // Original no-auth only greeting (backward compatible).
        _socksSocket.add([0x05, 0x01, 0x00]);
      }

      // Wait for server response (2 bytes per RFC 1928).
      var response = await _waitForResponse(2);

      if (_isolationToken != null && response[1] == 0x02) {
        // Sub-negotiate per RFC 1929.
        final tokenBytes = utf8.encode(_isolationToken!);
        _socksSocket.add([
          0x01, // Sub-negotiation version.
          tokenBytes.length, // ULEN.
          ...tokenBytes, // UNAME (token as username).
          tokenBytes.length, // PLEN.
          ...tokenBytes, // PASSWD (token as password).
        ]);

        var authResponse = await _waitForResponse(2);
        if (authResponse[1] != 0x00) {
          throw SocksHandshakeException(
            proxyHost: proxyHost,
            proxyPort: proxyPort,
            message: 'SOCKS5 authentication failed: '
                'username/password auth rejected',
          );
        }
      } else if (response[1] != 0x00) {
        // Server rejected all methods or selected unknown method.
        throw SocksHandshakeException(
          proxyHost: proxyHost,
          proxyPort: proxyPort,
          message: 'SOCKS5 handshake failed '
              '(proxy: $proxyHost:$proxyPort): '
              'proxy rejected authentication method '
              '(response: 0x${response[1].toRadixString(16).padLeft(2, '0')})',
        );
      }
    } catch (e) {
      if (e is! SocksCancelledException) {
        _state = ConnectionState.error;
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
    if (_state != ConnectionState.connecting) {
      throw StateError(
          'Cannot connectTo: must call connect() first (state: $_state)');
    }

    _targetDomain = domain;
    _targetPort = port;

    try {
      // Connect command.
      var request = [
        0x05, // SOCKS version.
        0x01, // Connect command.
        0x00, // Reserved.
        0x03, // Domain name.
        domain.length,
        ...domain.codeUnits,
        (port >> 8) & 0xFF,
        port & 0xFF
      ];

      // Send the connect command to the SOCKS proxy server.
      _socksSocket.add(request);

      // Wait for server response (variable length per RFC 1928).
      var response = await _waitForConnectResponse();

      // Check if the connection was successful.
      if (response[1] != 0x00) {
        final replyCode = SocksReplyCode.fromByte(response[1]);
        throw SocksRequestException(
          replyCode: replyCode,
          proxyHost: proxyHost,
          proxyPort: proxyPort,
          targetDomain: domain,
          targetPort: port,
          message: 'SOCKS5 request failed '
              '(proxy: $proxyHost:$proxyPort, '
              'target: $domain:$port, '
              'reply: ${replyCode?.description ?? "unknown (0x${response[1].toRadixString(16).padLeft(2, '0')})"})',
        );
      }

      // Upgrade to SSL if needed.
      if (sslEnabled) {
        _sslUpgrading = true;
        try {
          // Upgrade to SSL.
          _secureSocksSocket = await SecureSocket.secure(
            _socksSocket,
            host: domain,
            onBadCertificate: _allowBadCertificates ? (_) => true : null,
          );
          _sslUpgrading = false;
          _sslUpgraded = true;

          // Listen to the secure socket.
          _subscription = _secureSocksSocket.listen(
            (data) {
              // Add the data to the response controller.
              _secureResponseController.add(data);
            },
            onError: (e) {
              _secureResponseController.addError(
                e is SocksException
                    ? e
                    : SocksConnectionException(
                        message: 'SOCKS5 connection error: $e',
                      ),
              );
            },
            onDone: () {
              // Close the response controller when the socket is closed.
              _secureResponseController.close();
            },
          );
        } catch (e) {
          _sslUpgrading = false;
          if (_cancelCompleter?.isCompleted == true) {
            throw SocksCancelledException(
              message: 'SOCKS5 connection cancelled during SSL upgrade.',
            );
          }
          rethrow;
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
    } catch (e) {
      if (e is! SocksCancelledException) {
        _state = ConnectionState.error;
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

  /// Closes the connection to the Tor proxy.
  ///
  /// Returns:
  ///  A Future that resolves to void.
  /// Whether SSL upgrade consumed the raw socket.
  bool _sslUpgraded = false;

  Future<void> close() async {
    _state = ConnectionState.disconnected;
    // Ensure all data is sent before closing.
    try {
      if (sslEnabled && _sslUpgraded) {
        await _secureSocksSocket.flush();
      } else {
        await _socksSocket.flush();
      }
    } finally {
      await _subscription?.cancel();
      _outputController?.close();
      if (sslEnabled && _sslUpgraded) {
        await _secureSocksSocket.close();
        if (!_secureResponseController.isClosed) {
          _secureResponseController.close();
        }
      }
      if (!_sslUpgraded) {
        await _socksSocket.close();
      }
      if (!_responseController.isClosed) {
        _responseController.close();
      }
      _sslUpgraded = false;
    }
  }

  /// Cancels an in-flight connect operation. No-op if not connecting.
  Future<void> cancel() async {
    if (_state != ConnectionState.connecting) return;

    final c = _cancelCompleter;
    if (c == null || c.isCompleted) return;

    c.completeError(
      SocksCancelledException(
        message: 'SOCKS5 connection cancelled.',
      ),
    );

    // Destroy socket to force pending operations to fail.
    if (_sslUpgrading) {
      _sslUpgrading = false;
    }
    _socksSocket.destroy();

    await _subscription?.cancel();
    _outputController?.close();
    if (!_responseController.isClosed) _responseController.close();
    if (!_secureResponseController.isClosed) {
      _secureResponseController.close();
    }

    _state = ConnectionState.disconnected;
  }

  /// Reconnects to the previously connected target.
  ///
  /// Throws [StateError] if [connectTo] was never called.
  Future<void> reconnect({String? isolationToken}) async {
    if (_targetDomain == null || _targetPort == null) {
      throw StateError('Cannot reconnect: no target known. '
          'Call connectTo() before reconnect().');
    }

    if (isolationToken != null) {
      _isolationToken = isolationToken;
    }

    try {
      await close();
    } catch (_) {
      // Connection may already be broken.
    }

    // Broadcast controllers can't be reused after close.
    _responseController = StreamController.broadcast();
    _secureResponseController = StreamController.broadcast();
    _outputController = null;

    // Re-establish connection sequence.
    await _init();
    await connect();
    await connectTo(_targetDomain!, _targetPort!);
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
