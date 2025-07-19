import 'dart:async';
import 'dart:convert';
import 'dart:io';

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

  /// Private constructor.
  SOCKSSocket._(this.proxyHost, this.proxyPort, this.sslEnabled,
      this._handshakeTimeout, this._operationTimeout);

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
    Duration handshakeTimeout = const Duration(seconds: 30),
    Duration operationTimeout = const Duration(seconds: 30),
  }) async {
    // Create a SOCKS socket instance.
    var instance = SOCKSSocket._(
        proxyHost, proxyPort, sslEnabled, handshakeTimeout, operationTimeout);

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
  })  : _handshakeTimeout = const Duration(seconds: 30),
        _operationTimeout = const Duration(seconds: 30) {
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
        _responseController.addError(e);
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
              Exception('SOCKS5 handshake buffer overflow '
                  '(${buffer.length} bytes).'));
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
            Exception('Connection closed before SOCKS5 response received.'));
        }
      },
    );

    return completer.future.timeout(
      _handshakeTimeout,
      onTimeout: () {
        sub.cancel();
        throw TimeoutException(
          'SOCKS5 handshake timed out after '
          '${_handshakeTimeout.inSeconds} seconds.');
      },
    );
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
              Exception('SOCKS5 handshake buffer overflow '
                  '(${buffer.length} bytes).'));
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
            Exception('Connection closed before SOCKS5 response received.'));
        }
      },
    );

    return completer.future.timeout(
      _handshakeTimeout,
      onTimeout: () {
        sub.cancel();
        throw TimeoutException(
          'SOCKS5 handshake timed out after '
          '${_handshakeTimeout.inSeconds} seconds.');
      },
    );
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
    _state = ConnectionState.connecting;
    try {
      // Greeting and method selection.
      _socksSocket.add([0x05, 0x01, 0x00]);

      // Wait for server response (2 bytes per RFC 1928).
      var response = await _waitForResponse(2);

      // Check if the connection was successful.
      if (response[1] != 0x00) {
        throw Exception(
            'socks_socket.connect(): Failed to connect to SOCKS5 proxy.');
      }
    } catch (e) {
      _state = ConnectionState.error;
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
        throw Exception(
            'socks_socket.connectTo(): Failed to connect to target through SOCKS5 proxy.');
      }

      // Upgrade to SSL if needed.
      if (sslEnabled) {
        // Upgrade to SSL.
        _secureSocksSocket = await SecureSocket.secure(
          _socksSocket,
          host: domain,
          // onBadCertificate: (_) => true, // Uncomment this to bypass certificate validation (NOT recommended for production).
        );

        // Listen to the secure socket.
        _subscription = _secureSocksSocket.listen(
          (data) {
            // Add the data to the response controller.
            _secureResponseController.add(data);
          },
          onError: (e) {
            _secureResponseController.addError(e);
          },
          onDone: () {
            // Close the response controller when the socket is closed.
            _secureResponseController.close();
          },
        );
      }

      _state = ConnectionState.connected;
    } catch (e) {
      _state = ConnectionState.error;
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
  Future<void> close() async {
    _state = ConnectionState.disconnected;
    // Ensure all data is sent before closing.
    try {
      if (sslEnabled) {
        await _secureSocksSocket.flush();
      }
      await _socksSocket.flush();
    } finally {
      await _subscription?.cancel();
      _outputController?.close();
      if (sslEnabled) {
        await _secureSocksSocket.close();
        if (!_secureResponseController.isClosed) {
          _secureResponseController.close();
        }
      }
      await _socksSocket.close();
      if (!_responseController.isClosed) {
        _responseController.close();
      }
    }
  }

  /// Reconnects to the previously connected target.
  ///
  /// Throws [StateError] if [connectTo] was never called.
  Future<void> reconnect() async {
    if (_targetDomain == null || _targetPort == null) {
      throw StateError('Cannot reconnect: no target known. '
          'Call connectTo() before reconnect().');
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
