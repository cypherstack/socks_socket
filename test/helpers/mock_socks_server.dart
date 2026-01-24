import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

/// Mock SOCKS5 server. Handles handshake then echoes data.
class MockSocksServer {
  ServerSocket? _server;
  RawServerSocket? _rawServer;

  int get port => _server?.port ?? _rawServer!.port;

  final List<dynamic> _clients = [];

  bool rejectConnection = false;

  int replyCode = 0x01;

  Duration? responseDelay;

  bool fragmentResponses = false;

  bool hangOnGreeting = false;

  bool dropConnection = false;

  bool sendInvalidResponse = false;

  bool requireAuth = false;

  bool rejectAuth = false;

  String? lastUsername;

  String? lastPassword;

  bool sslEnabled = false;

  SecurityContext? securityContext;

  Future<void> start() async {
    lastUsername = null;
    lastPassword = null;

    if (sslEnabled) {
      // RawServerSocket for SSL to avoid subscription conflicts.
      _rawServer =
          await RawServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      _rawServer!.listen(
        (rawClient) => _handleRawClient(rawClient),
        onError: (_) {},
      );
    } else {
      _server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      _server!.listen(
        (client) => _handlePlainClient(client),
        onError: (_) {},
      );
    }
  }

  Future<void> _handlePlainClient(Socket client) async {
    _clients.add(client);

    try {
      if (dropConnection) {
        client.destroy();
        return;
      }

      if (hangOnGreeting) {
        client.listen((_) {}, onError: (_) {}, onDone: () {});
        return;
      }

      const phaseGreeting = 0;
      const phaseConnect = 1;
      const phaseEcho = 2;

      var phase = phaseGreeting;
      final buffer = <int>[];
      Completer<void>? phaseCompleter;

      client.listen(
        (data) {
          if (phase == phaseEcho) {
            try {
              client.add(data);
            } catch (_) {}
            return;
          }
          buffer.addAll(data);
          final c = phaseCompleter;
          if (c != null && !c.isCompleted) c.complete();
        },
        onError: (_) {
          final c = phaseCompleter;
          if (c != null && !c.isCompleted) c.complete();
        },
        onDone: () {
          final c = phaseCompleter;
          if (c != null && !c.isCompleted) c.complete();
        },
      );

      // --- Phase: Greeting ---
      // Wait for at least 2 bytes to read VER and NMETHODS.
      while (buffer.length < 2) {
        phaseCompleter = Completer<void>();
        await phaseCompleter.future;
      }
      // Read NMETHODS to know total greeting length: 2 + NMETHODS.
      final nmethods = buffer[1];
      final greetingLen = 2 + nmethods;
      while (buffer.length < greetingLen) {
        phaseCompleter = Completer<void>();
        await phaseCompleter.future;
      }

      // Extract offered methods.
      final methods = buffer.sublist(2, greetingLen);
      final offersAuth = methods.contains(0x02);

      if (requireAuth && offersAuth) {
        // Select username/password auth (0x02).
        await _sendResponse(client, [0x05, 0x02]);

        // Consume greeting bytes.
        if (buffer.length > greetingLen) {
          final excess = buffer.sublist(greetingLen);
          buffer
            ..clear()
            ..addAll(excess);
        } else {
          buffer.clear();
        }

        // Wait for auth sub-negotiation: at least 2 bytes (VER + ULEN).
        while (buffer.length < 2) {
          phaseCompleter = Completer<void>();
          await phaseCompleter.future;
        }
        final ulen = buffer[1];
        // Need: 1 (ver) + 1 (ulen) + ulen (username) + 1 (plen).
        while (buffer.length < 2 + ulen + 1) {
          phaseCompleter = Completer<void>();
          await phaseCompleter.future;
        }
        final plen = buffer[2 + ulen];
        final totalAuthLen = 2 + ulen + 1 + plen;
        while (buffer.length < totalAuthLen) {
          phaseCompleter = Completer<void>();
          await phaseCompleter.future;
        }

        // Extract username and password.
        lastUsername = String.fromCharCodes(buffer.sublist(2, 2 + ulen));
        lastPassword =
            String.fromCharCodes(buffer.sublist(2 + ulen + 1, totalAuthLen));

        if (rejectAuth) {
          await _sendResponse(client, [0x01, 0x01]); // Auth failure.
          return;
        }
        await _sendResponse(client, [0x01, 0x00]); // Auth success.

        // Consume auth bytes before connect phase.
        if (buffer.length > totalAuthLen) {
          final excess = buffer.sublist(totalAuthLen);
          buffer
            ..clear()
            ..addAll(excess);
        } else {
          buffer.clear();
        }
      } else {
        // Select no-auth (0x00) -- original behavior.
        await _sendResponse(client, [0x05, 0x00]);

        // Consume greeting bytes.
        if (buffer.length > greetingLen) {
          final excess = buffer.sublist(greetingLen);
          buffer
            ..clear()
            ..addAll(excess);
        } else {
          buffer.clear();
        }
      }

      // --- Phase: Connect Command ---
      phase = phaseConnect;

      while (true) {
        if (buffer.length >= 5) {
          final domainLen = buffer[4];
          final expectedLen = 5 + domainLen + 2;
          if (buffer.length >= expectedLen) break;
        }
        phaseCompleter = Completer<void>();
        await phaseCompleter.future;
      }

      if (sendInvalidResponse) {
        client.add([0x05]);
        await client.flush();
        return;
      }

      if (rejectConnection) {
        await _sendResponse(
            client, [0x05, replyCode, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        return;
      }

      await _sendResponse(
          client, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

      // Switch to echo mode.
      phase = phaseEcho;
      buffer.clear();
    } on SocketException {
      // Client may disconnect mid-handshake during timeout tests.
    } catch (_) {
      // Silently handle any other errors in mock server.
    }
  }

  Future<void> _handleRawClient(RawSocket rawClient) async {
    _clients.add(rawClient);

    try {
      final buffer = <int>[];
      Completer<void>? readCompleter;

      late StreamSubscription<RawSocketEvent> rawSub;
      rawSub = rawClient.listen((event) {
        if (event == RawSocketEvent.read) {
          final chunk = rawClient.read();
          if (chunk != null && chunk.isNotEmpty) {
            buffer.addAll(chunk);
          }
          final c = readCompleter;
          if (c != null && !c.isCompleted) c.complete();
        }
      }, onError: (_) {
        final c = readCompleter;
        if (c != null && !c.isCompleted) c.complete();
      }, onDone: () {
        final c = readCompleter;
        if (c != null && !c.isCompleted) c.complete();
      });

      Future<void> waitForBytes(int n) async {
        while (buffer.length < n) {
          final c = Completer<void>();
          readCompleter = c;
          await c.future;
        }
      }

      // Phase 1: Read SOCKS5 greeting (3 bytes).
      rawClient.readEventsEnabled = true;
      await waitForBytes(3);

      // Send greeting response.
      _writeRaw(rawClient, [0x05, 0x00]);

      // Phase 2: Read connect command.
      buffer.clear();
      await waitForBytes(5);
      final domainLen = buffer[4];
      final expectedLen = 5 + domainLen + 2;
      await waitForBytes(expectedLen);

      // Send connect success response.
      _writeRaw(rawClient, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

      // Pass existing subscription to RawSecureSocket.
      final secureRaw = await RawSecureSocket.secureServer(
        rawClient,
        securityContext!,
        subscription: rawSub,
      );
      _clients.add(secureRaw);

      // Echo mode on the secure connection.
      secureRaw.listen((event) {
        if (event == RawSocketEvent.read) {
          final data = secureRaw.read();
          if (data != null && data.isNotEmpty) {
            secureRaw.write(data);
          }
        }
      }, onError: (_) {}, onDone: () {});
    } on SocketException {
      // Client may disconnect mid-handshake.
    } catch (_) {
      // Silently handle errors.
    }
  }

  void _writeRaw(RawSocket socket, List<int> data) {
    socket.write(Uint8List.fromList(data));
  }

  Future<void> _sendResponse(Socket client, List<int> data) async {
    if (responseDelay != null) {
      await Future.delayed(responseDelay!);
    }
    if (fragmentResponses) {
      for (final byte in data) {
        client.add([byte]);
        await client.flush();
        await Future.delayed(const Duration(milliseconds: 1));
      }
    } else {
      client.add(data);
      await client.flush();
    }
  }

  void disconnectAllClients() {
    for (final client in _clients) {
      try {
        if (client is Socket) {
          client.destroy();
        } else if (client is RawSocket) {
          client.close();
        }
      } catch (_) {}
    }
    _clients.clear();
  }

  Future<void> stop() async {
    disconnectAllClients();
    await _server?.close();
    _rawServer?.close();
  }
}
