## 1.2.0

### Bug Fixes

- Fix SOCKS5 response reassembly for fragmented TCP packets that previously caused RangeError.
- Fix proxy connection hang when proxy drops connection without responding; now raises timeout error.
- Fix SSL socket leak in close() method; SSL socket is now properly closed before plain socket.
- Fix outputStream getter creating a new StreamController on every call.
- Fix error handler double-reporting errors as both Object and String.
- Deprecate non-async SOCKSSocket() constructor that caused LateInitializationError; use SOCKSSocket.create() instead.
- Fix broadcast stream subscription race during SOCKS5 handshake using Completer-based approach.

### Features

- Add configurable connection timeouts via handshakeTimeout and operationTimeout parameters (default 30s).
- Add newline option to write() for line-delimited protocols like ElectrumX.
- Add ConnectionState enum for checking connection state (disconnected, connecting, connected, error).
- Add reconnect() method for reconnecting after a dropped connection without creating a new instance.

### Internal

- Rewrite connect/connectTo to use Completer-based handshake helpers and state transitions.
- Add comprehensive test suite with mock SOCKS5 server covering happy path, fragmented responses, timeouts, SSL, and error conditions.

## 1.0.0

- Dart & Flutter 3.
- Supports SOCKS version 5 protocol.
- SSL support.
- Supports ElectrumX and Fulcrum servers via socket(s).
- Async support for non-blocking network communication.
- Lightweight and minimal dependencies.
- Working example.
