## 1.3.0

### Features

- Typed exception hierarchy: sealed `SocksException` with `SocksHandshakeException`, `SocksRequestException`, `SocksConnectionException`, and `SocksCancelledException`. All implement `Exception` for backward compatibility.
- `SocksReplyCode` enum covering all 8 SOCKS5 reply codes (RFC 1928) with `fromByte()` lookup.
- Tor circuit isolation via `isolationToken` parameter on `create()` and `reconnect()`. Sends token as SOCKS5 username/password auth (RFC 1929) to request separate Tor circuits.
- `cancel()` method to abort in-flight `connect()`/`connectTo()` operations. No-op when already connected or disconnected.

## 1.2.0

### Bug Fixes

- Fix fragmented SOCKS5 response reassembly (previously caused RangeError).
- Fix connection hang when proxy drops without responding; now times out.
- Fix SSL socket leak in `close()`.
- Fix `outputStream` creating a new `StreamController` on every access.
- Fix error handler double-reporting errors as both Object and String.
- Deprecate non-async `SOCKSSocket()` constructor (causes `LateInitializationError`); use `SOCKSSocket.create()`.
- Fix broadcast stream subscription race during handshake via Completer-based approach.

### Features

- Configurable `handshakeTimeout` and `operationTimeout` on `create()` (default 30s).
- `write()` newline option for line-delimited protocols.
- `ConnectionState` enum (disconnected, connecting, connected, error).
- `reconnect()` to re-establish a dropped connection without creating a new instance.

## 1.0.0

- Dart & Flutter 3.
- Supports SOCKS version 5 protocol.
- SSL support.
- Supports ElectrumX and Fulcrum servers via socket(s).
- Async support for non-blocking network communication.
- Lightweight and minimal dependencies.
- Working example.
