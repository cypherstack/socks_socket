## 2.0.0

- **Breaking:** Remove `SOCKSSocket.socket` so transport operations cannot bypass the wrapper's write queue and lifecycle tracking. Use `destroy()`, `close()`, `write()`, `outputStream`, and `inputStream` instead.
- **Breaking:** Caller-managed TLS through `SecureSocket.secure(socks.socket)` is no longer supported. Use `SOCKSSocket.create(sslEnabled: true, securityContext: ...)` to negotiate TLS during `connectTo()`.
- Add `destroy()` to abort without draining output; writes it cuts short fail instead of reporting success (#2). It also ends a connect, TLS handshake or `reconnect()` in flight, and a later `close()` completes normally even when it failed a close that was already draining.
- Add `closeOnPeerEof` to `create()`; pass `false` to keep writing after the peer half-closes (#3).
- `close()` now ends a `reconnect()` or TLS handshake in flight instead of being overtaken by the reconnect or waiting for the handshake deadline.
- Fail a handshake read or write at once when the socket reports its error synchronously, as macOS does for a reset peer, instead of waiting for the handshake deadline. `SocksConnection` shares the fix.
- Document that `reconnect()` works after `cancel()`.

## 1.4.0

- Add `SocksConnection.start` for `HttpClient.connectionFactory` (Dart 3.5).
- Validate targets, tokens and proxy replies.
- Keep handshake replies out of `inputStream`; buffer input until a listener attaches.
- Bound SSL handshakes; add `securityContext` and `requireIsolation` (defaults to true with a token: a no-auth proxy is now rejected).
- Serialize `write` and `outputStream`; report transport failures as `SocksConnectionException`.
- Reject overlapping connect calls; track peer close in `state`; `close()` or `cancel()` during connect spends the instance.
- Rename `ConnectionState` to `SocksSocketState` (alias kept); add `socks.dart` for Flutter.

## 1.3.0

### Features

- Typed exception hierarchy: sealed `SocksException` with `SocksHandshakeException`, `SocksRequestException`, `SocksConnectionException`, and `SocksCancelledException`. All implement `Exception` for backward compatibility.
- `SocksReplyCode` enum covering all 8 SOCKS5 reply codes (RFC 1928) with `fromByte()` lookup.
- Tor circuit isolation via `isolationToken` parameter on `create()` and `reconnect()`. Sends token as SOCKS5 username/password auth (RFC 1929) to request separate Tor circuits.
- `cancel()` method to abort in-flight `connect()`/`connectTo()` operations. No-op when already connected or disconnected.

## 1.2.0 (unpublished; included in 1.3.0)

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

## 1.1.1

- Example fixes only.

## 1.1.0

- Add `inputStream` and `outputStream`.

## 1.0.0

- Dart & Flutter 3.
- Supports SOCKS version 5 protocol.
- SSL support.
- Supports ElectrumX and Fulcrum servers via socket(s).
- Async support for non-blocking network communication.
- Lightweight and minimal dependencies.
- Working example.
