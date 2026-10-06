library;

import 'dart:async';
import 'dart:io';

import 'src/connection_socket.dart';
import 'src/reply_code.dart';
import 'src/socks_protocol.dart';

export 'src/reply_code.dart';

enum SocksConnectError { cancelled, timedOut, protocol, rejected }

class SocksConnectException extends SocketException {
  final SocksConnectError code;
  final int? replyCode;
  const SocksConnectException(this.code, String message, {this.replyCode})
      : super(message);

  SocksReplyCode? get reply =>
      replyCode == null ? null : SocksReplyCode.fromByte(replyCode!);
}

class SocksCredentials {
  final List<int> _authRequest;
  SocksCredentials(String username, String password)
      : _authRequest = encodeSocksCredentials(username, password);

  factory SocksCredentials.isolation(String token) =>
      SocksCredentials(token, token);
}

class SocksConnection {
  static ConnectionTask<Socket> start({
    required InternetAddress proxyHost,
    required int proxyPort,
    required String targetHost,
    required int targetPort,
    String? tlsHost,
    SecurityContext? securityContext,
    SocksCredentials? credentials,
    List<String>? supportedProtocols,
    Duration timeout = const Duration(seconds: 30),
  }) {
    for (final port in [proxyPort, targetPort]) {
      if (port < 1 || port > 65535) throw ArgumentError.value(port, 'port');
    }
    if (proxyHost.type == InternetAddressType.unix) {
      throw ArgumentError('A numeric IP proxy address is required');
    }
    if (timeout <= Duration.zero) throw ArgumentError.value(timeout, 'timeout');
    if (tlsHost != null && tlsHost.isEmpty) {
      throw ArgumentError.value(tlsHost, 'tlsHost');
    }
    final request = encodeSocksDestination(targetHost, targetPort);
    final operation = _ConnectOperation();
    operation.run(proxyHost, proxyPort, request, tlsHost, securityContext,
        credentials, supportedProtocols, timeout);
    return ConnectionTask.fromSocket(operation.result.future, operation.cancel);
  }
}

class _ConnectOperation {
  final result = Completer<Socket>();
  _ConnectOperation() {
    result.future.ignore();
  }

  ConnectionTask<RawSocket>? _tcp;
  RawSocket? _raw;
  RawChannel? _channel;
  Timer? _timer;
  bool _aborted = false;

  void cancel() => _fail(const SocksConnectException(
      SocksConnectError.cancelled, 'SOCKS connection cancelled'));

  void _fail(Object error, [StackTrace? stack]) {
    _aborted = true;
    _timer?.cancel();
    _tcp?.cancel();
    _channel?.destroy();
    _raw?.close();
    if (!result.isCompleted) result.completeError(error, stack);
  }

  Future<void> run(
      InternetAddress host,
      int port,
      List<int> request,
      String? tlsHost,
      SecurityContext? context,
      SocksCredentials? credentials,
      List<String>? supportedProtocols,
      Duration timeout) async {
    _timer = Timer(
        timeout,
        () => _fail(const SocksConnectException(
            SocksConnectError.timedOut, 'SOCKS connection deadline exceeded')));
    try {
      _tcp = await RawSocket.startConnect(host, port);
      if (_aborted) _tcp!.cancel();
      final raw = await _tcp!.socket;
      _raw = raw;
      if (_aborted) {
        raw.close();
        return;
      }
      var channel = _channel = RawChannel(raw);
      await negotiateSocks(
          write: channel.write,
          read: channel.read,
          credentials: credentials?._authRequest);
      await channel.write(request);
      final reply = <int>[...await channel.read(4)];
      var length = socksConnectReplyLength(reply);
      if (length == null) {
        reply.addAll(await channel.read(1));
        length = socksConnectReplyLength(reply);
      }
      if (length != null && length > reply.length) {
        reply.addAll(await channel.read(length - reply.length));
      }
      checkSocksConnectReply(reply);
      if (tlsHost != null) {
        final secured = await RawSecureSocket.secure(raw,
            subscription: channel.detach(),
            host: tlsHost,
            context: context,
            supportedProtocols: supportedProtocols);
        _raw = secured;
        if (_aborted) {
          secured.close();
          return;
        }
        channel = _channel = RawChannel(secured);
      }
      if (_aborted) {
        channel.destroy();
        return;
      }
      _timer?.cancel();
      result.complete(channel.socket());
    } on SocksProtocolFailure catch (error, stack) {
      _fail(
          SocksConnectException(
              error.rejected
                  ? SocksConnectError.rejected
                  : SocksConnectError.protocol,
              error.message,
              replyCode: error.replyCode),
          stack);
    } catch (error, stack) {
      _fail(error, stack);
    }
  }
}
