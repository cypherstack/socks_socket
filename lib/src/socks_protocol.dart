import 'dart:convert';
import 'dart:io';

class SocksProtocolFailure implements Exception {
  final String message;
  final bool rejected;
  final int? replyCode;
  const SocksProtocolFailure(this.message,
      {this.rejected = false, this.replyCode});
}

List<int> encodeSocksCredentials(String username, String password) {
  final user = utf8.encode(username);
  final pass = utf8.encode(password);
  if (user.isEmpty || user.length > 255 || pass.isEmpty || pass.length > 255) {
    throw ArgumentError(
        'SOCKS credentials must each contain 1–255 UTF-8 bytes');
  }
  return [1, user.length, ...user, pass.length, ...pass];
}

List<int> encodeSocksDestination(String host, int port) {
  if (port < 1 || port > 65535) throw ArgumentError.value(port, 'port');
  final address = InternetAddress.tryParse(host);
  late List<int> destination;
  if (address != null) {
    destination = [
      address.type == InternetAddressType.IPv4 ? 1 : 4,
      ...address.rawAddress
    ];
  } else {
    if (host.isEmpty ||
        host.length > 255 ||
        host.codeUnits.any((c) => c <= 32 || c >= 127) ||
        host.contains(RegExp(r'[/\\:@]'))) {
      throw ArgumentError('Use an ASCII destination hostname or numeric IP');
    }
    destination = [3, host.length, ...ascii.encode(host)];
  }
  return [5, 1, 0, ...destination, port >> 8, port & 255];
}

/// Null means more header bytes are needed; -1 denotes a malformed reply.
int? socksConnectReplyLength(List<int> reply) {
  if (reply.isEmpty) return null;
  if (reply[0] != 5) return -1;
  if (reply.length < 4) return null;
  if (reply[2] != 0) return -1;
  if (reply[1] != 0) return 4;
  switch (reply[3]) {
    case 1:
      return 10;
    case 4:
      return 22;
    case 3:
      if (reply.length < 5) return null;
      return reply[4] == 0 ? -1 : 7 + reply[4];
    default:
      return -1;
  }
}

Future<void> negotiateSocks({
  required Future<void> Function(List<int>) write,
  required Future<List<int>> Function(int) read,
  Future<List<int>> Function(List<int>, int)? exchange,
  List<int>? credentials,
  bool allowNoAuthFallback = false,
}) async {
  Future<List<int>> requestReply(List<int> request, int replyLength) async {
    if (exchange != null) return exchange(request, replyLength);
    await write(request);
    return read(replyLength);
  }

  final methods = credentials == null ? [0] : [if (allowNoAuthFallback) 0, 2];
  final greeting = await requestReply([5, methods.length, ...methods], 2);
  if (greeting[0] != 5) {
    throw const SocksProtocolFailure('invalid reply version');
  }
  if (greeting[1] == 0xFF) {
    throw const SocksProtocolFailure('proxy rejected authentication method',
        rejected: true);
  }
  if (credentials != null && greeting[1] == 0 && !allowNoAuthFallback) {
    throw const SocksProtocolFailure(
        'proxy selected no-auth but isolation is required');
  }
  if (!methods.contains(greeting[1])) {
    throw const SocksProtocolFailure('proxy rejected authentication method');
  }
  if (greeting[1] == 2) {
    final auth = await requestReply(credentials!, 2);
    if (auth[0] != 1 || auth[1] != 0) {
      throw const SocksProtocolFailure('username/password auth rejected',
          rejected: true);
    }
  }
}

void checkSocksConnectReply(List<int> reply) {
  final length = socksConnectReplyLength(reply);
  if (length == null || length < 0 || reply.length != length) {
    throw const SocksProtocolFailure('Invalid SOCKS reply');
  }
  if (reply[1] != 0) {
    throw SocksProtocolFailure('Proxy rejected CONNECT',
        rejected: true, replyCode: reply[1]);
  }
}
