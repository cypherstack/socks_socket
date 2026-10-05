/// SOCKS5 reply codes as defined in RFC 1928 section 6.
enum SocksReplyCode {
  generalFailure(0x01, 'General SOCKS server failure'),

  connectionNotAllowed(0x02, 'Connection not allowed by ruleset'),

  networkUnreachable(0x03, 'Network unreachable'),

  hostUnreachable(0x04, 'Host unreachable'),

  connectionRefused(0x05, 'Connection refused'),

  ttlExpired(0x06, 'TTL expired'),

  commandNotSupported(0x07, 'Command not supported'),

  addressTypeNotSupported(0x08, 'Address type not supported');

  final int byte;

  final String description;

  const SocksReplyCode(this.byte, this.description);

  /// Null for unknown codes and for success (0x00).
  static SocksReplyCode? fromByte(int byte) {
    for (final code in values) {
      if (code.byte == byte) return code;
    }
    return null;
  }
}
