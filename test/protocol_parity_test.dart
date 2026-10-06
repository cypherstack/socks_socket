import 'dart:io';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/tunnel_proxy.dart';

void main() {
  for (final legacy in [true, false]) {
    group('shared protocol (legacy=$legacy)', () {
      Future<void> connect(TunnelProxy proxy,
          {String host = 'example.invalid', String? token}) async {
        await proxy.start();
        addTearDown(proxy.close);
        if (legacy) {
          final socket = await SOCKSSocket.create(
            proxyHost: InternetAddress.loopbackIPv4.address,
            proxyPort: proxy.port,
            isolationToken: token,
          );
          addTearDown(() => socket.close().catchError((_) {}));
          await socket.connect();
          await socket.connectTo(host, 443);
        } else {
          final socket = await SocksConnection.start(
            proxyHost: InternetAddress.loopbackIPv4,
            proxyPort: proxy.port,
            targetHost: host,
            targetPort: 443,
            credentials:
                token == null ? null : SocksCredentials.isolation(token),
          ).socket;
          addTearDown(socket.destroy);
        }
      }

      test('empty credentials fail before opening a TCP connection', () async {
        if (legacy) {
          await expectLater(
              SOCKSSocket.create(
                  proxyHost: '127.0.0.1', proxyPort: 1, isolationToken: ''),
              throwsArgumentError);
        } else {
          expect(() => SocksCredentials.isolation(''), throwsArgumentError);
        }
      });

      for (final entry in [
        ('127.0.0.1', 1),
        ('::1', 4),
        ('example.invalid', 3)
      ]) {
        test('encodes ${entry.$1} with address type ${entry.$2}', () async {
          final proxy = TunnelProxy();
          await connect(proxy, host: entry.$1);
          expect(proxy.target, entry.$1);
          expect(proxy.targetType, entry.$2);
        });
      }

      test('accepts 255-byte credentials', () async {
        final proxy = TunnelProxy();
        await connect(proxy, token: 'a' * 255);
        expect(proxy.username, 'a' * 255);
        expect(proxy.password, 'a' * 255);
      });

      test('rejects malformed authentication replies', () async {
        await expectLater(
            connect(TunnelProxy(authReply: [2, 0]), token: 'token'),
            throwsA(legacy
                ? isA<SocksHandshakeException>()
                : isA<SocksConnectException>()));
      });

      test('preserves rejected CONNECT reply codes', () async {
        await expectLater(
            connect(TunnelProxy(replyCode: 5)),
            throwsA(legacy
                ? isA<SocksRequestException>().having((e) => e.replyCode,
                    'reply', SocksReplyCode.connectionRefused)
                : isA<SocksConnectException>().having((e) => e.reply, 'reply',
                    SocksReplyCode.connectionRefused)));
      });
    });
  }
}
