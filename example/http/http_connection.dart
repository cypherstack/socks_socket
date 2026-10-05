import 'dart:io';
import 'package:socks_socket/socks_connection.dart';

Future<void> main(List<String> args) async {
  if (args.isEmpty || args.length > 2) {
    print(
        'Usage: dart --packages=.dart_tool/package_config.json example/http/http_connection.dart PROXY_PORT [URL]');
    return;
  }
  final target =
      args.length == 2 ? Uri.parse(args[1]) : Uri.https('example.org', '/');
  final client = HttpClient()..findProxy = (_) => 'DIRECT';
  client.connectionFactory = (uri, _, __) async => SocksConnection.start(
        proxyHost: InternetAddress.loopbackIPv4,
        proxyPort: int.parse(args.first),
        targetHost: uri.host,
        targetPort: uri.port,
        tlsHost: uri.scheme == 'https' ? uri.host : null,
      );
  try {
    final response = await (await client.getUrl(target)).close();
    print('HTTP ${response.statusCode}');
    await response.drain<void>();
  } finally {
    client.close(force: true);
  }
}
