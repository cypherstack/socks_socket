import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';

import 'helpers/tunnel_proxy.dart';

void main() {
  test('HTTP example fetches a URL through the local SOCKS proxy', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    final requests = <HttpRequest>[];
    server.listen((request) {
      requests.add(request);
      request.response.write('example smoke test');
      request.response.close();
    });

    final proxy = TunnelProxy(upstreamPort: server.port);
    await proxy.start();
    addTearDown(proxy.close);

    final process = await Process.start(Platform.resolvedExecutable, [
      '--packages=.dart_tool/package_config.json',
      'example/http/http_connection.dart',
      '${proxy.port}',
      'http://example.invalid:${server.port}/smoke?check=1',
    ], environment: {
      'http_proxy': 'http://configured-proxy.invalid:3128',
      'https_proxy': 'http://configured-proxy.invalid:3128',
      'no_proxy': '',
      'NO_PROXY': '',
    });
    addTearDown(() {
      process.kill();
    });
    final stdout = process.stdout.transform(utf8.decoder).join();
    final stderr = process.stderr.transform(utf8.decoder).join();

    expect(await process.exitCode.timeout(const Duration(seconds: 10)), 0,
        reason: await stderr);
    expect((await stdout).trim(), 'HTTP 200');
    expect(proxy.connections, 1);
    expect(proxy.target, 'example.invalid');
    expect(proxy.targetPort, server.port);
    expect(requests, hasLength(1));
    expect(requests.single.method, 'GET');
    expect(requests.single.uri.toString(), '/smoke?check=1');
  });
}
