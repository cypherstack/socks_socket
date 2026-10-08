import 'dart:async';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/tunnel_peer.dart';

void main() {
  for (final tls in [false, true]) {
    test('closeOutput rejects a racing write and a new output sink (TLS=$tls)',
        () async {
      final (client, peer) = await connectTunnel(tls: tls);
      final response = client.inputStream.first;
      response.ignore();
      await client.write('request');

      final closing = client.closeOutput();
      closing.ignore();
      expect(() => client.outputStream.add([0]), throwsStateError);
      final late = Future<void>.microtask(() => client.write('late'));
      await expectLater(late, throwsStateError);
      await closing.timeout(tunnelDeadline);
      await peer.done.future.timeout(tunnelDeadline);
      expect(peer.bytes.takeBytes(), 'request'.codeUnits);

      peer.socket.add([42]);
      await peer.socket.flush();
      expect(await response.timeout(tunnelDeadline), [42]);
      await client.close().timeout(tunnelDeadline);
    });

    test('closeOutput rejects new writes while draining an upload (TLS=$tls)',
        () async {
      final (client, peer) = await connectTunnel(tls: tls);
      final source = StreamController<List<int>>();
      addTearDown(() async {
        client.destroy();
        await source.close();
      });
      final response = client.inputStream.first;
      response.ignore();
      final output = client.outputStream;
      final uploading = output.addStream(source.stream);
      uploading.ignore();
      source.add([65]);
      await peer.firstChunk.future.timeout(tunnelDeadline);

      final closing = client.closeOutput();
      closing.ignore();
      await expectLater(client.write('late'), throwsStateError);
      expect(() => output.add([0]), throwsStateError);
      expect(() => output.addStream(Stream.value([0])), throwsStateError);
      source.add([66]);
      await source.close();
      await Future.wait([uploading, closing, client.closeOutput()])
          .timeout(tunnelDeadline);
      await peer.done.future.timeout(tunnelDeadline);
      expect(peer.bytes.takeBytes(), [65, 66]);

      peer.socket.add([42]);
      await peer.socket.flush();
      expect(await response.timeout(tunnelDeadline), [42]);
      expect(client.state, SocksSocketState.connected);
      await client.close().timeout(tunnelDeadline);
    });

    test('closeOutput timeout cancels an unfinished upload (TLS=$tls)',
        () async {
      final (client, peer) = await connectTunnel(
        tls: tls,
        operationTimeout: const Duration(milliseconds: 100),
      );
      final source = StreamController<List<int>>();
      addTearDown(() async {
        client.destroy();
        await source.close();
      });
      final inputDone = client.inputStream.drain<void>();
      final output = client.outputStream;
      final uploading = output.addStream(source.stream);
      uploading.ignore();
      source.add([65]);
      await peer.firstChunk.future.timeout(tunnelDeadline);

      await expectLater(client.closeOutput().timeout(tunnelDeadline),
          throwsA(isA<TimeoutException>()));
      expect(source.hasListener, isFalse);
      await expectLater(uploading, throwsA(isA<TimeoutException>()));
      await expectLater(output.done, throwsA(isA<TimeoutException>()));
      await inputDone.timeout(tunnelDeadline);
      await peer.done.future.timeout(tunnelDeadline);
      expect(client.state, SocksSocketState.error);
      await expectLater(client.write('late'), throwsStateError);
      await expectLater(client.close().timeout(tunnelDeadline),
          throwsA(isA<TimeoutException>()));
    });

    for (final peerEof in [false, true]) {
      test(
          '${peerEof ? 'peer EOF' : 'close()'} during closeOutput drains the upload (TLS=$tls)',
          () async {
        final (client, peer) = await connectTunnel(tls: tls);
        final inputDone = client.inputStream.drain<void>();
        final source = StreamController<List<int>>();
        addTearDown(() async {
          client.destroy();
          await source.close();
        });
        final uploading = client.outputStream.addStream(source.stream);
        uploading.ignore();
        source.add([65]);
        await peer.firstChunk.future.timeout(tunnelDeadline);
        final closingOutput = client.closeOutput();
        closingOutput.ignore();
        if (peerEof) {
          await peer.socket.close();
          await inputDone.timeout(tunnelDeadline);
        }
        final closing = client.close();
        closing.ignore();
        expect(client.state, SocksSocketState.disconnected);
        source.add([66]);
        await source.close();
        await Future.wait([uploading, closingOutput, closing])
            .timeout(tunnelDeadline);
        await inputDone.timeout(tunnelDeadline);
        await peer.done.future.timeout(tunnelDeadline);
        expect(peer.bytes.takeBytes(), [65, 66]);
      });
    }

    test(
        'destroy() interrupts closeOutput and a later close succeeds (TLS=$tls)',
        () async {
      final (client, peer) = await connectTunnel(tls: tls);
      final source = StreamController<List<int>>();
      addTearDown(() async {
        client.destroy();
        await source.close();
      });
      final inputDone = client.inputStream.drain<void>();
      final uploading = client.outputStream.addStream(source.stream);
      uploading.ignore();
      source.add([65]);
      await peer.firstChunk.future.timeout(tunnelDeadline);
      final closingOutput = client.closeOutput();
      closingOutput.ignore();
      client.destroy();

      final destroyed = throwsA(isA<SocksConnectionException>()
          .having((error) => error.message, 'message', contains('destroyed')));
      await expectLater(uploading, destroyed);
      await expectLater(closingOutput, destroyed);
      await client.close().timeout(tunnelDeadline);
      await inputDone.timeout(tunnelDeadline);
      expect(source.hasListener, isFalse);
      expect(client.state, SocksSocketState.disconnected);
    });
  }
}
