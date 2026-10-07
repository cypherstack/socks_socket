import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/tunnel_peer.dart';

const _deadline = tunnelDeadline;

// SOL_SOCKET and SO_LINGER differ between Linux and macOS.
final _solSocket = Platform.isMacOS ? 0xffff : 1;
final _soLinger = Platform.isMacOS ? 0x80 : 13;

void main() {
  for (final tls in [false, true]) {
    test('peer EOF drains a pending write (TLS=$tls)', () async {
      final (client, peer) = await connectTunnel(tls: tls);
      final eof = client.inputStream.drain<void>();
      peer.input.pause();
      // Exceed the transport buffers without accessing the client's socket.
      final payload = 'A' * (8 * 1024 * 1024);
      var flushed = false;
      final writing = client.write(payload).then((_) => flushed = true);
      writing.ignore();
      await Future<void>.delayed(const Duration(milliseconds: 200));
      expect(flushed, isFalse, reason: 'The regression needs a pending write');
      await peer.socket.close();
      await eof.timeout(_deadline);
      peer.input.resume();
      await writing.timeout(_deadline);
      await client.close().timeout(_deadline);
      await peer.done.future.timeout(_deadline);
      expect(peer.bytes.takeBytes(), payload.codeUnits);
    });

    test('peer EOF drains an accepted outputStream (TLS=$tls)', () async {
      final (client, peer) = await connectTunnel(tls: tls);
      final eof = client.inputStream.drain<void>();
      final source = StreamController<List<int>>();
      addTearDown(source.close);
      final output = client.outputStream;
      final uploading = output.addStream(source.stream);
      uploading.ignore();
      source.add([65]);
      await peer.firstChunk.future.timeout(_deadline);
      await peer.socket.close();
      await eof.timeout(_deadline);

      expect(client.state, ConnectionState.disconnected);
      await expectLater(client.write('new write'), throwsStateError);
      expect(() => output.add([67]), throwsStateError);
      expect(() => output.addStream(Stream.value([68])), throwsStateError);
      source.add([66]);
      await source.close();
      await uploading.timeout(_deadline);
      await output.done.timeout(_deadline);
      await client.close().timeout(_deadline);
      await peer.done.future.timeout(_deadline);
      expect(peer.bytes.takeBytes(), [65, 66]);
    });
    test('closeOnPeerEof: false keeps writes open after peer EOF (TLS=$tls)',
        () async {
      final (client, peer) =
          await connectTunnel(tls: tls, closeOnPeerEof: false);
      final eof = client.inputStream.drain<void>();
      await peer.socket.close();
      await eof.timeout(_deadline);

      expect(client.state, ConnectionState.connected);
      await client.write('A').timeout(_deadline);
      await client.outputStream
          .addStream(Stream.value([66]))
          .timeout(_deadline);
      client.outputStream.add([67]);
      await client.close().timeout(_deadline);
      await peer.done.future.timeout(_deadline);
      expect(peer.bytes.takeBytes(), [65, 66, 67]);
      expect(client.state, ConnectionState.disconnected);
    });
  }

  test('an output sink first used after peer EOF rejects new uploads',
      () async {
    final (client, peer) = await connectTunnel();
    final eof = client.inputStream.drain<void>();
    await peer.socket.close();
    await eof.timeout(_deadline);
    expect(() => client.outputStream.add([65]), throwsStateError);
    expect(() => client.outputStream.addStream(Stream.value([66])),
        throwsStateError);
    await client.close().timeout(_deadline);
    await peer.done.future.timeout(_deadline);
    expect(peer.bytes.length, 0);
  });

  test('reset after peer EOF cancels a paused outputStream source', () async {
    final (client, peer) = await connectTunnel();
    final eof = client.inputStream.drain<void>();
    final source = StreamController<List<int>>();
    addTearDown(() async {
      client.destroy();
      await source.close();
    });
    final uploading = client.outputStream.addStream(source.stream);
    final failed =
        expectLater(uploading, throwsA(isA<SocksConnectionException>()));
    source.add([65]);
    await peer.firstChunk.future.timeout(_deadline);
    peer.input.pause();
    source.add(List<int>.filled(8 * 1024 * 1024, 66));
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(source.isPaused, isTrue);
    await peer.socket.close();
    await eof.timeout(_deadline);
    // SO_LINGER {on=1, seconds=0}: reset the remaining write side.
    peer.socket.setRawOption(RawSocketOption(_solSocket, _soLinger,
        Uint8List.view(Int32List.fromList([1, 0]).buffer)));
    peer.socket.destroy();
    await failed.timeout(_deadline);
    await expectLater(client.close().timeout(_deadline),
        throwsA(isA<SocksConnectionException>()));
    expect(source.hasListener, isFalse);
    await source.close().timeout(_deadline);
  }, testOn: 'linux || mac-os');

  test('close times out when an outputStream upload never ends', () async {
    final (client, peer) = await connectTunnel(
      operationTimeout: const Duration(milliseconds: 100),
    );
    final eof = client.inputStream.drain<void>();
    final source = StreamController<List<int>>();
    addTearDown(source.close);
    final output = client.outputStream;
    output.addStream(source.stream).ignore();
    source.add([65]);
    await peer.firstChunk.future.timeout(_deadline);
    await peer.socket.close();
    await eof.timeout(_deadline);
    await expectLater(
        client.close().timeout(_deadline), throwsA(isA<TimeoutException>()));
    await peer.done.future.timeout(_deadline);
    expect(client.state, ConnectionState.disconnected);
    expect(source.hasListener, isFalse);
  });
}
