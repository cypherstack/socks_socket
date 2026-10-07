import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:socks_socket/socks_socket.dart';
import 'package:test/test.dart';

import 'helpers/tunnel_peer.dart';

const _deadline = tunnelDeadline;

// SOL_SOCKET, SO_SNDBUF and SO_LINGER differ between Linux and macOS.
final _solSocket = Platform.isMacOS ? 0xffff : 1;
final _soSndbuf = Platform.isMacOS ? 0x1001 : 7;
final _soLinger = Platform.isMacOS ? 0x80 : 13;

void main() {
  test('peer EOF drains a pending underlying socket flush', () async {
    final (client, peer) = await connectTunnel();
    final eof = client.inputStream.drain<void>();
    // Linux SO_SNDBUF: force the upload to remain pending while reads pause.
    client.socket.setRawOption(RawSocketOption.fromInt(1, 7, 4096));
    peer.input.pause();
    final payload = List<int>.generate(512 * 1024, (i) => i % 251);
    client.socket.add(payload);
    var flushed = false;
    final flushing = client.socket.flush().then((_) => flushed = true);
    flushing.ignore();
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(flushed, isFalse, reason: 'The regression needs a pending flush');
    await peer.socket.close();
    await eof.timeout(_deadline);
    peer.input.resume();
    await flushing.timeout(_deadline);
    await client.close().timeout(_deadline);
    await peer.done.future.timeout(_deadline);
    expect(peer.bytes.takeBytes(), payload);
  }, testOn: 'linux');

  for (final tls in [false, true]) {
    test('peer EOF drains underlying socket.addStream (TLS=$tls)', () async {
      final (client, peer) = await connectTunnel(tls: tls);
      final eof = client.inputStream.drain<void>();
      final source = StreamController<List<int>>();
      addTearDown(source.close);
      final uploading = client.socket.addStream(source.stream);
      uploading.ignore();
      source.add([65]);
      await peer.firstChunk.future.timeout(_deadline);
      await peer.socket.close();
      await eof.timeout(_deadline);
      source.add([66]);
      await source.close();
      await uploading.timeout(_deadline);
      await client.close().timeout(_deadline);
      await peer.done.future.timeout(_deadline);
      expect(peer.bytes.takeBytes(), [65, 66]);
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

  test('reset after peer EOF cancels a paused underlying upload source',
      () async {
    final (client, peer) = await connectTunnel();
    final eof = client.inputStream.drain<void>();
    final source = StreamController<List<int>>();
    addTearDown(() async {
      client.socket.destroy();
      await source.close();
    });
    // Shrink SO_SNDBUF to keep the source paused in an in-flight write.
    client.socket
        .setRawOption(RawSocketOption.fromInt(_solSocket, _soSndbuf, 4096));
    final uploading = client.socket.addStream(source.stream);
    final failed = expectLater(uploading, throwsA(isA<SocketException>()));
    source.add([65]);
    await peer.firstChunk.future.timeout(_deadline);
    peer.input.pause();
    source.add(List<int>.filled(512 * 1024, 66));
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(source.isPaused, isTrue);
    await peer.socket.close();
    await eof.timeout(_deadline);
    // SO_LINGER {on=1, seconds=0}: reset the remaining write side.
    peer.socket.setRawOption(RawSocketOption(_solSocket, _soLinger,
        Uint8List.view(Int32List.fromList([1, 0]).buffer)));
    peer.socket.destroy();
    await failed.timeout(_deadline);
    await client.close().timeout(_deadline);
    expect(source.hasListener, isFalse);
    await source.close().timeout(_deadline);
  }, testOn: 'linux || mac-os');

  for (final direct in [false, true]) {
    test('close times out when an upload never ends (direct=$direct)',
        () async {
      final (client, peer) = await connectTunnel(
        operationTimeout: const Duration(milliseconds: 100),
      );
      final eof = client.inputStream.drain<void>();
      final source = StreamController<List<int>>();
      addTearDown(source.close);
      final output = direct ? client.socket : client.outputStream;
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
}
