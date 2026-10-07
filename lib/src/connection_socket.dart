import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

class RawChannel {
  final RawSocket raw;
  late final StreamSubscription<RawSocketEvent> _subscription;
  late final StreamController<Uint8List> _incoming;
  Completer<void>? _readable;
  Completer<void>? _writable;
  bool _closed = false;
  bool _readClosed = false;
  bool _detached = false;
  bool _streaming = false;
  Object? _error;
  void Function()? _onDestroy;

  bool get isClosed => _closed;

  RawChannel(this.raw) {
    raw.readEventsEnabled = false;
    raw.writeEventsEnabled = false;
    _incoming = StreamController<Uint8List>(
      sync: true,
      onListen: () {
        if (!_readClosed && !_closed && !_detached) {
          raw.readEventsEnabled = true;
        }
      },
      onPause: () {
        if (!_closed && !_detached) raw.readEventsEnabled = false;
      },
      onResume: () {
        if (!_readClosed && !_closed && !_detached) {
          raw.readEventsEnabled = true;
        }
      },
      onCancel: () {
        if (!_readClosed && !_closed && !_detached) {
          _readClosed = true;
          raw.readEventsEnabled = false;
          raw.shutdown(SocketDirection.receive);
        }
      },
    );
    _subscription = raw.listen(_event, onError: (Object error) {
      _error = error;
      if (_streaming && !_incoming.isClosed) _incoming.addError(error);
      destroy();
    }, onDone: destroy);
  }

  void _event(RawSocketEvent event) {
    if (event == RawSocketEvent.read) {
      if (_streaming) {
        final bytes = raw.read();
        if (bytes != null) _incoming.add(bytes);
      } else {
        raw.readEventsEnabled = false;
        _readable?.complete();
        _readable = null;
      }
    } else if (event == RawSocketEvent.write) {
      raw.writeEventsEnabled = false;
      _writable?.complete();
      _writable = null;
    } else if (event == RawSocketEvent.readClosed) {
      _readClosed = true;
      _readable?.complete();
      _readable = null;
      if (_streaming && !_incoming.isClosed) _incoming.close();
    } else if (event == RawSocketEvent.closed) {
      destroy();
    }
  }

  Future<Uint8List> read(int count) async {
    final bytes = Uint8List(count);
    var offset = 0;
    while (offset < count) {
      _checkOpen();
      final chunk = raw.read(count - offset);
      if (chunk != null) {
        bytes.setRange(offset, offset + chunk.length, chunk);
        offset += chunk.length;
      } else {
        // A failed read reports its error, and closes this channel, before
        // returning; a waiter created now would never be completed.
        _checkOpen();
        if (_readClosed) {
          throw const SocketException('Incomplete SOCKS response');
        }
        final ready = _readable = Completer<void>();
        raw.readEventsEnabled = true;
        await ready.future;
      }
    }
    return bytes;
  }

  Future<void> write(List<int> bytes) async {
    var offset = 0;
    while (offset < bytes.length) {
      _checkOpen();
      offset += raw.write(bytes, offset);
      // A secure socket reports a failed write synchronously, closing this
      // channel before write() returns; a plain socket defers the report.
      _checkOpen();
      // Plain sockets may buffer the send; wait until writable before flushing.
      if (offset < bytes.length || raw is! RawSecureSocket) {
        final ready = _writable = Completer<void>();
        raw.writeEventsEnabled = true;
        await ready.future;
        _checkOpen();
      }
    }
  }

  void _checkOpen() {
    if (_closed) {
      throw _error ?? const SocketException('SOCKS transport closed');
    }
  }

  StreamSubscription<RawSocketEvent> detach() {
    _detached = true;
    raw.readEventsEnabled = false;
    raw.writeEventsEnabled = false;
    return _subscription;
  }

  Socket socket() {
    _streaming = true;
    if (_readClosed && !_incoming.isClosed) _incoming.close();
    return raw is RawSecureSocket ? _TlsSocket(this) : _ConnectionSocket(this);
  }

  void destroy() {
    if (_closed) return;
    _closed = true;
    raw.close();
    if (!_detached) _subscription.cancel();
    _readable?.complete();
    _readable = null;
    _writable?.complete();
    _writable = null;
    if (!_incoming.isClosed) _incoming.close();
    _onDestroy?.call();
  }
}

class _RawConsumer implements StreamConsumer<List<int>> {
  final RawChannel channel;
  StreamSubscription<List<int>>? _source;
  Completer<void>? _done;
  _RawConsumer(this.channel) {
    channel._onDestroy = () => _finish(
        channel._error ?? const SocketException('SOCKS transport closed'));
  }

  @override
  Future<void> addStream(Stream<List<int>> stream) {
    final done = _done = Completer<void>();
    final source = _source = stream.listen(null, cancelOnError: true);
    source
      ..onData((bytes) {
        source.pause();
        channel.write(bytes).then((_) {
          if (identical(_source, source)) source.resume();
        }, onError: _finish);
      })
      ..onError(_finish)
      ..onDone(_finish);
    if (channel._closed) {
      _finish(const SocketException('SOCKS transport closed'));
    }
    return done.future;
  }

  void _finish([Object? error, StackTrace? stack]) {
    final source = _source;
    final done = _done;
    _source = null;
    _done = null;
    source?.cancel();
    if (error == null) {
      done?.complete();
    } else {
      done?.completeError(error, stack);
      channel.destroy();
    }
  }

  @override
  Future<void> close() async {
    if (!channel._closed) channel.raw.shutdown(SocketDirection.send);
  }
}

class _ConnectionSocket extends StreamView<Uint8List> implements Socket {
  final RawChannel channel;
  late final IOSink _sink;
  _ConnectionSocket(this.channel) : super(channel._incoming.stream) {
    _sink = IOSink(_RawConsumer(channel));
    _sink.done.then<void>((_) {}, onError: (Object _) {});
  }
  @override
  InternetAddress get address => channel.raw.address;
  @override
  InternetAddress get remoteAddress => channel.raw.remoteAddress;
  @override
  int get port => channel.raw.port;
  @override
  int get remotePort => channel.raw.remotePort;
  @override
  Encoding get encoding => _sink.encoding;
  @override
  set encoding(Encoding value) => _sink.encoding = value;
  @override
  Future get done => _sink.done;
  @override
  void add(List<int> data) => _sink.add(data);
  @override
  void addError(Object error, [StackTrace? stackTrace]) =>
      throw UnsupportedError('Socket.addError');
  @override
  Future addStream(Stream<List<int>> stream) => _sink.addStream(stream);
  @override
  Future flush() => _sink.flush();
  @override
  Future close() => _sink.close();
  @override
  void destroy() {
    channel.destroy();
    try {
      _sink.close();
    } on StateError {
      // Aborted while a write was pending.
    }
  }

  @override
  void write(Object? object) => _sink.write(object);
  @override
  void writeln([Object? object = '']) => _sink.writeln(object);
  @override
  void writeAll(Iterable objects, [String separator = '']) =>
      _sink.writeAll(objects, separator);
  @override
  void writeCharCode(int charCode) => _sink.writeCharCode(charCode);
  @override
  bool setOption(SocketOption option, bool enabled) =>
      channel.raw.setOption(option, enabled);
  @override
  Uint8List getRawOption(RawSocketOption option) =>
      channel.raw.getRawOption(option);
  @override
  void setRawOption(RawSocketOption option) => channel.raw.setRawOption(option);
}

class _TlsSocket extends _ConnectionSocket implements SecureSocket {
  _TlsSocket(super.channel);
  RawSecureSocket get _secure => channel.raw as RawSecureSocket;
  @override
  X509Certificate? get peerCertificate => _secure.peerCertificate;
  @override
  String? get selectedProtocol => _secure.selectedProtocol;
  @override
  void renegotiate(
          {bool useSessionCache = true,
          bool requestClientCertificate = false,
          bool requireClientCertificate = false}) =>
      throw UnsupportedError('SecureSocket.renegotiate');
}
