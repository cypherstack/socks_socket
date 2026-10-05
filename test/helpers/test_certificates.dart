import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

class TestCertificates {
  final String caPem;
  final String leafPem;
  final String leafKeyPem;

  TestCertificates._(this.caPem, this.leafPem, this.leafKeyPem);

  factory TestCertificates.generate({
    List<String> dnsNames = const ['localhost'],
    List<InternetAddress> addresses = const [],
    Duration validity = const Duration(days: 30),
  }) {
    final random = FortunaRandom()
      ..seed(KeyParameter(Uint8List.fromList(
          List.generate(32, (_) => Random.secure().nextInt(256)))));
    final notBefore = DateTime.now().toUtc().subtract(const Duration(hours: 1));
    final notAfter = notBefore.add(validity);
    final caKey = _generateKey(random);
    final leafKey = _generateKey(random);
    final caName = _name('socks_socket test CA');
    final ca = _certificate(
      random: random,
      issuer: caName,
      subject: caName,
      notBefore: notBefore,
      notAfter: notAfter,
      subjectKey: caKey.publicKey,
      issuerKey: caKey,
      extensions: [
        _extension('2.5.29.19', _seq([_boolean(true)]), critical: true),
        // keyCertSign and cRLSign.
        _extension('2.5.29.15', _bitString([0x06], unusedBits: 1),
            critical: true),
        _extension('2.5.29.14', _octetString(_keyId(caKey.publicKey))),
      ],
    );
    final leaf = _certificate(
      random: random,
      issuer: caName,
      subject: _name(dnsNames.isEmpty ? 'socks_socket test' : dnsNames.first),
      notBefore: notBefore,
      notAfter: notAfter,
      subjectKey: leafKey.publicKey,
      issuerKey: caKey,
      extensions: [
        _extension('2.5.29.19', _seq([]), critical: true),
        // digitalSignature.
        _extension('2.5.29.15', _bitString([0x80], unusedBits: 7),
            critical: true),
        _extension('2.5.29.37', _seq([_oid('1.3.6.1.5.5.7.3.1')])),
        _extension(
            '2.5.29.17',
            _seq([
              for (final name in dnsNames) _tlv(0x82, ascii.encode(name)),
              for (final address in addresses) _tlv(0x87, address.rawAddress),
            ]),
            critical: dnsNames.isEmpty),
        _extension('2.5.29.14', _octetString(_keyId(leafKey.publicKey))),
        _extension(
            '2.5.29.35',
            _seq([
              _tlv(0x80, _keyId(caKey.publicKey)),
            ])),
      ],
    );
    return TestCertificates._(
      _pem('CERTIFICATE', ca),
      _pem('CERTIFICATE', leaf),
      _pem('PRIVATE KEY', _privateKeyInfo(leafKey)),
    );
  }

  SecurityContext serverContext() => SecurityContext(withTrustedRoots: false)
    ..useCertificateChainBytes(utf8.encode(leafPem))
    ..usePrivateKeyBytes(utf8.encode(leafKeyPem));

  SecurityContext clientContext() => SecurityContext(withTrustedRoots: false)
    ..setTrustedCertificatesBytes(utf8.encode(caPem));
}

class _KeyPair {
  final ECPublicKey publicKey;
  final ECPrivateKey privateKey;
  _KeyPair(this.publicKey, this.privateKey);
}

final _curve = ECCurve_secp256r1();

_KeyPair _generateKey(SecureRandom random) {
  final generator = ECKeyGenerator()
    ..init(ParametersWithRandom(ECKeyGeneratorParameters(_curve), random));
  final pair = generator.generateKeyPair();
  return _KeyPair(pair.publicKey, pair.privateKey);
}

List<int> _certificate({
  required SecureRandom random,
  required List<int> issuer,
  required List<int> subject,
  required DateTime notBefore,
  required DateTime notAfter,
  required ECPublicKey subjectKey,
  required _KeyPair issuerKey,
  required List<List<int>> extensions,
}) {
  final serial = random.nextBytes(16)..[0] &= 0x7F;
  final algorithm = _seq([_oid('1.2.840.10045.4.3.2')]);
  final tbs = _seq([
    _tlv(0xA0, _integer(BigInt.two)),
    _integer(_unsigned(serial)),
    algorithm,
    issuer,
    _seq([_time(notBefore), _time(notAfter)]),
    subject,
    _subjectPublicKeyInfo(subjectKey),
    _tlv(0xA3, _seq(extensions)),
  ]);
  final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64))
    ..init(true, PrivateKeyParameter<ECPrivateKey>(issuerKey.privateKey));
  final signature =
      signer.generateSignature(Uint8List.fromList(tbs)) as ECSignature;
  return _seq([
    tbs,
    algorithm,
    _bitString(_seq([_integer(signature.r), _integer(signature.s)])),
  ]);
}

List<int> _subjectPublicKeyInfo(ECPublicKey key) => _seq([
      _seq([_oid('1.2.840.10045.2.1'), _oid('1.2.840.10045.3.1.7')]),
      _bitString(key.Q!.getEncoded(false)),
    ]);

List<int> _privateKeyInfo(_KeyPair key) => _seq([
      _integer(BigInt.zero),
      _seq([_oid('1.2.840.10045.2.1'), _oid('1.2.840.10045.3.1.7')]),
      _octetString(_seq([
        _integer(BigInt.one),
        _octetString(_fixed(key.privateKey.d!, 32)),
        _tlv(0xA1, _bitString(key.publicKey.Q!.getEncoded(false))),
      ])),
    ]);

List<int> _keyId(ECPublicKey key) =>
    SHA1Digest().process(key.Q!.getEncoded(false));

List<int> _name(String commonName) => _seq([
      _tlv(0x31, _seq([_oid('2.5.4.3'), _tlv(0x0C, utf8.encode(commonName))])),
    ]);

List<int> _extension(String oid, List<int> value, {bool critical = false}) =>
    _seq([_oid(oid), if (critical) _boolean(true), _octetString(value)]);

List<int> _time(DateTime time) {
  String two(int value) => value.toString().padLeft(2, '0');
  final text = '${two(time.year % 100)}${two(time.month)}${two(time.day)}'
      '${two(time.hour)}${two(time.minute)}${two(time.second)}Z';
  return _tlv(0x17, ascii.encode(text));
}

String _pem(String label, List<int> der) {
  final body = base64.encode(der);
  final lines = [
    for (var i = 0; i < body.length; i += 64)
      body.substring(i, min(i + 64, body.length)),
  ];
  return '-----BEGIN $label-----\n${lines.join('\n')}\n-----END $label-----\n';
}

BigInt _unsigned(List<int> bytes) =>
    bytes.fold(BigInt.zero, (value, byte) => (value << 8) | BigInt.from(byte));

List<int> _fixed(BigInt value, int length) => [
      for (var i = length - 1; i >= 0; i--)
        ((value >> (8 * i)) & BigInt.from(0xFF)).toInt(),
    ];

List<int> _integer(BigInt value) {
  final bytes = <int>[];
  var rest = value;
  do {
    bytes.insert(0, (rest & BigInt.from(0xFF)).toInt());
    rest >>= 8;
  } while (rest > BigInt.zero);
  if (bytes.first & 0x80 != 0) bytes.insert(0, 0);
  return _tlv(0x02, bytes);
}

List<int> _oid(String dotted) {
  final parts = dotted.split('.').map(int.parse).toList();
  final bytes = <int>[parts[0] * 40 + parts[1]];
  for (final part in parts.skip(2)) {
    final chunk = <int>[part & 0x7F];
    for (var rest = part >> 7; rest > 0; rest >>= 7) {
      chunk.insert(0, 0x80 | (rest & 0x7F));
    }
    bytes.addAll(chunk);
  }
  return _tlv(0x06, bytes);
}

List<int> _boolean(bool value) => _tlv(0x01, [value ? 0xFF : 0x00]);

List<int> _octetString(List<int> bytes) => _tlv(0x04, bytes);

List<int> _bitString(List<int> bytes, {int unusedBits = 0}) =>
    _tlv(0x03, [unusedBits, ...bytes]);

List<int> _seq(List<List<int>> items) =>
    _tlv(0x30, [for (final item in items) ...item]);

List<int> _tlv(int tag, List<int> value) {
  final length = value.length;
  final header = <int>[tag];
  if (length < 0x80) {
    header.add(length);
  } else {
    final bytes = <int>[];
    for (var rest = length; rest > 0; rest >>= 8) {
      bytes.insert(0, rest & 0xFF);
    }
    header
      ..add(0x80 | bytes.length)
      ..addAll(bytes);
  }
  return [...header, ...value];
}
