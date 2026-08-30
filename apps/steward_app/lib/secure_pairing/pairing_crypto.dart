import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'pairing_errors.dart';

const pairingProtocolVersion = 'pairing_auth/1';
const dataStewardHuman32Alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
const _ulidAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

Uint8List secureRandomBytes(int length, {Random? random}) {
  if (length <= 0) throw ArgumentError.value(length, 'length');
  final rng = random ?? Random.secure();
  return Uint8List.fromList(
    List<int>.generate(length, (_) => rng.nextInt(256)),
  );
}

String encodeBase64UrlNoPadding(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

Uint8List decodeBase64UrlExact(String value, int expectedBytes) {
  if (!RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value)) {
    securePairingFailure('secret_invalid', PairingFailureKind.integrity);
  }
  try {
    final padded = value.padRight((value.length + 3) ~/ 4 * 4, '=');
    final decoded = Uint8List.fromList(base64Url.decode(padded));
    if (decoded.length != expectedBytes ||
        encodeBase64UrlNoPadding(decoded) != value) {
      securePairingFailure('secret_invalid', PairingFailureKind.integrity);
    }
    return decoded;
  } on SecurePairingException {
    rethrow;
  } on Object {
    securePairingFailure('secret_invalid', PairingFailureKind.integrity);
  }
}

String sha256Hex(List<int> bytes) => sha256.convert(bytes).toString();

bool constantTimeEquals(List<int> left, List<int> right) {
  var mismatch = left.length ^ right.length;
  final length = min(left.length, right.length);
  for (var i = 0; i < length; i++) {
    mismatch |= left[i] ^ right[i];
  }
  return mismatch == 0;
}

String generateUlid({DateTime? now, Random? random}) {
  final timestamp = (now ?? DateTime.now().toUtc()).millisecondsSinceEpoch;
  if (timestamp < 0 || timestamp > 0xFFFFFFFFFFFF) {
    throw ArgumentError.value(timestamp, 'timestamp');
  }
  var value = BigInt.from(timestamp);
  for (final byte in secureRandomBytes(10, random: random)) {
    value = (value << 8) | BigInt.from(byte);
  }
  final chars = List<String>.filled(26, '0');
  for (var i = 25; i >= 0; i--) {
    chars[i] = _ulidAlphabet[(value & BigInt.from(31)).toInt()];
    value >>= 5;
  }
  return chars.join();
}

String requestedCapabilitiesDigest(Iterable<String> capabilities) {
  final sorted = canonicalCapabilities(capabilities);
  return sha256Hex(utf8.encode(jsonEncode(sorted)));
}

List<String> canonicalCapabilities(Iterable<String> capabilities) {
  final values = capabilities.toSet().toList()..sort();
  if (values.isEmpty ||
      values.length > 32 ||
      values.length != capabilities.length) {
    securePairingFailure('capabilities_invalid', PairingFailureKind.integrity);
  }
  final token = RegExp(r'^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)+$');
  if (values.any((value) => value.length > 64 || !token.hasMatch(value))) {
    securePairingFailure('capabilities_invalid', PairingFailureKind.integrity);
  }
  return List<String>.unmodifiable(values);
}

String pairingTranscript({
  required String hubId,
  required String certFingerprint,
  required String pairingSessionId,
  required String pairingAttemptId,
  required String ottDigest,
  required String deviceCredentialDigest,
  required String claimSecretDigest,
  required String clientNonce,
  required String capabilitiesDigest,
}) =>
    'protocol_version=$pairingProtocolVersion\n'
    'hub_id=$hubId\n'
    'cert_fingerprint=$certFingerprint\n'
    'pairing_session_id=$pairingSessionId\n'
    'pairing_attempt_id=$pairingAttemptId\n'
    'ott_digest=$ottDigest\n'
    'device_credential_digest=$deviceCredentialDigest\n'
    'claim_secret_digest=$claimSecretDigest\n'
    'client_nonce=$clientNonce\n'
    'requested_capabilities_digest=$capabilitiesDigest\n';

String human32ForTranscript(String transcript) {
  final firstFive = sha256.convert(utf8.encode(transcript)).bytes.take(5);
  var value = BigInt.zero;
  for (final byte in firstFive) {
    value = (value << 8) | BigInt.from(byte);
  }
  final out = StringBuffer();
  for (var shift = 35; shift >= 0; shift -= 5) {
    out.write(
      dataStewardHuman32Alphabet[((value >> shift) & BigInt.from(31)).toInt()],
    );
  }
  return out.toString();
}
