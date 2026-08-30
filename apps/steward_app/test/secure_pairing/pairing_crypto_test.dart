import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/secure_pairing/pairing_crypto.dart';
import 'package:steward_app/secure_pairing/pairing_errors.dart';
import 'package:steward_app/secure_pairing/strict_json.dart';

void main() {
  test('DataSteward Human32 matches all normative vectors', () {
    const vectors = <(String, String)>[
      (
        'protocol_version=pairing_auth/1\n'
            'hub_id=01ARZ3NDEKTSV4RRFFQ69G5FAV\n'
            'cert_fingerprint=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
            'pairing_session_id=01ARZ3NDEKTSV4RRFFQ69G5FAW\n'
            'pairing_attempt_id=01ARZ3NDEKTSV4RRFFQ69G5FAX\n'
            'ott_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'
            'device_credential_digest=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n'
            'claim_secret_digest=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n'
            'client_nonce=AAAAAAAAAAAAAAAAAAAAAA\n'
            'requested_capabilities_digest=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n',
        '2EJ9Y5EW',
      ),
      (
        'protocol_version=pairing_auth/1\n'
            'hub_id=01BX5ZZKBKACTAV9WEVGEMMVRZ\n'
            'cert_fingerprint=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n'
            'pairing_session_id=01BX5ZZKBKACTAV9WEVGEMMVS0\n'
            'pairing_attempt_id=01BX5ZZKBKACTAV9WEVGEMMVS1\n'
            'ott_digest=0000000000000000000000000000000000000000000000000000000000000000\n'
            'device_credential_digest=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n'
            'claim_secret_digest=1111111111111111111111111111111111111111111111111111111111111111\n'
            'client_nonce=BBBBBBBBBBBBBBBBBBBBBB\n'
            'requested_capabilities_digest=2222222222222222222222222222222222222222222222222222222222222222\n',
        'J5PLXKDR',
      ),
      (
        'protocol_version=pairing_auth/1\n'
            'hub_id=01HXYZEXAMPLE000000000001\n'
            'cert_fingerprint=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n'
            'pairing_session_id=01HXYZEXAMPLE000000000002\n'
            'pairing_attempt_id=01HXYZEXAMPLE000000000003\n'
            'ott_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
            'device_credential_digest=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'
            'claim_secret_digest=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n'
            'client_nonce=CCCCCCCCCCCCCCCCCCCCCC\n'
            'requested_capabilities_digest=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\n',
        'ZHSEF84R',
      ),
    ];
    for (final vector in vectors) {
      expect(human32ForTranscript(vector.$1), vector.$2);
    }
  });

  test('secure encodings and ULID are canonical', () {
    final bytes = List<int>.generate(32, (index) => index);
    final encoded = encodeBase64UrlNoPadding(bytes);
    expect(encoded, hasLength(43));
    expect(decodeBase64UrlExact(encoded, 32), bytes);
    final ulid = generateUlid(
      now: DateTime.fromMillisecondsSinceEpoch(1700000000000, isUtc: true),
      random: Random(7),
    );
    expect(ulid, matches(r'^[0-7][0-9A-HJKMNP-TV-Z]{25}$'));
  });

  test('strict JSON rejects duplicate keys and non-finite values', () {
    expect(
      () => decodeStrictJsonObject('{"a":1,"a":2}'),
      throwsA(isA<SecurePairingException>()),
    );
    expect(
      () => decodeStrictJsonObject('{"a":1e999}'),
      throwsA(isA<SecurePairingException>()),
    );
    expect(decodeStrictJsonObject('{"a":[true,null,"x"]}')['a'], isA<List>());
  });

  test('capabilities are sorted and duplicates fail closed', () {
    expect(canonicalCapabilities(['session.sync', 'fs.read']), [
      'fs.read',
      'session.sync',
    ]);
    expect(
      () => canonicalCapabilities(['session.sync', 'session.sync']),
      throwsA(isA<SecurePairingException>()),
    );
    expect(requestedCapabilitiesDigest(['session.sync']), hasLength(64));
  });

  test('public error text never contains supplied secret', () {
    final secret = encodeBase64UrlNoPadding(List<int>.filled(32, 77));
    final error = classifyPairingError('auth_revoked');
    expect(error.toString(), isNot(contains(secret)));
    expect(error.retryable, isFalse);
    expect(classifyPairingError('auth_unavailable').retryable, isTrue);
  });
}
