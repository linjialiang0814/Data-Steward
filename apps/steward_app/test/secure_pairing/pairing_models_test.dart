import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/secure_pairing/pairing_crypto.dart';
import 'package:steward_app/secure_pairing/pairing_errors.dart';
import 'package:steward_app/secure_pairing/pairing_models.dart';

void main() {
  test('QR descriptor is strict and secret stays only in parsed object', () {
    final token = encodeBase64UrlNoPadding(List<int>.filled(32, 1));
    final qr = PairingQrDescriptor.fromJson(
      jsonEncode({
        'protocol_version': pairingProtocolVersion,
        'hub_id': '01ARZ3NDEKTSV4RRFFQ69G5FAV',
        'base_url': 'https://192.0.2.10:9443',
        'cert_fingerprint': 'a' * 64,
        'pairing_session_id': '01ARZ3NDEKTSV4RRFFQ69G5FAW',
        'pairing_token': token,
        'expires_at': '2026-08-01T00:00:00Z',
      }),
    );
    expect(qr.baseUrl.scheme, 'https');
    expect(qr.pairingToken, token);
  });

  test('QR rejects http, zero bind, extras, and duplicate keys', () {
    final token = encodeBase64UrlNoPadding(List<int>.filled(32, 1));
    Map<String, Object?> valid() => {
      'protocol_version': pairingProtocolVersion,
      'hub_id': '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      'base_url': 'https://127.0.0.1:9443',
      'cert_fingerprint': 'a' * 64,
      'pairing_session_id': '01ARZ3NDEKTSV4RRFFQ69G5FAW',
      'pairing_token': token,
      'expires_at': '2026-08-01T00:00:00Z',
    };
    for (final base in ['http://127.0.0.1:9443', 'https://0.0.0.0:9443']) {
      final value = valid()..['base_url'] = base;
      expect(
        () => PairingQrDescriptor.fromJson(jsonEncode(value)),
        throwsA(isA<SecurePairingException>()),
      );
    }
    final extra = valid()..['credential'] = token;
    expect(
      () => PairingQrDescriptor.fromJson(jsonEncode(extra)),
      throwsA(isA<SecurePairingException>()),
    );
  });

  test('hello and confirm response invariants fail closed', () {
    final hello = {
      'protocol_version': pairingProtocolVersion,
      'pairing_session_id': '01ARZ3NDEKTSV4RRFFQ69G5FAW',
      'pairing_attempt_id': '01ARZ3NDEKTSV4RRFFQ69G5FAX',
      'device_id': '01ARZ3NDEKTSV4RRFFQ69G5FAY',
      'credential_status': 'PENDING',
      'short_verification_code': '2EJ9Y5EW',
      'server_time': '2026-08-01T00:00:00Z',
      'pending_expires_at_hint': '2026-08-01T00:05:00Z',
    };
    expect(
      ClientHelloResponse.fromJson(jsonEncode(hello)).shortCode,
      '2EJ9Y5EW',
    );
    hello['credential_status'] = 'ACTIVE';
    expect(
      () => ClientHelloResponse.fromJson(jsonEncode(hello)),
      throwsA(isA<SecurePairingException>()),
    );

    final confirm = {
      'protocol_version': pairingProtocolVersion,
      'pairing_attempt_id': '01ARZ3NDEKTSV4RRFFQ69G5FAX',
      'device_id': '01ARZ3NDEKTSV4RRFFQ69G5FAY',
      'credential_status': 'ACTIVE',
      'granted_capabilities': ['session.sync'],
      'capability_epoch': 1,
    };
    expect(
      ClientConfirmResponse.fromJson(jsonEncode(confirm)).capabilityEpoch,
      1,
    );
    confirm['capability_epoch'] = 0;
    expect(
      () => ClientConfirmResponse.fromJson(jsonEncode(confirm)),
      throwsA(isA<SecurePairingException>()),
    );
  });
}
