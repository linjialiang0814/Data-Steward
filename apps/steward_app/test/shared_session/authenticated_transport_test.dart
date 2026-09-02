import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/secure_pairing/pairing_errors.dart';
import 'package:steward_app/secure_pairing/pairing_vault.dart';
import 'package:steward_app/secure_pairing/pinned_transport.dart';
import 'package:steward_app/shared_session/authenticated_transport.dart';
import 'package:steward_app/shared_session/hub_rest_client.dart';
import 'package:steward_app/shared_session/shared_session_errors.dart';

void main() {
  test('private authenticated base accepts RFC1918 HTTPS only', () {
    expect(
      validateAuthenticatedPrivateBaseUri(
        Uri.parse('https://192.168.1.2:9443'),
        scheme: 'https',
      ).host,
      '192.168.1.2',
    );
    for (final value in [
      'http://192.168.1.2:9443',
      'https://127.0.0.1:9443',
      'https://8.8.8.8:9443',
      'https://192.168.1.2',
      'https://user@192.168.1.2:9443',
    ]) {
      expect(
        () => validateAuthenticatedPrivateBaseUri(
          Uri.parse(value),
          scheme: 'https',
        ),
        throwsA(isA<NetworkBoundaryException>()),
      );
    }
  });

  test(
    'authenticated health pins TLS and sends exact device headers',
    () async {
      final transport = _FakePinnedTransport();
      final credential = _credential();
      final rest = HubRestClient(
        baseUri: credential.baseUrl,
        client: PinnedAuthenticatedHttpClient(
          credential: credential,
          transport: transport,
        ),
        authenticatedPrivateLan: true,
        expectedTransportScope: 'private_lan_authenticated_service',
      );

      final health = await rest.health();

      expect(health.databaseReady, isTrue);
      expect(transport.fingerprint, 'a' * 64);
      expect(
        transport.headers['Authorization'],
        'Bearer ${credential.deviceCredential}',
      );
      expect(transport.headers['X-DataSteward-Device-Id'], credential.deviceId);
      expect(transport.headers['X-DataSteward-Capability-Epoch'], '1');
      expect(transport.headers['X-DataSteward-Protocol'], 'pairing_auth/1');
      rest.close();
    },
  );

  test(
    'flat permanent auth error is parsed without response leakage',
    () async {
      final rest = HubRestClient(
        baseUri: Uri.parse('https://192.168.1.2:9443'),
        client: PinnedAuthenticatedHttpClient(
          credential: _credential(),
          transport: _FakePinnedTransport(revoked: true),
        ),
        authenticatedPrivateLan: true,
        expectedTransportScope: 'private_lan_authenticated_service',
      );
      await expectLater(
        rest.createConversation(title: 'x'),
        throwsA(
          isA<HubApiException>().having(
            (value) => value.code,
            'code',
            'auth_revoked',
          ),
        ),
      );
      rest.close();
    },
  );

  test('REST adapter preserves transport and integrity failures', () async {
    for (final scenario in <(SecurePairingException, Matcher)>[
      (
        const SecurePairingException(
          'transient_network',
          PairingFailureKind.transient,
        ),
        isA<TransportException>().having(
          (value) => value.code,
          'code',
          'transient_network',
        ),
      ),
      (
        const SecurePairingException(
          'protocol_integrity_error',
          PairingFailureKind.integrity,
        ),
        isA<ProtocolIntegrityException>(),
      ),
      (
        const SecurePairingException(
          'capability_denied',
          PairingFailureKind.permanent,
        ),
        isA<HubApiException>()
            .having((value) => value.code, 'code', 'capability_denied')
            .having((value) => value.statusCode, 'status', 403),
      ),
    ]) {
      final rest = HubRestClient(
        baseUri: Uri.parse('https://192.168.1.2:9443'),
        client: PinnedAuthenticatedHttpClient(
          credential: _credential(),
          transport: _FakePinnedTransport(failure: scenario.$1),
        ),
        authenticatedPrivateLan: true,
        expectedTransportScope: 'private_lan_authenticated_service',
      );
      await expectLater(rest.health(), throwsA(scenario.$2));
      rest.close();
    }
  });
}

ActiveDeviceCredential _credential() => ActiveDeviceCredential(
  deviceId: '01ARZ3NDEKTSV4RRFFQ69G5FAX',
  hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
  baseUrl: Uri.parse('https://192.168.1.2:9443'),
  certFingerprint: 'a' * 64,
  deviceCredential: 'A' * 43,
  capabilityEpoch: 1,
  grantedCapabilities: const ['session.sync'],
);

final class _FakePinnedTransport implements PairingHttpTransport {
  _FakePinnedTransport({this.revoked = false, this.failure});

  final bool revoked;
  final SecurePairingException? failure;
  String? fingerprint;
  Map<String, String> headers = const {};

  @override
  Future<PinnedHttpResponse> send({
    required Uri uri,
    required String expectedFingerprint,
    required String method,
    required Map<String, String> headers,
    String? body,
  }) async {
    if (failure case final value?) throw value;
    fingerprint = expectedFingerprint;
    this.headers = Map<String, String>.of(headers);
    if (revoked) {
      return const PinnedHttpResponse(
        statusCode: 401,
        body: '{"error_code":"auth_revoked","message_key":"auth.auth_revoked"}',
        headers: {},
      );
    }
    return PinnedHttpResponse(
      statusCode: 200,
      body: jsonEncode({
        'status': 'ok',
        'protocol_version': 1,
        'database_ready': true,
        'transport_scope': 'private_lan_authenticated_service',
      }),
      headers: const {},
    );
  }
}
