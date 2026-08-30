import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/secure_pairing/pairing_client.dart';
import 'package:steward_app/secure_pairing/pairing_controller.dart';
import 'package:steward_app/secure_pairing/pairing_crypto.dart';
import 'package:steward_app/secure_pairing/pairing_errors.dart';
import 'package:steward_app/secure_pairing/pairing_vault.dart';
import 'package:steward_app/secure_pairing/pinned_transport.dart';

void main() {
  test(
    'client independently verifies code then atomically activates vault',
    () async {
      final vault = _MemoryVault();
      final transport = _ContractTransport(vault);
      final controller = SecurePairingController(
        client: SecurePairingClient(http: transport),
        vault: vault,
      );
      final code = await controller.begin(
        qrJson: transport.qrJson,
        requestedCapabilities: const ['session.sync'],
        displayName: 'Huawei Android',
      );
      expect(code, hasLength(8));
      expect(controller.state, SecurePairingState.awaitingHumanConfirmation);
      expect(await controller.confirm(), isTrue);
      expect(controller.state, SecurePairingState.active);
      expect((await vault.loadActive()).grantedCapabilities, ['session.sync']);
    },
  );

  test(
    'different client material produces a different screenshot-race code',
    () {
      final base = pairingTranscript(
        hubId: _ContractTransport.hubId,
        certFingerprint: 'a' * 64,
        pairingSessionId: _ContractTransport.sessionId,
        pairingAttemptId: '01ARZ3NDEKTSV4RRFFQ69G5FAX',
        ottDigest: 'b' * 64,
        deviceCredentialDigest: 'c' * 64,
        claimSecretDigest: 'd' * 64,
        clientNonce: encodeBase64UrlNoPadding(List<int>.filled(16, 1)),
        capabilitiesDigest: requestedCapabilitiesDigest(['session.sync']),
      );
      final changed = base.replaceFirst(
        'client_nonce=${encodeBase64UrlNoPadding(List<int>.filled(16, 1))}',
        'client_nonce=${encodeBase64UrlNoPadding(List<int>.filled(16, 2))}',
      );
      expect(human32ForTranscript(base), isNot(human32ForTranscript(changed)));
    },
  );

  test('confirm loss recovers through claim-authenticated status', () async {
    final vault = _MemoryVault();
    final transport = _ContractTransport(vault, confirmPending: true);
    final controller = SecurePairingController(
      client: SecurePairingClient(http: transport),
      vault: vault,
    );
    await controller.begin(
      qrJson: transport.qrJson,
      requestedCapabilities: const ['session.sync'],
    );
    expect(await controller.confirm(), isFalse);
    transport.statusActive = true;
    expect(await controller.recoverAfterConfirmLoss(), isTrue);
    expect(await vault.status(), PairingVaultStatus.active);
    expect((await vault.loadActive()).grantedCapabilities, ['session.sync']);
    expect(transport.confirmRequestCount, 2);
  });

  test('process restart restores pinned pending context after hello', () async {
    final vault = _MemoryVault();
    final transport = _ContractTransport(vault);
    final first = SecurePairingController(
      client: SecurePairingClient(http: transport),
      vault: vault,
    );
    await first.begin(
      qrJson: transport.qrJson,
      requestedCapabilities: const ['session.sync'],
    );
    await first.close();

    final restored = SecurePairingController(
      client: SecurePairingClient(http: transport),
      vault: vault,
    );
    await restored.restorePending();
    expect(restored.state, SecurePairingState.awaitingHumanConfirmation);
    expect(await restored.confirm(), isTrue);
    final active = await vault.loadActive();
    expect(active.certFingerprint, 'a' * 64);
    expect(active.baseUrl, Uri.parse('https://127.0.0.1:9443'));
  });

  test('WAIT_STABLE retries exactly the same pending attempt once', () async {
    final vault = _MemoryVault();
    final transport = _ContractTransport(vault, transientHelloFailures: 1);
    final controller = SecurePairingController(
      client: SecurePairingClient(http: transport),
      vault: vault,
    );
    await expectLater(
      controller.begin(
        qrJson: transport.qrJson,
        requestedCapabilities: const ['session.sync'],
      ),
      throwsA(isA<SecurePairingException>()),
    );
    expect(controller.state, SecurePairingState.waitStable);
    await controller.retryHelloAfterStable(qrJson: transport.qrJson);
    expect(transport.helloAttemptIds, hasLength(2));
    expect(transport.helloAttemptIds.toSet(), hasLength(1));
    expect(controller.state, SecurePairingState.awaitingHumanConfirmation);
  });

  test(
    'WAIT_STABLE can be cancelled without retaining pending material',
    () async {
      final vault = _MemoryVault();
      final transport = _ContractTransport(vault, transientHelloFailures: 1);
      final controller = SecurePairingController(
        client: SecurePairingClient(http: transport),
        vault: vault,
      );
      await expectLater(
        controller.begin(
          qrJson: transport.qrJson,
          requestedCapabilities: const ['session.sync'],
        ),
        throwsA(isA<SecurePairingException>()),
      );
      expect(controller.state, SecurePairingState.waitStable);

      await controller.reset();

      expect(controller.state, SecurePairingState.idle);
      expect(await vault.status(), PairingVaultStatus.empty);
      expect(controller.shortCode, isNull);
      expect(controller.safeHubLabel, isNull);
    },
  );
}

final class _MemoryVault implements PairingVault {
  PairingVaultStatus _status = PairingVaultStatus.empty;
  PendingPairingMaterial? pending;
  ActiveDeviceCredential? active;

  @override
  Future<PairingVaultStatus> status() async => _status;

  @override
  Future<PendingPairingMaterial> createPending({
    required String pairingAttemptId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required String pairingSessionId,
    required List<String> requestedCapabilities,
  }) async {
    if (_status != PairingVaultStatus.empty) throw StateError('not empty');
    pending = PendingPairingMaterial(
      pairingAttemptId: pairingAttemptId,
      hubId: hubId,
      baseUrl: baseUrl,
      certFingerprint: certFingerprint,
      pairingSessionId: pairingSessionId,
      requestedCapabilities: requestedCapabilities,
      deviceCredential: encodeBase64UrlNoPadding(List<int>.filled(32, 17)),
      claimSecret: encodeBase64UrlNoPadding(List<int>.filled(32, 34)),
      clientNonce: encodeBase64UrlNoPadding(List<int>.filled(16, 51)),
    );
    _status = PairingVaultStatus.pending;
    return pending!;
  }

  @override
  Future<PendingPairingMaterial> loadPending() async => pending!;

  @override
  Future<void> saveHello({
    required String deviceId,
    required String shortCode,
  }) async {
    final value = pending!;
    pending = PendingPairingMaterial(
      pairingAttemptId: value.pairingAttemptId,
      hubId: value.hubId,
      baseUrl: value.baseUrl,
      certFingerprint: value.certFingerprint,
      pairingSessionId: value.pairingSessionId,
      requestedCapabilities: value.requestedCapabilities,
      deviceCredential: value.deviceCredential,
      claimSecret: value.claimSecret,
      clientNonce: value.clientNonce,
      deviceId: deviceId,
      shortCode: shortCode,
    );
  }

  @override
  Future<void> activate({
    required String deviceId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  }) async {
    active = ActiveDeviceCredential(
      deviceId: deviceId,
      hubId: hubId,
      baseUrl: baseUrl,
      certFingerprint: certFingerprint,
      deviceCredential: pending!.deviceCredential,
      capabilityEpoch: capabilityEpoch,
      grantedCapabilities: grantedCapabilities,
    );
    pending = null;
    _status = PairingVaultStatus.active;
  }

  @override
  Future<ActiveDeviceCredential> loadActive() async => active!;

  @override
  Future<ActiveDeviceCredential> updateActiveEndpoint({
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
  }) async {
    final value = active!;
    active = ActiveDeviceCredential(
      deviceId: value.deviceId,
      hubId: value.hubId,
      baseUrl: baseUrl,
      certFingerprint: value.certFingerprint,
      deviceCredential: value.deviceCredential,
      capabilityEpoch: value.capabilityEpoch,
      grantedCapabilities: value.grantedCapabilities,
    );
    return active!;
  }

  @override
  Future<ActiveDeviceCredential> updateActiveAuthorization({
    required String deviceId,
    required String hubId,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  }) async {
    final value = active!;
    active = ActiveDeviceCredential(
      deviceId: value.deviceId,
      hubId: value.hubId,
      baseUrl: value.baseUrl,
      certFingerprint: value.certFingerprint,
      deviceCredential: value.deviceCredential,
      capabilityEpoch: capabilityEpoch,
      grantedCapabilities: grantedCapabilities,
    );
    return active!;
  }

  @override
  Future<ActiveDeviceCredential> updateActiveEndpointAndAuthorization({
    required String deviceId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  }) async {
    final current = active!;
    active = ActiveDeviceCredential(
      deviceId: deviceId,
      hubId: hubId,
      baseUrl: baseUrl,
      certFingerprint: certFingerprint,
      deviceCredential: current.deviceCredential,
      capabilityEpoch: capabilityEpoch,
      grantedCapabilities: grantedCapabilities,
    );
    return active!;
  }

  @override
  Future<void> delete() async {
    pending = null;
    active = null;
    _status = PairingVaultStatus.empty;
  }
}

final class _ContractTransport implements PairingHttpTransport {
  _ContractTransport(
    this.vault, {
    this.confirmPending = false,
    this.transientHelloFailures = 0,
  });

  static const hubId = '01ARZ3NDEKTSV4RRFFQ69G5FAV';
  static const sessionId = '01ARZ3NDEKTSV4RRFFQ69G5FAW';
  static const deviceId = '01ARZ3NDEKTSV4RRFFQ69G5FAY';
  final _MemoryVault vault;
  final bool confirmPending;
  int transientHelloFailures;
  final List<String> helloAttemptIds = [];
  bool statusActive = false;
  int confirmRequestCount = 0;

  String get token => encodeBase64UrlNoPadding(List<int>.filled(32, 68));
  String get qrJson => jsonEncode({
    'protocol_version': pairingProtocolVersion,
    'hub_id': hubId,
    'base_url': 'https://127.0.0.1:9443',
    'cert_fingerprint': 'a' * 64,
    'pairing_session_id': sessionId,
    'pairing_token': token,
    'expires_at': '2026-08-01T00:02:00Z',
  });

  @override
  Future<PinnedHttpResponse> send({
    required Uri uri,
    required String expectedFingerprint,
    required String method,
    required Map<String, String> headers,
    String? body,
  }) async {
    if (uri.path.endsWith('/client_hello')) {
      final request = jsonDecode(body!) as Map<String, dynamic>;
      helloAttemptIds.add(request['pairing_attempt_id'] as String);
      if (transientHelloFailures > 0) {
        transientHelloFailures--;
        throw const SecurePairingException(
          'transient_network',
          PairingFailureKind.transient,
        );
      }
      final material = vault.pending!;
      final code = human32ForTranscript(
        pairingTranscript(
          hubId: hubId,
          certFingerprint: 'a' * 64,
          pairingSessionId: sessionId,
          pairingAttemptId: request['pairing_attempt_id'] as String,
          ottDigest: sha256Hex(decodeBase64UrlExact(token, 32)),
          deviceCredentialDigest: request['device_credential_digest'] as String,
          claimSecretDigest: sha256Hex(
            decodeBase64UrlExact(material.claimSecret, 32),
          ),
          clientNonce: material.clientNonce,
          capabilitiesDigest: requestedCapabilitiesDigest(['session.sync']),
        ),
      );
      return _json({
        'protocol_version': pairingProtocolVersion,
        'pairing_session_id': sessionId,
        'pairing_attempt_id': request['pairing_attempt_id'],
        'device_id': deviceId,
        'credential_status': 'PENDING',
        'short_verification_code': code,
        'server_time': '2026-08-01T00:00:00Z',
        'pending_expires_at_hint': '2026-08-01T00:05:00Z',
      });
    }
    if (uri.path.endsWith('/client_confirm')) {
      confirmRequestCount++;
      final remainsPending = confirmPending && !statusActive;
      return _json({
        'protocol_version': pairingProtocolVersion,
        'pairing_attempt_id': vault.pending!.pairingAttemptId,
        'device_id': deviceId,
        'credential_status': remainsPending ? 'PENDING' : 'ACTIVE',
        'granted_capabilities': remainsPending ? <String>[] : ['session.sync'],
        'capability_epoch': remainsPending ? 0 : 1,
      });
    }
    if (uri.path.endsWith('/status')) {
      return _json({
        'protocol_version': pairingProtocolVersion,
        'pairing_session_id': sessionId,
        'pairing_attempt_id': vault.pending!.pairingAttemptId,
        'session_state': statusActive ? 'ACTIVE_PAIR' : 'AWAITING_CONFIRM',
        'credential_status': statusActive ? 'ACTIVE' : 'PENDING',
        'device_id': deviceId,
        'capability_epoch': statusActive ? 1 : 0,
      });
    }
    throw StateError('unexpected path');
  }

  PinnedHttpResponse _json(Map<String, Object?> value) => PinnedHttpResponse(
    statusCode: 200,
    body: jsonEncode(value),
    headers: const {},
  );
}
