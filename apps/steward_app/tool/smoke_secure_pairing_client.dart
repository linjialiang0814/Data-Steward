import 'dart:convert';
import 'dart:io';

import 'package:steward_app/secure_pairing/pairing_client.dart';
import 'package:steward_app/secure_pairing/pairing_controller.dart';
import 'package:steward_app/secure_pairing/pairing_crypto.dart';
import 'package:steward_app/secure_pairing/pairing_errors.dart';
import 'package:steward_app/secure_pairing/pairing_models.dart';
import 'package:steward_app/secure_pairing/pairing_vault.dart';
import 'package:steward_app/secure_pairing/pinned_transport.dart';
import 'package:steward_app/secure_pairing/strict_json.dart';

Future<void> main() async {
  var stageName = 'input';
  final qrJson = stdin.readLineSync(encoding: utf8);
  if (qrJson == null) _fail('input_missing');
  final vault = _SmokeVault();
  const transport = IoPinFirstTransport();
  final controller = SecurePairingController(
    client: const SecurePairingClient(http: transport),
    vault: vault,
  );
  final qr = PairingQrDescriptor.fromJson(qrJson);
  final publicFragments = <String>[];
  try {
    stageName = 'begin';
    final shortCode = await controller.begin(
      qrJson: qrJson,
      requestedCapabilities: const ['session.sync'],
      displayName: 'B3D Dart Smoke',
    );
    final pending = await vault.loadPending();
    final stage = jsonEncode({
      'stage': 'awaiting_hub_confirm',
      'pairing_attempt_id': pending.pairingAttemptId,
      'device_id': pending.deviceId,
      'short_code': shortCode,
    });
    publicFragments.add(stage);
    stdout.writeln(stage);
    final command = stdin.readLineSync(encoding: utf8);
    if (command != 'hub_confirmed') _fail('control_invalid');
    stageName = 'confirm';
    if (!await controller.confirm()) _fail('activation_pending');
    final active = await vault.loadActive();

    stageName = 'rest';
    final create = await transport.send(
      uri: qr.baseUrl.replace(path: '/v1/conversations'),
      expectedFingerprint: qr.certFingerprint,
      method: 'POST',
      headers: deviceAuthorizationHeaders(
        ActiveCredentialView(
          deviceId: active.deviceId,
          deviceCredential: active.deviceCredential,
          capabilityEpoch: active.capabilityEpoch,
        ),
      ),
      body: jsonEncode({'title': 'B3D cross-language contract'}),
    );
    if (create.statusCode != 201) _fail('conversation_create_failed');
    final createBody = decodeStrictJsonObject(create.body);
    final conversationId = createBody['conversation_id'];
    if (conversationId is! String || conversationId.isEmpty) {
      _fail('conversation_response_invalid');
    }

    stageName = 'wss_connect';
    final socket = await AuthenticatedPinnedWebSocket.connect(
      uri: qr.baseUrl.replace(
        scheme: 'wss',
        path:
            '/v1/conversations/${Uri.encodeComponent(conversationId)}/events/ws',
        queryParameters: const {'after_seq': '0'},
      ),
      expectedFingerprint: qr.certFingerprint,
      deviceId: active.deviceId,
      credential: active.deviceCredential,
      capabilityEpoch: active.capabilityEpoch,
    );
    stageName = 'wss_ready';
    final ready = await socket.frames.first.timeout(
      const Duration(seconds: 10),
    );
    if (ready is! String) _fail('ready_frame_invalid');
    final readyBody = decodeStrictJsonObject(ready, maxUtf8Bytes: 4096);
    requireExactKeys(readyBody, const {'kind', 'last_conversation_seq'});
    if (readyBody['kind'] != 'ready' ||
        readyBody['last_conversation_seq'] != 0) {
      _fail('ready_frame_invalid');
    }
    await socket.close();

    stageName = 'wrong_pin';
    var wrongPinRejected = false;
    try {
      await transport.send(
        uri: qr.baseUrl.replace(path: '/health'),
        expectedFingerprint: qr.certFingerprint.replaceFirst(
          qr.certFingerprint[0],
          qr.certFingerprint[0] == '0' ? '1' : '0',
        ),
        method: 'GET',
        headers: const {},
      );
    } on SecurePairingException catch (error) {
      wrongPinRejected = error.code == 'tls_pin_mismatch';
    }
    if (!wrongPinRejected) _fail('wrong_pin_not_rejected');

    final secretMarkers = [
      qr.pairingToken,
      active.deviceCredential,
      vault.originalClaimSecret,
    ];
    final finalOutput = jsonEncode({
      'status': 'PASS',
      'client_language': 'dart',
      'hub_language': 'python',
      'human32_verified': true,
      'pairing_active': true,
      'authenticated_rest': true,
      'authenticated_wss': true,
      'wrong_pin_rejected': true,
      'permanent_auth_retry': classifyPairingError('auth_revoked').retryable,
      'secret_marker_count': publicFragments
          .where((fragment) => secretMarkers.any(fragment.contains))
          .length,
    });
    publicFragments.add(finalOutput);
    if (secretMarkers.any(finalOutput.contains)) {
      _fail('secret_output_detected');
    }
    stdout.writeln(finalOutput);
  } on Object catch (error) {
    final failure = jsonEncode({
      'status': 'FAIL',
      'stage': stageName,
      'error_code': switch (error) {
        SecurePairingException value => value.code,
        StateError value => value.message,
        _ => null,
      },
      'error_type': error.runtimeType.toString(),
    });
    if (!publicFragments.contains(failure)) stdout.writeln(failure);
    exitCode = 1;
  } finally {
    await controller.close();
  }
}

final class _SmokeVault implements PairingVault {
  PairingVaultStatus _status = PairingVaultStatus.empty;
  PendingPairingMaterial? _pending;
  ActiveDeviceCredential? _active;
  String originalClaimSecret = '';

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
    if (_status != PairingVaultStatus.empty) _fail('vault_not_empty');
    final credential = encodeBase64UrlNoPadding(secureRandomBytes(32));
    originalClaimSecret = encodeBase64UrlNoPadding(secureRandomBytes(32));
    _pending = PendingPairingMaterial(
      pairingAttemptId: pairingAttemptId,
      hubId: hubId,
      baseUrl: baseUrl,
      certFingerprint: certFingerprint,
      pairingSessionId: pairingSessionId,
      requestedCapabilities: requestedCapabilities,
      deviceCredential: credential,
      claimSecret: originalClaimSecret,
      clientNonce: encodeBase64UrlNoPadding(secureRandomBytes(16)),
    );
    _status = PairingVaultStatus.pending;
    return _pending!;
  }

  @override
  Future<PendingPairingMaterial> loadPending() async =>
      _pending ?? (throw StateError('pending_missing'));

  @override
  Future<void> saveHello({
    required String deviceId,
    required String shortCode,
  }) async {
    final current = await loadPending();
    _pending = PendingPairingMaterial(
      pairingAttemptId: current.pairingAttemptId,
      hubId: current.hubId,
      baseUrl: current.baseUrl,
      certFingerprint: current.certFingerprint,
      pairingSessionId: current.pairingSessionId,
      requestedCapabilities: current.requestedCapabilities,
      deviceCredential: current.deviceCredential,
      claimSecret: current.claimSecret,
      clientNonce: current.clientNonce,
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
    final current = await loadPending();
    _active = ActiveDeviceCredential(
      deviceId: deviceId,
      hubId: hubId,
      baseUrl: baseUrl,
      certFingerprint: certFingerprint,
      deviceCredential: current.deviceCredential,
      capabilityEpoch: capabilityEpoch,
      grantedCapabilities: grantedCapabilities,
    );
    _pending = null;
    _status = PairingVaultStatus.active;
  }

  @override
  Future<ActiveDeviceCredential> loadActive() async =>
      _active ?? (throw StateError('active_missing'));

  @override
  Future<ActiveDeviceCredential> updateActiveEndpoint({
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
  }) async {
    final current = await loadActive();
    _active = ActiveDeviceCredential(
      deviceId: current.deviceId,
      hubId: hubId,
      baseUrl: baseUrl,
      certFingerprint: certFingerprint,
      deviceCredential: current.deviceCredential,
      capabilityEpoch: current.capabilityEpoch,
      grantedCapabilities: current.grantedCapabilities,
    );
    return _active!;
  }

  @override
  Future<ActiveDeviceCredential> updateActiveAuthorization({
    required String deviceId,
    required String hubId,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  }) async {
    final current = await loadActive();
    _active = ActiveDeviceCredential(
      deviceId: deviceId,
      hubId: hubId,
      baseUrl: current.baseUrl,
      certFingerprint: current.certFingerprint,
      deviceCredential: current.deviceCredential,
      capabilityEpoch: capabilityEpoch,
      grantedCapabilities: grantedCapabilities,
    );
    return _active!;
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
    final current = await loadActive();
    _active = ActiveDeviceCredential(
      deviceId: deviceId,
      hubId: hubId,
      baseUrl: baseUrl,
      certFingerprint: certFingerprint,
      deviceCredential: current.deviceCredential,
      capabilityEpoch: capabilityEpoch,
      grantedCapabilities: grantedCapabilities,
    );
    return _active!;
  }

  @override
  Future<void> delete() async {
    _pending = null;
    _active = null;
    originalClaimSecret = '';
    _status = PairingVaultStatus.empty;
  }
}

Never _fail(String code) => throw StateError(code);
