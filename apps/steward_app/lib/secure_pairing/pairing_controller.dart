import 'dart:async';
import 'dart:convert';

import 'pairing_client.dart';
import 'pairing_crypto.dart';
import 'pairing_errors.dart';
import 'pairing_models.dart';
import 'pairing_vault.dart';

enum SecurePairingState {
  idle,
  connecting,
  awaitingHumanConfirmation,
  awaitingHubConfirmation,
  active,
  waitStable,
  failed,
}

final class SecurePairingController {
  SecurePairingController({required this.client, required this.vault});

  final SecurePairingClient client;
  final PairingVault vault;
  final StreamController<SecurePairingState> _states =
      StreamController<SecurePairingState>.broadcast();
  SecurePairingState _state = SecurePairingState.idle;
  PairingQrDescriptor? _qr;
  List<String> _requestedCapabilities = const [];
  List<String> _activeGrants = const [];
  String? _shortCode;
  String? _safeHubLabel;

  SecurePairingState get state => _state;
  Stream<SecurePairingState> get states => _states.stream;
  String? get shortCode => _shortCode;
  String? get safeHubLabel => _safeHubLabel;
  List<String> get requestedCapabilities => _requestedCapabilities;
  List<String> get activeGrants => _activeGrants;

  Future<void> initialize() async {
    if (_state != SecurePairingState.idle) return;
    switch (await vault.status()) {
      case PairingVaultStatus.empty:
        return;
      case PairingVaultStatus.pending:
        await restorePending();
        return;
      case PairingVaultStatus.active:
        final active = await vault.loadActive();
        _activeGrants = active.grantedCapabilities;
        _safeHubLabel = _safeLabel(active.hubId, active.certFingerprint);
        _set(SecurePairingState.active);
        return;
    }
  }

  Future<String> begin({
    required String qrJson,
    required List<String> requestedCapabilities,
    String? displayName,
  }) async {
    if (_state != SecurePairingState.idle ||
        await vault.status() != PairingVaultStatus.empty) {
      throw const SecurePairingException(
        'pairing_state_invalid',
        PairingFailureKind.permanent,
      );
    }
    _set(SecurePairingState.connecting);
    try {
      final qr = PairingQrDescriptor.fromJson(qrJson);
      final capabilities = canonicalCapabilities(requestedCapabilities);
      final attemptId = generateUlid();
      final material = await vault.createPending(
        pairingAttemptId: attemptId,
        hubId: qr.hubId,
        baseUrl: qr.baseUrl,
        certFingerprint: qr.certFingerprint,
        pairingSessionId: qr.pairingSessionId,
        requestedCapabilities: capabilities,
      );
      _validateMaterial(
        material,
        attemptId,
        qr: qr,
        capabilities: capabilities,
      );
      _qr = qr;
      _safeHubLabel = _safeLabel(qr.hubId, qr.certFingerprint);
      _requestedCapabilities = capabilities;
      return await _sendHello(
        qr: qr,
        material: material,
        capabilities: capabilities,
        displayName: displayName,
      );
    } on SecurePairingException catch (error) {
      if (!error.retryable) await vault.delete();
      _set(
        error.retryable
            ? SecurePairingState.waitStable
            : SecurePairingState.failed,
      );
      rethrow;
    }
  }

  Future<String> retryHelloAfterStable({
    required String qrJson,
    String? displayName,
  }) async {
    if (_state != SecurePairingState.waitStable ||
        await vault.status() != PairingVaultStatus.pending) {
      throw const SecurePairingException(
        'pairing_state_invalid',
        PairingFailureKind.permanent,
      );
    }
    final qr = PairingQrDescriptor.fromJson(qrJson);
    final material = await vault.loadPending();
    _validateMaterial(material, material.pairingAttemptId);
    if (material.hubId != qr.hubId ||
        material.baseUrl != qr.baseUrl ||
        material.certFingerprint != qr.certFingerprint ||
        material.pairingSessionId != qr.pairingSessionId) {
      throw const SecurePairingException(
        'pairing_attempt_conflict',
        PairingFailureKind.permanent,
      );
    }
    _qr = qr;
    _safeHubLabel = _safeLabel(qr.hubId, qr.certFingerprint);
    _requestedCapabilities = material.requestedCapabilities;
    _set(SecurePairingState.connecting);
    try {
      return await _sendHello(
        qr: qr,
        material: material,
        capabilities: material.requestedCapabilities,
        displayName: displayName,
      );
    } on SecurePairingException catch (error) {
      if (!error.retryable) await vault.delete();
      _set(
        error.retryable
            ? SecurePairingState.waitStable
            : SecurePairingState.failed,
      );
      rethrow;
    }
  }

  Future<String> retryAfterStable({String? displayName}) async {
    final qr = _qr;
    if (qr == null ||
        _state != SecurePairingState.waitStable ||
        await vault.status() != PairingVaultStatus.pending) {
      throw const SecurePairingException(
        'pairing_state_invalid',
        PairingFailureKind.permanent,
      );
    }
    final material = await vault.loadPending();
    _validateMaterial(material, material.pairingAttemptId, qr: qr);
    _set(SecurePairingState.connecting);
    try {
      return await _sendHello(
        qr: qr,
        material: material,
        capabilities: material.requestedCapabilities,
        displayName: displayName,
      );
    } on SecurePairingException catch (error) {
      if (!error.retryable) await vault.delete();
      _set(
        error.retryable
            ? SecurePairingState.waitStable
            : SecurePairingState.failed,
      );
      rethrow;
    }
  }

  Future<String> _sendHello({
    required PairingQrDescriptor qr,
    required PendingPairingMaterial material,
    required List<String> capabilities,
    required String? displayName,
  }) async {
    final attemptId = material.pairingAttemptId;
    final credentialDigest = sha256Hex(
      decodeBase64UrlExact(material.deviceCredential, 32),
    );
    final claimDigest = sha256Hex(
      decodeBase64UrlExact(material.claimSecret, 32),
    );
    final response = await client.hello(
      qr: qr,
      pairingAttemptId: attemptId,
      pairingToken: qr.pairingToken,
      claimSecret: material.claimSecret,
      deviceCredentialDigest: credentialDigest,
      clientNonce: material.clientNonce,
      requestedCapabilities: capabilities,
      displayName: displayName,
    );
    final localCode = human32ForTranscript(
      pairingTranscript(
        hubId: qr.hubId,
        certFingerprint: qr.certFingerprint,
        pairingSessionId: qr.pairingSessionId,
        pairingAttemptId: attemptId,
        ottDigest: sha256Hex(decodeBase64UrlExact(qr.pairingToken, 32)),
        deviceCredentialDigest: credentialDigest,
        claimSecretDigest: claimDigest,
        clientNonce: material.clientNonce,
        capabilitiesDigest: requestedCapabilitiesDigest(capabilities),
      ),
    );
    if (!constantTimeEquals(
      ascii.encode(localCode),
      ascii.encode(response.shortCode),
    )) {
      await vault.delete();
      throw const SecurePairingException(
        'short_code_integrity',
        PairingFailureKind.integrity,
      );
    }
    await vault.saveHello(deviceId: response.deviceId, shortCode: localCode);
    _shortCode = localCode;
    _set(SecurePairingState.awaitingHumanConfirmation);
    return localCode;
  }

  Future<bool> confirm() async {
    final qr = _qr;
    if (qr == null || _state != SecurePairingState.awaitingHumanConfirmation) {
      throw const SecurePairingException(
        'pairing_state_invalid',
        PairingFailureKind.permanent,
      );
    }
    final material = await vault.loadPending();
    if (material.deviceId == null || material.shortCode == null) _integrity();
    final response = await client.confirm(
      qr: qr,
      pairingAttemptId: material.pairingAttemptId,
      claimSecret: material.claimSecret,
      shortCode: material.shortCode!,
    );
    if (response.deviceId != material.deviceId) _integrity();
    if (response.status == 'ACTIVE') {
      await _activate(
        response.deviceId,
        response.capabilityEpoch,
        response.grantedCapabilities,
      );
      return true;
    }
    _set(SecurePairingState.awaitingHubConfirmation);
    return false;
  }

  Future<void> restorePending() async {
    if (_state != SecurePairingState.idle ||
        await vault.status() != PairingVaultStatus.pending) {
      throw const SecurePairingException(
        'pairing_state_invalid',
        PairingFailureKind.permanent,
      );
    }
    final material = await vault.loadPending();
    _validateMaterial(material, material.pairingAttemptId);
    if (material.deviceId == null || material.shortCode == null) {
      await vault.delete();
      throw const SecurePairingException(
        'pairing_restart_required',
        PairingFailureKind.permanent,
      );
    }
    _qr = PairingQrDescriptor.fromJson(
      jsonEncode({
        'protocol_version': pairingProtocolVersion,
        'hub_id': material.hubId,
        'base_url': material.baseUrl.toString(),
        'cert_fingerprint': material.certFingerprint,
        'pairing_session_id': material.pairingSessionId,
        'pairing_token': encodeBase64UrlNoPadding(List<int>.filled(32, 0)),
        'expires_at': '1970-01-01T00:00:00Z',
      }),
    );
    _requestedCapabilities = material.requestedCapabilities;
    _shortCode = material.shortCode;
    _safeHubLabel = _safeLabel(material.hubId, material.certFingerprint);
    _set(SecurePairingState.awaitingHumanConfirmation);
  }

  Future<bool> recoverAfterConfirmLoss() async {
    final qr = _qr;
    if (qr == null) {
      throw const SecurePairingException(
        'pairing_state_invalid',
        PairingFailureKind.permanent,
      );
    }
    final material = await vault.loadPending();
    final status = await client.status(
      qr: qr,
      pairingAttemptId: material.pairingAttemptId,
      claimSecret: material.claimSecret,
    );
    if (status.credentialStatus == 'ACTIVE' &&
        status.deviceId != null &&
        status.capabilityEpoch >= 1) {
      if (material.deviceId == null || material.shortCode == null) _integrity();
      if (status.deviceId != material.deviceId) _integrity();
      final response = await client.confirm(
        qr: qr,
        pairingAttemptId: material.pairingAttemptId,
        claimSecret: material.claimSecret,
        shortCode: material.shortCode!,
      );
      if (response.status != 'ACTIVE' ||
          response.deviceId != status.deviceId ||
          response.capabilityEpoch != status.capabilityEpoch) {
        _integrity();
      }
      await _activate(
        response.deviceId,
        response.capabilityEpoch,
        response.grantedCapabilities,
      );
      return true;
    }
    if (status.credentialStatus == 'PENDING') {
      _set(SecurePairingState.awaitingHubConfirmation);
      return false;
    }
    throw const SecurePairingException(
      'pairing_expired',
      PairingFailureKind.permanent,
    );
  }

  Future<void> _activate(
    String deviceId,
    int epoch,
    List<String> grants,
  ) async {
    if (grants.any((grant) => !_requestedCapabilities.contains(grant))) {
      _integrity();
    }
    await vault.activate(
      deviceId: deviceId,
      hubId: _qr!.hubId,
      baseUrl: _qr!.baseUrl,
      certFingerprint: _qr!.certFingerprint,
      capabilityEpoch: epoch,
      grantedCapabilities: grants,
    );
    _activeGrants = List<String>.unmodifiable(grants);
    _shortCode = null;
    _set(SecurePairingState.active);
  }

  Future<void> reset() async {
    await vault.delete();
    _qr = null;
    _requestedCapabilities = const [];
    _activeGrants = const [];
    _shortCode = null;
    _safeHubLabel = null;
    _set(SecurePairingState.idle);
  }

  void _validateMaterial(
    PendingPairingMaterial value,
    String attemptId, {
    PairingQrDescriptor? qr,
    List<String>? capabilities,
  }) {
    if (value.pairingAttemptId != attemptId) _integrity();
    requireUlid(value.pairingAttemptId);
    requireUlid(value.hubId);
    requireUlid(value.pairingSessionId);
    requireDigest(value.certFingerprint);
    final canonical = canonicalCapabilities(value.requestedCapabilities);
    if ((qr != null &&
            (value.hubId != qr.hubId ||
                value.baseUrl != qr.baseUrl ||
                value.certFingerprint != qr.certFingerprint ||
                value.pairingSessionId != qr.pairingSessionId)) ||
        (capabilities != null &&
            canonical.join('\n') != capabilities.join('\n'))) {
      _integrity();
    }
    decodeBase64UrlExact(value.deviceCredential, 32);
    decodeBase64UrlExact(value.claimSecret, 32);
    decodeBase64UrlExact(value.clientNonce, 16);
  }

  void _set(SecurePairingState value) {
    _state = value;
    if (!_states.isClosed) _states.add(value);
  }

  Future<void> close() => _states.close();
}

String _safeLabel(String hubId, String fingerprint) =>
    'Hub ${hubId.substring(hubId.length - 6)} · pin ${fingerprint.substring(0, 8)}…';

Never _integrity() => throw const SecurePairingException(
  'protocol_integrity_error',
  PairingFailureKind.integrity,
);
