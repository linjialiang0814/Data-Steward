import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../secure_pairing/pairing_crypto.dart';
import '../secure_pairing/pairing_errors.dart';
import '../secure_pairing/pairing_models.dart';
import '../secure_pairing/pinned_transport.dart';
import '../secure_pairing/strict_json.dart';

final class PairingOperatorStatus {
  const PairingOperatorStatus({
    required this.sessionId,
    required this.hubId,
    required this.state,
    required this.expiresAt,
    required this.attemptId,
    required this.shortCode,
    required this.requestedCapabilities,
    required this.grantedCapabilities,
    required this.displayName,
    required this.platform,
    required this.clientConfirmed,
    required this.hubConfirmed,
    required this.credentialStatus,
  });

  final String sessionId;
  final String hubId;
  final String state;
  final DateTime expiresAt;
  final String? attemptId;
  final String? shortCode;
  final List<String> requestedCapabilities;
  final List<String> grantedCapabilities;
  final String? displayName;
  final String? platform;
  final bool clientConfirmed;
  final bool hubConfirmed;
  final String? credentialStatus;

  bool get hasClientRequest => attemptId != null && shortCode != null;
  bool get isActive => credentialStatus == 'ACTIVE';

  factory PairingOperatorStatus.fromJson(String source) {
    final value = decodeStrictJsonObject(source, maxUtf8Bytes: 16384);
    requireExactKeys(value, const {
      'protocol_version',
      'pairing_session_id',
      'hub_id',
      'state',
      'expires_at_server',
      'terminal_reason',
      'pairing_attempt_id',
      'device_id',
      'short_verification_code',
      'requested_capabilities',
      'granted_capabilities',
      'display_name',
      'platform',
      'client_confirmed',
      'hub_confirmed',
      'credential_status',
      'capability_epoch',
    });
    if (value['protocol_version'] != pairingProtocolVersion) _integrity();
    final requested = _capabilities(
      value['requested_capabilities'],
      empty: true,
    );
    final granted = _capabilities(value['granted_capabilities'], empty: true);
    if (granted.any((capability) => !requested.contains(capability))) {
      _integrity();
    }
    final expires = DateTime.tryParse(
      value['expires_at_server'] as String? ?? '',
    );
    if (expires == null || !expires.isUtc) _integrity();
    final attempt = value['pairing_attempt_id'];
    final code = value['short_verification_code'];
    if (attempt != null) requireUlid(attempt);
    if (code != null &&
        (code is! String ||
            !RegExp(
              r'^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8}$',
            ).hasMatch(code))) {
      _integrity();
    }
    for (final key in const ['client_confirmed', 'hub_confirmed']) {
      if (value[key] is! bool) _integrity();
    }
    const states = {
      'PAIRING_ACTIVE',
      'AWAITING_CONFIRM',
      'ACTIVE_PAIR',
      'ABORTED_TIMEOUT',
      'ABORTED_CANCEL',
      'ABORTED_MISMATCH',
      'ABORTED_HUB_RESTART',
      'ABORTED_PROTOCOL',
    };
    const credentialStates = {'PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED'};
    final state = _string(value['state']);
    final credential = _optionalString(value['credential_status']);
    if (!states.contains(state) ||
        (credential != null && !credentialStates.contains(credential))) {
      _integrity();
    }
    return PairingOperatorStatus(
      sessionId: requireUlid(value['pairing_session_id']),
      hubId: requireUlid(value['hub_id']),
      state: state,
      expiresAt: expires,
      attemptId: attempt as String?,
      shortCode: code as String?,
      requestedCapabilities: requested,
      grantedCapabilities: granted,
      displayName: _optionalString(value['display_name']),
      platform: _optionalString(value['platform']),
      clientConfirmed: value['client_confirmed']! as bool,
      hubConfirmed: value['hub_confirmed']! as bool,
      credentialStatus: credential,
    );
  }
}

final class PairingOperatorClient {
  const PairingOperatorClient({required this.http});

  final PairingHttpTransport http;

  Future<PairingOperatorStatus> create({
    required Uri controlBaseUrl,
    required String fingerprint,
    required String operatorToken,
    required String pairingTokenDigest,
  }) async {
    final response = await _send(
      controlBaseUrl: controlBaseUrl,
      fingerprint: fingerprint,
      operatorToken: operatorToken,
      method: 'POST',
      path: '/v1/operator/pairing/sessions',
      body: jsonEncode({
        'pairing_token_digest': pairingTokenDigest,
        'ttl_seconds': 300,
      }),
    );
    if (response.statusCode != 201) _error(response);
    final created = decodeStrictJsonObject(response.body);
    requireExactKeys(created, const {
      'protocol_version',
      'hub_id',
      'cert_fingerprint',
      'pairing_session_id',
      'state',
      'expires_at_server',
    });
    if (created['protocol_version'] != pairingProtocolVersion ||
        created['state'] != 'PAIRING_ACTIVE' ||
        requireDigest(created['cert_fingerprint']) != fingerprint) {
      _integrity();
    }
    final sessionId = requireUlid(created['pairing_session_id']);
    return status(
      controlBaseUrl: controlBaseUrl,
      fingerprint: fingerprint,
      operatorToken: operatorToken,
      sessionId: sessionId,
    );
  }

  Future<PairingOperatorStatus> status({
    required Uri controlBaseUrl,
    required String fingerprint,
    required String operatorToken,
    required String sessionId,
  }) async {
    final response = await _send(
      controlBaseUrl: controlBaseUrl,
      fingerprint: fingerprint,
      operatorToken: operatorToken,
      method: 'GET',
      path: '/v1/operator/pairing/sessions/${Uri.encodeComponent(sessionId)}',
    );
    if (response.statusCode != 200) _error(response);
    final result = PairingOperatorStatus.fromJson(response.body);
    if (result.sessionId != sessionId) _integrity();
    return result;
  }

  Future<PairingOperatorStatus> confirm({
    required Uri controlBaseUrl,
    required String fingerprint,
    required String operatorToken,
    required String sessionId,
    required String attemptId,
    required List<String> grants,
  }) async {
    final response = await _send(
      controlBaseUrl: controlBaseUrl,
      fingerprint: fingerprint,
      operatorToken: operatorToken,
      method: 'POST',
      path:
          '/v1/operator/pairing/sessions/${Uri.encodeComponent(sessionId)}'
          '/attempts/${Uri.encodeComponent(attemptId)}/confirm',
      body: jsonEncode({'granted_capabilities': canonicalCapabilities(grants)}),
    );
    if (response.statusCode != 200) _error(response);
    return PairingOperatorStatus.fromJson(response.body);
  }

  Future<void> cancel({
    required Uri controlBaseUrl,
    required String fingerprint,
    required String operatorToken,
    required String sessionId,
  }) async {
    final response = await _send(
      controlBaseUrl: controlBaseUrl,
      fingerprint: fingerprint,
      operatorToken: operatorToken,
      method: 'POST',
      path:
          '/v1/operator/pairing/sessions/${Uri.encodeComponent(sessionId)}/cancel',
    );
    if (response.statusCode != 200) _error(response);
  }

  Future<PinnedHttpResponse> _send({
    required Uri controlBaseUrl,
    required String fingerprint,
    required String operatorToken,
    required String method,
    required String path,
    String? body,
  }) {
    if (operatorToken.length != 43) {
      throw const SecurePairingException(
        'operator_token_invalid',
        PairingFailureKind.permanent,
      );
    }
    return http.send(
      uri: controlBaseUrl.replace(path: path, query: null, fragment: null),
      expectedFingerprint: fingerprint,
      method: method,
      headers: {
        'Authorization': 'DataSteward-Operator $operatorToken',
        'X-DataSteward-Protocol': pairingProtocolVersion,
      },
      body: body,
    );
  }

  Never _error(PinnedHttpResponse response) {
    final value = decodeStrictJsonObject(response.body, maxUtf8Bytes: 4096);
    requireExactKeys(value, const {'error_code', 'message_key'});
    final code = value['error_code'];
    if (code is! String || value['message_key'] != 'operator.$code') {
      _integrity();
    }
    throw SecurePairingException(
      code,
      response.statusCode >= 500
          ? PairingFailureKind.transient
          : PairingFailureKind.permanent,
    );
  }
}

enum PairingHostState {
  setup,
  creating,
  waitingForPhone,
  awaitingApproval,
  active,
  failed,
}

final class PairingHostController extends ChangeNotifier {
  PairingHostController({required this.client});

  final PairingOperatorClient client;
  PairingHostState state = PairingHostState.setup;
  PairingOperatorStatus? status;
  String? qrPayload;
  String? safeErrorCode;
  Uri? _controlUrl;
  String? _fingerprint;
  String? _operatorToken;
  final Set<String> selectedGrants = {};

  Future<void> create({
    required String controlUrl,
    required String advertisedUrl,
    required String fingerprint,
    required String operatorToken,
  }) async {
    _set(PairingHostState.creating);
    try {
      final control = _operatorControlUrl(controlUrl);
      final advertised = _httpsUrl(advertisedUrl);
      requireDigest(fingerprint);
      decodeBase64UrlExact(operatorToken, 32);
      final rawPairingToken = encodeBase64UrlNoPadding(secureRandomBytes(32));
      final result = await client.create(
        controlBaseUrl: control,
        fingerprint: fingerprint,
        operatorToken: operatorToken,
        pairingTokenDigest: sha256Hex(
          decodeBase64UrlExact(rawPairingToken, 32),
        ),
      );
      _controlUrl = control;
      _fingerprint = fingerprint;
      _operatorToken = operatorToken;
      status = result;
      qrPayload = jsonEncode({
        'protocol_version': pairingProtocolVersion,
        'hub_id': result.hubId,
        'base_url': advertised.toString(),
        'cert_fingerprint': fingerprint,
        'pairing_session_id': result.sessionId,
        'pairing_token': rawPairingToken,
        'expires_at': result.expiresAt.toIso8601String(),
      });
      safeErrorCode = null;
      _set(PairingHostState.waitingForPhone);
    } on SecurePairingException catch (error) {
      safeErrorCode = error.code;
      _clearSecrets();
      _set(PairingHostState.failed);
    }
  }

  Future<void> refresh() async {
    final current = status;
    if (current == null) return;
    try {
      final next = await client.status(
        controlBaseUrl: _controlUrl!,
        fingerprint: _fingerprint!,
        operatorToken: _operatorToken!,
        sessionId: current.sessionId,
      );
      status = next;
      selectedGrants
        ..removeWhere((value) => !next.requestedCapabilities.contains(value))
        ..addAll(
          selectedGrants.isEmpty
              ? next.requestedCapabilities
              : const <String>[],
        );
      _set(
        next.isActive
            ? PairingHostState.active
            : next.hasClientRequest
            ? PairingHostState.awaitingApproval
            : PairingHostState.waitingForPhone,
      );
      if (next.hasClientRequest) qrPayload = null;
      if (next.isActive) _clearSecrets();
    } on SecurePairingException catch (error) {
      safeErrorCode = error.code;
      _set(PairingHostState.failed);
    }
  }

  Future<void> confirm() async {
    final current = status;
    if (current?.attemptId == null || selectedGrants.isEmpty) return;
    try {
      status = await client.confirm(
        controlBaseUrl: _controlUrl!,
        fingerprint: _fingerprint!,
        operatorToken: _operatorToken!,
        sessionId: current!.sessionId,
        attemptId: current.attemptId!,
        grants: selectedGrants.toList(),
      );
      _set(PairingHostState.awaitingApproval);
    } on SecurePairingException catch (error) {
      safeErrorCode = error.code;
      _set(PairingHostState.failed);
    }
  }

  Future<void> cancel() async {
    final current = status;
    try {
      if (current != null && _operatorToken != null) {
        await client.cancel(
          controlBaseUrl: _controlUrl!,
          fingerprint: _fingerprint!,
          operatorToken: _operatorToken!,
          sessionId: current.sessionId,
        );
      }
      reset();
    } on SecurePairingException catch (error) {
      safeErrorCode = error.code;
      status = null;
      selectedGrants.clear();
      _clearSecrets();
      _set(PairingHostState.failed);
    }
  }

  void toggleGrant(String capability, bool selected) {
    selected
        ? selectedGrants.add(capability)
        : selectedGrants.remove(capability);
    notifyListeners();
  }

  void reset() {
    status = null;
    safeErrorCode = null;
    selectedGrants.clear();
    _clearSecrets();
    _set(PairingHostState.setup);
  }

  void _clearSecrets() {
    qrPayload = null;
    _operatorToken = null;
  }

  void _set(PairingHostState value) {
    state = value;
    notifyListeners();
  }
}

Uri _httpsUrl(String source) {
  final value = Uri.tryParse(source.trim());
  if (value == null ||
      value.scheme != 'https' ||
      !value.hasAuthority ||
      value.host.isEmpty ||
      value.host == '0.0.0.0' ||
      value.userInfo.isNotEmpty ||
      value.query.isNotEmpty ||
      value.fragment.isNotEmpty) {
    _integrity();
  }
  return value;
}

Uri _operatorControlUrl(String source) {
  final value = Uri.tryParse(source.trim());
  if (value == null ||
      !value.hasAuthority ||
      value.host.isEmpty ||
      value.userInfo.isNotEmpty ||
      value.query.isNotEmpty ||
      value.fragment.isNotEmpty ||
      (value.scheme != 'https' &&
          !(value.scheme == 'http' && value.host == '127.0.0.1'))) {
    _integrity();
  }
  return value;
}

List<String> _capabilities(Object? value, {required bool empty}) {
  if (value is! List || value.any((item) => item is! String)) _integrity();
  if (value.isEmpty) return empty ? const [] : _integrity();
  return canonicalCapabilities(value.cast<String>());
}

String _string(Object? value) {
  if (value is! String || value.isEmpty || value.length > 128) _integrity();
  return value;
}

String? _optionalString(Object? value) => value == null ? null : _string(value);

Never _integrity() => throw const SecurePairingException(
  'protocol_integrity_error',
  PairingFailureKind.integrity,
);
