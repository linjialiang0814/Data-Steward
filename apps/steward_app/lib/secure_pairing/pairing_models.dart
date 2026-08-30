import 'pairing_crypto.dart';
import 'pairing_errors.dart';
import 'strict_json.dart';

final _ulid = RegExp(r'^[0-7][0-9A-HJKMNP-TV-Z]{25}$');
final _digest = RegExp(r'^[0-9a-f]{64}$');
final _human32 = RegExp(r'^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8}$');

String requireUlid(Object? value) {
  if (value is! String || !_ulid.hasMatch(value)) _integrity();
  return value;
}

String requireDigest(Object? value) {
  if (value is! String || !_digest.hasMatch(value)) _integrity();
  return value;
}

int requireEpoch(Object? value, {bool allowZero = true}) {
  if (value is! int || value < (allowZero ? 0 : 1)) _integrity();
  return value;
}

Never _integrity() => securePairingFailure(
  'protocol_integrity_error',
  PairingFailureKind.integrity,
);

final class PairingQrDescriptor {
  PairingQrDescriptor({
    required this.hubId,
    required this.baseUrl,
    required this.certFingerprint,
    required this.pairingSessionId,
    required this.pairingToken,
    required this.expiresAt,
  });

  final String hubId;
  final Uri baseUrl;
  final String certFingerprint;
  final String pairingSessionId;
  final String pairingToken;
  final DateTime expiresAt;

  factory PairingQrDescriptor.fromJson(String source) {
    final map = decodeStrictJsonObject(source, maxUtf8Bytes: 4096);
    requireExactKeys(map, const {
      'protocol_version',
      'hub_id',
      'base_url',
      'cert_fingerprint',
      'pairing_session_id',
      'pairing_token',
      'expires_at',
    });
    if (map['protocol_version'] != pairingProtocolVersion) _integrity();
    final uri = Uri.tryParse(map['base_url'] as String? ?? '');
    if (uri == null ||
        uri.scheme != 'https' ||
        !uri.hasAuthority ||
        uri.host.isEmpty ||
        uri.host == '0.0.0.0' ||
        uri.userInfo.isNotEmpty ||
        uri.query.isNotEmpty ||
        uri.fragment.isNotEmpty) {
      _integrity();
    }
    final fingerprint = requireDigest(map['cert_fingerprint']);
    final token = map['pairing_token'];
    if (token is! String) _integrity();
    decodeBase64UrlExact(token, 32);
    final expires = DateTime.tryParse(map['expires_at'] as String? ?? '');
    if (expires == null || !expires.isUtc) _integrity();
    return PairingQrDescriptor(
      hubId: requireUlid(map['hub_id']),
      baseUrl: uri,
      certFingerprint: fingerprint,
      pairingSessionId: requireUlid(map['pairing_session_id']),
      pairingToken: token,
      expiresAt: expires,
    );
  }
}

final class ClientHelloResponse {
  ClientHelloResponse({
    required this.pairingSessionId,
    required this.pairingAttemptId,
    required this.deviceId,
    required this.shortCode,
  });

  final String pairingSessionId;
  final String pairingAttemptId;
  final String deviceId;
  final String shortCode;

  factory ClientHelloResponse.fromJson(String source) {
    final map = decodeStrictJsonObject(source);
    requireExactKeys(map, const {
      'protocol_version',
      'pairing_session_id',
      'pairing_attempt_id',
      'device_id',
      'credential_status',
      'short_verification_code',
      'server_time',
      'pending_expires_at_hint',
    });
    if (map['protocol_version'] != pairingProtocolVersion ||
        map['credential_status'] != 'PENDING') {
      _integrity();
    }
    final short = map['short_verification_code'];
    if (short is! String || !_human32.hasMatch(short)) _integrity();
    for (final key in const ['server_time', 'pending_expires_at_hint']) {
      final parsed = DateTime.tryParse(map[key] as String? ?? '');
      if (parsed == null || !parsed.isUtc) _integrity();
    }
    return ClientHelloResponse(
      pairingSessionId: requireUlid(map['pairing_session_id']),
      pairingAttemptId: requireUlid(map['pairing_attempt_id']),
      deviceId: requireUlid(map['device_id']),
      shortCode: short,
    );
  }
}

final class ClientConfirmResponse {
  ClientConfirmResponse({
    required this.pairingAttemptId,
    required this.deviceId,
    required this.status,
    required this.grantedCapabilities,
    required this.capabilityEpoch,
  });

  final String pairingAttemptId;
  final String deviceId;
  final String status;
  final List<String> grantedCapabilities;
  final int capabilityEpoch;

  factory ClientConfirmResponse.fromJson(String source) {
    final map = decodeStrictJsonObject(source);
    requireExactKeys(map, const {
      'protocol_version',
      'pairing_attempt_id',
      'device_id',
      'credential_status',
      'granted_capabilities',
      'capability_epoch',
    });
    final status = map['credential_status'];
    if (map['protocol_version'] != pairingProtocolVersion ||
        (status != 'PENDING' && status != 'ACTIVE')) {
      _integrity();
    }
    final rawCaps = map['granted_capabilities'];
    if (rawCaps is! List || rawCaps.any((value) => value is! String)) {
      _integrity();
    }
    final caps = rawCaps.isEmpty
        ? const <String>[]
        : canonicalCapabilities(rawCaps.cast<String>());
    final epoch = requireEpoch(map['capability_epoch']);
    if ((status == 'ACTIVE' && epoch < 1) ||
        (status == 'PENDING' && epoch != 0)) {
      _integrity();
    }
    return ClientConfirmResponse(
      pairingAttemptId: requireUlid(map['pairing_attempt_id']),
      deviceId: requireUlid(map['device_id']),
      status: status as String,
      grantedCapabilities: caps,
      capabilityEpoch: epoch,
    );
  }
}

final class PairingStatusResponse {
  PairingStatusResponse({
    required this.pairingSessionId,
    required this.pairingAttemptId,
    required this.sessionState,
    required this.credentialStatus,
    required this.deviceId,
    required this.capabilityEpoch,
  });

  final String pairingSessionId;
  final String pairingAttemptId;
  final String sessionState;
  final String credentialStatus;
  final String? deviceId;
  final int capabilityEpoch;

  factory PairingStatusResponse.fromJson(String source) {
    final map = decodeStrictJsonObject(source);
    requireExactKeys(map, const {
      'protocol_version',
      'pairing_session_id',
      'pairing_attempt_id',
      'session_state',
      'credential_status',
      'device_id',
      'capability_epoch',
    });
    const sessionStates = {
      'PAIRING_ACTIVE',
      'AWAITING_CONFIRM',
      'ACTIVE_PAIR',
      'ABORTED_TIMEOUT',
      'ABORTED_CANCEL',
      'ABORTED_MISMATCH',
      'ABORTED_HUB_RESTART',
      'ABORTED_PROTOCOL',
    };
    const credentialStates = {
      'PENDING',
      'ACTIVE',
      'UNKNOWN',
      'EXPIRED',
      'REVOKED',
    };
    if (map['protocol_version'] != pairingProtocolVersion ||
        !sessionStates.contains(map['session_state']) ||
        !credentialStates.contains(map['credential_status'])) {
      _integrity();
    }
    final device = map['device_id'];
    return PairingStatusResponse(
      pairingSessionId: requireUlid(map['pairing_session_id']),
      pairingAttemptId: requireUlid(map['pairing_attempt_id']),
      sessionState: map['session_state']! as String,
      credentialStatus: map['credential_status']! as String,
      deviceId: device == null ? null : requireUlid(device),
      capabilityEpoch: requireEpoch(map['capability_epoch']),
    );
  }
}
