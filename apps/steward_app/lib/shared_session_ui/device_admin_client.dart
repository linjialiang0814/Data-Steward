import 'dart:convert';

import 'package:http/http.dart' as http;

import '../secure_pairing/pairing_crypto.dart';
import '../secure_pairing/pairing_errors.dart';
import '../secure_pairing/pairing_models.dart';
import '../secure_pairing/strict_json.dart';
import '../shared_session/hub_rest_client.dart';

final class ManagedDeviceCredential {
  const ManagedDeviceCredential({
    required this.deviceId,
    required this.status,
    required this.capabilityEpoch,
    required this.requestedCapabilities,
    required this.grantedCapabilities,
    required this.displayName,
    required this.platform,
  });

  final String deviceId;
  final String status;
  final int capabilityEpoch;
  final List<String> requestedCapabilities;
  final List<String> grantedCapabilities;
  final String? displayName;
  final String platform;

  String get safeLabel =>
      displayName?.trim().isNotEmpty == true ? displayName!.trim() : platform;

  String get safeIdPrefix => '${deviceId.substring(0, 4)}…';

  factory ManagedDeviceCredential.fromJson(Object? source) {
    if (source is! Map<String, dynamic>) _integrity();
    requireExactKeys(source, const {
      'device_id',
      'status',
      'capability_epoch',
      'requested_capabilities',
      'granted_capabilities',
      'display_name',
      'platform',
    });
    final status = source['status'];
    final epoch = source['capability_epoch'];
    final platform = source['platform'];
    final displayName = source['display_name'];
    if (!const {'PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED'}.contains(status) ||
        epoch is! int ||
        epoch < 0 ||
        platform is! String ||
        platform.isEmpty ||
        platform.length > 64 ||
        (displayName != null &&
            (displayName is! String || displayName.length > 80))) {
      _integrity();
    }
    final requested = _capabilities(source['requested_capabilities']);
    final granted = _capabilities(
      source['granted_capabilities'],
      allowEmpty: true,
    );
    if (granted.any((value) => !requested.contains(value))) _integrity();
    return ManagedDeviceCredential(
      deviceId: requireUlid(source['device_id']),
      status: status! as String,
      capabilityEpoch: epoch,
      requestedCapabilities: requested,
      grantedCapabilities: granted,
      displayName: displayName as String?,
      platform: platform,
    );
  }
}

final class DeviceAuthorizationTransition {
  const DeviceAuthorizationTransition({
    required this.deviceId,
    required this.status,
    required this.capabilityEpoch,
    required this.grantedCapabilities,
    required this.changed,
    required this.closedConnectionCount,
  });

  final String deviceId;
  final String status;
  final int capabilityEpoch;
  final List<String> grantedCapabilities;
  final bool changed;
  final int closedConnectionCount;

  factory DeviceAuthorizationTransition.fromJson(String source) {
    final value = decodeStrictJsonObject(source, maxUtf8Bytes: 16384);
    requireExactKeys(value, const {
      'device_id',
      'status',
      'capability_epoch',
      'granted_capabilities',
      'changed',
      'closed_connection_count',
    });
    final status = value['status'];
    final epoch = value['capability_epoch'];
    final changed = value['changed'];
    final closed = value['closed_connection_count'];
    if (!const {'ACTIVE', 'REVOKED'}.contains(status) ||
        epoch is! int ||
        epoch < 1 ||
        changed is! bool ||
        closed is! int ||
        closed < 0) {
      _integrity();
    }
    return DeviceAuthorizationTransition(
      deviceId: requireUlid(value['device_id']),
      status: status! as String,
      capabilityEpoch: epoch,
      grantedCapabilities: _capabilities(value['granted_capabilities']),
      changed: changed,
      closedConnectionCount: closed,
    );
  }
}

abstract interface class DeviceAdminApi {
  Future<List<ManagedDeviceCredential>> listDevices();

  Future<DeviceAuthorizationTransition> updateCapabilities({
    required String deviceId,
    required int expectedEpoch,
    required List<String> grants,
  });

  Future<DeviceAuthorizationTransition> revoke({
    required String deviceId,
    required int expectedEpoch,
  });

  void close();
}

final class DeviceAdminClient implements DeviceAdminApi {
  DeviceAdminClient({
    required Uri baseUri,
    required this.operatorToken,
    http.Client? client,
  }) : baseUri = validateLoopbackBaseUri(baseUri, scheme: 'http'),
       _client = client ?? createDirectHttpClient() {
    decodeBase64UrlExact(operatorToken, 32);
  }

  final Uri baseUri;
  final String operatorToken;
  final http.Client _client;
  bool _closed = false;

  @override
  Future<List<ManagedDeviceCredential>> listDevices() async {
    final response = await _send('GET', '/v1/operator/devices');
    _expectOk(response, 200);
    final value = decodeStrictJsonObject(response.body, maxUtf8Bytes: 65536);
    requireExactKeys(value, const {'devices'});
    final devices = value['devices'];
    if (devices is! List || devices.length > 32) _integrity();
    return List<ManagedDeviceCredential>.unmodifiable(
      devices.map(ManagedDeviceCredential.fromJson),
    );
  }

  @override
  Future<DeviceAuthorizationTransition> updateCapabilities({
    required String deviceId,
    required int expectedEpoch,
    required List<String> grants,
  }) async {
    final response = await _send(
      'PUT',
      '/v1/operator/devices/${Uri.encodeComponent(requireUlid(deviceId))}'
          '/capabilities',
      body: {
        'expected_capability_epoch': expectedEpoch,
        'granted_capabilities': canonicalCapabilities(grants),
      },
    );
    _expectOk(response, 200);
    return DeviceAuthorizationTransition.fromJson(response.body);
  }

  @override
  Future<DeviceAuthorizationTransition> revoke({
    required String deviceId,
    required int expectedEpoch,
  }) async {
    final response = await _send(
      'POST',
      '/v1/operator/devices/${Uri.encodeComponent(requireUlid(deviceId))}'
          '/revoke',
      body: {'expected_capability_epoch': expectedEpoch},
    );
    _expectOk(response, 200);
    return DeviceAuthorizationTransition.fromJson(response.body);
  }

  Future<_AdminResponse> _send(
    String method,
    String path, {
    Map<String, Object>? body,
  }) async {
    if (_closed) {
      throw const SecurePairingException(
        'operator_unavailable',
        PairingFailureKind.permanent,
      );
    }
    try {
      final request = http.Request(method, baseUri.replace(path: path))
        ..headers['accept'] = 'application/json'
        ..headers['authorization'] = 'DataSteward-Operator $operatorToken'
        ..headers['x-datasteward-protocol'] = pairingProtocolVersion;
      if (body != null) {
        request.headers['content-type'] = 'application/json';
        request.body = jsonEncode(body);
      }
      final streamed = await _client
          .send(request)
          .timeout(const Duration(seconds: 5));
      final type = streamed.headers['content-type']?.toLowerCase();
      if (type == null || !type.startsWith('application/json')) _integrity();
      final bytes = <int>[];
      await for (final chunk in streamed.stream) {
        if (bytes.length + chunk.length > 65536) _integrity();
        bytes.addAll(chunk);
      }
      return _AdminResponse(
        streamed.statusCode,
        utf8.decode(bytes, allowMalformed: false),
      );
    } on SecurePairingException {
      rethrow;
    } on FormatException {
      _integrity();
    } on Object {
      throw const SecurePairingException(
        'operator_unavailable',
        PairingFailureKind.transient,
      );
    }
  }

  void _expectOk(_AdminResponse response, int status) {
    if (response.statusCode == status) return;
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

  @override
  void close() {
    if (_closed) return;
    _closed = true;
    _client.close();
  }
}

List<String> _capabilities(Object? source, {bool allowEmpty = false}) {
  if (source is! List ||
      source.length > 32 ||
      source.any((e) => e is! String)) {
    _integrity();
  }
  final values = source.cast<String>();
  if (values.isEmpty && allowEmpty) return const [];
  final canonical = canonicalCapabilities(values);
  if (canonical.join('\n') != values.join('\n')) _integrity();
  return List<String>.unmodifiable(values);
}

Never _integrity() => throw const SecurePairingException(
  'protocol_integrity_error',
  PairingFailureKind.integrity,
);

final class _AdminResponse {
  const _AdminResponse(this.statusCode, this.body);

  final int statusCode;
  final String body;
}
