import 'package:flutter/services.dart';

import 'pairing_crypto.dart';
import 'pairing_errors.dart';
import 'pairing_vault.dart';

final _ulid = RegExp(r'^[0-7][0-9A-HJKMNP-TV-Z]{25}$');
final _fingerprint = RegExp(r'^[0-9a-f]{64}$');

final class MethodChannelPairingVault implements PairingVault {
  const MethodChannelPairingVault({
    this.channel = const MethodChannel('io.datasteward.app/secure_pairing'),
  });

  final MethodChannel channel;

  @override
  Future<PairingVaultStatus> status() async {
    final value = await _invokeMap('status');
    return switch (value['status']) {
      'empty' => PairingVaultStatus.empty,
      'pending' => PairingVaultStatus.pending,
      'active' => PairingVaultStatus.active,
      _ => _fail(),
    };
  }

  @override
  Future<PendingPairingMaterial> createPending({
    required String pairingAttemptId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required String pairingSessionId,
    required List<String> requestedCapabilities,
  }) async => _pending(
    await _invokeMap('createPending', {
      'pairingAttemptId': pairingAttemptId,
      'hubId': hubId,
      'baseUrl': baseUrl.toString(),
      'certFingerprint': certFingerprint,
      'pairingSessionId': pairingSessionId,
      'requestedCapabilities': requestedCapabilities,
    }),
  );

  @override
  Future<PendingPairingMaterial> loadPending() async =>
      _pending(await _invokeMap('loadPending'));

  @override
  Future<void> saveHello({
    required String deviceId,
    required String shortCode,
  }) async {
    await _invokeMap('saveHello', {
      'deviceId': deviceId,
      'shortCode': shortCode,
    });
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
    await _invokeMap('activate', {
      'deviceId': deviceId,
      'hubId': hubId,
      'baseUrl': baseUrl.toString(),
      'certFingerprint': certFingerprint,
      'capabilityEpoch': capabilityEpoch,
      'grantedCapabilities': grantedCapabilities,
    });
  }

  @override
  Future<ActiveDeviceCredential> loadActive() async {
    final value = await _invokeMap('loadActive');
    final caps = value['grantedCapabilities'];
    if (value['deviceId'] is! String ||
        value['hubId'] is! String ||
        value['baseUrl'] is! String ||
        value['certFingerprint'] is! String ||
        value['deviceCredential'] is! String ||
        value['capabilityEpoch'] is! int ||
        caps is! List ||
        caps.any((element) => element is! String)) {
      _fail();
    }
    final baseUrl = _baseUrl(value['baseUrl']! as String);
    _requireUlid(value['deviceId']! as String);
    _requireUlid(value['hubId']! as String);
    _requireFingerprint(value['certFingerprint']! as String);
    decodeBase64UrlExact(value['deviceCredential']! as String, 32);
    final capabilities = caps.cast<String>();
    if (capabilities.isNotEmpty &&
        canonicalCapabilities(capabilities).join('\n') !=
            capabilities.join('\n')) {
      _fail();
    }
    return ActiveDeviceCredential(
      deviceId: value['deviceId']! as String,
      hubId: value['hubId']! as String,
      baseUrl: baseUrl,
      certFingerprint: value['certFingerprint']! as String,
      deviceCredential: value['deviceCredential']! as String,
      capabilityEpoch: value['capabilityEpoch']! as int,
      grantedCapabilities: List<String>.unmodifiable(caps.cast<String>()),
    );
  }

  @override
  Future<ActiveDeviceCredential> updateActiveEndpoint({
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
  }) async {
    _requireUlid(hubId);
    _requireFingerprint(certFingerprint);
    _baseUrl(baseUrl.toString());
    await _invokeMap('updateActiveEndpoint', {
      'hubId': hubId,
      'baseUrl': baseUrl.toString(),
      'certFingerprint': certFingerprint,
    });
    return loadActive();
  }

  @override
  Future<ActiveDeviceCredential> updateActiveAuthorization({
    required String deviceId,
    required String hubId,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  }) async {
    _requireUlid(deviceId);
    _requireUlid(hubId);
    if (capabilityEpoch < 1) _fail();
    final capabilities = canonicalCapabilities(grantedCapabilities);
    await _invokeMap('updateActiveAuthorization', {
      'deviceId': deviceId,
      'hubId': hubId,
      'capabilityEpoch': capabilityEpoch,
      'grantedCapabilities': capabilities,
    });
    return loadActive();
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
    _requireUlid(deviceId);
    _requireUlid(hubId);
    _requireFingerprint(certFingerprint);
    _baseUrl(baseUrl.toString());
    if (capabilityEpoch < 1) _fail();
    final capabilities = canonicalCapabilities(grantedCapabilities);
    await _invokeMap('updateActiveEndpointAndAuthorization', {
      'deviceId': deviceId,
      'hubId': hubId,
      'baseUrl': baseUrl.toString(),
      'certFingerprint': certFingerprint,
      'capabilityEpoch': capabilityEpoch,
      'grantedCapabilities': capabilities,
    });
    return loadActive();
  }

  @override
  Future<void> delete() async => _invokeMap('delete');

  Future<Map<Object?, Object?>> _invokeMap(
    String method, [
    Map<String, Object?>? args,
  ]) async {
    try {
      final value = await channel.invokeMethod<Object?>(method, args);
      if (value is! Map) _fail();
      return value.cast<Object?, Object?>();
    } on MissingPluginException {
      throw const SecurePairingException(
        'secure_storage_unsupported',
        PairingFailureKind.unsupported,
      );
    } on PlatformException catch (error) {
      final code =
          const {
            'secure_storage_unavailable',
            'secure_storage_corrupt',
            'secure_storage_state',
            'secure_storage_invalid',
          }.contains(error.code)
          ? error.code
          : 'secure_storage_unavailable';
      throw SecurePairingException(code, PairingFailureKind.permanent);
    }
  }

  PendingPairingMaterial _pending(Map<Object?, Object?> value) {
    final requested = value['requestedCapabilities'];
    if (value['pairingAttemptId'] is! String ||
        value['hubId'] is! String ||
        value['baseUrl'] is! String ||
        value['certFingerprint'] is! String ||
        value['pairingSessionId'] is! String ||
        requested is! List ||
        requested.any((element) => element is! String) ||
        value['deviceCredential'] is! String ||
        value['claimSecret'] is! String ||
        value['clientNonce'] is! String ||
        (value['deviceId'] != null && value['deviceId'] is! String) ||
        (value['shortCode'] != null && value['shortCode'] is! String)) {
      _fail();
    }
    final baseUrl = _baseUrl(value['baseUrl']! as String);
    for (final id in [
      value['pairingAttemptId']! as String,
      value['hubId']! as String,
      value['pairingSessionId']! as String,
    ]) {
      _requireUlid(id);
    }
    _requireFingerprint(value['certFingerprint']! as String);
    decodeBase64UrlExact(value['deviceCredential']! as String, 32);
    decodeBase64UrlExact(value['claimSecret']! as String, 32);
    decodeBase64UrlExact(value['clientNonce']! as String, 16);
    final capabilities = requested.cast<String>();
    if (canonicalCapabilities(capabilities).join('\n') !=
        capabilities.join('\n')) {
      _fail();
    }
    return PendingPairingMaterial(
      pairingAttemptId: value['pairingAttemptId']! as String,
      hubId: value['hubId']! as String,
      baseUrl: baseUrl,
      certFingerprint: value['certFingerprint']! as String,
      pairingSessionId: value['pairingSessionId']! as String,
      requestedCapabilities: List<String>.unmodifiable(capabilities),
      deviceCredential: value['deviceCredential']! as String,
      claimSecret: value['claimSecret']! as String,
      clientNonce: value['clientNonce']! as String,
      deviceId: value['deviceId'] as String?,
      shortCode: value['shortCode'] as String?,
    );
  }

  Never _fail() => throw const SecurePairingException(
    'secure_storage_corrupt',
    PairingFailureKind.permanent,
  );

  Uri _baseUrl(String value) {
    final uri = Uri.tryParse(value);
    if (uri == null ||
        uri.scheme != 'https' ||
        !uri.hasAuthority ||
        uri.host.isEmpty ||
        uri.host == '0.0.0.0' ||
        uri.userInfo.isNotEmpty ||
        uri.query.isNotEmpty ||
        uri.fragment.isNotEmpty) {
      _fail();
    }
    return uri;
  }

  void _requireUlid(String value) {
    if (!_ulid.hasMatch(value)) _fail();
  }

  void _requireFingerprint(String value) {
    if (!_fingerprint.hasMatch(value)) _fail();
  }
}
