import 'package:flutter/services.dart';

abstract interface class HubEndpointDiscovery {
  Future<Uri> discover({
    required String hubId,
    required String certFingerprint,
    Duration timeout,
  });

  Future<void> cancel();
}

final class EndpointDiscoveryException implements Exception {
  const EndpointDiscoveryException(this.code);

  final String code;

  @override
  String toString() => 'EndpointDiscoveryException($code)';
}

final class MethodChannelHubEndpointDiscovery implements HubEndpointDiscovery {
  const MethodChannelHubEndpointDiscovery({MethodChannel? channel})
    : _channel = channel ?? const MethodChannel(_channelName);

  static const _channelName = 'io.datasteward.app/lan_discovery';
  static const _schema = 'data-steward.lan-discovery/v1';
  final MethodChannel _channel;

  @override
  Future<Uri> discover({
    required String hubId,
    required String certFingerprint,
    Duration timeout = const Duration(seconds: 6),
  }) async {
    if (!RegExp(r'^[0-7][0-9A-HJKMNP-TV-Z]{25}$').hasMatch(hubId) ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(certFingerprint)) {
      throw const EndpointDiscoveryException('discovery_request_invalid');
    }
    if (timeout < const Duration(seconds: 3) ||
        timeout > const Duration(seconds: 10)) {
      throw const EndpointDiscoveryException('discovery_request_invalid');
    }
    try {
      final raw = await _channel.invokeMethod<Object>('discoverHub', {
        'hubId': hubId,
        'certFingerprint': certFingerprint,
        'protocolVersion': '1',
        'timeoutMs': timeout.inMilliseconds,
      });
      if (raw is! Map) _invalid();
      final value = Map<String, Object?>.from(raw);
      if (value.length != 2 ||
          !value.keys.toSet().containsAll(const {
            'schema_version',
            'base_url',
          })) {
        _invalid();
      }
      if (value['schema_version'] != _schema) _invalid();
      final uri = Uri.tryParse(value['base_url'] as String? ?? '');
      if (uri == null ||
          uri.scheme != 'https' ||
          !uri.hasPort ||
          uri.userInfo.isNotEmpty ||
          (uri.path.isNotEmpty && uri.path != '/') ||
          uri.query.isNotEmpty ||
          uri.fragment.isNotEmpty ||
          !_privateIpv4(uri.host)) {
        _invalid();
      }
      return uri.replace(path: '', query: null, fragment: null);
    } on PlatformException catch (error) {
      final code =
          const {
            'discovery_busy',
            'discovery_cancelled',
            'discovery_unavailable',
            'discovery_not_found',
            'discovery_ambiguous',
            'discovery_saturated',
          }.contains(error.code)
          ? error.code
          : 'discovery_unavailable';
      throw EndpointDiscoveryException(code);
    } on MissingPluginException {
      throw const EndpointDiscoveryException('discovery_unavailable');
    } on FormatException {
      throw const EndpointDiscoveryException('discovery_integrity');
    } on TypeError {
      throw const EndpointDiscoveryException('discovery_integrity');
    }
  }

  @override
  Future<void> cancel() async {
    try {
      await _channel.invokeMethod<void>('cancelDiscovery');
    } on PlatformException {
      // Cancellation is idempotent and carries no product data.
    } on MissingPluginException {
      // Unsupported platforms have no native discovery session.
    }
  }

  Never _invalid() =>
      throw const FormatException('lan_discovery_response_invalid');
}

bool _privateIpv4(String host) {
  final parts = host.split('.').map(int.tryParse).toList();
  if (parts.length != 4 ||
      parts.any((value) => value == null || value < 0 || value > 255)) {
    return false;
  }
  return parts[0] == 10 ||
      (parts[0] == 172 && parts[1]! >= 16 && parts[1]! <= 31) ||
      (parts[0] == 192 && parts[1] == 168);
}
