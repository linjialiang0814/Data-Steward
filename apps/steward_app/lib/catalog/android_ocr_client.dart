import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

import '../secure_pairing/pairing_errors.dart';
import '../secure_pairing/pairing_vault.dart';
import '../secure_pairing/strict_json.dart';
import '../shared_session/authenticated_transport.dart';
import 'catalog_bridge.dart';

const String androidOcrSyncSchema = 'data-steward.android-ocr-sync/v1';
const int _maxOcrResponseBytes = 64 * 1024;

final class AndroidOcrSyncFailure implements Exception {
  const AndroidOcrSyncFailure(this.code);
  final String code;
}

final class AndroidOcrSyncReceipt {
  const AndroidOcrSyncReceipt({
    required this.acceptedCount,
    required this.recognizedCount,
    required this.noTextCount,
    required this.lowConfidenceCount,
    required this.deduplicated,
    required this.projectionSha256,
  });

  final int acceptedCount;
  final int recognizedCount;
  final int noTextCount;
  final int lowConfidenceCount;
  final bool deduplicated;
  final String projectionSha256;
}

abstract interface class AndroidOcrOutbox {
  Future<String> save(String payload);
  Future<String?> load();
  Future<void> clear(String expectedSha256);
}

final class MethodChannelAndroidOcrOutbox implements AndroidOcrOutbox {
  const MethodChannelAndroidOcrOutbox({
    this.channel = const MethodChannel(catalogChannelName),
  });

  final MethodChannel channel;

  @override
  Future<String> save(String payload) async {
    final digest = sha256.convert(utf8.encode(payload)).toString();
    final value = await _invoke('saveOcrOutbox', {
      'payload': payload,
      'sha256': digest,
    });
    if (value['status'] != 'saved' || value['sha256'] != digest) {
      throw const AndroidOcrSyncFailure('ocr_outbox_corrupt');
    }
    return digest;
  }

  @override
  Future<String?> load() async {
    final value = await _invoke('loadOcrOutbox');
    if (value['status'] == 'empty' && value.length == 1) return null;
    if (value.length != 3 || value['status'] != 'pending') {
      throw const AndroidOcrSyncFailure('ocr_outbox_corrupt');
    }
    final payload = value['payload'];
    final digest = value['sha256'];
    if (payload is! String ||
        digest is! String ||
        sha256.convert(utf8.encode(payload)).toString() != digest) {
      throw const AndroidOcrSyncFailure('ocr_outbox_corrupt');
    }
    return payload;
  }

  @override
  Future<void> clear(String expectedSha256) async {
    final value = await _invoke('clearOcrOutbox', {'sha256': expectedSha256});
    if (value.length != 1 || value['status'] != 'cleared') {
      throw const AndroidOcrSyncFailure('ocr_outbox_corrupt');
    }
  }

  Future<Map<Object?, Object?>> _invoke(
    String method, [
    Map<String, Object?>? arguments,
  ]) async {
    try {
      final result = await channel.invokeMethod<Map<Object?, Object?>>(
        method,
        arguments,
      );
      if (result == null) {
        throw const AndroidOcrSyncFailure('ocr_outbox_corrupt');
      }
      return result;
    } on PlatformException catch (error) {
      throw AndroidOcrSyncFailure(error.code);
    } on MissingPluginException {
      throw const AndroidOcrSyncFailure('unsupported');
    }
  }
}

final class AndroidOcrSyncClient {
  AndroidOcrSyncClient({
    required this.credential,
    AndroidOcrOutbox? outbox,
    http.Client? client,
  }) : outbox = outbox ?? const MethodChannelAndroidOcrOutbox(),
       _client =
           client ?? PinnedAuthenticatedHttpClient(credential: credential);

  final ActiveDeviceCredential credential;
  final AndroidOcrOutbox outbox;
  final http.Client _client;

  Future<AndroidOcrSyncReceipt> sync(
    AndroidOcrBatchProjection projection,
  ) async {
    _requireCapability();
    final payload = _payload(projection);
    final digest = await outbox.save(payload);
    final receipt = await _post(payload);
    await outbox.clear(digest);
    return receipt;
  }

  Future<AndroidOcrSyncReceipt> retryPending() async {
    _requireCapability();
    final payload = await outbox.load();
    if (payload == null) throw const AndroidOcrSyncFailure('ocr_outbox_empty');
    final receipt = await _post(payload);
    await outbox.clear(sha256.convert(utf8.encode(payload)).toString());
    return receipt;
  }

  Future<int> forget(String rootId) async {
    _requireCapability();
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(rootId)) {
      throw const AndroidOcrSyncFailure('protocol_integrity_error');
    }
    final request = http.Request(
      'DELETE',
      credential.baseUrl.replace(path: '/v1/content/android-ocr/$rootId'),
    )..headers['accept'] = 'application/json';
    try {
      final streamed = await _client
          .send(request)
          .timeout(const Duration(seconds: 12));
      final contentType = streamed.headers['content-type']?.toLowerCase();
      if (contentType == null || !contentType.startsWith('application/json')) {
        throw const AndroidOcrSyncFailure('protocol_integrity_error');
      }
      final bytes = <int>[];
      await for (final chunk in streamed.stream) {
        if (bytes.length + chunk.length > _maxOcrResponseBytes) {
          throw const AndroidOcrSyncFailure('protocol_integrity_error');
        }
        bytes.addAll(chunk);
      }
      final response = http.Response.bytes(
        bytes,
        streamed.statusCode,
        headers: streamed.headers,
      );
      if (response.statusCode != 200) _throwResponse(response.body);
      final value = _object(response.body);
      final deleted = value['deleted_count'];
      if (value.length != 2 ||
          value['status'] != 'forgotten' ||
          deleted is! int ||
          deleted < 0 ||
          deleted > 512) {
        throw const AndroidOcrSyncFailure('protocol_integrity_error');
      }
      return deleted;
    } on AndroidOcrSyncFailure {
      rethrow;
    } on Object {
      throw const AndroidOcrSyncFailure('transient_network');
    }
  }

  String _payload(AndroidOcrBatchProjection projection) => jsonEncode({
    'schema_version': androidOcrSyncSchema,
    'idempotency_key':
        'ocr-${DateTime.now().microsecondsSinceEpoch}-${projection.snapshotSha256.substring(0, 12)}',
    'catalog_root_id': projection.catalogRootId,
    'snapshot_sha256': projection.snapshotSha256,
    'generated_at_ms': projection.generatedAtMillis,
    'items': [
      for (final item in projection.items)
        {
          'locator_token': item.locatorToken,
          'revision': item.revision,
          'format': item.format,
          'status': item.status,
          'text': item.text,
          'text_sha256': item.textSha256,
          'char_count': item.charCount,
          'truncated': item.truncated,
          'confidence': item.confidence,
          'language_hints': item.languageHints,
          'extractor_id': item.extractorId,
          'extractor_version': item.extractorVersion,
        },
    ],
  });

  Future<AndroidOcrSyncReceipt> _post(String payload) async {
    final request =
        http.Request(
            'POST',
            credential.baseUrl.replace(path: '/v1/content/android-ocr'),
          )
          ..headers['accept'] = 'application/json'
          ..headers['content-type'] = 'application/json'
          ..body = payload;
    try {
      final streamed = await _client
          .send(request)
          .timeout(const Duration(seconds: 20));
      final contentType = streamed.headers['content-type']?.toLowerCase();
      if (contentType == null || !contentType.startsWith('application/json')) {
        throw const AndroidOcrSyncFailure('protocol_integrity_error');
      }
      final bytes = <int>[];
      await for (final chunk in streamed.stream) {
        if (bytes.length + chunk.length > _maxOcrResponseBytes) {
          throw const AndroidOcrSyncFailure('protocol_integrity_error');
        }
        bytes.addAll(chunk);
      }
      final response = http.Response.bytes(
        bytes,
        streamed.statusCode,
        headers: streamed.headers,
      );
      if (response.statusCode != 200) _throwResponse(response.body);
      return _receipt(response.body, payload);
    } on AndroidOcrSyncFailure {
      rethrow;
    } on Object {
      throw const AndroidOcrSyncFailure('transient_network');
    }
  }

  AndroidOcrSyncReceipt _receipt(String body, String payload) {
    final value = _object(body);
    const keys = {
      'schema_version',
      'device_id',
      'catalog_root_id',
      'accepted_count',
      'recognized_count',
      'no_text_count',
      'low_confidence_count',
      'deduplicated',
      'projection_sha256',
    };
    final request = _object(payload);
    final accepted = _count(value['accepted_count']);
    final recognized = _count(value['recognized_count']);
    final noText = _count(value['no_text_count']);
    final lowConfidence = _count(value['low_confidence_count']);
    final projectionHash = value['projection_sha256'];
    if (value.length != keys.length ||
        !value.keys.toSet().containsAll(keys) ||
        value['schema_version'] != androidOcrSyncSchema ||
        value['device_id'] != credential.deviceId ||
        value['catalog_root_id'] != request['catalog_root_id'] ||
        accepted != recognized + noText ||
        lowConfidence > recognized ||
        accepted != (request['items']! as List<Object?>).length ||
        value['deduplicated'] is! bool ||
        projectionHash is! String ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(projectionHash)) {
      throw const AndroidOcrSyncFailure('protocol_integrity_error');
    }
    return AndroidOcrSyncReceipt(
      acceptedCount: accepted,
      recognizedCount: recognized,
      noTextCount: noText,
      lowConfidenceCount: lowConfidence,
      deduplicated: value['deduplicated']! as bool,
      projectionSha256: projectionHash,
    );
  }

  Never _throwResponse(String body) {
    final value = _object(body);
    final code = value['error_code'];
    if (value.length != 2 || code is! String || value['message_key'] != code) {
      throw const AndroidOcrSyncFailure('protocol_integrity_error');
    }
    throw AndroidOcrSyncFailure(code);
  }

  Map<String, Object?> _object(String source) {
    try {
      return decodeStrictJsonObject(source, maxUtf8Bytes: _maxOcrResponseBytes);
    } on SecurePairingException {
      throw const AndroidOcrSyncFailure('protocol_integrity_error');
    } on Object {
      throw const AndroidOcrSyncFailure('protocol_integrity_error');
    }
  }

  int _count(Object? value) {
    if (value is! int || value < 0 || value > 6) {
      throw const AndroidOcrSyncFailure('protocol_integrity_error');
    }
    return value;
  }

  void _requireCapability() {
    if (!credential.grantedCapabilities.contains('content.analyze')) {
      throw const AndroidOcrSyncFailure('capability_denied');
    }
  }

  void close() => _client.close();
}
