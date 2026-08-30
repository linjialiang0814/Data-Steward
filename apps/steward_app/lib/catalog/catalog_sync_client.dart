import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;

import '../secure_pairing/pairing_vault.dart';
import '../secure_pairing/pairing_errors.dart';
import '../secure_pairing/strict_json.dart';
import '../shared_session/authenticated_transport.dart';
import 'catalog_bridge.dart';
import 'today_materials.dart';

const catalogSyncSchema = 'data-steward.catalog-sync/v1';
const clusterOrganizationSchema = 'data-steward.cluster-organization/v1';
const _maxResponseBytes = 768 * 1024;

final class CatalogSyncFailure implements Exception {
  const CatalogSyncFailure(this.code);
  final String code;
}

final class CatalogSyncReceipt {
  const CatalogSyncReceipt({
    required this.acceptedSeq,
    required this.itemCount,
    required this.tombstoneCount,
    required this.changed,
    required this.deduplicated,
    required this.projectionSha256,
  });

  final int acceptedSeq;
  final int itemCount;
  final int tombstoneCount;
  final bool changed;
  final bool deduplicated;
  final String projectionSha256;
}

final class ClusterOrganizationPreview {
  const ClusterOrganizationPreview({
    required this.clusterId,
    required this.clusterTitle,
    required this.projectionSha256,
    required this.previewSha256,
    required this.pcFileCount,
    required this.virtualFileCount,
    required this.categoryCounts,
  });

  final String clusterId;
  final String clusterTitle;
  final String projectionSha256;
  final String previewSha256;
  final int pcFileCount;
  final int virtualFileCount;
  final Map<String, int> categoryCounts;
}

final class ClusterOrganizationReceipt {
  const ClusterOrganizationReceipt({
    required this.operation,
    required this.clusterId,
    required this.movedCount,
    required this.categoryCounts,
    required this.undoToken,
    required this.catalogRefreshPending,
  });

  final String operation;
  final String clusterId;
  final int movedCount;
  final Map<String, int> categoryCounts;
  final String undoToken;
  final bool catalogRefreshPending;
}

final class ClusterOrganizationStatus {
  const ClusterOrganizationStatus({
    required this.state,
    required this.movedCount,
    required this.categoryCounts,
    required this.undoToken,
    required this.canUndo,
  });

  const ClusterOrganizationStatus.idle()
    : state = 'idle',
      movedCount = 0,
      categoryCounts = const {
        'images': 0,
        'documents': 0,
        'media': 0,
        'archives': 0,
        'other': 0,
      },
      undoToken = null,
      canUndo = false;

  const ClusterOrganizationStatus.recoveryRequired()
    : state = 'recovery_required',
      movedCount = 0,
      categoryCounts = const {
        'images': 0,
        'documents': 0,
        'media': 0,
        'archives': 0,
        'other': 0,
      },
      undoToken = null,
      canUndo = false;

  factory ClusterOrganizationStatus.fromReceipt(
    ClusterOrganizationReceipt receipt,
  ) => ClusterOrganizationStatus(
    state: 'undo_available',
    movedCount: receipt.movedCount,
    categoryCounts: receipt.categoryCounts,
    undoToken: receipt.undoToken,
    canUndo: true,
  );

  factory ClusterOrganizationStatus.fromJson(Map<String, Object?> value) {
    const keys = {
      'schema_version',
      'state',
      'moved_count',
      'category_counts',
      'undo_token',
      'can_undo',
    };
    if (value.length != keys.length ||
        !value.keys.toSet().containsAll(keys) ||
        value['schema_version'] != clusterOrganizationSchema ||
        !const {
          'idle',
          'undo_available',
          'recovery_required',
        }.contains(value['state']) ||
        value['can_undo'] is! bool) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    final state = value['state']! as String;
    final movedCount = CatalogSyncClient._nonNegativeInt(value['moved_count']);
    final categories = CatalogSyncClient._categoryCounts(
      value['category_counts'],
    );
    final undoToken = value['undo_token'];
    final canUndo = value['can_undo']! as bool;
    final total = categories.values.fold<int>(0, (sum, item) => sum + item);
    final validUndoToken =
        undoToken is String &&
        RegExp(r'^org-[0-9a-f]{16}$').hasMatch(undoToken);
    final valid = switch (state) {
      'idle' => movedCount == 0 && total == 0 && undoToken == null && !canUndo,
      'undo_available' =>
        movedCount > 0 && total == movedCount && validUndoToken && canUndo,
      'recovery_required' =>
        movedCount > 0 && total == movedCount && undoToken == null && !canUndo,
      _ => false,
    };
    if (!valid) throw const CatalogSyncFailure('protocol_integrity_error');
    return ClusterOrganizationStatus(
      state: state,
      movedCount: movedCount,
      categoryCounts: categories,
      undoToken: undoToken as String?,
      canUndo: canUndo,
    );
  }

  final String state;
  final int movedCount;
  final Map<String, int> categoryCounts;
  final String? undoToken;
  final bool canUndo;
}

abstract interface class CatalogOutbox {
  Future<String?> load();
  Future<String> save(String payload);
  Future<void> clear(String sha256Value);
}

final class MethodChannelCatalogOutbox implements CatalogOutbox {
  const MethodChannelCatalogOutbox({
    this.channel = const MethodChannel(catalogChannelName),
  });

  final MethodChannel channel;

  @override
  Future<String?> load() async {
    try {
      final value = await channel.invokeMethod<Map<Object?, Object?>>(
        'loadCatalogOutbox',
      );
      if (value == null) throw const CatalogSyncFailure('outbox_corrupt');
      if (value['status'] == 'empty' && value.length == 1) return null;
      if (value.keys.toSet().difference({
            'status',
            'payload',
            'sha256',
          }).isNotEmpty ||
          value.length != 3 ||
          value['status'] != 'pending' ||
          value['payload'] is! String ||
          value['sha256'] is! String) {
        throw const CatalogSyncFailure('outbox_corrupt');
      }
      final payload = value['payload']! as String;
      final digest = value['sha256']! as String;
      if (sha256.convert(utf8.encode(payload)).toString() != digest) {
        throw const CatalogSyncFailure('outbox_corrupt');
      }
      return payload;
    } on PlatformException catch (error) {
      throw CatalogSyncFailure(error.code);
    }
  }

  @override
  Future<String> save(String payload) async {
    final digest = sha256.convert(utf8.encode(payload)).toString();
    try {
      final value = await channel.invokeMethod<Map<Object?, Object?>>(
        'saveCatalogOutbox',
        {'payload': payload, 'sha256': digest},
      );
      if (value == null ||
          value.length != 2 ||
          value['status'] != 'saved' ||
          value['sha256'] != digest) {
        throw const CatalogSyncFailure('outbox_corrupt');
      }
      return digest;
    } on PlatformException catch (error) {
      throw CatalogSyncFailure(error.code);
    }
  }

  @override
  Future<void> clear(String sha256Value) async {
    try {
      final value = await channel.invokeMethod<Map<Object?, Object?>>(
        'clearCatalogOutbox',
        {'sha256': sha256Value},
      );
      if (value == null || value.length != 1 || value['status'] != 'cleared') {
        throw const CatalogSyncFailure('outbox_corrupt');
      }
    } on PlatformException catch (error) {
      throw CatalogSyncFailure(error.code);
    }
  }
}

final class CatalogSyncClient {
  CatalogSyncClient({
    required this.credential,
    CatalogOutbox? outbox,
    http.Client? client,
  }) : outbox = outbox ?? const MethodChannelCatalogOutbox(),
       _client =
           client ?? PinnedAuthenticatedHttpClient(credential: credential);

  final ActiveDeviceCredential credential;
  final CatalogOutbox outbox;
  final http.Client _client;

  Future<TodayMaterialsProjection> fetchToday() async {
    if (!credential.grantedCapabilities.contains('catalog.sync')) {
      throw const CatalogSyncFailure('capability_denied');
    }
    final response = await _send('GET', '/v1/catalog/today');
    if (response.statusCode != 200) _throwResponse(response);
    try {
      return TodayMaterialsProjection.fromJson(_object(response.body));
    } on FormatException {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
  }

  Future<ClusterOrganizationPreview> previewOrganization({
    required String clusterId,
    required String projectionSha256,
  }) async {
    _requireOrganizationCapability();
    final response = await _send(
      'POST',
      '/v1/catalog/organization/preview',
      body: jsonEncode({
        'schema_version': clusterOrganizationSchema,
        'cluster_id': clusterId,
        'projection_sha256': projectionSha256,
      }),
    );
    if (response.statusCode != 200) _throwResponse(response);
    final value = _object(response.body);
    const keys = {
      'schema_version',
      'cluster_id',
      'cluster_title',
      'projection_sha256',
      'preview_sha256',
      'pc_file_count',
      'virtual_file_count',
      'category_counts',
      'can_execute',
    };
    if (value.length != keys.length ||
        !value.keys.toSet().containsAll(keys) ||
        value['schema_version'] != clusterOrganizationSchema ||
        value['cluster_id'] != clusterId ||
        value['projection_sha256'] != projectionSha256 ||
        value['can_execute'] != true) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return ClusterOrganizationPreview(
      clusterId: clusterId,
      clusterTitle: _safeString(value['cluster_title']),
      projectionSha256: projectionSha256,
      previewSha256: _digest(value['preview_sha256']),
      pcFileCount: _nonNegativeInt(value['pc_file_count']),
      virtualFileCount: _nonNegativeInt(value['virtual_file_count']),
      categoryCounts: _categoryCounts(value['category_counts']),
    );
  }

  Future<ClusterOrganizationReceipt> executeOrganization({
    required ClusterOrganizationPreview preview,
  }) async {
    _requireOrganizationCapability();
    final response = await _send(
      'POST',
      '/v1/catalog/organization/execute',
      body: jsonEncode({
        'schema_version': clusterOrganizationSchema,
        'cluster_id': preview.clusterId,
        'projection_sha256': preview.projectionSha256,
        'preview_sha256': preview.previewSha256,
      }),
    );
    if (response.statusCode != 200) _throwResponse(response);
    return _organizationReceipt(response.body, expectedOperation: 'organize');
  }

  Future<ClusterOrganizationReceipt> undoOrganization(String undoToken) async {
    _requireOrganizationCapability();
    final response = await _send(
      'POST',
      '/v1/catalog/organization/undo',
      body: jsonEncode({
        'schema_version': clusterOrganizationSchema,
        'undo_token': undoToken,
      }),
    );
    if (response.statusCode != 200) _throwResponse(response);
    return _organizationReceipt(response.body, expectedOperation: 'undo');
  }

  Future<ClusterOrganizationStatus> organizationStatus() async {
    _requireOrganizationCapability();
    final response = await _send('GET', '/v1/catalog/organization/status');
    if (response.statusCode != 200) _throwResponse(response);
    return ClusterOrganizationStatus.fromJson(_object(response.body));
  }

  void _requireOrganizationCapability() {
    if (!credential.grantedCapabilities.contains('catalog.sync') ||
        !credential.grantedCapabilities.contains('files.organize')) {
      throw const CatalogSyncFailure('capability_denied');
    }
  }

  ClusterOrganizationReceipt _organizationReceipt(
    String body, {
    required String expectedOperation,
  }) {
    final value = _object(body);
    const keys = {
      'schema_version',
      'operation',
      'cluster_id',
      'moved_count',
      'category_counts',
      'undo_token',
      'catalog_refresh_pending',
    };
    if (value.length != keys.length ||
        !value.keys.toSet().containsAll(keys) ||
        value['schema_version'] != clusterOrganizationSchema ||
        value['operation'] != expectedOperation ||
        value['catalog_refresh_pending'] is! bool) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return ClusterOrganizationReceipt(
      operation: expectedOperation,
      clusterId: value['cluster_id'] is String
          ? value['cluster_id']! as String
          : throw const CatalogSyncFailure('protocol_integrity_error'),
      movedCount: _nonNegativeInt(value['moved_count']),
      categoryCounts: _categoryCounts(value['category_counts']),
      undoToken: _safeString(value['undo_token']),
      catalogRefreshPending: value['catalog_refresh_pending']! as bool,
    );
  }

  Future<CatalogSyncReceipt> sync({
    required CatalogSnapshot snapshot,
    required String provider,
    String displayName = 'Mobile materials',
  }) async {
    if (!credential.grantedCapabilities.contains('catalog.sync')) {
      throw const CatalogSyncFailure('capability_denied');
    }
    var payload = _payload(
      snapshot: snapshot,
      provider: provider,
      displayName: displayName,
      baseSeq: 0,
    );
    await outbox.save(payload);
    final baseSeq = await _baseSeq(snapshot.catalogRootId);
    payload = _payload(
      snapshot: snapshot,
      provider: provider,
      displayName: displayName,
      baseSeq: baseSeq,
    );
    final digest = await outbox.save(payload);
    final receipt = await _postPayload(payload);
    await outbox.clear(digest);
    return receipt;
  }

  String _payload({
    required CatalogSnapshot snapshot,
    required String provider,
    required String displayName,
    required int baseSeq,
  }) => jsonEncode({
    'schema_version': catalogSyncSchema,
    'idempotency_key':
        'android-${DateTime.now().microsecondsSinceEpoch}-${snapshot.snapshotSha256.substring(0, 12)}',
    'catalog_root_id': snapshot.catalogRootId,
    'platform': 'android',
    'provider': provider,
    'display_name': displayName,
    'base_seq': baseSeq,
    'snapshot_sha256': snapshot.snapshotSha256,
    'generated_at_ms': snapshot.generatedAtMillis,
    'item_count': snapshot.itemCount,
    'skipped_count': snapshot.skippedCount,
    'complete_snapshot': true,
    'items': [for (final item in snapshot.items) _itemWire(item)],
  });

  Future<CatalogSyncReceipt> retryPending() async {
    var payload = await outbox.load();
    if (payload == null) throw const CatalogSyncFailure('outbox_empty');
    final value = _object(payload);
    const requestKeys = {
      'schema_version',
      'idempotency_key',
      'catalog_root_id',
      'platform',
      'provider',
      'display_name',
      'base_seq',
      'snapshot_sha256',
      'generated_at_ms',
      'item_count',
      'skipped_count',
      'complete_snapshot',
      'items',
    };
    if (value.length != requestKeys.length ||
        !value.keys.toSet().containsAll(requestKeys) ||
        value['schema_version'] != catalogSyncSchema ||
        value['platform'] != 'android') {
      throw const CatalogSyncFailure('outbox_corrupt');
    }
    final rootId = value['catalog_root_id'];
    final snapshotHash = value['snapshot_sha256'];
    if (rootId is! String || !RegExp(r'^[0-9a-f]{64}$').hasMatch(rootId)) {
      throw const CatalogSyncFailure('outbox_corrupt');
    }
    if (snapshotHash is! String ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(snapshotHash)) {
      throw const CatalogSyncFailure('outbox_corrupt');
    }
    final baseSeq = await _baseSeq(rootId);
    if (value['base_seq'] != baseSeq) {
      value['base_seq'] = baseSeq;
      value['idempotency_key'] =
          'android-${DateTime.now().microsecondsSinceEpoch}-${snapshotHash.substring(0, 12)}';
      payload = jsonEncode(value);
    }
    final digest = await outbox.save(payload);
    final receipt = await _postPayload(payload);
    await outbox.clear(digest);
    return receipt;
  }

  Future<int> _baseSeq(String rootId) async {
    final response = await _send('GET', '/v1/catalog/roots');
    if (response.statusCode != 200) _throwResponse(response);
    final body = _object(response.body);
    if (body.length != 1 ||
        body['roots'] is! List<Object?> ||
        (body['roots']! as List<Object?>).length > 512) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    var result = 0;
    final seen = <String>{};
    for (final raw in body['roots']! as List<Object?>) {
      if (raw is! Map<String, Object?>) {
        throw const CatalogSyncFailure('protocol_integrity_error');
      }
      const rootKeys = {
        'device_id',
        'catalog_root_id',
        'platform',
        'provider',
        'display_name',
        'catalog_seq',
        'snapshot_sha256',
        'item_count',
        'skipped_count',
        'last_synced_at',
      };
      if (raw.length != rootKeys.length ||
          !raw.keys.toSet().containsAll(rootKeys)) {
        throw const CatalogSyncFailure('protocol_integrity_error');
      }
      final deviceId = raw['device_id'];
      final catalogRootId = raw['catalog_root_id'];
      final seq = raw['catalog_seq'];
      final snapshotHash = raw['snapshot_sha256'];
      if (deviceId is! String ||
          catalogRootId is! String ||
          seq is! int ||
          seq < 1 ||
          snapshotHash is! String ||
          !RegExp(r'^[0-9a-f]{64}$').hasMatch(snapshotHash) ||
          !seen.add('$deviceId\u0000$catalogRootId')) {
        throw const CatalogSyncFailure('protocol_integrity_error');
      }
      if (raw['device_id'] == credential.deviceId &&
          raw['catalog_root_id'] == rootId) {
        result = seq;
      }
    }
    return result;
  }

  Future<CatalogSyncReceipt> _postPayload(String payload) async {
    final response = await _send(
      'POST',
      '/v1/catalog/snapshots',
      body: payload,
    );
    if (response.statusCode != 200) _throwResponse(response);
    final value = _object(response.body);
    const keys = {
      'device_id',
      'catalog_root_id',
      'accepted_seq',
      'snapshot_sha256',
      'item_count',
      'tombstone_count',
      'changed',
      'deduplicated',
      'projection_sha256',
    };
    if (value.keys.toSet().difference(keys).isNotEmpty ||
        value.length != keys.length) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    final seq = value['accepted_seq'];
    final count = value['item_count'];
    final tombstones = value['tombstone_count'];
    final projection = value['projection_sha256'];
    final requestValue = _object(payload);
    final expectedRootId = requestValue['catalog_root_id'];
    final expectedSnapshot = requestValue['snapshot_sha256'];
    final expectedCount = requestValue['item_count'];
    if (value['device_id'] != credential.deviceId ||
        value['catalog_root_id'] != expectedRootId ||
        value['snapshot_sha256'] != expectedSnapshot ||
        seq is! int ||
        seq < 0 ||
        count is! int ||
        count < 0 ||
        count != expectedCount ||
        tombstones is! int ||
        tombstones < 0 ||
        value['changed'] is! bool ||
        value['deduplicated'] is! bool ||
        projection is! String ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(projection)) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return CatalogSyncReceipt(
      acceptedSeq: seq,
      itemCount: count,
      tombstoneCount: tombstones,
      changed: value['changed']! as bool,
      deduplicated: value['deduplicated']! as bool,
      projectionSha256: projection,
    );
  }

  Future<http.Response> _send(
    String method,
    String path, {
    String? body,
  }) async {
    try {
      final request = http.Request(
        method,
        credential.baseUrl.replace(path: path),
      )..headers['accept'] = 'application/json';
      if (body != null) {
        request.headers['content-type'] = 'application/json';
        request.body = body;
      }
      final streamed = await _client
          .send(request)
          .timeout(const Duration(seconds: 12));
      final contentType = streamed.headers['content-type']?.toLowerCase();
      if (contentType == null || !contentType.startsWith('application/json')) {
        throw const CatalogSyncFailure('protocol_integrity_error');
      }
      final bytes = <int>[];
      await for (final chunk in streamed.stream) {
        if (bytes.length + chunk.length > _maxResponseBytes) {
          throw const CatalogSyncFailure('protocol_integrity_error');
        }
        bytes.addAll(chunk);
      }
      return http.Response.bytes(
        bytes,
        streamed.statusCode,
        headers: streamed.headers,
      );
    } on CatalogSyncFailure {
      rethrow;
    } on Object {
      throw const CatalogSyncFailure('transient_network');
    }
  }

  Never _throwResponse(http.Response response) {
    final value = _object(response.body);
    final code = value['error_code'];
    final expectedKeys = code == 'catalog_cursor_conflict'
        ? const {'error_code', 'message_key', 'server_catalog_seq'}
        : const {'error_code', 'message_key'};
    if (code is! String ||
        value.length != expectedKeys.length ||
        !value.keys.toSet().containsAll(expectedKeys) ||
        !{code, 'auth.$code'}.contains(value['message_key'])) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    if (code == 'catalog_cursor_conflict' &&
        (value['server_catalog_seq'] is! int ||
            (value['server_catalog_seq']! as int) < 0)) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    throw CatalogSyncFailure(code);
  }

  Map<String, Object?> _object(String source) {
    try {
      return decodeStrictJsonObject(source, maxUtf8Bytes: _maxResponseBytes);
    } on SecurePairingException {
      throw const CatalogSyncFailure('protocol_integrity_error');
    } on CatalogSyncFailure {
      rethrow;
    } on Object {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
  }

  void close() => _client.close();

  static String _safeString(Object? value) {
    if (value is! String || value.isEmpty || value.length > 128) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return value;
  }

  static String _digest(Object? value) {
    final result = _safeString(value);
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(result)) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return result;
  }

  static int _nonNegativeInt(Object? value) {
    if (value is! int || value < 0 || value > 512) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return value;
  }

  static Map<String, int> _categoryCounts(Object? value) {
    const categories = {'images', 'documents', 'media', 'archives', 'other'};
    if (value is! Map<String, Object?> ||
        value.length != categories.length ||
        !value.keys.toSet().containsAll(categories)) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return {
      for (final category in categories)
        category: _nonNegativeInt(value[category]),
    };
  }
}

Map<String, Object?> _itemWire(CatalogItem item) => {
  'locator_token': item.locatorToken,
  'display_name': item.displayName,
  'extension': item.extension,
  'mime_family': item.mimeFamily,
  'size_bytes': item.sizeBytes,
  'modified_at_ms': item.modifiedAtMillis,
  'revision': item.revision,
  'content_eligible': item.contentEligible,
};
