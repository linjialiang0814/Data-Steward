import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:steward_app/catalog/catalog_bridge.dart';
import 'package:steward_app/catalog/catalog_sync_client.dart';
import 'package:steward_app/secure_pairing/pairing_vault.dart';
import 'package:flutter_test/flutter_test.dart';

final class MemoryOutbox implements CatalogOutbox {
  String? payload;
  int saves = 0;
  int clears = 0;

  @override
  Future<String?> load() async => payload;

  @override
  Future<String> save(String value) async {
    payload = value;
    saves += 1;
    return _digest(value);
  }

  @override
  Future<void> clear(String sha256Value) async {
    if (_digest(payload!) != sha256Value) throw StateError('digest mismatch');
    payload = null;
    clears += 1;
  }

  String _digest(String value) =>
      // The client validates the native digest; this fake only needs a stable token.
      value.length.toRadixString(16).padLeft(64, '0');
}

void main() {
  const deviceId = '01ARZ3NDEKTSV4RRFFQ69G5FAV';
  const rootId =
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  final credential = ActiveDeviceCredential(
    deviceId: deviceId,
    hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAW',
    baseUrl: Uri.parse('https://192.0.2.1:9443'),
    certFingerprint:
        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    deviceCredential: 'A' * 43,
    capabilityEpoch: 1,
    grantedCapabilities: const ['catalog.sync', 'session.sync'],
  );
  const snapshot = CatalogSnapshot(
    catalogRootId: rootId,
    snapshotSha256:
        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    generatedAtMillis: 1785805200000,
    itemCount: 1,
    skippedCount: 0,
    items: [
      CatalogItem(
        locatorToken:
            'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        displayName: 'course-note.md',
        extension: 'md',
        mimeFamily: 'text',
        sizeBytes: 12,
        modifiedAtMillis: 1785805200000,
        revision:
            'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        contentEligible: true,
      ),
    ],
  );

  test(
    'queues before network, posts authenticated snapshot and clears',
    () async {
      final outbox = MemoryOutbox();
      var postCount = 0;
      final client = CatalogSyncClient(
        credential: credential,
        outbox: outbox,
        client: MockClient((request) async {
          if (request.method == 'GET') {
            return http.Response(
              jsonEncode({'roots': <Object?>[]}),
              200,
              headers: {'content-type': 'application/json'},
            );
          }
          postCount += 1;
          final body = jsonDecode(request.body) as Map<String, Object?>;
          expect(body['platform'], 'android');
          expect(body['base_seq'], 0);
          return http.Response(
            jsonEncode({
              'device_id': deviceId,
              'catalog_root_id': rootId,
              'accepted_seq': 1,
              'snapshot_sha256': snapshot.snapshotSha256,
              'item_count': 1,
              'tombstone_count': 0,
              'changed': true,
              'deduplicated': false,
              'projection_sha256': 'f' * 64,
            }),
            200,
            headers: {'content-type': 'application/json'},
          );
        }),
      );
      final receipt = await client.sync(
        snapshot: snapshot,
        provider: 'fixture',
      );
      expect(receipt.acceptedSeq, 1);
      expect(postCount, 1);
      expect(outbox.saves, 2);
      expect(outbox.clears, 1);
      expect(outbox.payload, isNull);
    },
  );

  test(
    'network failure keeps latest snapshot pending without retries',
    () async {
      final outbox = MemoryOutbox();
      var calls = 0;
      final client = CatalogSyncClient(
        credential: credential,
        outbox: outbox,
        client: MockClient((request) async {
          calls += 1;
          throw http.ClientException('offline');
        }),
      );
      await expectLater(
        client.sync(snapshot: snapshot, provider: 'fixture'),
        throwsA(
          isA<CatalogSyncFailure>().having(
            (value) => value.code,
            'code',
            'transient_network',
          ),
        ),
      );
      expect(calls, 1);
      expect(outbox.saves, 1);
      expect(outbox.payload, isNotNull);
    },
  );

  test('missing catalog capability fails before queue or network', () async {
    final outbox = MemoryOutbox();
    var calls = 0;
    final denied = ActiveDeviceCredential(
      deviceId: credential.deviceId,
      hubId: credential.hubId,
      baseUrl: credential.baseUrl,
      certFingerprint: credential.certFingerprint,
      deviceCredential: credential.deviceCredential,
      capabilityEpoch: 1,
      grantedCapabilities: const ['session.sync'],
    );
    final client = CatalogSyncClient(
      credential: denied,
      outbox: outbox,
      client: MockClient((request) async {
        calls += 1;
        return http.Response(
          '{}',
          500,
          headers: {'content-type': 'application/json'},
        );
      }),
    );
    await expectLater(
      client.sync(snapshot: snapshot, provider: 'fixture'),
      throwsA(
        isA<CatalogSyncFailure>().having(
          (value) => value.code,
          'code',
          'capability_denied',
        ),
      ),
    );
    expect(calls, 0);
    expect(outbox.saves, 0);
  });

  test(
    'duplicate response keys fail closed while queued snapshot remains',
    () async {
      final outbox = MemoryOutbox();
      final client = CatalogSyncClient(
        credential: credential,
        outbox: outbox,
        client: MockClient(
          (request) async => http.Response(
            '{"roots":[],"roots":[]}',
            200,
            headers: {'content-type': 'application/json'},
          ),
        ),
      );
      await expectLater(
        client.sync(snapshot: snapshot, provider: 'fixture'),
        throwsA(
          isA<CatalogSyncFailure>().having(
            (value) => value.code,
            'code',
            'protocol_integrity_error',
          ),
        ),
      );
      expect(outbox.saves, 1);
      expect(outbox.payload, isNotNull);
    },
  );

  test(
    'organization client previews, executes and undoes explicitly',
    () async {
      final organizeCredential = ActiveDeviceCredential(
        deviceId: credential.deviceId,
        hubId: credential.hubId,
        baseUrl: credential.baseUrl,
        certFingerprint: credential.certFingerprint,
        deviceCredential: credential.deviceCredential,
        capabilityEpoch: 1,
        grantedCapabilities: const [
          'catalog.sync',
          'files.organize',
          'session.sync',
        ],
      );
      final paths = <String>[];
      final client = CatalogSyncClient(
        credential: organizeCredential,
        client: MockClient((request) async {
          paths.add(request.url.path);
          const counts = {
            'images': 0,
            'documents': 1,
            'media': 0,
            'archives': 0,
            'other': 0,
          };
          if (request.method == 'GET') {
            return http.Response(
              jsonEncode({
                'schema_version': clusterOrganizationSchema,
                'state': 'undo_available',
                'moved_count': 1,
                'category_counts': counts,
                'undo_token': 'org-0123456789abcdef',
                'can_undo': true,
              }),
              200,
              headers: {'content-type': 'application/json'},
            );
          }
          final input = jsonDecode(request.body) as Map<String, dynamic>;
          expect(input['schema_version'], clusterOrganizationSchema);
          if (request.url.path.endsWith('/preview')) {
            return http.Response(
              jsonEncode({
                'schema_version': clusterOrganizationSchema,
                'cluster_id': 'cl-0123456789abcdef',
                'cluster_title': '项目资料',
                'projection_sha256': 'a' * 64,
                'preview_sha256': 'b' * 64,
                'pc_file_count': 1,
                'virtual_file_count': 1,
                'category_counts': counts,
                'can_execute': true,
              }),
              200,
              headers: {'content-type': 'application/json'},
            );
          }
          final operation = request.url.path.endsWith('/undo')
              ? 'undo'
              : 'organize';
          return http.Response(
            jsonEncode({
              'schema_version': clusterOrganizationSchema,
              'operation': operation,
              'cluster_id': operation == 'undo' ? '' : 'cl-0123456789abcdef',
              'moved_count': 1,
              'category_counts': counts,
              'undo_token': 'org-0123456789abcdef',
              'catalog_refresh_pending': false,
            }),
            200,
            headers: {'content-type': 'application/json'},
          );
        }),
      );

      final preview = await client.previewOrganization(
        clusterId: 'cl-0123456789abcdef',
        projectionSha256: 'a' * 64,
      );
      expect(preview.pcFileCount, 1);
      final receipt = await client.executeOrganization(preview: preview);
      expect(receipt.movedCount, 1);
      final restored = await client.organizationStatus();
      expect(restored.state, 'undo_available');
      expect(restored.undoToken, receipt.undoToken);
      expect(restored.canUndo, isTrue);
      final undone = await client.undoOrganization(receipt.undoToken);
      expect(undone.operation, 'undo');
      expect(paths, [
        '/v1/catalog/organization/preview',
        '/v1/catalog/organization/execute',
        '/v1/catalog/organization/status',
        '/v1/catalog/organization/undo',
      ]);
      client.close();
    },
  );

  test('organization status rejects inconsistent recovery envelopes', () async {
    final organizeCredential = ActiveDeviceCredential(
      deviceId: credential.deviceId,
      hubId: credential.hubId,
      baseUrl: credential.baseUrl,
      certFingerprint: credential.certFingerprint,
      deviceCredential: credential.deviceCredential,
      capabilityEpoch: 1,
      grantedCapabilities: const ['catalog.sync', 'files.organize'],
    );
    final client = CatalogSyncClient(
      credential: organizeCredential,
      client: MockClient(
        (_) async => http.Response(
          jsonEncode({
            'schema_version': clusterOrganizationSchema,
            'state': 'undo_available',
            'moved_count': 1,
            'category_counts': const {
              'images': 0,
              'documents': 1,
              'media': 0,
              'archives': 0,
              'other': 0,
            },
            'undo_token': null,
            'can_undo': true,
          }),
          200,
          headers: {'content-type': 'application/json'},
        ),
      ),
    );
    await expectLater(
      client.organizationStatus(),
      throwsA(
        isA<CatalogSyncFailure>().having(
          (value) => value.code,
          'code',
          'protocol_integrity_error',
        ),
      ),
    );
    client.close();
  });
}
