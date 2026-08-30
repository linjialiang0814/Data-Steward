import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:steward_app/catalog/catalog_sync_client.dart';
import 'package:steward_app/catalog/today_materials.dart';
import 'package:steward_app/catalog/today_materials_view.dart';
import 'package:steward_app/secure_pairing/pairing_vault.dart';

void main() {
  test(
    'strict projection parser verifies counts, order and canonical hash',
    () {
      final value = _emptyProjection();
      final parsed = TodayMaterialsProjection.fromJson(value);
      expect(parsed.localDay, '2026-08-04');
      expect(parsed.assetCount, 0);

      final tampered = Map<String, Object?>.from(value)..['asset_count'] = 1;
      expect(
        () => TodayMaterialsProjection.fromJson(tampered),
        throwsFormatException,
      );
    },
  );

  test('authenticated client fetches Today projection once', () async {
    var calls = 0;
    final credential = ActiveDeviceCredential(
      deviceId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAW',
      baseUrl: Uri.parse('https://192.0.2.1:9443'),
      certFingerprint: 'b' * 64,
      deviceCredential: 'A' * 43,
      capabilityEpoch: 1,
      grantedCapabilities: const ['catalog.sync'],
    );
    final client = CatalogSyncClient(
      credential: credential,
      client: MockClient((request) async {
        calls += 1;
        expect(request.url.path, '/v1/catalog/today');
        return http.Response(
          jsonEncode(_emptyProjection()),
          200,
          headers: {'content-type': 'application/json'},
        );
      }),
    );
    final result = await client.fetchToday();
    client.close();
    expect(result.assetCount, 0);
    expect(calls, 1);
  });

  testWidgets('Today card explains sources and keeps feedback non-destructive', (
    tester,
  ) async {
    final projection = TodayMaterialsProjection(
      localDay: '2026-08-04',
      timezoneOffsetMinutes: 480,
      rootCount: 2,
      assetCount: 3,
      clusters: [
        TodayCluster(
          clusterId: 'cl-0123456789abcdef',
          title: '高等数学资料',
          startAtMillis: 1785801600000,
          endAtMillis: 1785802200000,
          sourcePlatforms: const ['android', 'windows'],
          mimeFamilies: const ['document', 'text'],
          assetCount: 2,
          confidencePermille: 900,
          confidenceBand: 'high',
          reasons: const ['文件名包含相同课程或事项关键词', '资料来自手机和电脑'],
          assets: const [
            TodayAsset(
              assetId:
                  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              displayName: '高数笔记.md',
              platform: 'android',
              sourceDisplayName: '手机资料',
              mimeFamily: 'text',
              effectiveAtMillis: 1785801600000,
              timeSource: 'modified',
            ),
            TodayAsset(
              assetId:
                  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
              displayName: 'calculus-slides.pdf',
              platform: 'windows',
              sourceDisplayName: '电脑资料',
              mimeFamily: 'document',
              effectiveAtMillis: 1785802200000,
              timeSource: 'modified',
            ),
          ],
        ),
      ],
      unassigned: const [
        TodayAsset(
          assetId:
              'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
          displayName: 'IMG_001.jpg',
          platform: 'android',
          sourceDisplayName: '手机资料',
          mimeFamily: 'image',
          effectiveAtMillis: 1785802300000,
          timeSource: 'observed',
        ),
      ],
      projectionSha256: 'd' * 64,
    );
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            child: TodayMaterialsView(
              projection: projection,
              loading: false,
              onRefresh: () {},
            ),
          ),
        ),
      ),
    );
    expect(find.text('高等数学资料'), findsOneWidget);
    expect(find.textContaining('手机 + 电脑'), findsOneWidget);
    expect(find.textContaining('信息不足，未强制归类'), findsOneWidget);

    await tester.tap(find.text('高等数学资料'));
    await tester.pumpAndSettle();
    expect(find.text('资料来自手机和电脑'), findsOneWidget);
    await tester.tap(find.text('保留这个分组'));
    await tester.pumpAndSettle();
    expect(find.text('已保留'), findsOneWidget);
    expect(find.textContaining('虚拟分组'), findsOneWidget);
  });

  testWidgets('organization requires preview, explicit confirm and supports undo', (
    tester,
  ) async {
    final projection = TodayMaterialsProjection(
      localDay: '2026-08-04',
      timezoneOffsetMinutes: 480,
      rootCount: 2,
      assetCount: 2,
      clusters: [
        TodayCluster(
          clusterId: 'cl-0123456789abcdef',
          title: '项目资料',
          startAtMillis: 1785801600000,
          endAtMillis: 1785802200000,
          sourcePlatforms: const ['android', 'windows'],
          mimeFamilies: const ['document', 'text'],
          assetCount: 2,
          confidencePermille: 900,
          confidenceBand: 'high',
          reasons: const ['文件名相关'],
          assets: const [
            TodayAsset(
              assetId:
                  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              displayName: 'project-notes.md',
              platform: 'android',
              sourceDisplayName: '手机资料',
              mimeFamily: 'text',
              effectiveAtMillis: 1785801600000,
              timeSource: 'modified',
            ),
            TodayAsset(
              assetId:
                  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
              displayName: 'project-slides.pdf',
              platform: 'windows',
              sourceDisplayName: '电脑资料',
              mimeFamily: 'document',
              effectiveAtMillis: 1785802200000,
              timeSource: 'modified',
            ),
          ],
        ),
      ],
      unassigned: const [],
      projectionSha256: 'd' * 64,
    );
    var executeCount = 0;
    var undoCount = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            child: TodayMaterialsView(
              projection: projection,
              loading: false,
              onRefresh: () {},
              onPreviewOrganization: (cluster, digest) async =>
                  ClusterOrganizationPreview(
                    clusterId: cluster.clusterId,
                    clusterTitle: cluster.title,
                    projectionSha256: digest,
                    previewSha256: 'e' * 64,
                    pcFileCount: 1,
                    virtualFileCount: 1,
                    categoryCounts: const {
                      'images': 0,
                      'documents': 1,
                      'media': 0,
                      'archives': 0,
                      'other': 0,
                    },
                  ),
              onExecuteOrganization: (preview) async {
                executeCount += 1;
                return const ClusterOrganizationReceipt(
                  operation: 'organize',
                  clusterId: 'cl-0123456789abcdef',
                  movedCount: 1,
                  categoryCounts: {
                    'images': 0,
                    'documents': 1,
                    'media': 0,
                    'archives': 0,
                    'other': 0,
                  },
                  undoToken: 'org-0123456789abcdef',
                  catalogRefreshPending: false,
                );
              },
              onUndoOrganization: (token) async {
                undoCount += 1;
                return const ClusterOrganizationReceipt(
                  operation: 'undo',
                  clusterId: '',
                  movedCount: 1,
                  categoryCounts: {
                    'images': 0,
                    'documents': 1,
                    'media': 0,
                    'archives': 0,
                    'other': 0,
                  },
                  undoToken: 'org-0123456789abcdef',
                  catalogRefreshPending: false,
                );
              },
            ),
          ),
        ),
      ),
    );

    await tester.tap(find.text('项目资料'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('准备整理'));
    await tester.pumpAndSettle();
    expect(find.textContaining('1 个手机文件只保留为虚拟分组'), findsOneWidget);
    expect(executeCount, 0);
    await tester.tap(find.text('确认整理'));
    await tester.pumpAndSettle();
    expect(executeCount, 1);
    expect(find.text('撤销本次整理'), findsOneWidget);

    await tester.tap(find.text('撤销本次整理'));
    await tester.pumpAndSettle();
    expect(undoCount, 1);
    expect(find.textContaining('已撤销整理'), findsOneWidget);
  });

  testWidgets(
    'restored organization status exposes global undo after rebuild',
    (tester) async {
      var undoCount = 0;
      Future<void> pump(ClusterOrganizationStatus status) => tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: TodayMaterialsView(
              projection: TodayMaterialsProjection.fromJson(_emptyProjection()),
              loading: false,
              onRefresh: () {},
              organizationStatus: status,
              onUndoOrganization: (_) async {
                undoCount += 1;
                return const ClusterOrganizationReceipt(
                  operation: 'undo',
                  clusterId: '',
                  movedCount: 2,
                  categoryCounts: {
                    'images': 0,
                    'documents': 2,
                    'media': 0,
                    'archives': 0,
                    'other': 0,
                  },
                  undoToken: 'org-0123456789abcdef',
                  catalogRefreshPending: false,
                );
              },
            ),
          ),
        ),
      );

      await pump(
        const ClusterOrganizationStatus(
          state: 'undo_available',
          movedCount: 2,
          categoryCounts: {
            'images': 0,
            'documents': 2,
            'media': 0,
            'archives': 0,
            'other': 0,
          },
          undoToken: 'org-0123456789abcdef',
          canUndo: true,
        ),
      );
      expect(
        find.byKey(const Key('s6-pending-organization-card')),
        findsOneWidget,
      );
      expect(find.text('上次整理仍可撤销'), findsOneWidget);
      await tester.tap(find.byKey(const Key('s6-undo-restored-organization')));
      await tester.pumpAndSettle();
      expect(undoCount, 1);

      await pump(const ClusterOrganizationStatus.idle());
      await tester.pumpAndSettle();
      expect(
        find.byKey(const Key('s6-pending-organization-card')),
        findsNothing,
      );
    },
  );

  testWidgets('recovery-required status never exposes an undo action', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: TodayMaterialsView(
            projection: TodayMaterialsProjection.fromJson(_emptyProjection()),
            loading: false,
            onRefresh: () {},
            organizationStatus:
                const ClusterOrganizationStatus.recoveryRequired(),
            onUndoOrganization: (_) => throw StateError('must not run'),
          ),
        ),
      ),
    );
    expect(find.text('上次整理需要人工核对'), findsOneWidget);
    expect(
      find.byKey(const Key('s6-undo-restored-organization')),
      findsNothing,
    );
  });

  testWidgets('organization actions wrap without narrow-screen overflow', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(360, 800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final projection = TodayMaterialsProjection(
      localDay: '2026-08-05',
      timezoneOffsetMinutes: 480,
      rootCount: 1,
      assetCount: 1,
      clusters: [
        TodayCluster(
          clusterId: 'cl-0123456789abcdef',
          title: '窄屏整理测试',
          startAtMillis: 1785888000000,
          endAtMillis: 1785888000000,
          sourcePlatforms: const ['windows'],
          mimeFamilies: const ['text'],
          assetCount: 1,
          confidencePermille: 900,
          confidenceBand: 'high',
          reasons: const ['fixture'],
          assets: const [
            TodayAsset(
              assetId:
                  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              displayName: 'fixture.md',
              platform: 'windows',
              sourceDisplayName: 'fixture',
              mimeFamily: 'text',
              effectiveAtMillis: 1785888000000,
              timeSource: 'modified',
            ),
          ],
        ),
      ],
      unassigned: const [],
      projectionSha256: 'd' * 64,
    );
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            child: TodayMaterialsView(
              projection: projection,
              loading: false,
              onRefresh: () {},
              onPreviewOrganization: (_, _) => throw StateError('not tapped'),
              onExecuteOrganization: (_) => throw StateError('not tapped'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('窄屏整理测试'));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
    expect(find.text('准备整理'), findsOneWidget);
  });

  testWidgets('visible status refresh pauses after one network failure', (
    tester,
  ) async {
    var calls = 0;
    Future<void> refresh() async {
      calls += 1;
      if (calls == 1) throw const CatalogSyncFailure('transient_network');
    }

    Widget page(bool active) => MaterialApp(
      home: TodayMaterialsView(
        projection: TodayMaterialsProjection.fromJson(_emptyProjection()),
        loading: false,
        onRefresh: () {},
        onRefreshOrganizationStatus: refresh,
        active: active,
      ),
    );

    await tester.pumpWidget(page(true));
    await tester.pump(const Duration(seconds: 5));
    expect(calls, 1);
    await tester.pump(const Duration(seconds: 15));
    expect(calls, 1);

    await tester.pumpWidget(page(false));
    await tester.pumpWidget(page(true));
    await tester.pump(const Duration(seconds: 5));
    expect(calls, 2);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}

Map<String, Object?> _emptyProjection() {
  final value = <String, Object?>{
    'schema_version': todayMaterialsSchema,
    'rule_version': todayClusterRuleVersion,
    'local_day': '2026-08-04',
    'timezone_offset_minutes': 480,
    'source_projection_sha256': 'a' * 64,
    'root_count': 2,
    'asset_count': 0,
    'cluster_count': 0,
    'unassigned_count': 0,
    'clusters': <Object?>[],
    'unassigned': <Object?>[],
  };
  // Python catalog_clustering.py golden vector for this exact projection.
  value['projection_sha256'] =
      '1fd8d989363b74e988cd44c06ab3c915eee8eed0249c4a70de674ae1633921f5';
  return value;
}
