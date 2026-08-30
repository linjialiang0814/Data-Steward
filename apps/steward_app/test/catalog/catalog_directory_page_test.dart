import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:steward_app/catalog/catalog_bridge.dart';
import 'package:steward_app/catalog/catalog_directory_page.dart';

void main() {
  testWidgets(
    'starts metadata-only and requires explicit directory selection',
    (tester) async {
      await pumpPage(tester, FakeCatalogBridge());

      expect(find.text('尚未授权资料目录'), findsOneWidget);
      expect(find.textContaining('默认只同步本级文件元数据'), findsOneWidget);
      expect(button(tester, '刷新本地清单').onPressed, isNull);
      expect(button(tester, '忘记资料目录').onPressed, isNull);
    },
  );

  testWidgets('selection and refresh show only local metadata', (tester) async {
    final bridge = FakeCatalogBridge(
      selected: authorized(),
      snapshot: fakeSnapshot(),
    );
    await pumpPage(tester, bridge);

    await tester.tap(find.text('选择资料目录'));
    await tester.pumpAndSettle();
    expect(find.text('资料目录已授权'), findsOneWidget);
    expect(find.text('手机目录默认只同步元数据；图片文字识别需要单独授权并手动触发'), findsOneWidget);

    await tester.tap(find.text('刷新本地清单'));
    await tester.pumpAndSettle();
    await tester.drag(find.byType(ListView), const Offset(0, -500));
    await tester.pumpAndSettle();
    expect(find.text('2 个文件 · 跳过 1 项'), findsOneWidget);
    expect(find.text('课堂笔记.md'), findsOneWidget);
    expect(find.text('IMG_20260804.jpg'), findsOneWidget);
    expect(find.textContaining('content://'), findsNothing);
  });

  testWidgets('persisted authorization is clearly restored', (tester) async {
    await pumpPage(
      tester,
      FakeCatalogBridge(initial: authorized(restored: true)),
    );

    expect(find.text('本次由持久授权恢复'), findsOneWidget);
    expect(find.text('更换资料目录'), findsOneWidget);
  });

  testWidgets('forget requires confirmation and never claims file deletion', (
    tester,
  ) async {
    final bridge = FakeCatalogBridge(initial: authorized());
    await pumpPage(tester, bridge);

    await tester.tap(find.text('忘记资料目录'));
    await tester.pumpAndSettle();
    expect(find.text('忘记手机资料目录？'), findsOneWidget);
    expect(find.textContaining('不会删除或修改'), findsOneWidget);
    await tester.tap(find.text('确认忘记'));
    await tester.pumpAndSettle();

    expect(bridge.forgetCalls, 1);
    expect(find.text('尚未授权资料目录'), findsOneWidget);
  });

  testWidgets('failure is sanitized and does not display platform details', (
    tester,
  ) async {
    final bridge = FakeCatalogBridge(
      initial: authorized(),
      snapshotFailure: const CatalogFailure('catalog_invalid_entry'),
    );
    await pumpPage(tester, bridge);

    await tester.tap(find.text('刷新本地清单'));
    await tester.pumpAndSettle();
    expect(find.textContaining('异常元数据'), findsOneWidget);
    expect(find.textContaining('content://'), findsNothing);
    expect(find.textContaining(r'C:\Users'), findsNothing);
  });

  testWidgets('busy state prevents duplicate refresh', (tester) async {
    final completer = Completer<CatalogSnapshot>();
    final bridge = FakeCatalogBridge(
      initial: authorized(),
      snapshotCompleter: completer,
    );
    await pumpPage(tester, bridge);

    final callback = button(tester, '刷新本地清单').onPressed!;
    callback();
    callback();
    await tester.pump();
    expect(bridge.snapshotCalls, 1);
    completer.complete(fakeSnapshot());
    await tester.pumpAndSettle();
    expect(bridge.snapshotCalls, 1);
  });

  testWidgets('active page refreshes once when app resumes', (tester) async {
    final bridge = FakeCatalogBridge(
      initial: authorized(),
      snapshot: fakeSnapshot(),
    );
    await pumpPage(tester, bridge);

    expect(bridge.snapshotCalls, 0);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();

    expect(bridge.snapshotCalls, 1);
    expect(find.textContaining('本地清单已刷新，共 2 个文件'), findsOneWidget);
    await tester.pump(const Duration(seconds: 10));
    expect(bridge.snapshotCalls, 1);
  });
}

Future<void> pumpPage(WidgetTester tester, CatalogBridge bridge) async {
  await tester.pumpWidget(
    MaterialApp(home: CatalogDirectoryPage(bridge: bridge)),
  );
  await tester.pumpAndSettle();
}

ButtonStyleButton button(WidgetTester tester, String label) =>
    tester.widget<ButtonStyleButton>(
      find.ancestor(
        of: find.text(label),
        matching: find.byWidgetPredicate(
          (widget) => widget is ButtonStyleButton,
        ),
      ),
    );

CatalogDirectoryState authorized({bool restored = false}) =>
    CatalogDirectoryState(
      status: 'authorized',
      authorized: true,
      canRead: true,
      restored: restored,
      contentAnalysisEnabled: false,
      provider: 'com.android.externalstorage.documents',
      catalogRootId: 'e' * 64,
    );

CatalogSnapshot fakeSnapshot() => CatalogSnapshot(
  catalogRootId: 'e' * 64,
  snapshotSha256: 'f' * 64,
  generatedAtMillis: 1234,
  itemCount: 2,
  skippedCount: 1,
  items: [
    CatalogItem(
      locatorToken: 'a' * 64,
      displayName: '课堂笔记.md',
      extension: 'md',
      mimeFamily: 'text',
      sizeBytes: 12,
      modifiedAtMillis: 1000,
      revision: 'b' * 64,
      contentEligible: true,
    ),
    CatalogItem(
      locatorToken: 'c' * 64,
      displayName: 'IMG_20260804.jpg',
      extension: 'jpg',
      mimeFamily: 'image',
      sizeBytes: 2048,
      modifiedAtMillis: 2000,
      revision: 'd' * 64,
      contentEligible: false,
    ),
  ],
);

final class FakeCatalogBridge implements CatalogBridge {
  FakeCatalogBridge({
    this.initial = const CatalogDirectoryState.notAuthorized(),
    this.selected,
    this.snapshot,
    this.snapshotFailure,
    this.snapshotCompleter,
  });

  final CatalogDirectoryState initial;
  final CatalogDirectoryState? selected;
  final CatalogSnapshot? snapshot;
  final CatalogFailure? snapshotFailure;
  final Completer<CatalogSnapshot>? snapshotCompleter;
  int snapshotCalls = 0;
  int forgetCalls = 0;

  @override
  Future<CatalogSnapshot> buildCatalogSnapshot() async {
    snapshotCalls += 1;
    final failure = snapshotFailure;
    if (failure != null) throw failure;
    if (snapshotCompleter != null) return snapshotCompleter!.future;
    return snapshot ?? fakeSnapshot();
  }

  @override
  Future<AndroidOcrBatchProjection> analyzeCatalogImages(
    CatalogSnapshot snapshot,
  ) => throw const CatalogFailure('ocr_unavailable');

  @override
  Future<CatalogDirectoryState> setContentAnalysisEnabled(bool enabled) async =>
      CatalogDirectoryState(
        status: 'authorized',
        authorized: true,
        canRead: true,
        restored: true,
        contentAnalysisEnabled: enabled,
        provider: initial.provider ?? 'com.android.externalstorage.documents',
        catalogRootId: initial.catalogRootId ?? 'e' * 64,
      );

  @override
  Future<CatalogDirectoryState> forgetCatalogDirectory() async {
    forgetCalls += 1;
    return const CatalogDirectoryState(
      status: 'forgotten',
      authorized: false,
      canRead: false,
      restored: false,
      contentAnalysisEnabled: false,
      permissionReleased: true,
    );
  }

  @override
  Future<CatalogDirectoryState> getCatalogState() async => initial;

  @override
  Future<CatalogDirectoryState> selectCatalogDirectory() async =>
      selected ?? authorized();
}
