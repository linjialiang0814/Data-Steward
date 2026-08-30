import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/app_ui/steward_memory_page.dart';
import 'package:steward_app/shared_session/protocol_models.dart';
import 'package:steward_app/shared_session_ui/memory_center_controller.dart';

void main() {
  testWidgets('active memory is shown without internal identifiers', (
    tester,
  ) async {
    final controller = _FakeMemoryController(
      snapshot: const MemoryCenterSnapshot(
        status: 'active',
        supportCount: 3,
        activationThreshold: 3,
        version: 4,
        actions: [
          ProductAction(
            actionId: 'act-internal',
            assistantMessageId: 'message-internal',
            kind: 'memory_forget',
            label: '忘记这项习惯',
            description: '后续建议不再调用这项习惯。',
            risk: 'preference',
            requiresConfirmation: true,
            requiredCapability: 'session.sync',
            status: 'available',
          ),
        ],
      ),
    );

    await tester.pumpWidget(_app(controller));
    await tester.pumpAndSettle();

    expect(find.text('默认工作区·按类型整理'), findsOneWidget);
    expect(find.text('已启用'), findsOneWidget);
    expect(find.text('学习进度 3/3'), findsOneWidget);
    expect(
      find.byKey(const Key('memory-page-action-memory_forget')),
      findsOneWidget,
    );
    expect(find.textContaining('act-internal'), findsNothing);
    expect(find.textContaining('message-internal'), findsNothing);
    expect(find.textContaining('先体验智能归档'), findsNothing);
  });

  testWidgets(
    'paused memory can be re-enabled and disconnected state is explicit',
    (tester) async {
      final controller = _FakeMemoryController(
        snapshot: const MemoryCenterSnapshot(
          status: 'forgotten',
          supportCount: 3,
          activationThreshold: 3,
          version: 5,
          actions: [
            ProductAction(
              actionId: 'act-reactivate',
              assistantMessageId: 'message-reactivate',
              kind: 'memory_approve',
              label: '启用这个习惯',
              description: '以后可主动引用这项整理偏好',
              risk: 'memory',
              requiresConfirmation: true,
              requiredCapability: 'session.sync',
              status: 'available',
            ),
          ],
        ),
      );

      await tester.pumpWidget(_app(controller));
      await tester.pumpAndSettle();
      expect(find.text('已停用'), findsOneWidget);
      expect(find.text('学习进度 3/3'), findsOneWidget);
      expect(
        find.byKey(const Key('memory-page-action-memory_approve')),
        findsOneWidget,
      );

      await tester.pumpWidget(_app(null));
      await tester.pumpAndSettle();
      expect(find.text('已停用'), findsOneWidget);
      expect(
        find.byKey(const Key('memory-page-offline-cache')),
        findsOneWidget,
      );
      expect(find.text('前往共享会话'), findsOneWidget);
      expect(
        tester
            .widget<FilledButton>(
              find.byKey(const Key('memory-page-action-memory_approve')),
            )
            .onPressed,
        isNull,
      );
    },
  );

  testWidgets(
    'first launch without a controller stays explicitly unavailable',
    (tester) async {
      await tester.pumpWidget(_app(null));
      expect(find.text('记忆服务尚未就绪'), findsOneWidget);
    },
  );

  testWidgets('failed refresh cannot erase the last verified memory snapshot', (
    tester,
  ) async {
    final controller = _FakeMemoryController(
      snapshot: const MemoryCenterSnapshot(
        status: 'active',
        supportCount: 3,
        activationThreshold: 3,
        version: 7,
        actions: [],
      ),
    );
    MemoryCenterSnapshot? lifted;

    await tester.pumpWidget(
      MaterialApp(
        home: StewardMemoryPage(
          controller: controller,
          onOpenSession: () {},
          onSnapshotChanged: (value) => lifted = value,
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(lifted?.status, 'active');

    controller.snapshot = null;
    controller.notifyListeners();
    await tester.pumpAndSettle();
    expect(find.text('已启用'), findsOneWidget);
    expect(find.byKey(const Key('memory-page-stale-cache')), findsOneWidget);

    controller.available = false;
    controller.notifyListeners();
    await tester.pumpAndSettle();
    expect(find.text('已启用'), findsOneWidget);
    expect(find.byKey(const Key('memory-page-offline-cache')), findsOneWidget);
  });

  testWidgets('lifted snapshot survives memory page recreation', (
    tester,
  ) async {
    const snapshot = MemoryCenterSnapshot(
      status: 'active',
      supportCount: 3,
      activationThreshold: 3,
      version: 7,
      actions: [],
    );

    await tester.pumpWidget(
      MaterialApp(
        home: StewardMemoryPage(
          key: const ValueKey('online-memory-page'),
          controller: null,
          initialSnapshot: snapshot,
          onOpenSession: () {},
        ),
      ),
    );
    expect(find.text('已启用'), findsOneWidget);
    expect(find.byKey(const Key('memory-page-offline-cache')), findsOneWidget);
  });

  testWidgets('snapshot is cleared when the authenticated identity changes', (
    tester,
  ) async {
    final first = _FakeMemoryController(
      snapshot: const MemoryCenterSnapshot(
        status: 'active',
        supportCount: 3,
        activationThreshold: 3,
        version: 7,
        actions: [
          ProductAction(
            actionId: 'old-action',
            assistantMessageId: 'old-message',
            kind: 'memory_forget',
            label: '忘记这项习惯',
            description: '旧设备动作',
            risk: 'preference',
            requiresConfirmation: true,
            requiredCapability: 'session.sync',
            status: 'available',
          ),
        ],
      ),
    );
    final second = _FakeMemoryController(snapshot: null);

    await tester.pumpWidget(
      MaterialApp(
        home: StewardMemoryPage(
          controller: first,
          onOpenSession: () {},
          snapshotIdentityKey: 'hub-a:device-a:1',
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('已启用'), findsOneWidget);
    expect(
      find.byKey(const Key('memory-page-action-memory_forget')),
      findsOneWidget,
    );

    await tester.pumpWidget(
      MaterialApp(
        home: StewardMemoryPage(
          controller: second,
          onOpenSession: () {},
          snapshotIdentityKey: 'hub-b:device-b:1',
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('记忆状态暂时不可用'), findsOneWidget);
    expect(find.text('已启用'), findsNothing);
    expect(
      find.byKey(const Key('memory-page-action-memory_forget')),
      findsNothing,
    );
  });

  testWidgets('late snapshot from the previous identity is discarded', (
    tester,
  ) async {
    final delayed = Completer<MemoryCenterSnapshot?>();
    final first = _FakeMemoryController(
      snapshot: null,
      memoryCompleter: delayed,
    );
    final second = _FakeMemoryController(
      snapshot: const MemoryCenterSnapshot(
        status: 'forgotten',
        supportCount: 3,
        activationThreshold: 3,
        version: 8,
        actions: [],
      ),
    );

    await tester.pumpWidget(
      MaterialApp(
        home: StewardMemoryPage(
          controller: first,
          onOpenSession: () {},
          snapshotIdentityKey: 'hub-a:device-a:1',
        ),
      ),
    );
    await tester.pump();

    await tester.pumpWidget(
      MaterialApp(
        home: StewardMemoryPage(
          controller: second,
          onOpenSession: () {},
          snapshotIdentityKey: 'hub-b:device-b:1',
        ),
      ),
    );
    delayed.complete(
      const MemoryCenterSnapshot(
        status: 'active',
        supportCount: 3,
        activationThreshold: 3,
        version: 7,
        actions: [],
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('已停用'), findsOneWidget);
    expect(find.text('已启用'), findsNothing);
  });
}

Widget _app(MemoryCenterController? controller) => MaterialApp(
  home: StewardMemoryPage(controller: controller, onOpenSession: () {}),
);

final class _FakeMemoryController extends ChangeNotifier
    implements MemoryCenterController {
  _FakeMemoryController({required this.snapshot, this.memoryCompleter});

  MemoryCenterSnapshot? snapshot;
  final Completer<MemoryCenterSnapshot?>? memoryCompleter;
  bool available = true;

  @override
  bool get actionBusy => false;

  @override
  bool get canLoadMemory => available;

  @override
  Future<ProductActionExecution> executeAction(ProductAction action) =>
      throw UnimplementedError();

  @override
  Future<MemoryCenterSnapshot?> memoryCenter() async =>
      memoryCompleter?.future ?? snapshot;
}
