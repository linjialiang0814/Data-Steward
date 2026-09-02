import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/main.dart';
import 'package:steward_app/saf_bridge.dart';
import 'package:steward_app/shared_session/hub_websocket_client.dart';
import 'package:steward_app/shared_session/protocol_codec.dart';
import 'package:steward_app/shared_session/protocol_models.dart';
import 'package:steward_app/shared_session/session_projection.dart';
import 'package:steward_app/shared_session/shared_session_errors.dart';
import 'package:steward_app/shared_session_ui/shared_session_controller.dart';
import 'package:steward_app/shared_session_ui/shared_session_page.dart';

import '../shared_session/test_helpers.dart';

void main() {
  testWidgets('Windows app displays shared session page', (tester) async {
    final controller = _controller(FakeUiTransport());

    await tester.pumpWidget(StewardApp(sharedSessionController: controller));

    expect(find.text('智能会话'), findsOneWidget);
    expect(find.text('从一个安全任务开始'), findsOneWidget);
    expect(find.textContaining('Spike'), findsNothing);
    expect(find.text('看下电脑有几个图片文件'), findsOneWidget);
    controller.dispose();
  });

  testWidgets('explicit SAF bridge keeps Android SAF page', (tester) async {
    await tester.pumpWidget(const StewardApp(safBridge: _FakeSafBridge()));
    await _settle(tester);

    expect(find.text('Android SAF 风险验证页（非最终产品）'), findsOneWidget);
    expect(find.text('智能会话'), findsNothing);
  });

  testWidgets('ready timeline shows simulated sources role and sequence', (
    tester,
  ) async {
    final transport = FakeUiTransport(
      events: <WireEvent>[
        _event(1, actor: 'phone-sim'),
        _event(2, actor: 'pad-sim'),
      ],
    );
    final controller = _controller(transport);
    await tester.pumpWidget(StewardApp(sharedSessionController: controller));
    await _startController(tester, controller);
    await _settle(tester);

    expect(find.text('连接状态：已连接'), findsOneWidget);
    expect(find.textContaining('来源：手机'), findsNothing);
    await tester.tap(find.text('查看消息详情').first);
    await _settle(tester);
    expect(find.textContaining('来源：手机'), findsOneWidget);
    expect(find.textContaining('角色：user'), findsOneWidget);
    expect(find.textContaining('序号：1'), findsOneWidget);
    controller.dispose();
  });

  testWidgets(
    'assistant suggestion uses action buttons and hides internal ids',
    (tester) async {
      final transport = _ActionUiTransport(
        events: <WireEvent>[
          _event(
            1,
            actor: 'data-steward-memory',
            role: 'assistant',
            content: '我建议按类型整理；目前只是预览。',
          ),
        ],
      );
      final controller = _controller(transport);
      await tester.pumpWidget(StewardApp(sharedSessionController: controller));
      await _startController(tester, controller);
      await _settle(tester);

      expect(find.byKey(const Key('product-action-card')), findsWidgets);
      expect(find.text('接受建议'), findsWidgets);
      expect(find.textContaining('sg-'), findsNothing);
      expect(find.textContaining('mem-'), findsNothing);
      expect(find.textContaining('sha256'), findsNothing);
      await tester.tap(find.byKey(const Key('product-action-archive_accept')));
      await _settle(tester);
      expect(transport.executedKinds, ['archive_accept']);
      controller.dispose();
    },
  );

  testWidgets('organize execution immediately exposes undo action', (
    tester,
  ) async {
    final transport = _OrganizeActionUiTransport(
      events: <WireEvent>[
        _event(
          1,
          actor: 'data-steward-agent',
          role: 'assistant',
          content: 'I can organize these files after confirmation.',
        ),
      ],
    );
    final controller = _controller(transport);
    await tester.pumpWidget(StewardApp(sharedSessionController: controller));
    await _startController(tester, controller);
    await _settle(tester);

    await tester.tap(find.byKey(const Key('product-action-organize_execute')));
    await _settle(tester);
    await tester.tap(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.byType(FilledButton),
      ),
    );
    await _settle(tester);

    expect(controller.events, hasLength(2));
    expect(
      find.byKey(const Key('product-action-organize_undo')),
      findsOneWidget,
    );
    expect(
      find.byKey(const Key('product-action-organize_execute')),
      findsNothing,
    );
    controller.dispose();
  });

  testWidgets('send is disabled until ready and while busy', (tester) async {
    final transport = FakeUiTransport();
    final controller = _controller(transport);
    await tester.pumpWidget(StewardApp(sharedSessionController: controller));

    expect(_button(tester).onPressed, isNull);
    await _startController(tester, controller);
    await _settle(tester);
    expect(_button(tester).onPressed, isNotNull);

    transport.appendCompleter = Completer<AppendMessageResult>();
    await tester.enterText(
      find.byKey(const Key('message-input')),
      'contract message',
    );
    await tester.tap(find.byKey(const Key('send-button')));
    await tester.pump();
    expect(_button(tester).onPressed, isNull);
    transport.completeAppend();
    await _settle(tester);
    controller.dispose();
  });

  testWidgets('enter sends while shift enter preserves a multiline draft', (
    tester,
  ) async {
    final transport = FakeUiTransport();
    final controller = _controller(transport);
    await tester.pumpWidget(StewardApp(sharedSessionController: controller));
    await _startController(tester, controller);
    await _settle(tester);

    final input = find.byKey(const Key('message-input'));
    await tester.tap(input);
    await tester.enterText(input, '第一行');
    await tester.sendKeyDownEvent(LogicalKeyboardKey.shiftLeft);
    await tester.sendKeyDownEvent(LogicalKeyboardKey.enter, character: '\n');
    await tester.sendKeyUpEvent(LogicalKeyboardKey.enter);
    await tester.sendKeyUpEvent(LogicalKeyboardKey.shiftLeft);
    await tester.pump();
    expect(transport.events, isEmpty);

    await tester.enterText(input, '第一行\n第二行');
    await tester.sendKeyDownEvent(LogicalKeyboardKey.enter);
    await tester.sendKeyUpEvent(LogicalKeyboardKey.enter);
    await _settle(tester);

    expect(transport.events, hasLength(1));
    expect(transport.events.single.payload.content, '第一行\n第二行');
    expect(tester.widget<TextField>(input).controller!.text, isEmpty);
    controller.dispose();
  });

  testWidgets('quick start updates the composer without sending', (
    tester,
  ) async {
    final transport = FakeUiTransport();
    final controller = _controller(transport);
    final consumed = <int>[];
    await tester.pumpWidget(
      MaterialApp(
        home: SharedSessionPage(
          key: const ValueKey('first-session-page'),
          controller: controller,
          initialDraft: '汇总今天的资料',
          initialDraftRevision: 1,
          onInitialDraftConsumed: consumed.add,
        ),
      ),
    );
    await _startController(tester, controller);
    await _settle(tester);

    final input = find.byKey(const Key('message-input'));
    expect(tester.widget<TextField>(input).controller!.text, '汇总今天的资料');
    expect(transport.events, isEmpty);
    expect(consumed, [1]);

    await tester.pumpWidget(
      MaterialApp(
        home: SharedSessionPage(
          key: const ValueKey('second-session-page'),
          controller: controller,
          initialDraftRevision: 1,
          onInitialDraftConsumed: consumed.add,
        ),
      ),
    );
    await tester.pump();
    expect(tester.widget<TextField>(input).controller!.text, isEmpty);
    expect(transport.events, isEmpty);
    expect(consumed, [1]);
    controller.dispose();
  });

  testWidgets('cursor ahead reset requires explicit confirmation', (
    tester,
  ) async {
    final store = _UiCursorStore(8);
    final controller = _controller(
      FakeUiTransport(events: <WireEvent>[_event(1)]),
      store: store,
    );
    await tester.pumpWidget(StewardApp(sharedSessionController: controller));
    await _startController(tester, controller);
    await _settle(tester);

    expect(find.text('连接状态：同步状态需修复'), findsOneWidget);
    await tester.tap(find.text('重置同步游标'));
    await _settle(tester);
    expect(find.text('重置应用私有同步游标？'), findsOneWidget);
    expect(find.textContaining('不删除 Hub 会话或消息'), findsOneWidget);
    expect(store.value, 8);

    await tester.tap(find.text('确认重置'));
    await _settle(tester);
    expect(store.value, 0);
    controller.dispose();
  });

  testWidgets('revoked session exposes explicit return-to-scanner recovery', (
    tester,
  ) async {
    final controller = _controller(
      FakeUiTransport(healthAuthError: 'auth_revoked'),
    );
    var returned = false;
    await tester.pumpWidget(
      MaterialApp(
        home: SharedSessionPage(
          controller: controller,
          onReturnToServiceScanner: () async => returned = true,
        ),
      ),
    );
    await _startController(tester, controller);
    await _settle(tester);
    expect(controller.state, SharedSessionViewState.authorizationChanged);
    expect(
      find.byKey(const Key('c3-return-to-service-scanner')),
      findsOneWidget,
    );
    await tester.tap(find.byKey(const Key('c3-return-to-service-scanner')));
    await tester.pump();
    expect(returned, isTrue);
    controller.dispose();
  });

  testWidgets('offline mobile session can return to service scanner', (
    tester,
  ) async {
    final controller = _controller(FakeUiTransport(offline: true));
    var returned = false;
    await tester.pumpWidget(
      MaterialApp(
        home: SharedSessionPage(
          controller: controller,
          onReturnToServiceScanner: () async => returned = true,
        ),
      ),
    );
    await _startController(tester, controller);
    await _settle(tester);

    expect(controller.state, SharedSessionViewState.offline);
    expect(find.text('扫描服务码更新电脑地址'), findsOneWidget);
    expect(find.text('了解'), findsNothing);
    await tester.tap(find.byKey(const Key('c3-return-to-service-scanner')));
    await tester.pump();
    expect(returned, isTrue);
    controller.dispose();
  });

  testWidgets('offline session offers retry and service-code recovery', (
    tester,
  ) async {
    final socket = FakeHubSocket();
    late HubWebSocketClient socketClient;
    final controller = _controller(
      FakeUiTransport(),
      socket: socket,
      onSocketClient: (value) => socketClient = value,
    );
    var retryCount = 0;
    var returned = false;
    await tester.pumpWidget(
      MaterialApp(
        home: SharedSessionPage(
          controller: controller,
          onRetryConnection: () async => retryCount += 1,
          onReturnToServiceScanner: () async => returned = true,
        ),
      ),
    );
    await _startController(tester, controller);
    await _settle(tester);
    expect(controller.state, SharedSessionViewState.ready);

    expect(await socketClient.handleCloseCode(1001, attempt: 0), isFalse);
    await tester.pump();

    expect(controller.state, SharedSessionViewState.offline);
    expect(controller.safeError, isNull);
    expect(find.textContaining('等待网络稳定'), findsOneWidget);
    expect(find.text('网络稳定后重连'), findsOneWidget);
    expect(find.text('扫描服务码更新电脑地址'), findsOneWidget);
    await tester.tap(find.byKey(const Key('s4-retry-established-session')));
    await tester.pump();
    expect(retryCount, 1);
    expect(returned, isFalse);
    await tester.tap(find.byKey(const Key('c3-return-to-service-scanner')));
    await tester.pump();
    expect(returned, isTrue);
    controller.dispose();
  });

  testWidgets('800x600 and narrow layouts avoid overflow and sensitive text', (
    tester,
  ) async {
    final transport = FakeUiTransport(
      events: <WireEvent>[
        _event(1, actor: 'phone-sim'),
        _event(2, actor: 'pad-sim'),
      ],
    );
    final controller = _controller(transport);
    await tester.pumpWidget(StewardApp(sharedSessionController: controller));
    await _startController(tester, controller);

    for (final size in <Size>[const Size(800, 600), const Size(320, 600)]) {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      await tester.pumpWidget(StewardApp(sharedSessionController: controller));
      await _settle(tester);
      expect(tester.takeException(), isNull);
    }
    final visibleText = tester
        .widgetList<Text>(find.byType(Text))
        .map((widget) => widget.data ?? '')
        .join('\n');
    expect(visibleText, isNot(contains('http://')));
    expect(visibleText, isNot(contains('127.0.0.1')));
    expect(visibleText, isNot(contains(r'C:\')));
    expect(visibleText, isNot(contains('event-')));
    expect(visibleText, isNot(contains(demoConversationId)));

    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    controller.dispose();
  });

  testWidgets('offline protocol corrupt and cursor states are visible', (
    tester,
  ) async {
    final cases = <({SharedSessionController controller, String label})>[
      (
        controller: _controller(FakeUiTransport(offline: true)),
        label: '连接状态：Hub 离线',
      ),
      (
        controller: _controller(FakeUiTransport(invalidHealth: true)),
        label: '连接状态：协议错误',
      ),
      (
        controller: _controller(
          FakeUiTransport(),
          store: _UiCursorStore(0)..corrupt = true,
        ),
        label: '连接状态：本地状态损坏',
      ),
    ];
    for (final entry in cases) {
      await tester.pumpWidget(
        StewardApp(sharedSessionController: entry.controller),
      );
      await _startController(tester, entry.controller);
      await _settle(tester);
      expect(find.text(entry.label), findsOneWidget);
      entry.controller.dispose();
    }
  });

  testWidgets('Bootstrap factory failure shows sanitized retry state', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        home: WindowsSharedSessionBootstrap(
          controllerFactory: () async {
            throw Exception(r'C:\private\cursor-state');
          },
        ),
      ),
    );
    await _settle(tester);

    expect(find.text('本地初始化失败'), findsOneWidget);
    expect(find.text('重试初始化'), findsOneWidget);
    final text = tester
        .widgetList<Text>(find.byType(Text))
        .map((widget) => widget.data ?? '')
        .join('\n');
    expect(text, isNot(contains(r'C:\private')));
    expect(text, isNot(contains('Exception')));
  });

  testWidgets('Bootstrap retry rejects duplicate clicks while busy', (
    tester,
  ) async {
    final retry = Completer<SharedSessionController>();
    var calls = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: WindowsSharedSessionBootstrap(
          controllerFactory: () {
            calls += 1;
            if (calls == 1) return Future<SharedSessionController>.error('x');
            return retry.future;
          },
        ),
      ),
    );
    await _settle(tester);
    final callback = tester
        .widget<FilledButton>(find.byKey(const Key('bootstrap-retry-button')))
        .onPressed!;

    callback();
    callback();
    await tester.pump();

    expect(calls, 2);
    retry.complete(_unconfiguredController());
    await _settle(tester);
  });

  testWidgets('Bootstrap dispose releases late controller', (tester) async {
    final factory = Completer<SharedSessionController>();
    final controller = _unconfiguredController();
    await tester.pumpWidget(
      MaterialApp(
        home: WindowsSharedSessionBootstrap(
          controllerFactory: () => factory.future,
        ),
      ),
    );
    await tester.pump();

    await tester.pumpWidget(const MaterialApp(home: SizedBox()));
    factory.complete(controller);
    await _settle(tester);

    await expectLater(controller.start(), throwsA(isA<ProjectionException>()));
  });
}

SharedSessionController _controller(
  FakeUiTransport transport, {
  _UiCursorStore? store,
  FakeHubSocket? socket,
  void Function(HubWebSocketClient)? onSocketClient,
}) {
  final resolvedSocket = socket ?? FakeHubSocket();
  return SharedSessionController(
    config: const DemoHubConfig(8123),
    cursorStore: store ?? _UiCursorStore(0),
    transportFactory: (_) => transport,
    socketFactory: (_, projection) {
      final client = HubWebSocketClient(
        baseUri: Uri.parse('ws://127.0.0.1:8123'),
        conversationId: demoConversationId,
        projection: projection,
        connector: (_) async {
          Timer.run(
            () => resolvedSocket.add(
              '{"kind":"ready","last_conversation_seq":'
              '${projection.lastConversationSeq}}',
            ),
          );
          return resolvedSocket;
        },
      );
      onSocketClient?.call(client);
      return client;
    },
    clientMessageIdFactory: () => 'fixed-secure-id-value',
  );
}

IconButton _button(WidgetTester tester) =>
    tester.widget<IconButton>(find.byKey(const Key('send-button')));

Future<void> _settle(WidgetTester tester) async {
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 350));
  await tester.pump();
}

Future<void> _startController(
  WidgetTester tester,
  SharedSessionController controller,
) async {
  final started = controller.start();
  await tester.pump();
  await tester.pump(Duration.zero);
  await started;
  await tester.pump();
}

SharedSessionController _unconfiguredController() => SharedSessionController(
  config: null,
  cursorStore: _UiCursorStore(0),
  transportFactory: (_) => FakeUiTransport(),
  socketFactory: (_, _) => throw UnimplementedError(),
);

class FakeUiTransport implements SharedSessionTransport {
  FakeUiTransport({
    List<WireEvent>? events,
    this.offline = false,
    this.invalidHealth = false,
    this.healthAuthError,
  }) : events = events ?? <WireEvent>[];

  final List<WireEvent> events;
  final bool offline;
  final bool invalidHealth;
  final String? healthAuthError;
  Completer<AppendMessageResult>? appendCompleter;

  @override
  Future<HealthStatus> health() async {
    if (offline) throw const TransportException();
    if (healthAuthError case final String code) {
      throw HubApiException(statusCode: 401, code: code);
    }
    return HealthStatus(
      protocolVersion: invalidHealth ? 2 : 1,
      databaseReady: true,
    );
  }

  @override
  Future<ConversationCreation> createDemoConversation() async =>
      const ConversationCreation(
        conversationId: demoConversationId,
        alreadyExisted: false,
      );

  @override
  Future<ReplayPage> replay({required int afterSeq, required int limit}) async {
    final page = events
        .where((event) => event.conversationSeq > afterSeq)
        .take(limit)
        .toList();
    return ReplayPage(
      events: page,
      lastConversationSeq: page.isEmpty ? afterSeq : page.last.conversationSeq,
    );
  }

  @override
  Future<AppendMessageResult> append({
    required String clientMessageId,
    required String content,
  }) async {
    final event = _event(events.length + 1, content: content);
    events.add(event);
    final result = AppendMessageResult(deduplicated: false, event: event);
    return appendCompleter?.future ?? result;
  }

  void completeAppend() {
    appendCompleter?.complete(
      AppendMessageResult(deduplicated: false, event: events.last),
    );
    appendCompleter = null;
  }

  @override
  void close() {}
}

final class _ActionUiTransport extends FakeUiTransport
    implements ProductActionTransport {
  _ActionUiTransport({required super.events});

  final List<String> executedKinds = [];

  ProductAction get _accept => const ProductAction(
    actionId: 'act-0123456789abcdef',
    assistantMessageId: 'message-1',
    kind: 'archive_accept',
    label: '接受建议',
    description: '记录这次选择，不会移动文件',
    risk: 'preference',
    requiresConfirmation: false,
    requiredCapability: 'session.sync',
    status: 'available',
  );

  @override
  Future<List<ProductAction>> listActions({
    required String assistantMessageId,
  }) async => assistantMessageId == 'message-1' ? [_accept] : const [];

  @override
  Future<ProductActionExecution> executeAction({
    required String assistantMessageId,
    required String actionId,
  }) async {
    executedKinds.add(_accept.kind);
    return ProductActionExecution(event: events.first, actions: const []);
  }

  @override
  Future<MemoryCenterSnapshot> memoryCenter() async =>
      const MemoryCenterSnapshot(
        status: 'learning',
        supportCount: 1,
        activationThreshold: 3,
        version: 1,
        actions: [],
      );
}

final class _OrganizeActionUiTransport extends FakeUiTransport
    implements ProductActionTransport {
  _OrganizeActionUiTransport({required super.events});

  bool executed = false;

  ProductAction get _organize => ProductAction(
    actionId: 'act-1111111111111111',
    assistantMessageId: 'message-1',
    kind: 'organize_execute',
    label: 'Confirm organization',
    description: 'Move the previewed files after confirmation.',
    risk: 'file_move',
    requiresConfirmation: true,
    requiredCapability: 'files.organize',
    status: executed ? 'completed' : 'available',
  );

  ProductAction get _undo => const ProductAction(
    actionId: 'act-2222222222222222',
    assistantMessageId: 'message-2',
    kind: 'organize_undo',
    label: 'Undo organization',
    description: 'Move the organized files back to the authorized folder.',
    risk: 'file_move',
    requiresConfirmation: true,
    requiredCapability: 'files.organize',
    status: 'available',
  );

  @override
  Future<List<ProductAction>> listActions({
    required String assistantMessageId,
  }) async => switch (assistantMessageId) {
    'message-1' => [_organize],
    'message-2' => [_undo],
    _ => const [],
  };

  @override
  Future<ProductActionExecution> executeAction({
    required String assistantMessageId,
    required String actionId,
  }) async {
    executed = true;
    final result = _event(
      2,
      actor: 'data-steward-agent',
      role: 'assistant',
      content: 'Organization completed. You can undo it.',
    );
    events.add(result);
    return ProductActionExecution(event: result, actions: [_undo]);
  }

  @override
  Future<MemoryCenterSnapshot> memoryCenter() async =>
      const MemoryCenterSnapshot(
        status: 'none',
        supportCount: 0,
        activationThreshold: 3,
        version: 0,
        actions: [],
      );
}

final class _UiCursorStore implements ResettableCursorStore {
  _UiCursorStore(this.value);

  int value;
  bool corrupt = false;

  @override
  Future<int> read(String conversationId) async {
    if (corrupt) throw const ProjectionException('local_state_corrupt');
    return value;
  }

  @override
  Future<void> write(String conversationId, int conversationSeq) async {
    value = conversationSeq;
  }

  @override
  Future<void> reset(String conversationId) async {
    value = 0;
  }
}

WireEvent _event(
  int sequence, {
  String actor = 'windows-demo',
  String role = 'user',
  String? content,
}) => decodeWireEvent(
  wireEventMap(
    sequence: sequence,
    eventId: 'event-$sequence',
    conversationId: demoConversationId,
    actor: actor,
    role: role,
    content: content ?? 'message-$sequence',
  ),
  expectedConversationId: demoConversationId,
);

final class _FakeSafBridge implements SafBridge {
  const _FakeSafBridge();

  @override
  Future<SafPermissionState> getPermissionState() async =>
      const SafPermissionState.notAuthorized();

  @override
  Future<SafPermissionState> selectDirectory() async =>
      const SafPermissionState.notAuthorized();

  @override
  Future<SafOperationResult> writeProbe() async =>
      const SafOperationResult(status: 'unsupported');

  @override
  Future<SafOperationResult> readProbe() async =>
      const SafOperationResult(status: 'unsupported');

  @override
  Future<SafOperationResult> deleteProbe() async =>
      const SafOperationResult(status: 'unsupported');
}
