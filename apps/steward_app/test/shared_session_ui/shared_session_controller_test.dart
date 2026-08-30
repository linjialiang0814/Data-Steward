import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/shared_session/hub_websocket_client.dart';
import 'package:steward_app/shared_session/protocol_codec.dart';
import 'package:steward_app/shared_session/protocol_models.dart';
import 'package:steward_app/shared_session/session_projection.dart';
import 'package:steward_app/shared_session/shared_session_errors.dart';
import 'package:steward_app/shared_session_ui/shared_session_controller.dart';

import '../shared_session/test_helpers.dart';

void main() {
  test('unconfigured controller does not create transport', () async {
    var transportCreated = false;
    final controller = SharedSessionController(
      config: null,
      cursorStore: FakeCursorStore(),
      transportFactory: (_) {
        transportCreated = true;
        return FakeTransport();
      },
      socketFactory: _unusedSocketFactory,
    );

    await controller.start();

    expect(controller.state, SharedSessionViewState.unconfigured);
    expect(transportCreated, isFalse);
    controller.dispose();
  });

  test('startup follows health create replay connect ready order', () async {
    final fixture = await ControllerFixture.create(eventCount: 2);

    await fixture.controller.start();

    expect(fixture.transport.calls, <String>[
      'health',
      'create',
      'replay:0',
      'replay:2',
    ]);
    expect(fixture.socketFactoryCalls, 1);
    expect(fixture.controller.state, SharedSessionViewState.ready);
    expect(fixture.controller.lastConversationSeq, 2);
    await fixture.close();
  });

  test('multi-page replay is complete and bounded', () async {
    final fixture = await ControllerFixture.create(eventCount: 5, pageSize: 2);

    await fixture.controller.start();

    expect(
      fixture.transport.calls.where((value) => value.startsWith('replay')),
      <String>['replay:0', 'replay:2', 'replay:4', 'replay:5'],
    );
    expect(fixture.controller.events, hasLength(5));
    await fixture.close();
  });

  test('persisted cursor behind hub is filled and advanced', () async {
    final store = FakeCursorStore(initial: 1);
    final fixture = await ControllerFixture.create(
      eventCount: 3,
      cursorStore: store,
    );

    await fixture.controller.start();

    expect(fixture.controller.persistedAtStart, 1);
    expect(store.value, 3);
    expect(fixture.controller.lastConversationSeq, 3);
    await fixture.close();
  });

  test('cursor ahead blocks websocket and send without reset', () async {
    final fixture = await ControllerFixture.create(
      eventCount: 1,
      cursorStore: FakeCursorStore(initial: 9),
    );

    await fixture.controller.start();

    expect(fixture.controller.state, SharedSessionViewState.cursorAhead);
    expect(fixture.socketFactoryCalls, 0);
    expect(fixture.controller.canSend, isFalse);
    await fixture.close();
  });

  test('local state corruption blocks replay and websocket', () async {
    final store = FakeCursorStore()..readError = true;
    final fixture = await ControllerFixture.create(
      eventCount: 1,
      cursorStore: store,
    );

    await fixture.controller.start();

    expect(fixture.controller.state, SharedSessionViewState.localStateCorrupt);
    expect(fixture.transport.calls, <String>['health', 'create']);
    expect(fixture.socketFactoryCalls, 0);
    await fixture.close();
  });

  test('revoked REST credential enters permanent non-retrying state', () async {
    final transport = FakeTransport()..healthAuthError = 'auth_revoked';
    final controller = SharedSessionController(
      config: const DemoHubConfig(8123),
      cursorStore: FakeCursorStore(),
      transportFactory: (_) => transport,
      socketFactory: _unusedSocketFactory,
    );

    await controller.start();

    expect(controller.state, SharedSessionViewState.authorizationChanged);
    expect(controller.safeError, contains('撤销'));
    expect(controller.canSend, isFalse);
    controller.dispose();
  });

  test(
    'live websocket event is persisted before visible notification',
    () async {
      final store = FakeCursorStore();
      final fixture = await ControllerFixture.create(cursorStore: store);
      await fixture.controller.start();
      final notified = Completer<void>();
      fixture.controller.addListener(() {
        if (fixture.controller.lastConversationSeq == 1 &&
            !notified.isCompleted) {
          notified.complete();
        }
      });

      fixture.socket.add(
        eventFrameJson(
          sequence: 1,
          delivery: 'live',
          conversationId: demoConversationId,
        ),
      );
      await notified.future.timeout(const Duration(seconds: 2));

      expect(store.value, 1);
      expect(fixture.controller.events, hasLength(1));
      await fixture.close();
    },
  );

  test('persistence failure closes socket and disables send', () async {
    final store = FakeCursorStore();
    final fixture = await ControllerFixture.create(cursorStore: store);
    await fixture.controller.start();
    store.writeError = true;
    final failed = Completer<void>();
    fixture.controller.addListener(() {
      if (fixture.controller.state ==
              SharedSessionViewState.localStateCorrupt &&
          !failed.isCompleted) {
        failed.complete();
      }
    });

    fixture.socket.add(
      eventFrameJson(
        sequence: 1,
        delivery: 'live',
        conversationId: demoConversationId,
      ),
    );
    await failed.future.timeout(const Duration(seconds: 2));

    expect(fixture.socket.closed, isTrue);
    expect(fixture.controller.canSend, isFalse);
    await fixture.close();
  });

  test('duplicate start and busy send are rejected', () async {
    final fixture = await ControllerFixture.create();
    await fixture.controller.start();

    await expectLater(
      fixture.controller.start(),
      throwsA(isA<ProjectionException>()),
    );
    fixture.transport.appendCompleter = Completer<AppendMessageResult>();
    final first = fixture.controller.send('message');
    await expectLater(
      fixture.controller.send('message'),
      throwsA(isA<ProjectionException>()),
    );
    fixture.transport.completeAppend();
    await first;
    await fixture.close();
  });

  test('REST and websocket same event appears once', () async {
    final fixture = await ControllerFixture.create();
    await fixture.controller.start();
    fixture.transport.onBeforeAppendReturn = (event) {
      fixture.socket.add(
        jsonEncode(<String, Object>{
          'kind': 'event',
          'delivery': 'live',
          'event': wireEventMap(
            sequence: 1,
            eventId: 'event-1',
            conversationId: demoConversationId,
            actor: 'windows-demo',
            content: 'message',
          ),
        }),
      );
    };

    await fixture.controller.send('message');
    await Future<void>.delayed(Duration.zero);

    expect(fixture.controller.events, hasLength(1));
    await fixture.close();
  });

  test('explicit retry reuses original client message id', () async {
    final fixture = await ControllerFixture.create();
    await fixture.controller.start();
    fixture.transport.failNextAppend = true;

    await expectLater(fixture.controller.send('message'), throwsA(anything));
    final firstId = fixture.transport.clientMessageIds.single;
    await fixture.controller.retryPending();

    expect(fixture.transport.clientMessageIds, <String>[firstId, firstId]);
    expect(fixture.controller.pendingContent, isNull);
    await fixture.close();
  });

  test(
    'validated websocket acceptance reconciles a lost REST acknowledgement',
    () async {
      final fixture = await ControllerFixture.create();
      await fixture.controller.start();
      fixture.transport.appendCompleter = Completer<AppendMessageResult>();

      final sending = fixture.controller.send('message');
      while (fixture.transport.clientMessageIds.isEmpty) {
        await Future<void>.delayed(Duration.zero);
      }
      fixture.socket.add(
        jsonEncode(<String, Object>{
          'kind': 'event',
          'delivery': 'live',
          'event': wireEventMap(
            sequence: 1,
            eventId: 'event-1',
            conversationId: demoConversationId,
            actor: 'phone-device',
            content: 'message',
            clientMessageId: fixture.transport.clientMessageIds.single,
          ),
        }),
      );
      await Future<void>.delayed(Duration.zero);
      fixture.transport.appendCompleter!.completeError(
        const TransportException(),
      );

      await expectLater(sending, completes);
      expect(fixture.controller.pendingContent, isNull);
      expect(fixture.controller.safeError, isNull);
      expect(fixture.controller.events, hasLength(1));
      await fixture.close();
    },
  );

  test(
    'explicit memory refresh rebuilds a transport closed by timeout',
    () async {
      final fixture = await ControllerFixture.create();
      await fixture.controller.start();
      fixture.transport.failNextMemory = true;

      expect(await fixture.controller.memoryCenter(), isNull);
      expect(fixture.transport.memoryCalls, 1);
      expect(fixture.transportFactoryCalls, 1);

      final recovered = await fixture.controller.memoryCenter();
      expect(recovered?.status, 'active');
      expect(fixture.transport.memoryCalls, 2);
      expect(fixture.transportFactoryCalls, 2);
      await fixture.close();
    },
  );

  test('dispose prevents later websocket state updates', () async {
    final fixture = await ControllerFixture.create();
    await fixture.controller.start();
    var notifications = 0;
    fixture.controller.addListener(() => notifications += 1);

    fixture.controller.dispose();
    fixture.socket.add(
      eventFrameJson(
        sequence: 1,
        delivery: 'live',
        conversationId: demoConversationId,
      ),
    );
    await Future<void>.delayed(Duration.zero);

    expect(notifications, 0);
  });
}

final class ControllerFixture {
  ControllerFixture._({
    required this.controller,
    required this.transport,
    required this.socket,
    required this.cursorStore,
  });

  final SharedSessionController controller;
  final FakeTransport transport;
  final FakeHubSocket socket;
  final FakeCursorStore cursorStore;
  int socketFactoryCalls = 0;
  int transportFactoryCalls = 0;

  static Future<ControllerFixture> create({
    int eventCount = 0,
    int pageSize = 100,
    FakeCursorStore? cursorStore,
  }) async {
    final transport = FakeTransport(eventCount: eventCount);
    final socket = FakeHubSocket();
    final store = cursorStore ?? FakeCursorStore();
    late final ControllerFixture fixture;
    final controller = SharedSessionController(
      config: const DemoHubConfig(8123),
      cursorStore: store,
      transportFactory: (_) {
        fixture.transportFactoryCalls += 1;
        return transport;
      },
      socketFactory: (_, projection) {
        fixture.socketFactoryCalls += 1;
        final client = HubWebSocketClient(
          baseUri: Uri.parse('ws://127.0.0.1:8123'),
          conversationId: demoConversationId,
          projection: projection,
          connector: (_) async {
            Timer.run(() {
              socket.add(
                '{"kind":"ready","last_conversation_seq":'
                '${projection.lastConversationSeq}}',
              );
            });
            return socket;
          },
        );
        return client;
      },
      clientMessageIdFactory: () => 'fixed-client-message-id',
      pageSize: pageSize,
    );
    fixture = ControllerFixture._(
      controller: controller,
      transport: transport,
      socket: socket,
      cursorStore: store,
    );
    return fixture;
  }

  Future<void> close() async {
    await controller.close();
    controller.dispose();
  }
}

final class FakeCursorStore implements ResettableCursorStore {
  FakeCursorStore({int initial = 0}) : value = initial;

  int value;
  bool readError = false;
  bool writeError = false;

  @override
  Future<int> read(String conversationId) async {
    if (readError) {
      throw const ProjectionException('local_state_corrupt');
    }
    return value;
  }

  @override
  Future<void> write(String conversationId, int conversationSeq) async {
    if (writeError) {
      throw const ProjectionException('local_state_corrupt');
    }
    if (conversationSeq < value) {
      throw const ProjectionException('cursor_regression');
    }
    value = conversationSeq;
  }

  @override
  Future<void> reset(String conversationId) async {
    value = 0;
  }
}

final class FakeTransport
    implements SharedSessionTransport, ProductActionTransport {
  FakeTransport({int eventCount = 0})
    : events = List<WireEvent>.generate(
        eventCount,
        (index) =>
            _event(index + 1, actor: index.isEven ? 'phone-sim' : 'pad-sim'),
      );

  final List<WireEvent> events;
  final List<String> calls = <String>[];
  final List<String> clientMessageIds = <String>[];
  bool failNextAppend = false;
  bool failNextMemory = false;
  int memoryCalls = 0;
  String? healthAuthError;
  Completer<AppendMessageResult>? appendCompleter;
  void Function(WireEvent event)? onBeforeAppendReturn;

  @override
  Future<HealthStatus> health() async {
    calls.add('health');
    if (healthAuthError case final String code) {
      throw HubApiException(statusCode: 401, code: code);
    }
    return const HealthStatus(protocolVersion: 1, databaseReady: true);
  }

  @override
  Future<ConversationCreation> createDemoConversation() async {
    calls.add('create');
    return const ConversationCreation(
      conversationId: demoConversationId,
      alreadyExisted: false,
    );
  }

  @override
  Future<ReplayPage> replay({required int afterSeq, required int limit}) async {
    calls.add('replay:$afterSeq');
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
    clientMessageIds.add(clientMessageId);
    if (failNextAppend) {
      failNextAppend = false;
      throw const TransportException();
    }
    final event = _event(events.length + 1, content: content);
    events.add(event);
    onBeforeAppendReturn?.call(event);
    final result = AppendMessageResult(deduplicated: false, event: event);
    final completer = appendCompleter;
    if (completer != null) return completer.future;
    return result;
  }

  void completeAppend() {
    final event = events.last;
    appendCompleter?.complete(
      AppendMessageResult(deduplicated: false, event: event),
    );
    appendCompleter = null;
  }

  @override
  Future<MemoryCenterSnapshot> memoryCenter() async {
    memoryCalls += 1;
    if (failNextMemory) {
      failNextMemory = false;
      throw const TransportException();
    }
    return const MemoryCenterSnapshot(
      status: 'active',
      supportCount: 3,
      activationThreshold: 3,
      version: 7,
      actions: [],
    );
  }

  @override
  Future<List<ProductAction>> listActions({
    required String assistantMessageId,
  }) async => const [];

  @override
  Future<ProductActionExecution> executeAction({
    required String assistantMessageId,
    required String actionId,
  }) => throw UnimplementedError();

  @override
  void close() {}
}

HubWebSocketClient _unusedSocketFactory(
  DemoHubConfig config,
  SessionProjection projection,
) => throw UnimplementedError();

WireEvent _event(
  int sequence, {
  String actor = 'windows-demo',
  String? content,
}) => decodeWireEvent(
  wireEventMap(
    sequence: sequence,
    eventId: 'event-$sequence',
    conversationId: demoConversationId,
    actor: actor,
    content: content ?? 'message-$sequence',
  ),
  expectedConversationId: demoConversationId,
);
