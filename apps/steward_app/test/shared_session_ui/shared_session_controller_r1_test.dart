import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/shared_session/hub_websocket_client.dart';
import 'package:steward_app/shared_session/protocol_codec.dart';
import 'package:steward_app/shared_session/protocol_models.dart';
import 'package:steward_app/shared_session/session_projection.dart';
import 'package:steward_app/shared_session/shared_session_errors.dart';
import 'package:steward_app/shared_session_ui/shared_session_controller.dart';

import '../shared_session/test_helpers.dart';

void main() {
  test('append transport error retains pending and original ID', () async {
    final fixture = R1Fixture();
    await fixture.start();
    fixture.primary.appendError = const TransportException();

    await expectLater(fixture.controller.send('message'), throwsA(anything));

    expect(fixture.controller.pendingContent, 'message');
    expect(fixture.primary.clientMessageIds, <String>['r1-client-id']);
    expect(fixture.controller.canRetry, isTrue);
    await fixture.close();
  });

  test('retry creates fresh transport and reuses original ID', () async {
    final replacement = R1Transport();
    final fixture = R1Fixture(replacements: <R1Transport>[replacement]);
    await fixture.start();
    fixture.primary.appendError = const TransportException();
    await expectLater(fixture.controller.send('message'), throwsA(anything));

    await fixture.controller.retryPending();

    expect(fixture.createdTransports, 2);
    expect(replacement.clientMessageIds, <String>['r1-client-id']);
    expect(fixture.controller.pendingContent, isNull);
    await fixture.close();
  });

  test('retry replacement performs health create then append', () async {
    final replacement = R1Transport();
    final fixture = R1Fixture(replacements: <R1Transport>[replacement]);
    await fixture.start();
    fixture.primary.appendError = const TransportException();
    await expectLater(fixture.controller.send('message'), throwsA(anything));

    await fixture.controller.retryPending();

    expect(replacement.calls, <String>[
      'health',
      'create',
      'append:r1-client-id',
    ]);
    await fixture.close();
  });

  test('persistence unavailable permits explicit same-ID retry', () async {
    final fixture = R1Fixture();
    await fixture.start();
    fixture.primary.appendError = const HubApiException(
      statusCode: 503,
      code: 'persistence_unavailable',
    );
    await expectLater(fixture.controller.send('message'), throwsA(anything));
    fixture.primary.appendError = null;

    await fixture.controller.retryPending();

    expect(fixture.createdTransports, 1);
    expect(fixture.primary.clientMessageIds, <String>[
      'r1-client-id',
      'r1-client-id',
    ]);
    await fixture.close();
  });

  test('idempotency conflict fails closed and disables retry', () async {
    final fixture = R1Fixture();
    await fixture.start();
    fixture.primary.appendError = const HubApiException(
      statusCode: 409,
      code: 'idempotency_conflict',
    );

    await expectLater(fixture.controller.send('message'), throwsA(anything));

    expect(fixture.controller.state, SharedSessionViewState.protocolError);
    expect(fixture.controller.pendingContent, isNull);
    expect(fixture.controller.canRetry, isFalse);
    expect(fixture.primary.closeCount, 1);
    expect(fixture.socket.closed, isTrue);
    await fixture.close();
  });

  test('append protocol error closes resources and disables retry', () async {
    final fixture = R1Fixture();
    await fixture.start();
    fixture.primary.appendError = const ProtocolIntegrityException();

    await expectLater(fixture.controller.send('message'), throwsA(anything));

    expect(fixture.controller.state, SharedSessionViewState.protocolError);
    expect(fixture.controller.canRetry, isFalse);
    expect(fixture.primary.closeCount, 1);
    expect(fixture.socket.closed, isTrue);
    await fixture.close();
  });

  test('append projection gap closes resources and disables retry', () async {
    final fixture = R1Fixture();
    await fixture.start();
    fixture.primary.appendResult = AppendMessageResult(
      deduplicated: false,
      event: _event(2),
    );

    await expectLater(fixture.controller.send('message'), throwsA(anything));

    expect(fixture.controller.state, SharedSessionViewState.protocolError);
    expect(fixture.controller.events, isEmpty);
    expect(fixture.controller.canRetry, isFalse);
    expect(fixture.primary.closeCount, 1);
    await fixture.close();
  });

  test('accepted event with cursor failure clears pending', () async {
    final store = R1CursorStore();
    final fixture = R1Fixture(store: store);
    await fixture.start();
    store.writeError = true;

    await expectLater(fixture.controller.send('message'), throwsA(anything));

    expect(fixture.controller.pendingContent, isNull);
    expect(fixture.controller.canRetry, isFalse);
    await fixture.close();
  });

  test('accepted event with cursor failure appears only once', () async {
    final store = R1CursorStore();
    final fixture = R1Fixture(store: store);
    await fixture.start();
    store.writeError = true;

    await expectLater(fixture.controller.send('message'), throwsA(anything));

    expect(fixture.controller.events, hasLength(1));
    expect(fixture.controller.events.single.conversationSeq, 1);
    await fixture.close();
  });

  test(
    'accepted cursor failure enters local corrupt and closes resources',
    () async {
      final store = R1CursorStore();
      final fixture = R1Fixture(store: store);
      await fixture.start();
      store.writeError = true;

      await expectLater(fixture.controller.send('message'), throwsA(anything));

      expect(
        fixture.controller.state,
        SharedSessionViewState.localStateCorrupt,
      );
      expect(fixture.primary.closeCount, 1);
      expect(fixture.socket.closed, isTrue);
      await fixture.close();
    },
  );

  test('dispose during delayed health never creates socket', () async {
    final health = Completer<HealthStatus>();
    final transport = R1Transport(healthCompleter: health);
    final fixture = R1Fixture(primary: transport);
    final started = fixture.controller.start();
    await _flush();

    fixture.controller.dispose();
    health.complete(
      const HealthStatus(protocolVersion: 1, databaseReady: true),
    );
    await started;

    expect(fixture.socketFactoryCalls, 0);
    expect(transport.closeCount, 1);
  });

  test(
    'close during delayed replay does not update projection or cursor',
    () async {
      final replay = Completer<ReplayPage>();
      final transport = R1Transport(replayCompleter: replay);
      final store = R1CursorStore();
      final fixture = R1Fixture(primary: transport, store: store);
      final started = fixture.controller.start();
      await _flush();

      await fixture.controller.close();
      replay.complete(
        ReplayPage(events: <WireEvent>[_event(1)], lastConversationSeq: 1),
      );
      await started;

      expect(fixture.controller.events, isEmpty);
      expect(store.writes, isEmpty);
      expect(transport.closeCount, 1);
    },
  );

  test('dispose during delayed append ignores accepted result', () async {
    final append = Completer<AppendMessageResult>();
    final fixture = R1Fixture(primary: R1Transport(appendCompleter: append));
    await fixture.start();
    var notifications = 0;
    fixture.controller.addListener(() => notifications += 1);
    final sending = fixture.controller.send('message');
    await _flush();
    final beforeDispose = notifications;

    fixture.controller.dispose();
    append.complete(AppendMessageResult(deduplicated: false, event: _event(1)));
    await sending;

    expect(fixture.controller.events, isEmpty);
    expect(notifications, beforeDispose);
  });

  test('late connector socket is immediately released after close', () async {
    final connector = Completer<HubSocket>();
    final socket = FakeHubSocket();
    final transport = R1Transport();
    late SharedSessionController controller;
    controller = SharedSessionController(
      config: const DemoHubConfig(8123),
      cursorStore: R1CursorStore(),
      transportFactory: (_) => transport,
      socketFactory: (_, projection) => HubWebSocketClient(
        baseUri: Uri.parse('ws://127.0.0.1:8123'),
        conversationId: demoConversationId,
        projection: projection,
        connector: (_) => connector.future,
      ),
      clientMessageIdFactory: () => 'r1-client-id',
    );
    final started = controller.start();
    await _flush();

    await controller.close();
    connector.complete(socket);
    await started;

    expect(socket.closed, isTrue);
    expect(transport.closeCount, 1);
    controller.dispose();
  });

  test('offline startup releases transport', () async {
    final transport = R1Transport(healthError: const TransportException());
    final fixture = R1Fixture(primary: transport);

    await fixture.controller.start();

    expect(fixture.controller.state, SharedSessionViewState.offline);
    expect(transport.closeCount, 1);
    await fixture.close();
  });

  test('protocol startup failure releases transport', () async {
    final transport = R1Transport(invalidHealth: true);
    final fixture = R1Fixture(primary: transport);

    await fixture.controller.start();

    expect(fixture.controller.state, SharedSessionViewState.protocolError);
    expect(transport.closeCount, 1);
    await fixture.close();
  });
}

final class R1Fixture {
  R1Fixture({
    R1Transport? primary,
    List<R1Transport>? replacements,
    R1CursorStore? store,
  }) : primary = primary ?? R1Transport(),
       store = store ?? R1CursorStore(),
       _replacementQueue = replacements ?? <R1Transport>[] {
    controller = SharedSessionController(
      config: const DemoHubConfig(8123),
      cursorStore: this.store,
      transportFactory: (_) {
        createdTransports += 1;
        if (createdTransports == 1) return this.primary;
        return _replacementQueue.removeAt(0);
      },
      socketFactory: (_, projection) {
        socketFactoryCalls += 1;
        return HubWebSocketClient(
          baseUri: Uri.parse('ws://127.0.0.1:8123'),
          conversationId: demoConversationId,
          projection: projection,
          connector: (_) async {
            Timer.run(
              () => socket.add(
                '{"kind":"ready","last_conversation_seq":'
                '${projection.lastConversationSeq}}',
              ),
            );
            return socket;
          },
        );
      },
      clientMessageIdFactory: () => 'r1-client-id',
    );
  }

  late final SharedSessionController controller;
  final R1Transport primary;
  final R1CursorStore store;
  final List<R1Transport> _replacementQueue;
  final FakeHubSocket socket = FakeHubSocket();
  int createdTransports = 0;
  int socketFactoryCalls = 0;

  Future<void> start() => controller.start();

  Future<void> close() async {
    await controller.close();
    controller.dispose();
  }
}

final class R1Transport implements SharedSessionTransport {
  R1Transport({
    this.healthCompleter,
    this.replayCompleter,
    this.appendCompleter,
    this.healthError,
    this.invalidHealth = false,
  });

  final Completer<HealthStatus>? healthCompleter;
  final Completer<ReplayPage>? replayCompleter;
  final Completer<AppendMessageResult>? appendCompleter;
  final Object? healthError;
  final bool invalidHealth;
  final List<String> calls = <String>[];
  final List<String> clientMessageIds = <String>[];
  Object? appendError;
  AppendMessageResult? appendResult;
  int closeCount = 0;

  @override
  Future<HealthStatus> health() async {
    calls.add('health');
    if (healthError case final Object error) throw error;
    final completer = healthCompleter;
    if (completer != null) return completer.future;
    return HealthStatus(
      protocolVersion: invalidHealth ? 2 : 1,
      databaseReady: true,
    );
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
    final completer = replayCompleter;
    if (completer != null) return completer.future;
    return ReplayPage(
      events: const <WireEvent>[],
      lastConversationSeq: afterSeq,
    );
  }

  @override
  Future<AppendMessageResult> append({
    required String clientMessageId,
    required String content,
  }) async {
    calls.add('append:$clientMessageId');
    clientMessageIds.add(clientMessageId);
    if (appendError case final Object error) throw error;
    final completer = appendCompleter;
    if (completer != null) return completer.future;
    return appendResult ??
        AppendMessageResult(
          deduplicated: false,
          event: _event(1, content: content),
        );
  }

  @override
  void close() {
    closeCount += 1;
  }
}

final class R1CursorStore implements ResettableCursorStore {
  int value = 0;
  bool writeError = false;
  final List<int> writes = <int>[];

  @override
  Future<int> read(String conversationId) async => value;

  @override
  Future<void> write(String conversationId, int conversationSeq) async {
    if (writeError) throw const ProjectionException('local_state_corrupt');
    writes.add(conversationSeq);
    value = conversationSeq;
  }

  @override
  Future<void> reset(String conversationId) async {
    value = 0;
  }
}

Future<void> _flush() async {
  await Future<void>.delayed(Duration.zero);
  await Future<void>.delayed(Duration.zero);
}

WireEvent _event(int sequence, {String? content}) => decodeWireEvent(
  wireEventMap(
    sequence: sequence,
    eventId: 'r1-event-$sequence',
    conversationId: demoConversationId,
    actor: 'windows-demo',
    content: content ?? 'message-$sequence',
  ),
  expectedConversationId: demoConversationId,
);
