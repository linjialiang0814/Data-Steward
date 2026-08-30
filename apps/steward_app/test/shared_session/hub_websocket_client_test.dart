import 'dart:convert';
import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/shared_session/hub_websocket_client.dart';
import 'package:steward_app/shared_session/session_projection.dart';
import 'package:steward_app/shared_session/shared_session_errors.dart';

import 'test_helpers.dart';

void main() {
  test('connector timeout is bounded and late socket is released', () async {
    final pending = Completer<HubSocket>();
    final socket = FakeHubSocket();
    final client = HubWebSocketClient(
      baseUri: Uri.parse('ws://127.0.0.1:8123'),
      conversationId: 'conversation-1',
      projection: SessionProjection(conversationId: 'conversation-1'),
      connector: (_) => pending.future,
      connectTimeout: const Duration(milliseconds: 10),
    );

    await expectLater(client.connect(), throwsA(isA<TransportException>()));
    pending.complete(socket);
    await Future<void>.delayed(Duration.zero);

    expect(socket.closeCount, 1);
    expect(client.state, HubWebSocketState.protocolError);
    await client.close();
  });

  test('connector exception is mapped to sanitized transport error', () async {
    final client = HubWebSocketClient(
      baseUri: Uri.parse('ws://127.0.0.1:8123'),
      conversationId: 'conversation-1',
      projection: SessionProjection(conversationId: 'conversation-1'),
      connector: (_) => throw StateError('secret socket detail'),
    );

    try {
      await client.connect();
      fail('expected transport failure');
    } on TransportException catch (error) {
      expect(error.toString(), isNot(contains('secret')));
      expect(error.toString(), isNot(contains('127.0.0.1')));
    }
    await client.close();
  });

  test(
    'connecting rejects duplicate connect without second connector',
    () async {
      final pending = Completer<HubSocket>();
      var connectorCalls = 0;
      final client = HubWebSocketClient(
        baseUri: Uri.parse('ws://127.0.0.1:8123'),
        conversationId: 'conversation-1',
        projection: SessionProjection(conversationId: 'conversation-1'),
        connector: (_) {
          connectorCalls += 1;
          return pending.future;
        },
      );

      final firstConnect = client.connect();
      await expectLater(client.connect(), throwsA(isA<ProjectionException>()));
      pending.complete(FakeHubSocket());
      await firstConnect;

      expect(connectorCalls, 1);
      await client.close();
    },
  );

  test('rejects a binary WebSocket frame', () async {
    final fixture = await _fixture();

    expect(
      () => fixture.client.processFrame(<int>[1, 2, 3]),
      throwsA(isA<ProtocolIntegrityException>()),
    );
    await fixture.client.close();
  });

  test('applies replay then ready then live in order', () async {
    final fixture = await _fixture();

    fixture.client.processFrame(eventFrameJson());
    fixture.client.processFrame(
      jsonEncode(<String, Object>{'kind': 'ready', 'last_conversation_seq': 1}),
    );
    fixture.client.processFrame(eventFrameJson(sequence: 2, delivery: 'live'));

    expect(fixture.client.state, HubWebSocketState.ready);
    expect(fixture.projection.lastConversationSeq, 2);
    expect(fixture.projection.events, hasLength(2));
    await fixture.client.close();
  });

  test('ready rejects duplicate connect', () async {
    final fixture = await _fixture();
    fixture.client.processFrame(
      jsonEncode(<String, Object>{'kind': 'ready', 'last_conversation_seq': 0}),
    );

    await expectLater(
      fixture.client.connect(),
      throwsA(isA<ProjectionException>()),
    );
    expect(fixture.socket.closeCount, 0);
    await fixture.client.close();
  });

  test('deduplicates the same event id across replay delivery', () async {
    final fixture = await _fixture();

    fixture.client.processFrame(eventFrameJson());
    fixture.client.processFrame(eventFrameJson());

    expect(fixture.projection.events, hasLength(1));
    await fixture.client.close();
  });

  test('rejects a ready cursor different from projection', () async {
    final fixture = await _fixture();

    expect(
      () => fixture.client.processFrame(
        jsonEncode(<String, Object>{
          'kind': 'ready',
          'last_conversation_seq': 1,
        }),
      ),
      throwsA(isA<ProtocolIntegrityException>()),
    );
    await fixture.client.close();
  });

  test('cursor ahead enters protocol error and keeps watermark', () async {
    final fixture = await _fixture();
    final frame = jsonEncode(<String, Object>{
      'kind': 'error',
      'error': <String, Object>{
        'code': 'cursor_ahead',
        'message': 'replay cursor exceeds server state',
        'server_last_conversation_seq': 2,
      },
    });

    expect(
      () => fixture.client.processFrame(frame),
      throwsA(isA<HubApiException>()),
    );
    expect(fixture.client.state, HubWebSocketState.protocolError);
    expect(fixture.client.cursorAheadServerWatermark, 2);
    await fixture.client.close();
  });

  test('1008 and 1011 stop automatic retry', () async {
    final first = await _fixture();
    final second = await _fixture();

    expect(await first.client.handleCloseCode(1008, attempt: 0), isFalse);
    expect(await second.client.handleCloseCode(1011, attempt: 0), isFalse);
    expect(first.client.state, HubWebSocketState.protocolError);
    expect(second.client.state, HubWebSocketState.protocolError);
    await first.client.close();
    await second.client.close();
  });

  test('authenticated 1008 is a permanent authorization change', () async {
    final client = HubWebSocketClient(
      baseUri: Uri.parse('wss://192.168.1.2:9443'),
      conversationId: 'conversation-1',
      projection: SessionProjection(conversationId: 'conversation-1'),
      authenticatedPrivateLan: true,
      connector: (_) async => FakeHubSocket(),
    );

    expect(await client.handleCloseCode(1008, attempt: 0), isFalse);
    expect(client.state, HubWebSocketState.authorizationChanged);
    await client.close();
  });

  test('1013 uses bounded injected reconnect delay', () async {
    Duration? delayed;
    final fixture = await _fixture(
      delay: (duration) async {
        delayed = duration;
      },
      random: () => 1,
    );

    expect(await fixture.client.handleCloseCode(1013, attempt: 2), isTrue);
    expect(fixture.client.state, HubWebSocketState.reconnecting);
    expect(delayed, const Duration(milliseconds: 500));
    expect(await fixture.client.handleCloseCode(1013, attempt: 3), isFalse);
    await fixture.client.close();
  });

  test('1013 reconnects from the current projection cursor', () async {
    final first = FakeHubSocket();
    final second = FakeHubSocket();
    final sockets = <FakeHubSocket>[first, second];
    final connectedUris = <Uri>[];
    final projection = SessionProjection(conversationId: 'conversation-1');
    final client = HubWebSocketClient(
      baseUri: Uri.parse('ws://127.0.0.1:8123'),
      conversationId: 'conversation-1',
      projection: projection,
      connector: (uri) async {
        connectedUris.add(uri);
        return sockets.removeAt(0);
      },
      delay: (_) async {},
    );
    await client.connect();
    client.processFrame(eventFrameJson());
    final reconnected = client.states.firstWhere(
      (state) => state == HubWebSocketState.replaying,
    );

    await first.serverClose(1013);
    await reconnected;

    expect(connectedUris, hasLength(2));
    expect(connectedUris.last.queryParameters['after_seq'], '1');
    await client.close();
  });

  test('stream onError releases active socket once', () async {
    final fixture = await _fixture();
    final failed = fixture.client.states.firstWhere(
      (state) => state == HubWebSocketState.protocolError,
    );

    fixture.socket.addError(StateError('secret stream error'));
    await failed;

    expect(fixture.socket.closeCount, 1);
    await fixture.client.close();
    expect(fixture.socket.closeCount, 1);
  });

  test('1013 releases old socket before reconnect connector', () async {
    final first = FakeHubSocket();
    final second = FakeHubSocket();
    var connectorCalls = 0;
    final client = HubWebSocketClient(
      baseUri: Uri.parse('ws://127.0.0.1:8123'),
      conversationId: 'conversation-1',
      projection: SessionProjection(conversationId: 'conversation-1'),
      connector: (_) async {
        connectorCalls += 1;
        if (connectorCalls == 1) return first;
        expect(first.closeCount, 1);
        return second;
      },
      delay: (_) async {},
    );
    await client.connect();
    final reconnected = client.states.firstWhere(
      (state) => state == HubWebSocketState.replaying,
    );

    await first.serverClose(1013);
    await reconnected;

    expect(first.closeCount, 1);
    expect(connectorCalls, 2);
    await client.close();
  });

  test('close during 1013 delay prevents reconnect', () async {
    final socket = FakeHubSocket();
    final delayStarted = Completer<void>();
    final releaseDelay = Completer<void>();
    var connectorCalls = 0;
    final client = HubWebSocketClient(
      baseUri: Uri.parse('ws://127.0.0.1:8123'),
      conversationId: 'conversation-1',
      projection: SessionProjection(conversationId: 'conversation-1'),
      connector: (_) async {
        connectorCalls += 1;
        return socket;
      },
      delay: (_) {
        delayStarted.complete();
        return releaseDelay.future;
      },
    );
    await client.connect();

    await socket.serverClose(1013);
    await delayStarted.future;
    await client.close();
    releaseDelay.complete();
    await Future<void>.delayed(Duration.zero);

    expect(connectorCalls, 1);
    expect(socket.closeCount, 1);
  });

  test('close cancels subscription and releases socket', () async {
    final fixture = await _fixture();

    await fixture.client.close();

    expect(fixture.socket.closed, isTrue);
    expect(fixture.socket.sentCloseCode, 1000);
    expect(fixture.client.state, HubWebSocketState.closed);
  });

  test('close is idempotent and closed client cannot reconnect', () async {
    final fixture = await _fixture();

    await fixture.client.close();
    await fixture.client.close();

    expect(fixture.socket.closeCount, 1);
    await expectLater(
      fixture.client.connect(),
      throwsA(isA<ProjectionException>()),
    );
  });
}

Future<_Fixture> _fixture({
  DelayFunction? delay,
  RandomFunction? random,
  Duration connectTimeout = const Duration(seconds: 5),
}) async {
  final socket = FakeHubSocket();
  final projection = SessionProjection(conversationId: 'conversation-1');
  final client = HubWebSocketClient(
    baseUri: Uri.parse('ws://127.0.0.1:8123'),
    conversationId: 'conversation-1',
    projection: projection,
    connector: (_) async => socket,
    delay: delay,
    random: random,
    connectTimeout: connectTimeout,
  );
  await client.connect();
  return _Fixture(client, socket, projection);
}

final class _Fixture {
  const _Fixture(this.client, this.socket, this.projection);

  final HubWebSocketClient client;
  final FakeHubSocket socket;
  final SessionProjection projection;
}
