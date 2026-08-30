import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:steward_app/shared_session/hub_rest_client.dart';
import 'package:steward_app/shared_session/shared_session_errors.dart';

import 'test_helpers.dart';

void main() {
  group('loopback URI boundary', () {
    test('accepts only explicit 127.0.0.1 HTTP base', () {
      final value = validateLoopbackBaseUri(
        Uri.parse('http://127.0.0.1:8123'),
        scheme: 'http',
      );
      expect(value.host, '127.0.0.1');
      expect(value.port, 8123);
    });

    for (final value in <String>[
      'http://localhost:8123',
      'http://0.0.0.0:8123',
      'http://192.168.1.10:8123',
      'http://8.8.8.8:8123',
      'http://[::1]:8123',
    ]) {
      test('rejects non-canonical host $value', () {
        expect(
          () => validateLoopbackBaseUri(Uri.parse(value), scheme: 'http'),
          throwsA(isA<NetworkBoundaryException>()),
        );
      });
    }

    test('rejects user info, fragment, implicit port, and HTTPS', () {
      for (final value in <String>[
        'http://user@127.0.0.1:8123',
        'http://127.0.0.1:8123/#fragment',
        'http://127.0.0.1',
        'https://127.0.0.1:8123',
      ]) {
        expect(
          () => validateLoopbackBaseUri(Uri.parse(value), scheme: 'http'),
          throwsA(isA<NetworkBoundaryException>()),
        );
      }
    });
  });

  test('parses a sanitized health response', () async {
    final client = _client(200, <String, Object>{
      'status': 'ok',
      'protocol_version': 1,
      'database_ready': true,
      'transport_scope': 'loopback_only',
    });
    final rest = HubRestClient(baseUri: _baseUri, client: client);

    final health = await rest.health();

    expect(health.protocolVersion, 1);
    expect(health.databaseReady, isTrue);
    rest.close();
  });

  test('device self parses the exact current authorization snapshot', () async {
    final client = _client(200, {
      'protocol_version': 'pairing_auth/1',
      'hub_id': '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      'device_id': '01ARZ3NDEKTSV4RRFFQ69G5FAX',
      'status': 'ACTIVE',
      'capability_epoch': 2,
      'granted_capabilities': ['files.read', 'session.sync'],
      'display_name': 'Huawei Android',
      'platform': 'android',
    });
    final rest = HubRestClient(baseUri: _baseUri, client: client);

    final snapshot = await rest.deviceSelf();

    expect(snapshot.capabilityEpoch, 2);
    expect(snapshot.grantedCapabilities, ['files.read', 'session.sync']);
    expect(snapshot.displayName, 'Huawei Android');
  });

  test('device self rejects unsorted or structurally loose grants', () async {
    final rest = HubRestClient(
      baseUri: _baseUri,
      client: _client(200, {
        'protocol_version': 'pairing_auth/1',
        'hub_id': '01ARZ3NDEKTSV4RRFFQ69G5FAV',
        'device_id': '01ARZ3NDEKTSV4RRFFQ69G5FAX',
        'status': 'ACTIVE',
        'capability_epoch': 2,
        'granted_capabilities': ['session.sync', 'files.read'],
        'display_name': null,
        'platform': 'android',
      }),
    );

    await expectLater(
      rest.deviceSelf(),
      throwsA(isA<ProtocolIntegrityException>()),
    );
  });

  test('creates a conversation on 201', () async {
    final rest = HubRestClient(
      baseUri: _baseUri,
      client: _client(201, _conversationResponse()),
    );

    final created = await rest.createConversation(title: 'contract');

    expect(created.conversationId, 'conversation-1');
    expect(created.alreadyExisted, isFalse);
    rest.close();
  });

  test('continues only conversation_already_exists conflict', () async {
    final rest = HubRestClient(
      baseUri: _baseUri,
      client: _client(409, _error('conversation_already_exists')),
    );

    final created = await rest.createConversation(
      title: 'contract',
      conversationId: 'conversation-1',
      continueIfAlreadyExists: true,
    );

    expect(created.alreadyExisted, isTrue);
    rest.close();
  });

  test('does not swallow another 409 conflict', () async {
    final rest = HubRestClient(
      baseUri: _baseUri,
      client: _client(409, _error('idempotency_conflict')),
    );

    expect(
      () => rest.createConversation(
        title: 'contract',
        conversationId: 'conversation-1',
        continueIfAlreadyExists: true,
      ),
      throwsA(
        isA<HubApiException>().having(
          (error) => error.code,
          'code',
          'idempotency_conflict',
        ),
      ),
    );
    rest.close();
  });

  for (final status in <int>[200, 201]) {
    test('validates message response on $status', () async {
      final rest = HubRestClient(
        baseUri: _baseUri,
        client: _client(status, _messageResponse(status)),
      );

      final result = await rest.appendMessage(
        conversationId: 'conversation-1',
        clientMessageId: 'client-1',
        actorDeviceId: 'windows',
        role: 'user',
        content: 'message-1',
      );

      expect(result.deduplicated, status == 200);
      expect(result.event.conversationSeq, 1);
      rest.close();
    });
  }

  test('parses product actions without hidden archive references', () async {
    final rest = HubRestClient(
      baseUri: _baseUri,
      client: _client(200, {
        'actions': [_actionJson('message-1')],
      }),
    );

    final actions = await rest.listProductActions(
      conversationId: 'conversation-1',
      assistantMessageId: 'message-1',
    );

    expect(actions.single.kind, 'archive_accept');
    expect(actions.single.label, '接受建议');
    expect(actions.single.description, isNot(contains('sg-')));
    rest.close();
  });

  test('parses memory center with opaque button action', () async {
    final rest = HubRestClient(
      baseUri: _baseUri,
      client: _client(200, {
        'status': 'candidate',
        'support_count': 3,
        'activation_threshold': 3,
        'version': 1,
        'actions': [
          {
            ..._actionJson('memory-center-v1'),
            'kind': 'memory_approve',
            'label': '启用这个习惯',
            'description': '以后可主动引用这项整理偏好',
            'risk': 'memory',
            'requires_confirmation': true,
          },
        ],
      }),
    );

    final memory = await rest.memoryCenter(conversationId: 'conversation-1');

    expect(memory.status, 'candidate');
    expect(memory.supportCount, 3);
    expect(memory.actions.single.kind, 'memory_approve');
    rest.close();
  });

  test('preserves cursor ahead server watermark', () async {
    final body = <String, Object>{
      'error': <String, Object>{
        'code': 'cursor_ahead',
        'message': 'replay cursor exceeds server state',
        'server_last_conversation_seq': 3,
      },
    };
    final rest = HubRestClient(baseUri: _baseUri, client: _client(409, body));

    expect(
      () => rest.replayEvents(conversationId: 'conversation-1', afterSeq: 99),
      throwsA(
        isA<HubApiException>()
            .having((error) => error.code, 'code', 'cursor_ahead')
            .having((error) => error.serverLastConversationSeq, 'watermark', 3),
      ),
    );
    rest.close();
  });

  test('stable errors do not expose response body in text', () async {
    final rest = HubRestClient(
      baseUri: _baseUri,
      client: _client(
        503,
        _error('persistence_unavailable', message: 'secret-content'),
      ),
    );

    try {
      await rest.health();
      fail('expected HubApiException');
    } on HubApiException catch (error) {
      expect(error.toString(), isNot(contains('secret-content')));
      expect(error.toString(), isNot(contains('127.0.0.1')));
    } finally {
      rest.close();
    }
  });

  test('slow response chunks cannot extend the total deadline', () async {
    final client = _SlowClient();
    final rest = HubRestClient(
      baseUri: _baseUri,
      client: client,
      timeout: const Duration(milliseconds: 25),
    );

    await expectLater(rest.health(), throwsA(isA<TransportException>()));

    expect(client.closed, isTrue);
  });

  test('oversized request is rejected before send', () async {
    final client = _CountingClient();
    final rest = HubRestClient(
      baseUri: _baseUri,
      client: client,
      maxRequestBytes: 16,
    );

    await expectLater(
      rest.appendMessage(
        conversationId: 'conversation-1',
        clientMessageId: 'client-1',
        actorDeviceId: 'windows',
        role: 'user',
        content: 'content exceeds request boundary',
      ),
      throwsA(isA<ProtocolIntegrityException>()),
    );

    expect(client.sendCount, 0);
    rest.close();
  });

  test('health rejects missing or extra fields', () async {
    final valid = <String, Object>{
      'status': 'ok',
      'protocol_version': 1,
      'database_ready': true,
      'transport_scope': 'loopback_only',
    };
    final invalidBodies = <Map<String, Object>>[
      Map<String, Object>.from(valid)..remove('database_ready'),
      <String, Object>{...valid, 'extra': true},
    ];

    for (final body in invalidBodies) {
      final rest = HubRestClient(baseUri: _baseUri, client: _client(200, body));
      await expectLater(
        rest.health(),
        throwsA(isA<ProtocolIntegrityException>()),
      );
      rest.close();
    }
  });

  test(
    'create rejects field, ID, title, next sequence, or time mismatch',
    () async {
      final invalidBodies = <Map<String, Object>>[
        <String, Object>{..._conversationResponse(), 'extra': true},
        Map<String, Object>.from(_conversationResponse())..remove('updated_at'),
        <String, Object>{
          ..._conversationResponse(),
          'conversation_id': 'other',
        },
        <String, Object>{..._conversationResponse(), 'title': 'other'},
        <String, Object>{..._conversationResponse(), 'next_seq': 0},
        <String, Object>{
          ..._conversationResponse(),
          'created_at': '2026-07-28T08:00:00+08:00',
        },
      ];

      for (final body in invalidBodies) {
        final rest = HubRestClient(
          baseUri: _baseUri,
          client: _client(201, body),
        );
        await expectLater(
          rest.createConversation(
            title: 'contract',
            conversationId: 'conversation-1',
          ),
          throwsA(isA<ProtocolIntegrityException>()),
        );
        rest.close();
      }
    },
  );

  test('message rejects top-level message ID mismatch', () async {
    final body = _messageResponse(201)..['message_id'] = 'different';
    final rest = HubRestClient(baseUri: _baseUri, client: _client(201, body));

    await expectLater(
      _append(rest),
      throwsA(isA<ProtocolIntegrityException>()),
    );
    rest.close();
  });

  test('message status and deduplicated semantics must agree', () async {
    for (final entry in <({int status, bool deduplicated})>[
      (status: 200, deduplicated: false),
      (status: 201, deduplicated: true),
    ]) {
      final body = _messageResponse(entry.status)
        ..['deduplicated'] = entry.deduplicated;
      final rest = HubRestClient(
        baseUri: _baseUri,
        client: _client(entry.status, body),
      );
      await expectLater(
        _append(rest),
        throwsA(isA<ProtocolIntegrityException>()),
      );
      rest.close();
    }
  });

  test('replay validates contiguous sequences and last metadata', () async {
    final invalidBodies = <Map<String, Object>>[
      _replayBody(<int>[1, 3], last: 3),
      _replayBody(<int>[1, 1], last: 1),
      _replayBody(<int>[2, 1], last: 1),
      _replayBody(<int>[1, 2], last: 3),
      _replayBody(<int>[], last: 1),
    ];

    for (final body in invalidBodies) {
      final rest = HubRestClient(baseUri: _baseUri, client: _client(200, body));
      await expectLater(
        rest.replayEvents(conversationId: 'conversation-1', afterSeq: 0),
        throwsA(isA<ProtocolIntegrityException>()),
      );
      rest.close();
    }
  });

  test('replay validates limit before transport', () async {
    final client = _CountingClient();
    final rest = HubRestClient(baseUri: _baseUri, client: client);

    for (final limit in <int>[0, 501]) {
      await expectLater(
        rest.replayEvents(
          conversationId: 'conversation-1',
          afterSeq: 0,
          limit: limit,
        ),
        throwsA(isA<ProtocolIntegrityException>()),
      );
    }

    expect(client.sendCount, 0);
    rest.close();
  });

  test(
    'error envelope rejects shape, watermark, and status mismatch',
    () async {
      final invalid = <({int status, Map<String, Object> body})>[
        (
          status: 409,
          body: <String, Object>{
            ..._error('idempotency_conflict'),
            'extra': true,
          },
        ),
        (
          status: 409,
          body: <String, Object>{
            'error': <String, Object>{'code': 'idempotency_conflict'},
          },
        ),
        (
          status: 409,
          body: <String, Object>{
            'error': <String, Object>{
              'code': 'cursor_ahead',
              'message': 'safe',
              'server_last_conversation_seq': -1,
            },
          },
        ),
        (
          status: 409,
          body: <String, Object>{
            'error': <String, Object>{
              'code': 'idempotency_conflict',
              'message': 'safe',
              'server_last_conversation_seq': 1,
            },
          },
        ),
        (status: 404, body: _error('idempotency_conflict')),
      ];

      for (final entry in invalid) {
        final rest = HubRestClient(
          baseUri: _baseUri,
          client: _client(entry.status, entry.body),
        );
        try {
          await rest.health();
          fail('expected protocol integrity failure');
        } on ProtocolIntegrityException catch (error) {
          expect(error.toString(), isNot(contains('safe')));
          expect(error.toString(), isNot(contains('127.0.0.1')));
        } finally {
          rest.close();
        }
      }
    },
  );

  test('close releases the injected HTTP client', () {
    final tracking = _TrackingClient();
    final rest = HubRestClient(baseUri: _baseUri, client: tracking);

    rest.close();
    rest.close();

    expect(tracking.closed, isTrue);
    expect(tracking.closeCount, 1);
  });
}

final _baseUri = Uri.parse('http://127.0.0.1:8123');

MockClient _client(int status, Object body) => MockClient(
  (_) async => http.Response(
    jsonEncode(body),
    status,
    headers: const <String, String>{
      'content-type': 'application/json; charset=utf-8',
    },
  ),
);

Map<String, Object> _error(String code, {String message = 'safe'}) =>
    <String, Object>{
      'error': <String, Object>{'code': code, 'message': message},
    };

Map<String, Object> _conversationResponse() => <String, Object>{
  'conversation_id': 'conversation-1',
  'title': 'contract',
  'next_seq': 1,
  'created_at': '2026-07-28T00:00:00.000Z',
  'updated_at': '2026-07-28T00:00:00.000Z',
};

Map<String, Object> _messageResponse(int status) => <String, Object>{
  'message_id': 'message-1',
  'deduplicated': status == 200,
  'event': wireEventMap(),
};

Map<String, Object> _actionJson(String messageId) => <String, Object>{
  'action_id': 'act-0123456789abcdef',
  'assistant_message_id': messageId,
  'kind': 'archive_accept',
  'label': '接受建议',
  'description': '记录这次选择，不会移动文件',
  'risk': 'preference',
  'requires_confirmation': false,
  'required_capability': 'session.sync',
  'status': 'available',
};

Map<String, Object> _replayBody(List<int> sequences, {required int last}) =>
    <String, Object>{
      'events': sequences
          .map(
            (sequence) =>
                wireEventMap(sequence: sequence, eventId: 'event-$sequence'),
          )
          .toList(),
      'last_conversation_seq': last,
    };

Future<void> _append(HubRestClient rest) async {
  await rest.appendMessage(
    conversationId: 'conversation-1',
    clientMessageId: 'client-1',
    actorDeviceId: 'windows',
    role: 'user',
    content: 'message-1',
  );
}

final class _TrackingClient extends http.BaseClient {
  bool closed = false;
  int closeCount = 0;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    throw UnimplementedError();
  }

  @override
  void close() {
    if (!closed) {
      closed = true;
      closeCount += 1;
    }
  }
}

final class _CountingClient extends http.BaseClient {
  int sendCount = 0;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    sendCount += 1;
    throw StateError('unexpected send');
  }
}

final class _SlowClient extends http.BaseClient {
  bool closed = false;
  Timer? _timer;
  StreamController<List<int>>? _controller;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final body = utf8.encode(
      jsonEncode(<String, Object>{
        'status': 'ok',
        'protocol_version': 1,
        'database_ready': true,
        'transport_scope': 'loopback_only',
      }),
    );
    var index = 0;
    final controller = StreamController<List<int>>();
    _controller = controller;
    _timer = Timer.periodic(const Duration(milliseconds: 10), (timer) {
      controller.add(<int>[body[index]]);
      index += 1;
      if (index == body.length) {
        timer.cancel();
        controller.close();
      }
    });
    return http.StreamedResponse(
      controller.stream,
      200,
      headers: const <String, String>{
        'content-type': 'application/json; charset=utf-8',
      },
    );
  }

  @override
  void close() {
    closed = true;
    _timer?.cancel();
    _controller?.close();
  }
}
