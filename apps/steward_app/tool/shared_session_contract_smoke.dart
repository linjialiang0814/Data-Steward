import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:steward_app/shared_session/hub_rest_client.dart';
import 'package:steward_app/shared_session/hub_websocket_client.dart';
import 'package:steward_app/shared_session/session_projection.dart';
import 'package:steward_app/shared_session/shared_session_errors.dart';

Future<void> main() async {
  final temporary = await Directory.systemTemp.createTemp(
    'data-steward-dart-contract-',
  );
  final repository = _repositoryRoot();
  final database = File(
    '${temporary.path}${Platform.pathSeparator}shared-session.sqlite3',
  );
  final python = File(
    '${repository.path}${Platform.pathSeparator}'
    'services${Platform.pathSeparator}steward_hub${Platform.pathSeparator}'
    '.venv${Platform.pathSeparator}Scripts${Platform.pathSeparator}python.exe',
  );
  final source = Directory(
    '${repository.path}${Platform.pathSeparator}'
    'services${Platform.pathSeparator}steward_hub${Platform.pathSeparator}src',
  );

  _HubProcess? firstHub;
  _HubProcess? secondHub;
  HubRestClient? firstRest;
  HubRestClient? secondRest;
  HubWebSocketClient? firstWebSocket;
  HubWebSocketClient? secondWebSocket;
  var gracefulStops = 0;
  var submitted = 0;
  var deduplicated = 0;
  var stage = 'initialize';
  try {
    if (!python.existsSync()) throw const FormatException();
    const conversationId = 'dart-python-contract-v1';
    final projection = SessionProjection(conversationId: conversationId);

    final firstPort = await _availablePort();
    firstHub = await _startHub(
      python: python,
      source: source,
      database: database,
      port: firstPort,
      workingDirectory: repository,
    );
    stage = 'first_health';
    firstRest = await _waitForHealth(firstPort, firstHub);
    stage = 'create_conversation';
    await firstRest.createConversation(
      title: 'Dart Python Contract',
      conversationId: conversationId,
    );
    firstWebSocket = HubWebSocketClient(
      baseUri: Uri.parse('ws://127.0.0.1:$firstPort'),
      conversationId: conversationId,
      projection: projection,
    );
    stage = 'first_websocket';
    await firstWebSocket.connect();
    await firstWebSocket.waitForState(HubWebSocketState.ready);

    final messages = <({String actor, String id, String content})>[
      (actor: 'windows', id: 'dart-client-1', content: 'contract-message-1'),
      (actor: 'phone', id: 'dart-client-2', content: 'contract-message-2'),
      (actor: 'pad', id: 'dart-client-3', content: 'contract-message-3'),
    ];
    for (final message in messages) {
      stage = 'first_live_messages';
      await firstRest.appendMessage(
        conversationId: conversationId,
        clientMessageId: message.id,
        actorDeviceId: message.actor,
        role: 'user',
        content: message.content,
      );
      submitted += 1;
      await firstWebSocket.waitForSequence(submitted);
    }
    final savedCursor = projection.lastConversationSeq;
    await firstWebSocket.close();
    firstWebSocket = null;

    stage = 'offline_message';
    await firstRest.appendMessage(
      conversationId: conversationId,
      clientMessageId: 'dart-client-4',
      actorDeviceId: 'windows',
      role: 'user',
      content: 'contract-message-4',
    );
    submitted += 1;
    firstRest.close();
    firstRest = null;
    if (await firstHub.stop()) gracefulStops += 1;

    final secondPort = await _availablePort();
    secondHub = await _startHub(
      python: python,
      source: source,
      database: database,
      port: secondPort,
      workingDirectory: repository,
    );
    stage = 'second_health';
    secondRest = await _waitForHealth(secondPort, secondHub);
    secondWebSocket = HubWebSocketClient(
      baseUri: Uri.parse('ws://127.0.0.1:$secondPort'),
      conversationId: conversationId,
      projection: projection,
    );
    stage = 'second_websocket';
    await secondWebSocket.connect();
    await secondWebSocket.waitForState(HubWebSocketState.ready);
    final replayGapCount = projection.lastConversationSeq - savedCursor;

    stage = 'deduplicated_message';
    final duplicate = await secondRest.appendMessage(
      conversationId: conversationId,
      clientMessageId: 'dart-client-4',
      actorDeviceId: 'windows',
      role: 'user',
      content: 'contract-message-4',
    );
    submitted += 1;
    if (!duplicate.deduplicated || projection.apply(duplicate.event)) {
      throw const FormatException();
    }
    deduplicated += 1;

    stage = 'second_live_message';
    await secondRest.appendMessage(
      conversationId: conversationId,
      clientMessageId: 'dart-client-5',
      actorDeviceId: 'pad',
      role: 'user',
      content: 'contract-message-5',
    );
    submitted += 1;
    await secondWebSocket.waitForSequence(5);

    stage = 'rest_replay';
    final replay = await secondRest.replayEvents(
      conversationId: conversationId,
      afterSeq: 0,
      limit: 100,
    );
    final reopenedProjection = SessionProjection(
      conversationId: conversationId,
    );
    for (final event in replay.events) {
      reopenedProjection.apply(event);
    }
    final actorSequence = reopenedProjection.events
        .map((event) => event.actorDeviceId)
        .toList(growable: false);
    final sourcesValid =
        jsonEncode(actorSequence) ==
        jsonEncode(<String>['windows', 'phone', 'pad', 'windows', 'pad']);
    final restHash = reopenedProjection.semanticProjectionHash;
    final dartHash = projection.semanticProjectionHash;
    final transportConverged =
        sourcesValid &&
        replayGapCount == 1 &&
        replay.events.length == 5 &&
        projection.lastConversationSeq == 5 &&
        restHash == dartHash;

    await secondWebSocket.close();
    secondWebSocket = null;
    secondRest.close();
    secondRest = null;
    if (await secondHub.stop()) gracefulStops += 1;
    stage = 'database_projection';
    final reopenedHash = await _databaseProjectionHash(
      python: python,
      source: source,
      database: database,
      conversationId: conversationId,
      workingDirectory: repository,
    );
    final converged = transportConverged && reopenedHash == restHash;
    final leakedProcessCount =
        (firstHub.hasExited ? 0 : 1) + (secondHub.hasExited ? 0 : 1);

    final result = <String, Object>{
      'client_language': 'dart',
      'hub_language': 'python',
      'process_start_count': 2,
      'graceful_stop_count': gracefulStops,
      'submitted_count': submitted,
      'stored_count': replay.events.length,
      'deduplicated_count': deduplicated,
      'first_seq': replay.events.first.conversationSeq,
      'last_seq': replay.events.last.conversationSeq,
      'replay_gap_count': replayGapCount,
      'rest_projection_hash': restHash,
      'dart_projection_hash': dartHash,
      'reopened_projection_hash': reopenedHash,
      'converged': converged,
      'loopback_only': true,
      'leaked_process_count': leakedProcessCount,
    };
    if (!converged ||
        gracefulStops != 2 ||
        leakedProcessCount != 0 ||
        submitted != 6 ||
        deduplicated != 1) {
      throw const FormatException();
    }
    stage = 'complete';
    stdout.writeln(jsonEncode(result));
  } on Object catch (error) {
    stderr.writeln(
      jsonEncode(<String, Object>{
        'status': 'failed',
        'code': 'contract_smoke_failed',
        'stage': stage,
        'reason': error is _SmokeFailure ? error.code : 'invariant_failed',
      }),
    );
    exitCode = 1;
  } finally {
    await firstWebSocket?.close();
    await secondWebSocket?.close();
    firstRest?.close();
    secondRest?.close();
    await firstHub?.stop();
    await secondHub?.stop();
    if (temporary.existsSync()) {
      await temporary.delete(recursive: true);
    }
  }
}

Directory _repositoryRoot() {
  var current = Directory.current.absolute;
  while (true) {
    final app = Directory(
      '${current.path}${Platform.pathSeparator}apps'
      '${Platform.pathSeparator}steward_app',
    );
    final hub = Directory(
      '${current.path}${Platform.pathSeparator}services'
      '${Platform.pathSeparator}steward_hub',
    );
    if (app.existsSync() && hub.existsSync()) return current;
    final parent = current.parent;
    if (parent.path == current.path) throw const FormatException();
    current = parent;
  }
}

Future<int> _availablePort() async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = server.port;
  await server.close();
  return port;
}

Future<_HubProcess> _startHub({
  required File python,
  required Directory source,
  required File database,
  required int port,
  required Directory workingDirectory,
}) async {
  final process = await Process.start(
    python.path,
    <String>[
      '-m',
      'steward_hub.server',
      '--database',
      database.path,
      '--host',
      '127.0.0.1',
      '--port',
      '$port',
      '--workers',
      '1',
      '--shutdown-stdin',
    ],
    workingDirectory: workingDirectory.path,
    environment: <String, String>{
      ...Platform.environment,
      'PYTHONPATH': source.path,
    },
    runInShell: false,
  );
  return _HubProcess(process);
}

Future<HubRestClient> _waitForHealth(int port, _HubProcess process) async {
  final deadline = DateTime.now().add(const Duration(seconds: 10));
  var lastFailure = 'not_ready';
  while (DateTime.now().isBefore(deadline)) {
    if (process.hasExited) throw const FormatException();
    final client = HubRestClient(
      baseUri: Uri.parse('http://127.0.0.1:$port'),
      timeout: const Duration(milliseconds: 500),
    );
    try {
      final health = await client.health();
      if (health.databaseReady && health.protocolVersion == 1) return client;
    } on SharedSessionException catch (error) {
      lastFailure = error.code;
    } on Object {
      lastFailure = 'unexpected';
    }
    client.close();
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }
  throw _SmokeFailure('health_$lastFailure');
}

Future<String> _databaseProjectionHash({
  required File python,
  required Directory source,
  required File database,
  required String conversationId,
  required Directory workingDirectory,
}) async {
  const script = r'''
import hashlib
import json
import sys
from steward_hub.api import wire_event
from steward_hub.store import EventStore

store = EventStore(sys.argv[1])
try:
    events = [
        wire_event(event).model_dump(mode="json")
        for event in store.replay_events(
            conversation_id=sys.argv[2], after_seq=0, limit=500
        )
    ]
finally:
    store.close()
canonical = [
    {
        "actor_device_id": event["actor_device_id"],
        "causation_id": event["causation_id"],
        "conversation_seq": event["conversation_seq"],
        "correlation_id": event["correlation_id"],
        "event_type": event["event_type"],
        "payload": {
            field: event["payload"][field]
            for field in ("accepted_seq", "client_message_id", "content", "role")
        },
        "protocol_version": event["protocol_version"],
    }
    for event in events
]
encoded = json.dumps(
    canonical, ensure_ascii=False, separators=(",", ":"), sort_keys=True
).encode("utf-8")
print(hashlib.sha256(encoded).hexdigest())
''';
  final result = await Process.run(
    python.path,
    <String>['-c', script, database.path, conversationId],
    workingDirectory: workingDirectory.path,
    environment: <String, String>{
      ...Platform.environment,
      'PYTHONPATH': source.path,
    },
    runInShell: false,
  ).timeout(const Duration(seconds: 10));
  final hash = '${result.stdout}'.trim();
  if (result.exitCode != 0 || !RegExp(r'^[0-9a-f]{64}$').hasMatch(hash)) {
    throw const FormatException();
  }
  return hash;
}

final class _HubProcess {
  _HubProcess(this.process) {
    _stdout = process.stdout.listen((_) {});
    _stderr = process.stderr.listen((_) {});
    process.exitCode.then((code) {
      _exitCode = code;
    });
  }

  final Process process;
  late final StreamSubscription<List<int>> _stdout;
  late final StreamSubscription<List<int>> _stderr;
  int? _exitCode;
  bool _stopAttempted = false;

  bool get hasExited => _exitCode != null;

  Future<bool> stop() async {
    if (_stopAttempted) return _exitCode == 0;
    _stopAttempted = true;
    if (_exitCode != null) return false;
    try {
      process.stdin.writeln('shutdown');
      await process.stdin.flush();
      final code = await process.exitCode.timeout(const Duration(seconds: 5));
      _exitCode = code;
      await _stdout.cancel();
      await _stderr.cancel();
      return code == 0;
    } on Object {
      process.kill();
      try {
        _exitCode = await process.exitCode.timeout(const Duration(seconds: 3));
      } on Object {
        _exitCode = -1;
      }
      await _stdout.cancel();
      await _stderr.cancel();
      return false;
    }
  }
}

final class _SmokeFailure implements Exception {
  const _SmokeFailure(this.code);

  final String code;
}
