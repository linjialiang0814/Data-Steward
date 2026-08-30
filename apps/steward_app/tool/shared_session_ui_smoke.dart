import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:steward_app/shared_session/file_cursor_store.dart';
import 'package:steward_app/shared_session/hub_rest_client.dart';
import 'package:steward_app/shared_session/hub_websocket_client.dart';
import 'package:steward_app/shared_session_ui/shared_session_controller.dart';

Future<void> main() async {
  final repository = _repositoryRoot();
  final temporary = await Directory.systemTemp.createTemp(
    'data-steward-ui-smoke-',
  );
  final database = File('${temporary.path}/session.sqlite3');
  final cursorDirectory = Directory('${temporary.path}/cursor');
  final python = File(
    '${repository.path}/services/steward_hub/.venv/Scripts/python.exe',
  );
  final source = Directory('${repository.path}/services/steward_hub/src');
  _HubProcess? hub;
  SharedSessionController? first;
  SharedSessionController? second;
  var gracefulStops = 0;
  try {
    final port = await _availablePort();
    hub = await _startHub(
      python: python,
      source: source,
      database: database,
      port: port,
      workingDirectory: repository,
    );
    await _waitForHealth(port, hub);
    final config = DemoHubConfig(port);
    final preload = HubRestClient(baseUri: config.resolvedHttpBase);
    await preload.createConversation(
      title: 'Data Steward Shared Session Demo',
      conversationId: demoConversationId,
      continueIfAlreadyExists: true,
    );
    await preload.appendMessage(
      conversationId: demoConversationId,
      clientMessageId: 'ui-smoke-phone-1',
      actorDeviceId: 'phone-sim',
      role: 'user',
      content: 'phone simulated contract message',
    );
    await preload.appendMessage(
      conversationId: demoConversationId,
      clientMessageId: 'ui-smoke-pad-1',
      actorDeviceId: 'pad-sim',
      role: 'user',
      content: 'pad simulated contract message',
    );
    preload.close();

    final store = FileCursorStore(cursorDirectory);
    first = _controller(config, store, 'ui-smoke-windows-1');
    await first.start();
    await first.send('windows controller contract message');
    final firstCursor = first.lastConversationSeq;
    await first.close();
    first.dispose();
    first = null;

    second = _controller(config, store, 'unused-second-id');
    await second.start();
    final restored = second.persistedAtStart == firstCursor;
    final sequences = second.events
        .map((event) => event.conversationSeq)
        .toList(growable: false);
    final uniqueEvents = second.events.map((event) => event.eventId).toSet();
    final sources = second.events.map((event) => event.actorDeviceId).toSet();
    final gapCount = _gapCount(sequences);
    final duplicateCount = second.events.length - uniqueEvents.length;
    final projectionHash = second.semanticProjectionHash;
    final converged =
        restored &&
        second.state == SharedSessionViewState.ready &&
        sequences.length == 3 &&
        sequences.first == 1 &&
        sequences.last == 3 &&
        gapCount == 0 &&
        duplicateCount == 0 &&
        sources.containsAll(<String>{'phone-sim', 'pad-sim', 'windows-demo'});
    await second.close();
    second.dispose();
    second = null;
    if (await hub.stop()) gracefulStops += 1;
    final leaked = hub.hasExited ? 0 : 1;
    await temporary.delete(recursive: true);
    final temporaryArtifactCount = temporary.existsSync() ? 1 : 0;

    final result = <String, Object>{
      'process_start_count': 1,
      'graceful_stop_count': gracefulStops,
      'controller_start_count': 2,
      'durable_cursor_restored': restored,
      'stored_count': sequences.length,
      'first_seq': sequences.first,
      'last_seq': sequences.last,
      'source_count': sources.length,
      'duplicate_count': duplicateCount,
      'gap_count': gapCount,
      'projection_hash': projectionHash,
      'converged': converged,
      'loopback_only': true,
      'leaked_process_count': leaked,
      'temporary_artifact_count': temporaryArtifactCount,
    };
    if (!converged ||
        gracefulStops != 1 ||
        leaked != 0 ||
        temporaryArtifactCount != 0) {
      throw const FormatException();
    }
    stdout.writeln(jsonEncode(result));
  } on Object {
    stderr.writeln(
      jsonEncode(<String, Object>{
        'status': 'failed',
        'code': 'shared_session_ui_smoke_failed',
      }),
    );
    exitCode = 1;
  } finally {
    await first?.close();
    await second?.close();
    first?.dispose();
    second?.dispose();
    await hub?.stop();
    if (temporary.existsSync()) {
      await temporary.delete(recursive: true);
    }
  }
}

SharedSessionController _controller(
  DemoHubConfig config,
  FileCursorStore store,
  String clientMessageId,
) => SharedSessionController(
  config: config,
  cursorStore: store,
  transportFactory: (value) =>
      HubSharedSessionTransport(HubRestClient(baseUri: value.resolvedHttpBase)),
  socketFactory: (value, projection) => HubWebSocketClient(
    baseUri: value.resolvedWebsocketBase,
    conversationId: demoConversationId,
    projection: projection,
  ),
  clientMessageIdFactory: () => clientMessageId,
  pageSize: 2,
);

int _gapCount(List<int> sequences) {
  var gaps = 0;
  for (var index = 0; index < sequences.length; index += 1) {
    if (sequences[index] != index + 1) gaps += 1;
  }
  return gaps;
}

Directory _repositoryRoot() {
  var current = Directory.current.absolute;
  while (true) {
    if (Directory('${current.path}/services/steward_hub').existsSync() &&
        Directory('${current.path}/apps/steward_app').existsSync()) {
      return current;
    }
    if (current.parent.path == current.path) throw const FormatException();
    current = current.parent;
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

Future<void> _waitForHealth(int port, _HubProcess process) async {
  final deadline = DateTime.now().add(const Duration(seconds: 10));
  while (DateTime.now().isBefore(deadline)) {
    if (process.hasExited) throw const FormatException();
    final client = HubRestClient(
      baseUri: Uri.parse('http://127.0.0.1:$port'),
      timeout: const Duration(milliseconds: 500),
    );
    try {
      final health = await client.health();
      client.close();
      if (health.databaseReady) return;
    } on Object {
      client.close();
    }
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }
  throw TimeoutException('health');
}

final class _HubProcess {
  _HubProcess(this.process) {
    _stdout = process.stdout.listen((_) {});
    _stderr = process.stderr.listen((_) {});
    process.exitCode.then((value) => _exitCode = value);
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
      _exitCode = await process.exitCode.timeout(const Duration(seconds: 5));
      await _stdout.cancel();
      await _stderr.cancel();
      return _exitCode == 0;
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
