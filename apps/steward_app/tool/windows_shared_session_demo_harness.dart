import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:steward_app/shared_session/hub_rest_client.dart';
import 'package:steward_app/shared_session_ui/shared_session_controller.dart';

Future<void> main() async {
  final repository = _repositoryRoot();
  final temporary = await Directory.systemTemp.createTemp(
    'data-steward-windows-demo-',
  );
  final database = File('${temporary.path}/session.sqlite3');
  final cursorDirectory = Directory('${temporary.path}/cursor');
  final python = File(
    '${repository.path}/services/steward_hub/.venv/Scripts/python.exe',
  );
  final executable = File(
    '${repository.path}/apps/steward_app/build/windows/x64/runner/Debug/'
    'steward_app.exe',
  );
  _ManagedProcess? hub;
  Process? app;
  StreamSubscription<List<int>>? appStdout;
  StreamSubscription<List<int>>? appStderr;
  try {
    if (!python.existsSync() || !executable.existsSync()) {
      throw const FormatException();
    }
    final port = await _availablePort();
    hub = await _startHub(
      python: python,
      source: Directory('${repository.path}/services/steward_hub/src'),
      database: database,
      port: port,
      workingDirectory: repository,
    );
    await _waitForHealth(port, hub);
    final rest = HubRestClient(baseUri: Uri.parse('http://127.0.0.1:$port'));
    await rest.createConversation(
      title: 'Data Steward Shared Session Demo',
      conversationId: demoConversationId,
      continueIfAlreadyExists: true,
    );
    await rest.appendMessage(
      conversationId: demoConversationId,
      clientMessageId: 'demo-harness-phone-1',
      actorDeviceId: 'phone-sim',
      role: 'user',
      content: 'Phone simulated welcome message',
    );
    await rest.appendMessage(
      conversationId: demoConversationId,
      clientMessageId: 'demo-harness-pad-1',
      actorDeviceId: 'pad-sim',
      role: 'user',
      content: 'Pad simulated welcome message',
    );
    rest.close();

    app = await Process.start(
      executable.path,
      const <String>[],
      workingDirectory: executable.parent.path,
      environment: <String, String>{
        ...Platform.environment,
        'DATA_STEWARD_DEMO_MODE': '1',
        'DATA_STEWARD_HUB_PORT': '$port',
        'DATA_STEWARD_STATE_DIR': cursorDirectory.path,
      },
      runInShell: false,
    );
    appStdout = app.stdout.listen((_) {});
    appStderr = app.stderr.listen((_) {});
    stdout.writeln(
      jsonEncode(<String, Object>{
        'status': 'waiting_for_human',
        'app_pid': app.pid,
        'hub_pid': hub.process.pid,
        'loopback_only': true,
      }),
    );
    await stdout.flush();

    final appExit = await app.exitCode;
    await appStdout.cancel();
    await appStderr.cancel();
    appStdout = null;
    appStderr = null;
    final graceful = await hub.stop();
    await temporary.delete(recursive: true);
    stdout.writeln(
      jsonEncode(<String, Object>{
        'status': 'closed',
        'app_exit_code': appExit,
        'hub_graceful_stop': graceful,
        'temporary_artifact_count': temporary.existsSync() ? 1 : 0,
      }),
    );
    if (appExit != 0 || !graceful || temporary.existsSync()) exitCode = 1;
  } on Object {
    stderr.writeln(
      jsonEncode(<String, Object>{
        'status': 'failed',
        'code': 'windows_demo_harness_failed',
      }),
    );
    exitCode = 1;
  } finally {
    await appStdout?.cancel();
    await appStderr?.cancel();
    if (app != null) {
      // The harness never terminates the App; the user closes its own window.
    }
    await hub?.stop();
    if (temporary.existsSync()) {
      await temporary.delete(recursive: true);
    }
  }
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

Future<_ManagedProcess> _startHub({
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
  return _ManagedProcess(process);
}

Future<void> _waitForHealth(int port, _ManagedProcess process) async {
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

final class _ManagedProcess {
  _ManagedProcess(this.process) {
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
