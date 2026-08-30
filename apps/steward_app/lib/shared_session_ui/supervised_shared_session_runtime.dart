import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../secure_pairing/pairing_errors.dart';
import '../secure_pairing/pairing_crypto.dart';
import '../secure_pairing/pairing_models.dart';
import '../secure_pairing/strict_json.dart';

final class SupervisedSessionEnvironment {
  const SupervisedSessionEnvironment({
    required this.pythonExecutable,
    required this.hubRoot,
    required this.databasePath,
    required this.identityRoot,
    required this.privateIpv4,
    required this.privatePort,
    this.agentProvider,
    this.agentModel,
  });

  final String pythonExecutable;
  final String hubRoot;
  final String databasePath;
  final String identityRoot;
  final String privateIpv4;
  final int privatePort;
  final String? agentProvider;
  final String? agentModel;

  static SupervisedSessionEnvironment? fromEnvironment(
    Map<String, String> environment,
  ) {
    if (environment['DATA_STEWARD_C3_SUPERVISED'] != '1') return null;
    final python = environment['DATA_STEWARD_C3_PYTHON'];
    final hub = environment['DATA_STEWARD_C3_HUB_ROOT'];
    final database = environment['DATA_STEWARD_C3_DATABASE'];
    final identity = environment['DATA_STEWARD_C3_IDENTITY_ROOT'];
    final host = environment['DATA_STEWARD_C3_PRIVATE_IPV4'];
    final port = int.tryParse(
      environment['DATA_STEWARD_C3_PRIVATE_PORT'] ?? '',
    );
    final rawAgentProvider =
        environment['DATA_STEWARD_C3_HERMES_PROVIDER']?.trim() ?? '';
    final rawAgentModel =
        environment['DATA_STEWARD_C3_HERMES_MODEL']?.trim() ?? '';
    final hasAgentProvider = rawAgentProvider.isNotEmpty;
    final hasAgentModel = rawAgentModel.isNotEmpty;
    final address = host == null ? null : InternetAddress.tryParse(host);
    if ([
          python,
          hub,
          database,
          identity,
        ].any((value) => value == null || value.trim().isEmpty) ||
        address == null ||
        address.type != InternetAddressType.IPv4 ||
        !_isPrivate(address) ||
        port == null ||
        port < 1 ||
        port > 65535 ||
        hasAgentProvider != hasAgentModel ||
        (hasAgentProvider &&
            (!_agentProviders.contains(rawAgentProvider) ||
                !_agentModelPattern.hasMatch(rawAgentModel)))) {
      return null;
    }
    return SupervisedSessionEnvironment(
      pythonExecutable: python!,
      hubRoot: hub!,
      databasePath: database!,
      identityRoot: identity!,
      privateIpv4: address.address,
      privatePort: port,
      agentProvider: hasAgentProvider ? rawAgentProvider : null,
      agentModel: hasAgentModel ? rawAgentModel : null,
    );
  }
}

final class SupervisedSessionReady {
  const SupervisedSessionReady({
    required this.localUrl,
    required this.serviceUrl,
    required this.hubId,
    required this.certFingerprint,
    required this.operatorToken,
    required this.agentMode,
    required this.lanDiscoveryAvailable,
  });

  final Uri localUrl;
  final Uri serviceUrl;
  final String hubId;
  final String certFingerprint;
  final String operatorToken;
  final String agentMode;
  final bool lanDiscoveryAvailable;

  String get serviceDescriptorJson => jsonEncode({
    'protocol_version': 'shared_session_service/1',
    'hub_id': hubId,
    'base_url': serviceUrl.toString(),
    'cert_fingerprint': certFingerprint,
  });
}

final class SupervisedSharedSessionRuntime {
  SupervisedSharedSessionRuntime({
    required this.environment,
    this.startTimeout = const Duration(seconds: 35),
    this.stopTimeout = const Duration(seconds: 10),
  });

  final SupervisedSessionEnvironment environment;
  final Duration startTimeout;
  final Duration stopTimeout;
  Process? _process;
  StreamSubscription<String>? _stderr;

  Future<SupervisedSessionReady> start() async {
    if (_process != null) _state();
    _validateFiles();
    final localPort = await _allocatePort(InternetAddress.loopbackIPv4);
    final operatorToken = encodeBase64UrlNoPadding(secureRandomBytes(32));
    final operatorDigest = sha256Hex(decodeBase64UrlExact(operatorToken, 32));
    Process? process;
    try {
      process = await Process.start(
        File(environment.pythonExecutable).absolute.path,
        [
          '-m',
          'steward_hub.supervised_shared_session_runtime',
          '--database',
          File(environment.databasePath).absolute.path,
          '--identity-root',
          Directory(environment.identityRoot).absolute.path,
          '--private-host',
          environment.privateIpv4,
          '--private-port',
          '${environment.privatePort}',
          '--local-port',
          '$localPort',
          '--workers',
          '1',
          '--operator-token-digest',
          operatorDigest,
          if (environment.agentProvider != null) ...[
            '--agent-provider',
            environment.agentProvider!,
            '--agent-model',
            environment.agentModel!,
          ],
          '--acknowledge-private-lan-risk',
        ],
        workingDirectory: Directory(environment.hubRoot).absolute.path,
        environment: {
          'PYTHONPATH':
              '${Directory(environment.hubRoot).absolute.path}${Platform.pathSeparator}src',
        },
        includeParentEnvironment: true,
        runInShell: false,
      );
      _process = process;
      _stderr = process.stderr
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen((_) {});
      final line = await process.stdout
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .first
          .timeout(startTimeout);
      return _parseReady(
        line,
        localPort: localPort,
        operatorToken: operatorToken,
      );
    } on Object {
      await _stopFailed(process);
      throw const SecurePairingException(
        'c3_runtime_unavailable',
        PairingFailureKind.transient,
      );
    }
  }

  Future<void> stop() async {
    final process = _process;
    _process = null;
    if (process == null) return;
    try {
      process.stdin.writeln('shutdown');
      await process.stdin.flush();
      await process.stdin.close();
      await process.exitCode.timeout(stopTimeout);
    } on Object {
      process.kill();
      try {
        await process.exitCode.timeout(const Duration(seconds: 3));
      } on Object {
        // Exact owned child only.
      }
    } finally {
      await _stderr?.cancel();
      _stderr = null;
    }
  }

  void _validateFiles() {
    if (!File(environment.pythonExecutable).existsSync() ||
        !Directory(environment.hubRoot).existsSync() ||
        !Directory(environment.identityRoot).existsSync()) {
      throw const SecurePairingException(
        'c3_runtime_unavailable',
        PairingFailureKind.permanent,
      );
    }
  }

  SupervisedSessionReady _parseReady(
    String source, {
    required int localPort,
    required String operatorToken,
  }) {
    final value = decodeStrictJsonObject(source, maxUtf8Bytes: 2048);
    requireExactKeys(value, const {
      'event',
      'protocol_version',
      'auth_protocol_version',
      'local_url',
      'service_url',
      'hub_id',
      'cert_fingerprint',
      'transport_scope',
      'agent_mode',
      'lan_discovery_available',
    });
    if (value['event'] != 'c3_session_ready' ||
        value['protocol_version'] != 1 ||
        value['auth_protocol_version'] != 'pairing_auth/1' ||
        value['transport_scope'] != 'private_lan_authenticated_service' ||
        value['lan_discovery_available'] is! bool ||
        !const {'hermes', 'fallback'}.contains(value['agent_mode'])) {
      _integrity();
    }
    final local = Uri.tryParse(value['local_url'] as String? ?? '');
    final service = Uri.tryParse(value['service_url'] as String? ?? '');
    if (local == null ||
        local.scheme != 'http' ||
        local.host != '127.0.0.1' ||
        local.port != localPort ||
        service == null ||
        service.scheme != 'https' ||
        service.host != environment.privateIpv4 ||
        service.port != environment.privatePort) {
      _integrity();
    }
    return SupervisedSessionReady(
      localUrl: local,
      serviceUrl: service,
      hubId: requireUlid(value['hub_id']),
      certFingerprint: requireDigest(value['cert_fingerprint']),
      operatorToken: operatorToken,
      agentMode: value['agent_mode']! as String,
      lanDiscoveryAvailable: value['lan_discovery_available']! as bool,
    );
  }

  Future<void> _stopFailed(Process? process) async {
    process?.kill();
    if (process != null) {
      try {
        await process.exitCode.timeout(const Duration(seconds: 3));
      } on Object {
        // Exact owned child only.
      }
    }
    _process = null;
    await _stderr?.cancel();
    _stderr = null;
  }
}

const _agentProviders = {
  'openrouter',
  'openai',
  'deepseek',
  'dashscope',
  'volcengine',
};
final _agentModelPattern = RegExp(r'^[A-Za-z0-9._:/-]{1,128}$');

Future<int> _allocatePort(InternetAddress address) async {
  final socket = await ServerSocket.bind(address, 0, shared: false);
  try {
    return socket.port;
  } finally {
    await socket.close();
  }
}

bool _isPrivate(InternetAddress address) {
  final parts = address.address.split('.').map(int.parse).toList();
  return parts[0] == 10 ||
      (parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] == 192 && parts[1] == 168);
}

Never _state() => throw const SecurePairingException(
  'c3_runtime_state_invalid',
  PairingFailureKind.permanent,
);

Never _integrity() => throw const SecurePairingException(
  'protocol_integrity_error',
  PairingFailureKind.integrity,
);
