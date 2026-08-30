import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../secure_pairing/pairing_crypto.dart';
import '../secure_pairing/pairing_errors.dart';
import '../secure_pairing/pairing_models.dart';
import '../secure_pairing/strict_json.dart';

final class SupervisedPairingEnvironment {
  const SupervisedPairingEnvironment({
    required this.pythonExecutable,
    required this.hubRoot,
    required this.databasePath,
    required this.identityRoot,
    required this.privateIpv4,
  });

  final String pythonExecutable;
  final String hubRoot;
  final String databasePath;
  final String identityRoot;
  final String privateIpv4;

  static SupervisedPairingEnvironment? fromEnvironment(
    Map<String, String> environment,
  ) {
    if (environment['DATA_STEWARD_C2_SUPERVISED'] != '1') return null;
    final values = <String, String?>{
      'python': environment['DATA_STEWARD_C2_PYTHON'],
      'hubRoot': environment['DATA_STEWARD_C2_HUB_ROOT'],
      'database': environment['DATA_STEWARD_C2_DATABASE'],
      'identity': environment['DATA_STEWARD_C2_IDENTITY_ROOT'],
      'privateIpv4': environment['DATA_STEWARD_C2_PRIVATE_IPV4'],
    };
    if (values.values.any((value) => value == null || value.trim().isEmpty)) {
      return null;
    }
    final ip = InternetAddress.tryParse(values['privateIpv4']!);
    if (ip == null || ip.type != InternetAddressType.IPv4 || !_isPrivate(ip)) {
      return null;
    }
    return SupervisedPairingEnvironment(
      pythonExecutable: values['python']!,
      hubRoot: values['hubRoot']!,
      databasePath: values['database']!,
      identityRoot: values['identity']!,
      privateIpv4: ip.address,
    );
  }
}

final class SupervisedPairingReady {
  const SupervisedPairingReady({
    required this.controlUrl,
    required this.pairingUrl,
    required this.hubId,
    required this.certFingerprint,
    required this.operatorToken,
  });

  final Uri controlUrl;
  final Uri pairingUrl;
  final String hubId;
  final String certFingerprint;
  final String operatorToken;
}

abstract interface class PairingRuntime {
  SupervisedPairingEnvironment get environment;
  bool get running;
  Future<SupervisedPairingReady> start();
  Future<void> stop();
  Future<void> close();
}

final class SupervisedPairingRuntime implements PairingRuntime {
  SupervisedPairingRuntime({
    required this.environment,
    this.startTimeout = const Duration(seconds: 20),
    this.stopTimeout = const Duration(seconds: 10),
  });

  @override
  final SupervisedPairingEnvironment environment;
  final Duration startTimeout;
  final Duration stopTimeout;
  Process? _process;
  StreamSubscription<String>? _stderrSubscription;
  bool _closed = false;

  @override
  bool get running => _process != null;

  @override
  Future<SupervisedPairingReady> start() async {
    if (_closed || _process != null) _stateFailure();
    _validateFiles();
    final controlPort = await _allocatePort(InternetAddress.loopbackIPv4);
    final pairingAddress = InternetAddress(environment.privateIpv4);
    final pairingPort = await _allocatePort(pairingAddress);
    if (controlPort == pairingPort) _stateFailure();
    final operatorToken = encodeBase64UrlNoPadding(secureRandomBytes(32));
    final operatorDigest = sha256Hex(decodeBase64UrlExact(operatorToken, 32));
    final pythonPath = File(environment.pythonExecutable).absolute.path;
    final hubRoot = Directory(environment.hubRoot).absolute.path;
    Process? process;
    try {
      process = await Process.start(
        pythonPath,
        [
          '-m',
          'steward_hub.supervised_pairing_runtime',
          '--database',
          File(environment.databasePath).absolute.path,
          '--identity-root',
          Directory(environment.identityRoot).absolute.path,
          '--private-host',
          environment.privateIpv4,
          '--pairing-port',
          '$pairingPort',
          '--control-port',
          '$controlPort',
          '--operator-token-digest',
          operatorDigest,
          '--workers',
          '1',
          '--acknowledge-private-lan-risk',
        ],
        workingDirectory: hubRoot,
        environment: {'PYTHONPATH': '$hubRoot${Platform.pathSeparator}src'},
        includeParentEnvironment: true,
        runInShell: false,
      );
      _process = process;
      _stderrSubscription = process.stderr
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen((_) {});
      final line = await process.stdout
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .first
          .timeout(startTimeout);
      final ready = _parseReady(
        line,
        expectedControlPort: controlPort,
        expectedPairingPort: pairingPort,
        operatorToken: operatorToken,
      );
      return ready;
    } on SecurePairingException {
      await _stopFailedProcess(process);
      rethrow;
    } on Object {
      await _stopFailedProcess(process);
      throw const SecurePairingException(
        'c2_runtime_unavailable',
        PairingFailureKind.transient,
      );
    }
  }

  @override
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
        // Exact owned child only; caller receives no process details.
      }
    } finally {
      await _stderrSubscription?.cancel();
      _stderrSubscription = null;
    }
  }

  @override
  Future<void> close() async {
    _closed = true;
    await stop();
  }

  Future<void> _stopFailedProcess(Process? process) async {
    if (process != null) {
      process.kill();
      try {
        await process.exitCode.timeout(const Duration(seconds: 3));
      } on Object {
        // Exact owned child only.
      }
    }
    _process = null;
    await _stderrSubscription?.cancel();
    _stderrSubscription = null;
  }

  void _validateFiles() {
    if (!File(environment.pythonExecutable).existsSync() ||
        !Directory(environment.hubRoot).existsSync() ||
        !Directory(environment.identityRoot).existsSync()) {
      throw const SecurePairingException(
        'c2_runtime_unavailable',
        PairingFailureKind.permanent,
      );
    }
  }

  SupervisedPairingReady _parseReady(
    String source, {
    required int expectedControlPort,
    required int expectedPairingPort,
    required String operatorToken,
  }) {
    final value = decodeStrictJsonObject(source, maxUtf8Bytes: 2048);
    requireExactKeys(value, const {
      'event',
      'protocol_version',
      'control_url',
      'pairing_url',
      'hub_id',
      'cert_fingerprint',
      'transport_scope',
    });
    if (value['event'] != 'c2_pairing_ready' ||
        value['protocol_version'] != pairingProtocolVersion ||
        value['transport_scope'] != 'private_lan_pairing_only') {
      _integrity();
    }
    final control = Uri.tryParse(value['control_url'] as String? ?? '');
    final pairing = Uri.tryParse(value['pairing_url'] as String? ?? '');
    if (control == null ||
        control.scheme != 'https' ||
        control.host != '127.0.0.1' ||
        control.port != expectedControlPort ||
        pairing == null ||
        pairing.scheme != 'https' ||
        pairing.host != environment.privateIpv4 ||
        pairing.port != expectedPairingPort) {
      _integrity();
    }
    return SupervisedPairingReady(
      controlUrl: control,
      pairingUrl: pairing,
      hubId: requireUlid(value['hub_id']),
      certFingerprint: requireDigest(value['cert_fingerprint']),
      operatorToken: operatorToken,
    );
  }
}

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

Never _stateFailure() => throw const SecurePairingException(
  'c2_runtime_state_invalid',
  PairingFailureKind.permanent,
);

Never _integrity() => throw const SecurePairingException(
  'protocol_integrity_error',
  PairingFailureKind.integrity,
);
