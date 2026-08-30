import 'package:flutter/services.dart';

const String safChannelName = 'io.datasteward.app/saf';

class SafPermissionState {
  const SafPermissionState({
    required this.authorized,
    required this.canRead,
    required this.canWrite,
    required this.restored,
    this.provider,
    this.uriSha256,
  });

  const SafPermissionState.notAuthorized()
    : authorized = false,
      canRead = false,
      canWrite = false,
      restored = false,
      provider = null,
      uriSha256 = null;

  factory SafPermissionState.fromMap(Map<Object?, Object?> map) {
    return SafPermissionState(
      authorized: map['authorized'] == true,
      canRead: map['canRead'] == true,
      canWrite: map['canWrite'] == true,
      restored: map['restored'] == true,
      provider: map['provider'] as String?,
      uriSha256: map['uriSha256'] as String?,
    );
  }

  final bool authorized;
  final bool canRead;
  final bool canWrite;
  final bool restored;
  final String? provider;
  final String? uriSha256;
}

class SafOperationResult {
  const SafOperationResult({
    required this.status,
    this.commandId,
    this.sha256,
    this.timestamp,
  });

  factory SafOperationResult.fromMap(Map<Object?, Object?> map) {
    return SafOperationResult(
      status: map['status'] as String? ?? 'io_error',
      commandId: map['commandId'] as String?,
      sha256: map['sha256'] as String?,
      timestamp: map['timestamp'] as String?,
    );
  }

  final String status;
  final String? commandId;
  final String? sha256;
  final String? timestamp;
}

class SafFailure implements Exception {
  const SafFailure(this.code);

  final String code;
}

abstract interface class SafBridge {
  Future<SafPermissionState> getPermissionState();

  Future<SafPermissionState> selectDirectory();

  Future<SafOperationResult> writeProbe();

  Future<SafOperationResult> readProbe();

  Future<SafOperationResult> deleteProbe();
}

class MethodChannelSafBridge implements SafBridge {
  const MethodChannelSafBridge({
    this._channel = const MethodChannel(safChannelName),
  });

  final MethodChannel _channel;

  @override
  Future<SafPermissionState> getPermissionState() async {
    final map = await _invokeMap('getPermissionState');
    return SafPermissionState.fromMap(map);
  }

  @override
  Future<SafPermissionState> selectDirectory() async {
    final map = await _invokeMap('selectDirectory');
    return SafPermissionState.fromMap(map);
  }

  @override
  Future<SafOperationResult> writeProbe() async {
    final map = await _invokeMap('writeProbe');
    return SafOperationResult.fromMap(map);
  }

  @override
  Future<SafOperationResult> readProbe() async {
    final map = await _invokeMap('readProbe');
    return SafOperationResult.fromMap(map);
  }

  @override
  Future<SafOperationResult> deleteProbe() async {
    final map = await _invokeMap('deleteProbe');
    return SafOperationResult.fromMap(map);
  }

  Future<Map<Object?, Object?>> _invokeMap(String method) async {
    try {
      final result = await _channel.invokeMethod<Map<Object?, Object?>>(method);
      if (result == null) {
        throw const SafFailure('io_error');
      }
      return result;
    } on MissingPluginException {
      throw const SafFailure('unsupported');
    } on PlatformException catch (error) {
      throw SafFailure(_knownCode(error.code));
    }
  }

  String _knownCode(String code) {
    const knownCodes = <String>{
      'unsupported',
      'not_authorized',
      'picker_cancelled',
      'busy',
      'invalid_directory',
      'unsafe_directory',
      'unsafe_probe',
      'permission_lost',
      'probe_not_found',
      'io_error',
    };
    return knownCodes.contains(code) ? code : 'io_error';
  }
}
