import 'dart:async';
import 'dart:convert';

import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../secure_pairing/pairing_crypto.dart';
import '../secure_pairing/pairing_errors.dart';
import '../secure_pairing/strict_json.dart';
import '../shared_session/hub_rest_client.dart';

final class PcFileScopeView {
  const PcFileScopeView({
    required this.configured,
    required this.rootId,
    required this.displayName,
    required this.authorizedAt,
    required this.remembered,
    required this.restoreStatus,
  });

  final bool configured;
  final String? rootId;
  final String? displayName;
  final DateTime? authorizedAt;
  final bool remembered;
  final String restoreStatus;

  String get safeRootLabel =>
      rootId == null ? '—' : '${rootId!.substring(0, 7)}…';

  factory PcFileScopeView.fromJson(String source) {
    final value = decodeStrictJsonObject(source, maxUtf8Bytes: 8192);
    requireExactKeys(value, const {
      'configured',
      'root_id',
      'display_name',
      'authorized_at',
      'remembered',
      'restore_status',
      'scan_mode',
    });
    final configured = value['configured'];
    final rootId = value['root_id'];
    final displayName = value['display_name'];
    final authorizedAt = value['authorized_at'];
    final remembered = value['remembered'];
    final restoreStatus = value['restore_status'];
    if (configured is! bool ||
        remembered is! bool ||
        restoreStatus is! String ||
        !const {
          'not_configured',
          'active',
          'restored',
          'unavailable',
        }.contains(restoreStatus) ||
        value['scan_mode'] != 'direct_children_metadata_only') {
      _integrity();
    }
    if (!configured) {
      if (rootId != null || displayName != null || authorizedAt != null) {
        _integrity();
      }
      return PcFileScopeView(
        configured: false,
        rootId: null,
        displayName: null,
        authorizedAt: null,
        remembered: remembered,
        restoreStatus: restoreStatus,
      );
    }
    if (rootId is! String ||
        !RegExp(r'^pc-[0-9a-f]{12}$').hasMatch(rootId) ||
        displayName is! String ||
        displayName.trim().isEmpty ||
        displayName.length > 80 ||
        authorizedAt is! String) {
      _integrity();
    }
    final parsed = DateTime.tryParse(authorizedAt);
    if (parsed == null || !authorizedAt.endsWith('Z')) _integrity();
    return PcFileScopeView(
      configured: true,
      rootId: rootId,
      displayName: displayName,
      authorizedAt: parsed.toUtc(),
      remembered: remembered,
      restoreStatus: restoreStatus,
    );
  }
}

abstract interface class PcFileScopeApi {
  Future<PcFileScopeView> status();

  Future<PcFileScopeView> authorize(String path);

  Future<PcFileScopeView> revoke();

  void close();
}

final class PcFileScopeClient implements PcFileScopeApi {
  PcFileScopeClient({
    required Uri baseUri,
    required this.operatorToken,
    http.Client? client,
    this.timeout = const Duration(seconds: 8),
  }) : baseUri = validateLoopbackBaseUri(baseUri, scheme: 'http'),
       _client = client ?? createDirectHttpClient() {
    decodeBase64UrlExact(operatorToken, 32);
  }

  final Uri baseUri;
  final String operatorToken;
  final http.Client _client;
  final Duration timeout;
  bool _closed = false;

  @override
  Future<PcFileScopeView> status() async =>
      PcFileScopeView.fromJson((await _send('GET')).body);

  @override
  Future<PcFileScopeView> authorize(String path) async {
    if (path.isEmpty ||
        path.length > 1024 ||
        path.runes.any((rune) => rune < 32)) {
      _integrity();
    }
    return PcFileScopeView.fromJson(
      (await _send('PUT', body: {'path': path, 'remember': true})).body,
    );
  }

  @override
  Future<PcFileScopeView> revoke() async =>
      PcFileScopeView.fromJson((await _send('DELETE')).body);

  Future<_ScopeResponse> _send(
    String method, {
    Map<String, Object>? body,
  }) async {
    if (_closed) _unavailable(PairingFailureKind.permanent);
    try {
      final response = await _performSend(method, body: body).timeout(timeout);
      if (response.statusCode == 200) return response;
      final error = decodeStrictJsonObject(response.body, maxUtf8Bytes: 4096);
      requireExactKeys(error, const {'error_code', 'message_key'});
      final code = error['error_code'];
      if (code is! String || error['message_key'] != 'operator.$code') {
        _integrity();
      }
      throw SecurePairingException(
        code,
        response.statusCode >= 500
            ? PairingFailureKind.transient
            : PairingFailureKind.permanent,
      );
    } on SecurePairingException {
      rethrow;
    } on TimeoutException {
      close();
      _unavailable(PairingFailureKind.transient);
    } on FormatException {
      _integrity();
    } on Object {
      _unavailable(PairingFailureKind.transient);
    }
  }

  Future<_ScopeResponse> _performSend(
    String method, {
    Map<String, Object>? body,
  }) async {
    final request =
        http.Request(method, baseUri.replace(path: '/v1/operator/file-scope'))
          ..headers['accept'] = 'application/json'
          ..headers['authorization'] = 'DataSteward-Operator $operatorToken'
          ..headers['x-datasteward-protocol'] = pairingProtocolVersion;
    if (body != null) {
      request.headers['content-type'] = 'application/json; charset=utf-8';
      request.body = jsonEncode(body);
    }
    final streamed = await _client.send(request);
    final type = streamed.headers['content-type']?.toLowerCase();
    if (type == null || !type.startsWith('application/json')) _integrity();
    final bytes = <int>[];
    await for (final chunk in streamed.stream) {
      if (bytes.length + chunk.length > 8192) _integrity();
      bytes.addAll(chunk);
    }
    return _ScopeResponse(
      streamed.statusCode,
      utf8.decode(bytes, allowMalformed: false),
    );
  }

  @override
  void close() {
    if (_closed) return;
    _closed = true;
    _client.close();
  }
}

typedef PcDirectoryPicker = Future<String?> Function();

final class PcFileScopeController extends ChangeNotifier {
  PcFileScopeController({required this.api, PcDirectoryPicker? directoryPicker})
    : _directoryPicker = directoryPicker ?? _pickDirectory;

  final PcFileScopeApi api;
  final PcDirectoryPicker _directoryPicker;
  PcFileScopeView scope = const PcFileScopeView(
    configured: false,
    rootId: null,
    displayName: null,
    authorizedAt: null,
    remembered: false,
    restoreStatus: 'not_configured',
  );
  bool busy = false;
  String? safeMessage;
  bool _disposed = false;

  Future<void> load() async => _run(() => api.status());

  Future<void> selectAndAuthorize() async {
    if (busy || _disposed) return;
    final selected = await _directoryPicker();
    if (selected == null || _disposed) return;
    await _run(
      () => api.authorize(selected),
      success: 'PC 查询目录已授权；仅扫描直接子文件的元数据。',
    );
  }

  Future<void> revoke() async =>
      _run(() => api.revoke(), success: 'PC 查询目录授权已移除。');

  Future<void> _run(
    Future<PcFileScopeView> Function() action, {
    String? success,
  }) async {
    if (busy || _disposed) return;
    busy = true;
    safeMessage = null;
    notifyListeners();
    try {
      scope = await action();
      safeMessage = success;
    } on Object {
      safeMessage = 'PC 目录授权未完成；系统不会自动重试，也不会显示底层路径或错误。';
    } finally {
      busy = false;
      if (!_disposed) notifyListeners();
    }
  }

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    api.close();
    super.dispose();
  }
}

final class PcFileScopePanel extends StatefulWidget {
  const PcFileScopePanel({required this.controller, super.key});

  final PcFileScopeController controller;

  @override
  State<PcFileScopePanel> createState() => _PcFileScopePanelState();
}

final class _PcFileScopePanelState extends State<PcFileScopePanel> {
  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_changed);
  }

  @override
  void didUpdateWidget(PcFileScopePanel oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.controller != widget.controller) {
      oldWidget.controller.removeListener(_changed);
      widget.controller.addListener(_changed);
    }
  }

  @override
  void dispose() {
    widget.controller.removeListener(_changed);
    super.dispose();
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final controller = widget.controller;
    final scope = controller.scope;
    return Card(
      key: const Key('s2-pc-file-scope-panel'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'PC 文件查询范围',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 6),
            Text(
              scope.configured
                  ? '${scope.displayName} · ${scope.safeRootLabel}'
                  : scope.restoreStatus == 'unavailable'
                  ? '默认目录当前不可用，请重新检查或更换目录'
                  : '尚未授权目录',
              key: const Key('s2-pc-file-scope-status'),
            ),
            Text(
              scope.configured && scope.remembered
                  ? '默认工作区 · 启动时安全恢复 · 只读取直接子文件元数据'
                  : '只读元数据 · 仅直接子文件',
            ),
            if (controller.busy) const LinearProgressIndicator(),
            const SizedBox(height: 8),
            Wrap(
              spacing: 10,
              children: [
                FilledButton.icon(
                  key: const Key('s2-select-pc-directory'),
                  onPressed: controller.busy
                      ? null
                      : controller.selectAndAuthorize,
                  icon: const Icon(Icons.folder_open),
                  label: Text(scope.configured ? '更换目录' : '选择专用目录'),
                ),
                OutlinedButton.icon(
                  key: const Key('s2-revoke-pc-directory'),
                  onPressed: !controller.busy && scope.configured
                      ? controller.revoke
                      : null,
                  icon: const Icon(Icons.no_encryption_outlined),
                  label: const Text('忘记默认目录'),
                ),
                TextButton.icon(
                  key: const Key('s2-refresh-pc-directory-status'),
                  onPressed: controller.busy ? null : controller.load,
                  icon: const Icon(Icons.refresh),
                  label: const Text('刷新状态'),
                ),
              ],
            ),
            if (controller.safeMessage case final String message) ...[
              const SizedBox(height: 8),
              Text(message, key: const Key('s2-pc-file-scope-message')),
            ],
          ],
        ),
      ),
    );
  }
}

Future<String?> _pickDirectory() =>
    getDirectoryPath(confirmButtonText: '授权此目录');

Never _integrity() => throw const SecurePairingException(
  'protocol_integrity_error',
  PairingFailureKind.integrity,
);

Never _unavailable(PairingFailureKind kind) =>
    throw SecurePairingException('operator_unavailable', kind);

final class _ScopeResponse {
  const _ScopeResponse(this.statusCode, this.body);

  final int statusCode;
  final String body;
}
