import 'dart:io';

import 'package:flutter/material.dart';

import 'app_ui/steward_theme.dart';
import 'catalog/catalog_directory_page.dart';
import 'pairing_ui/platform_home.dart';
import 'saf_bridge.dart';
import 'shared_session_ui/shared_session_controller.dart';
import 'shared_session_ui/shared_session_page.dart';

void main() {
  runApp(const StewardApp());
}

class StewardApp extends StatelessWidget {
  const StewardApp({super.key, this.safBridge, this.sharedSessionController});

  final SafBridge? safBridge;
  final SharedSessionController? sharedSessionController;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Data Steward',
      debugShowCheckedModeBanner: false,
      theme: StewardTheme.light(),
      darkTheme: StewardTheme.dark(),
      themeMode: ThemeMode.system,
      home: _home(),
    );
  }

  Widget _home() {
    if (safBridge != null) {
      return SafRiskPage(bridge: safBridge!);
    }
    final controller = sharedSessionController;
    if (controller != null) {
      return SharedSessionPage(controller: controller);
    }
    return Platform.isWindows
        ? const WindowsStewardHome()
        : const AndroidStewardHome(
            filePage: SafRiskPage(bridge: MethodChannelSafBridge()),
          );
  }
}

class SafRiskPage extends StatefulWidget {
  const SafRiskPage({required this.bridge, super.key});

  final SafBridge bridge;

  @override
  State<SafRiskPage> createState() => _SafRiskPageState();
}

class _SafRiskPageState extends State<SafRiskPage> {
  SafPermissionState _permission = const SafPermissionState.notAuthorized();
  String _status = '未授权';
  String? _errorCode;
  String? _commandId;
  String? _sha256;
  bool _busy = false;
  bool _safetyBlocked = false;

  bool get _actionsEnabled =>
      _permission.authorized &&
      _permission.canRead &&
      _permission.canWrite &&
      !_busy &&
      !_safetyBlocked;

  @override
  void initState() {
    super.initState();
    _restorePermission();
  }

  Future<void> _restorePermission() async {
    await _run(() async {
      final permission = await widget.bridge.getPermissionState();
      if (!mounted) {
        return;
      }
      setState(() {
        _permission = permission;
        _status = permission.authorized ? '已授权' : '未授权';
        _safetyBlocked = false;
      });
    });
  }

  Future<void> _selectDirectory() async {
    await _run(() async {
      final permission = await widget.bridge.selectDirectory();
      if (!mounted) {
        return;
      }
      setState(() {
        _permission = permission;
        _status = '已授权';
        _safetyBlocked = false;
        _commandId = null;
        _sha256 = null;
      });
    });
  }

  Future<void> _writeProbe() async {
    await _run(() async {
      final result = await widget.bridge.writeProbe();
      if (!mounted) {
        return;
      }
      setState(() {
        _status = '写入成功';
        _commandId = result.commandId;
        _sha256 = result.sha256;
      });
    });
  }

  Future<void> _readProbe() async {
    await _run(() async {
      final result = await widget.bridge.readProbe();
      if (!mounted) {
        return;
      }
      setState(() {
        _status = '读取成功';
        _commandId = result.commandId;
        _sha256 = result.sha256;
      });
    });
  }

  Future<void> _deleteProbe() async {
    await _run(() async {
      final result = await widget.bridge.deleteProbe();
      if (!mounted) {
        return;
      }
      setState(() {
        _status = result.status == 'already_absent' ? '探针已不存在' : '删除成功';
        _commandId = null;
        _sha256 = null;
      });
    });
  }

  Future<void> _run(Future<void> Function() operation) async {
    if (_busy) {
      return;
    }
    setState(() {
      _busy = true;
      _errorCode = null;
    });
    try {
      await operation();
    } on SafFailure catch (failure) {
      if (!mounted) {
        return;
      }
      setState(() {
        _errorCode = failure.code;
        _status = _statusForFailure(failure.code);
        if (failure.code == 'permission_lost' ||
            failure.code == 'not_authorized') {
          _permission = const SafPermissionState.notAuthorized();
        }
        if (failure.code == 'unsafe_directory' ||
            failure.code == 'unsafe_probe' ||
            failure.code == 'invalid_directory') {
          _safetyBlocked = true;
        }
      });
    } finally {
      if (mounted) {
        setState(() {
          _busy = false;
        });
      }
    }
  }

  String _statusForFailure(String code) {
    return switch (code) {
      'unsupported' => '当前平台不支持',
      'not_authorized' => '未授权',
      'picker_cancelled' => '选择器已取消',
      'busy' => '操作进行中',
      'invalid_directory' => '目录无效',
      'unsafe_directory' => '安全错误',
      'unsafe_probe' => '探针归属异常',
      'permission_lost' => '权限失效',
      'probe_not_found' => '探针不存在',
      _ => '操作失败',
    };
  }

  String _safeErrorText(String code) {
    return switch (code) {
      'unsupported' => '此平台未提供 Android SAF 能力。',
      'not_authorized' => '请先选择专用测试目录。',
      'picker_cancelled' => '未更改现有授权。',
      'busy' => '请等待当前操作完成。',
      'invalid_directory' => '仅接受名称为 DataStewardDemo 的专用目录。',
      'unsafe_directory' => '目录包含非探针内容，已禁止继续操作。',
      'unsafe_probe' => '同名文件未通过归属校验，应用拒绝读取、覆盖或删除。',
      'permission_lost' => '持久授权已失效，请重新选择专用目录。',
      'probe_not_found' => '固定探针文件不存在。',
      _ => 'SAF 操作未完成，未暴露底层路径信息。',
    };
  }

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(title: const Text('Data Steward')),
      body: SafeArea(
        child: LayoutBuilder(
          builder: (context, constraints) {
            final horizontal = constraints.maxWidth < 360 ? 16.0 : 24.0;
            return SingleChildScrollView(
              padding: EdgeInsets.symmetric(
                horizontal: horizontal,
                vertical: 24,
              ),
              child: ConstrainedBox(
                constraints: BoxConstraints(
                  minHeight: constraints.maxHeight - 48,
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Data Steward', style: textTheme.headlineMedium),
                    const SizedBox(height: 8),
                    Text(
                      'Android SAF 风险验证页（非最终产品）',
                      style: textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      '仅验证用户主动授权的 DataStewardDemo 专用目录与固定探针。'
                      '不扫描其他目录，不展示完整 URI 或真实路径。',
                      style: textTheme.bodyMedium,
                    ),
                    const SizedBox(height: 12),
                    Text('Environment Ready', style: textTheme.bodyMedium),
                    const SizedBox(height: 4),
                    Text('SAF 独立验证环境', style: textTheme.titleMedium),
                    const SizedBox(height: 24),
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(16),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text('授权状态：$_status', style: textTheme.titleMedium),
                            if (_permission.provider != null) ...[
                              const SizedBox(height: 8),
                              Text('provider：${_permission.provider}'),
                            ],
                            if (_permission.uriSha256 != null) ...[
                              const SizedBox(height: 4),
                              Text('脱敏 URI hash：${_permission.uriSha256}'),
                            ],
                            if (_permission.authorized) ...[
                              const SizedBox(height: 4),
                              Text(
                                '持久授权恢复：${_permission.restored ? '是' : '否'}',
                              ),
                              const SizedBox(height: 4),
                              Text(
                                '读写授权：'
                                '${_permission.canRead && _permission.canWrite ? '可用' : '不可用'}',
                              ),
                            ],
                            if (_commandId != null) ...[
                              const SizedBox(height: 8),
                              Text('command ID：$_commandId'),
                            ],
                            if (_sha256 != null) ...[
                              const SizedBox(height: 4),
                              Text('读回 SHA-256：$_sha256'),
                            ],
                            if (_errorCode != null) ...[
                              const SizedBox(height: 8),
                              Text(
                                '安全错误：$_errorCode',
                                style: TextStyle(
                                  color: Theme.of(context).colorScheme.error,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                              const SizedBox(height: 4),
                              Text(_safeErrorText(_errorCode!)),
                            ],
                            if (_busy) ...[
                              const SizedBox(height: 12),
                              const LinearProgressIndicator(
                                semanticsLabel: 'SAF 操作进行中',
                              ),
                            ],
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 16),
                    Wrap(
                      spacing: 12,
                      runSpacing: 12,
                      children: [
                        FilledButton(
                          onPressed: _busy ? null : _selectDirectory,
                          child: const Text('选择专用目录'),
                        ),
                        FilledButton.tonal(
                          onPressed: _actionsEnabled ? _writeProbe : null,
                          child: const Text('写入/覆盖探针'),
                        ),
                        FilledButton.tonal(
                          onPressed: _actionsEnabled ? _readProbe : null,
                          child: const Text('读取探针'),
                        ),
                        FilledButton.tonal(
                          onPressed: _actionsEnabled ? _deleteProbe : null,
                          child: const Text('删除探针'),
                        ),
                      ],
                    ),
                    const SizedBox(height: 24),
                    const Divider(),
                    const SizedBox(height: 12),
                    Text('S5 资料目录验证', style: textTheme.titleMedium),
                    const SizedBox(height: 8),
                    const Text('资料目录与上面的 SAF 探针相互独立，只读取本级元数据。'),
                    const SizedBox(height: 12),
                    OutlinedButton.icon(
                      onPressed: _busy
                          ? null
                          : () => Navigator.of(context).push(
                              MaterialPageRoute<void>(
                                builder: (_) => const CatalogDirectoryPage(),
                              ),
                            ),
                      icon: const Icon(Icons.folder_copy_outlined),
                      label: const Text('打开资料目录 Gate'),
                    ),
                  ],
                ),
              ),
            );
          },
        ),
      ),
    );
  }
}
