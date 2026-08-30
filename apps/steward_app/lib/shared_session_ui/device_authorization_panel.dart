import 'dart:async';

import 'package:flutter/material.dart';

import 'device_admin_client.dart';

final class DeviceAuthorizationController extends ChangeNotifier {
  DeviceAuthorizationController({required this.api});

  final DeviceAdminApi api;
  List<ManagedDeviceCredential> devices = const [];
  bool busy = false;
  bool autoRefreshPaused = false;
  String? safeMessage;
  bool _disposed = false;
  bool _refreshing = false;

  ManagedDeviceCredential? get current {
    for (final device in devices) {
      if (device.status == 'ACTIVE') return device;
    }
    return devices.isEmpty ? null : devices.first;
  }

  bool get canDowngrade {
    final value = current;
    return !busy &&
        value?.status == 'ACTIVE' &&
        value!.grantedCapabilities.contains('session.sync') &&
        (value.grantedCapabilities.contains('files.read') ||
            value.grantedCapabilities.contains('files.organize'));
  }

  bool get canRevoke => !busy && current?.status == 'ACTIVE';

  Future<void> load() => _load(interactive: true);

  Future<void> refreshSilently() => _load(interactive: false);

  Future<void> _load({required bool interactive}) async {
    if (busy || _refreshing || _disposed) return;
    _refreshing = true;
    if (interactive) {
      busy = true;
      safeMessage = null;
      autoRefreshPaused = false;
      notifyListeners();
    }
    try {
      devices = await api.listDevices();
      autoRefreshPaused = false;
    } on Object {
      safeMessage = '设备授权状态暂不可用，未显示底层错误。';
      autoRefreshPaused = true;
    } finally {
      _refreshing = false;
      if (interactive) busy = false;
      if (!_disposed) notifyListeners();
    }
  }

  Future<void> downgrade() async {
    final value = current;
    if (!canDowngrade || value == null) return;
    await _transition(
      () => api.updateCapabilities(
        deviceId: value.deviceId,
        expectedEpoch: value.capabilityEpoch,
        grants: const ['session.sync'],
      ),
      success: (result) =>
          '权限已收紧，关闭 ${result.closedConnectionCount} 个实时连接；设备需重新配对。',
    );
  }

  Future<void> revoke() async {
    final value = current;
    if (!canRevoke || value == null) return;
    await _transition(
      () => api.revoke(
        deviceId: value.deviceId,
        expectedEpoch: value.capabilityEpoch,
      ),
      success: (result) => '设备授权已撤销，关闭 ${result.closedConnectionCount} 个实时连接。',
    );
  }

  Future<void> _transition(
    Future<DeviceAuthorizationTransition> Function() action, {
    required String Function(DeviceAuthorizationTransition) success,
  }) async {
    if (busy || _disposed) return;
    busy = true;
    safeMessage = null;
    notifyListeners();
    try {
      final result = await action();
      devices = await api.listDevices();
      safeMessage = success(result);
    } on Object {
      safeMessage = '授权变更未确认，请刷新状态后再决定，系统不会自动重试。';
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

final class DeviceAuthorizationPanel extends StatefulWidget {
  const DeviceAuthorizationPanel({required this.controller, super.key});

  final DeviceAuthorizationController controller;

  @override
  State<DeviceAuthorizationPanel> createState() =>
      _DeviceAuthorizationPanelState();
}

final class _DeviceAuthorizationPanelState
    extends State<DeviceAuthorizationPanel> {
  static const _refreshInterval = Duration(seconds: 3);
  Timer? _refreshTimer;

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_changed);
    _startAutoRefresh();
  }

  @override
  void didUpdateWidget(DeviceAuthorizationPanel oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.controller != widget.controller) {
      oldWidget.controller.removeListener(_changed);
      widget.controller.addListener(_changed);
      unawaited(widget.controller.load());
    }
  }

  @override
  void dispose() {
    _refreshTimer?.cancel();
    widget.controller.removeListener(_changed);
    super.dispose();
  }

  void _startAutoRefresh() {
    _refreshTimer = Timer.periodic(_refreshInterval, (_) {
      final controller = widget.controller;
      if (!controller.autoRefreshPaused) {
        unawaited(controller.refreshSilently());
      }
    });
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  Future<void> _confirmRevoke() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('撤销此设备？'),
        content: const Text('撤销立即生效，设备必须重新安全配对才能再次连接。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('取消'),
          ),
          FilledButton(
            key: const Key('c4-confirm-revoke'),
            onPressed: () => Navigator.pop(context, true),
            child: const Text('确认撤销'),
          ),
        ],
      ),
    );
    if (confirmed == true) await widget.controller.revoke();
  }

  @override
  Widget build(BuildContext context) {
    final controller = widget.controller;
    final device = controller.current;
    return Card(
      key: const Key('c4-device-authorization-panel'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Expanded(
                  child: Text(
                    '设备授权',
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                ),
                IconButton(
                  key: const Key('c4-refresh-devices'),
                  onPressed: controller.busy ? null : controller.load,
                  tooltip: '刷新设备状态',
                  icon: const Icon(Icons.refresh),
                ),
              ],
            ),
            Text(
              controller.autoRefreshPaused ? '实时刷新已暂停，请手动刷新' : '授权状态每 3 秒安全刷新',
              key: const Key('c4-live-refresh-status'),
            ),
            if (controller.busy) const LinearProgressIndicator(),
            if (device == null && !controller.busy)
              const Text('尚无已配对设备。')
            else if (device != null) ...[
              Text('${device.safeLabel} · ${device.safeIdPrefix}'),
              const SizedBox(height: 6),
              Text(
                '状态：${_statusLabel(device.status)} · '
                '授权版本：${device.capabilityEpoch}',
              ),
              Text('权限：${device.grantedCapabilities.join('、')}'),
              const SizedBox(height: 10),
              Wrap(
                spacing: 10,
                runSpacing: 8,
                children: [
                  OutlinedButton.icon(
                    key: const Key('c4-downgrade-capabilities'),
                    onPressed: controller.canDowngrade
                        ? controller.downgrade
                        : null,
                    icon: const Icon(Icons.security_update_warning),
                    label: const Text('移除文件读取权限'),
                  ),
                  FilledButton.tonalIcon(
                    key: const Key('c4-revoke-device'),
                    onPressed: controller.canRevoke ? _confirmRevoke : null,
                    icon: const Icon(Icons.link_off),
                    label: const Text('撤销设备'),
                  ),
                ],
              ),
            ],
            if (controller.safeMessage case final String message) ...[
              const SizedBox(height: 8),
              Text(message, key: const Key('c4-admin-message')),
            ],
          ],
        ),
      ),
    );
  }
}

String _statusLabel(String status) => switch (status) {
  'ACTIVE' => '已授权',
  'REVOKED' => '已撤销',
  'PENDING' => '待确认',
  'EXPIRED' => '已过期',
  _ => '未知',
};
