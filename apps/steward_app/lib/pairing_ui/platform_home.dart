import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../app_coordinator/steward_app_coordinator.dart';
import '../app_ui/steward_home_page.dart';
import '../app_ui/steward_memory_page.dart';
import '../app_ui/steward_shell.dart';
import '../app_ui/steward_theme.dart';
import '../app_ui/windows_device_center_page.dart';
import '../catalog/catalog_directory_page.dart';
import '../catalog/catalog_sync_client.dart';
import '../catalog/proactive_suggestion_client.dart';
import '../catalog/today_materials.dart';
import '../catalog/windows_catalog_page.dart';
import '../secure_pairing/method_channel_pairing_vault.dart';
import '../secure_pairing/pairing_crypto.dart';
import '../secure_pairing/pairing_vault.dart';
import '../shared_session/protocol_models.dart';
import '../shared_session_ui/mobile_authenticated_session_page.dart';
import '../shared_session_ui/memory_center_controller.dart';
import '../shared_session_ui/windows_c3_bootstrap.dart';
import 'mobile_pairing_page.dart';

const _destinations = <StewardShellDestination>[
  StewardShellDestination(
    label: '首页',
    icon: Icons.home_outlined,
    selectedIcon: Icons.home,
  ),
  StewardShellDestination(
    label: '会话',
    icon: Icons.forum_outlined,
    selectedIcon: Icons.forum,
  ),
  StewardShellDestination(
    label: '设备',
    icon: Icons.devices_outlined,
    selectedIcon: Icons.devices,
  ),
  StewardShellDestination(
    label: '记忆',
    icon: Icons.psychology_alt_outlined,
    selectedIcon: Icons.psychology_alt,
  ),
  StewardShellDestination(
    label: '今日',
    icon: Icons.folder_copy_outlined,
    selectedIcon: Icons.folder_copy,
  ),
];

final class WindowsStewardHome extends StatefulWidget {
  const WindowsStewardHome({super.key});

  @override
  State<WindowsStewardHome> createState() => _WindowsStewardHomeState();
}

final class _WindowsStewardHomeState extends State<WindowsStewardHome> {
  var _index = 0;
  WindowsC3Workspace? _workspace;
  String? _sessionDraft;
  var _sessionDraftRevision = 0;
  var _homeRefresh = 0;

  void _select(int value) => setState(() {
    _index = value;
    if (value == 0) _homeRefresh += 1;
  });

  void _onWorkspaceReady(WindowsC3Workspace workspace) {
    if (mounted) setState(() => _workspace = workspace);
  }

  void _startIntent(String value) => setState(() {
    _sessionDraft = value;
    _sessionDraftRevision += 1;
    _index = 1;
  });

  void _consumeIntent(int revision) {
    if (!mounted ||
        revision != _sessionDraftRevision ||
        _sessionDraft == null) {
      return;
    }
    setState(() => _sessionDraft = null);
  }

  @override
  Widget build(BuildContext context) {
    final ready = _workspace?.ready;
    final connected = ready != null;
    return StewardAdaptiveShell(
      selectedIndex: _index,
      onDestinationSelected: _select,
      destinations: _destinations,
      statusLabel: connected ? '安全 Hub 已就绪' : '正在启动安全 Hub',
      statusTone: connected
          ? StewardStatusTone.positive
          : StewardStatusTone.warning,
      pages: [
        StewardHomePage(
          connectionLabel: connected ? '电脑服务在线' : '电脑服务启动中',
          connectionTone: connected
              ? StewardStatusTone.positive
              : StewardStatusTone.warning,
          onOpenSession: () => _select(1),
          onOpenToday: () => _select(4),
          onOpenMemory: () => _select(3),
          onStartIntent: _startIntent,
          snapshotLoader: _workspace == null
              ? null
              : () => _loadWindowsHomeSnapshot(_workspace!),
          snapshotIdentityKey: ready?.hubId,
          snapshotKey: '${ready?.hubId}:$_homeRefresh',
        ),
        WindowsC3Bootstrap(
          onWorkspaceReady: _onWorkspaceReady,
          showManagement: false,
          initialDraft: _sessionDraft,
          initialDraftRevision: _sessionDraftRevision,
          onInitialDraftConsumed: _consumeIntent,
        ),
        WindowsDeviceCenterPage(workspace: _workspace),
        StewardMemoryPage(
          controller: _workspace?.memoryController,
          onOpenSession: () => _select(1),
          snapshotIdentityKey: ready?.hubId,
        ),
        WindowsCatalogPage(
          workspace: _workspace,
          onOpenDevices: () => _select(2),
          active: _index == 4,
        ),
      ],
    );
  }
}

final class AndroidStewardHome extends StatefulWidget {
  const AndroidStewardHome({required this.filePage, super.key});

  final Widget filePage;

  @override
  State<AndroidStewardHome> createState() => _AndroidStewardHomeState();
}

final class _AndroidStewardHomeState extends State<AndroidStewardHome>
    with WidgetsBindingObserver {
  var _index = 0;
  static const _vault = MethodChannelPairingVault();
  late final StewardAppCoordinator _coordinator = StewardAppCoordinator(
    vault: _vault,
  );
  MemoryCenterController? _memoryController;
  String? _memoryControllerIdentityKey;
  MemoryCenterSnapshot? _memorySnapshot;
  String? _memorySnapshotIdentityKey;
  String? _sessionDraft;
  var _sessionDraftRevision = 0;
  var _homeRefresh = 0;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    unawaited(_coordinator.initialize());
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      unawaited(_coordinator.refreshAuthorization());
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _coordinator.dispose();
    super.dispose();
  }

  void _select(int value) => setState(() {
    _index = value;
    if (value == 0) _homeRefresh += 1;
  });

  void _memoryControllerChanged(MemoryCenterController? controller) {
    if (!mounted || identical(controller, _memoryController)) return;
    setState(() {
      _memoryController = controller;
      _memoryControllerIdentityKey = controller == null
          ? null
          : _memoryIdentityKey(_coordinator.credential);
    });
  }

  void _memorySnapshotChanged(
    String? sourceIdentityKey,
    MemoryCenterSnapshot snapshot,
  ) {
    final identityKey = _memoryIdentityKey(_coordinator.credential);
    if (!mounted ||
        sourceIdentityKey == null ||
        sourceIdentityKey != identityKey) {
      return;
    }
    if (identityKey == _memorySnapshotIdentityKey &&
        identical(snapshot, _memorySnapshot)) {
      return;
    }
    setState(() {
      _memorySnapshot = snapshot;
      _memorySnapshotIdentityKey = identityKey;
    });
  }

  void _startIntent(String value) => setState(() {
    _sessionDraft = value;
    _sessionDraftRevision += 1;
    _index = 1;
  });

  void _consumeIntent(int revision) {
    if (!mounted ||
        revision != _sessionDraftRevision ||
        _sessionDraft == null) {
      return;
    }
    setState(() => _sessionDraft = null);
  }

  void _openDiagnostics() {
    Navigator.of(
      context,
    ).push(MaterialPageRoute<void>(builder: (_) => widget.filePage));
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: _coordinator,
    builder: (context, _) {
      final status = _coordinatorPresentation(_coordinator);
      final credential = _coordinator.credential;
      final memoryIdentityKey = _memoryIdentityKey(credential);
      final memoryController = _memoryControllerIdentityKey == memoryIdentityKey
          ? _memoryController
          : null;
      final memorySnapshot = _memorySnapshotIdentityKey == memoryIdentityKey
          ? _memorySnapshot
          : null;
      return StewardAdaptiveShell(
        selectedIndex: _index,
        onDestinationSelected: _select,
        destinations: _destinations,
        statusLabel: status.$1,
        statusTone: status.$2,
        pages: [
          StewardHomePage(
            connectionLabel: status.$1,
            connectionTone: status.$2,
            onOpenSession: () => _select(1),
            onOpenToday: () => _select(4),
            onOpenMemory: () => _select(3),
            onStartIntent: _startIntent,
            snapshotLoader: credential == null
                ? null
                : () => _loadAndroidHomeSnapshot(credential, memoryController),
            snapshotIdentityKey: memoryIdentityKey,
            snapshotKey:
                '$memoryIdentityKey:${memoryController != null}:$_homeRefresh',
            onOpenDiagnostics: _openDiagnostics,
          ),
          MobileAuthenticatedSessionPage(
            coordinator: _coordinator,
            onControllerChanged: _memoryControllerChanged,
            onOpenPairing: () => _select(2),
            initialDraft: _sessionDraft,
            initialDraftRevision: _sessionDraftRevision,
            onInitialDraftConsumed: _consumeIntent,
          ),
          MobilePairingPage(
            vault: _vault,
            onCredentialChanged: _coordinator.refreshAfterPairingChange,
          ),
          StewardMemoryPage(
            controller: memoryController,
            onOpenSession: () => _select(1),
            initialSnapshot: memorySnapshot,
            snapshotIdentityKey: memoryIdentityKey,
            onSnapshotChanged: (snapshot) =>
                _memorySnapshotChanged(memoryIdentityKey, snapshot),
          ),
          CatalogDirectoryPage(credential: credential, active: _index == 4),
        ],
      );
    },
  );
}

String? _memoryIdentityKey(ActiveDeviceCredential? credential) =>
    credential == null
    ? null
    : '${credential.hubId}:${credential.deviceId}:${credential.capabilityEpoch}';

(String, StewardStatusTone) _coordinatorPresentation(
  StewardAppCoordinator coordinator,
) => switch (coordinator.state) {
  StewardCredentialState.loading => ('正在核对安全状态', StewardStatusTone.neutral),
  StewardCredentialState.ready when coordinator.authorizationRefreshDeferred =>
    ('会话在线 · 授权待刷新', StewardStatusTone.warning),
  StewardCredentialState.ready => ('电脑已安全连接', StewardStatusTone.positive),
  StewardCredentialState.offline => ('电脑暂时离线', StewardStatusTone.warning),
  StewardCredentialState.capabilityDenied => (
    '缺少会话权限',
    StewardStatusTone.warning,
  ),
  StewardCredentialState.revoked => ('设备授权已撤销', StewardStatusTone.danger),
  StewardCredentialState.invalid => ('设备身份需重新验证', StewardStatusTone.danger),
  StewardCredentialState.unpaired => ('尚未连接电脑', StewardStatusTone.neutral),
};

Future<StewardHomeSnapshot> _loadWindowsHomeSnapshot(
  WindowsC3Workspace workspace,
) async {
  var today = '暂不可用';
  var pending = '暂无待处理';
  final client = http.Client();
  try {
    final request =
        http.Request(
            'GET',
            workspace.ready.localUrl.replace(
              path: '/v1/operator/catalog/today',
            ),
          )
          ..headers['accept'] = 'application/json'
          ..headers['x-datasteward-protocol'] = pairingProtocolVersion
          ..headers['authorization'] =
              'DataSteward-Operator ${workspace.ready.operatorToken}';
    final streamed = await client
        .send(request)
        .timeout(const Duration(seconds: 8));
    final bytes = await streamed.stream
        .fold<List<int>>(<int>[], (buffer, chunk) {
          if (buffer.length + chunk.length > 128 * 1024) {
            throw const FormatException('home_snapshot_too_large');
          }
          return buffer..addAll(chunk);
        })
        .timeout(const Duration(seconds: 8));
    if (streamed.statusCode == 200) {
      final raw = jsonDecode(utf8.decode(bytes));
      if (raw is Map<String, Object?>) {
        final projection = TodayMaterialsProjection.fromJson(raw);
        today = '${projection.assetCount} 项 · ${projection.rootCount} 个资料目录';
      }
    }
  } on Object {
    // A dashboard failure is non-blocking and must not trigger retries.
  } finally {
    client.close();
  }
  final suggestions = ProactiveSuggestionClient.operator(
    baseUri: workspace.ready.localUrl,
    operatorToken: workspace.ready.operatorToken,
  );
  try {
    final cards = await suggestions.inbox();
    final available = cards.where((item) => item.status == 'available').length;
    pending = available == 0 ? '暂无新建议' : '$available 条建议';
  } on Object {
    // Preserve the conservative default.
  } finally {
    suggestions.close();
  }
  return StewardHomeSnapshot(
    todayLabel: today,
    pendingLabel: pending,
    memoryLabel: await _memoryHomeLabel(workspace.memoryController),
  );
}

Future<StewardHomeSnapshot> _loadAndroidHomeSnapshot(
  ActiveDeviceCredential credential,
  MemoryCenterController? memory,
) async {
  var today = '暂不可用';
  var pending = '暂无待处理';
  final catalog = CatalogSyncClient(credential: credential);
  try {
    final projection = await catalog.fetchToday();
    today = '${projection.assetCount} 项 · ${projection.rootCount} 个资料目录';
  } on Object {
    // A dashboard failure is non-blocking and must not trigger retries.
  } finally {
    catalog.close();
  }
  final suggestions = ProactiveSuggestionClient.device(credential: credential);
  try {
    final cards = await suggestions.inbox();
    final available = cards.where((item) => item.status == 'available').length;
    pending = available == 0 ? '暂无新建议' : '$available 条建议';
  } on Object {
    // Preserve the conservative default.
  } finally {
    suggestions.close();
  }
  return StewardHomeSnapshot(
    todayLabel: today,
    pendingLabel: pending,
    memoryLabel: await _memoryHomeLabel(memory),
  );
}

Future<String> _memoryHomeLabel(MemoryCenterController? controller) async {
  if (controller == null || !controller.canLoadMemory) return '尚未形成习惯';
  try {
    final memory = await controller.memoryCenter();
    if (memory == null) return '尚未形成习惯';
    return switch (memory.status) {
      'active' => '已启用 1 条习惯',
      'candidate' => '1 条候选待确认',
      'learning' => '学习中 ${memory.supportCount}/${memory.activationThreshold}',
      'forgotten' => '习惯已停用',
      _ => '尚未形成习惯',
    };
  } on Object {
    return '暂不可用';
  }
}
