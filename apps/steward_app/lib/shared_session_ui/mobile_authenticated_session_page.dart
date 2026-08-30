import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../app_coordinator/steward_app_coordinator.dart';
import '../secure_pairing/pairing_models.dart';
import '../secure_pairing/pairing_vault.dart';
import '../secure_pairing/strict_json.dart';
import 'shared_session_bootstrap.dart';
import 'shared_session_controller.dart';
import 'shared_session_page.dart';

typedef MobileSessionControllerFactory =
    Future<SharedSessionController> Function(ActiveDeviceCredential credential);

final class SharedSessionServiceDescriptor {
  const SharedSessionServiceDescriptor({
    required this.hubId,
    required this.baseUrl,
    required this.certFingerprint,
  });

  final String hubId;
  final Uri baseUrl;
  final String certFingerprint;

  factory SharedSessionServiceDescriptor.fromJson(String source) {
    final value = decodeStrictJsonObject(source, maxUtf8Bytes: 2048);
    requireExactKeys(value, const {
      'protocol_version',
      'hub_id',
      'base_url',
      'cert_fingerprint',
    });
    if (value['protocol_version'] != 'shared_session_service/1') {
      throw const FormatException('service_descriptor_invalid');
    }
    final url = Uri.tryParse(value['base_url'] as String? ?? '');
    if (url == null ||
        url.scheme != 'https' ||
        !url.hasPort ||
        url.userInfo.isNotEmpty ||
        (url.path.isNotEmpty && url.path != '/') ||
        url.query.isNotEmpty ||
        url.fragment.isNotEmpty ||
        !_privateIpv4(url.host)) {
      throw const FormatException('service_descriptor_invalid');
    }
    return SharedSessionServiceDescriptor(
      hubId: requireUlid(value['hub_id']),
      baseUrl: url.replace(path: '', query: null, fragment: null),
      certFingerprint: requireDigest(value['cert_fingerprint']),
    );
  }
}

final class MobileAuthenticatedSessionPage extends StatefulWidget {
  const MobileAuthenticatedSessionPage({
    super.key,
    this.coordinator,
    this.onControllerChanged,
    this.controllerFactory,
    this.onOpenPairing,
    this.initialDraft,
    this.initialDraftRevision = 0,
    this.onInitialDraftConsumed,
  });

  final StewardAppCoordinator? coordinator;
  final ValueChanged<SharedSessionController?>? onControllerChanged;
  final MobileSessionControllerFactory? controllerFactory;
  final VoidCallback? onOpenPairing;
  final String? initialDraft;
  final int initialDraftRevision;
  final ValueChanged<int>? onInitialDraftConsumed;

  @override
  State<MobileAuthenticatedSessionPage> createState() =>
      _MobileAuthenticatedSessionPageState();
}

final class _MobileAuthenticatedSessionPageState
    extends State<MobileAuthenticatedSessionPage> {
  late final StewardAppCoordinator _coordinator =
      widget.coordinator ?? StewardAppCoordinator();
  late final bool _ownsCoordinator = widget.coordinator == null;
  SharedSessionController? _controller;
  bool _scannerVisible = false;
  bool _busy = false;
  bool _scanAccepted = false;
  bool _authorizationRefreshRequested = false;
  String? _error;
  String? _startedCredentialKey;
  String? _startingCredentialKey;
  bool _credentialRestartPending = false;
  bool _startScheduled = false;

  @override
  void initState() {
    super.initState();
    _coordinator.addListener(_coordinatorChanged);
    if (_ownsCoordinator) unawaited(_coordinator.initialize());
    _coordinatorChanged();
  }

  void _coordinatorChanged() {
    if (!mounted) return;
    setState(() {});
    if (_coordinator.canUseSharedSession) {
      final credential = _coordinator.credential;
      final activeKey = credential == null ? null : _credentialKey(credential);
      final runningChanged =
          _startedCredentialKey != null && _startedCredentialKey != activeKey;
      final startingChanged =
          _startingCredentialKey != null && _startingCredentialKey != activeKey;
      if (runningChanged || startingChanged) {
        _credentialRestartPending = true;
        if (_controller != null) _disposeController();
      }
      _scheduleSessionStart();
    } else if (_controller != null) {
      _disposeController();
    }
  }

  void _scheduleSessionStart() {
    if (_startScheduled || _busy || _controller != null || !mounted) return;
    _startScheduled = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _startScheduled = false;
      if (!mounted || !_coordinator.canUseSharedSession) return;
      unawaited(_startFromCoordinator());
    });
  }

  Future<void> _startFromCoordinator() async {
    final credential = _coordinator.credential;
    if (credential == null || _busy) return;
    final key = _credentialKey(credential);
    if (_controller != null && _startedCredentialKey == key) return;
    setState(() {
      _busy = true;
      _error = null;
      _scannerVisible = false;
    });
    _startingCredentialKey = key;
    _disposeController();
    try {
      final controller =
          await (widget.controllerFactory ?? _createAuthenticatedController)(
            credential,
          );
      if (!mounted ||
          !_coordinator.canUseSharedSession ||
          _currentCredentialKey() != key) {
        _credentialRestartPending = mounted && _coordinator.canUseSharedSession;
        controller.dispose();
        return;
      }
      _controller = controller;
      _startedCredentialKey = key;
      controller.addListener(_controllerChanged);
      setState(() {});
      await controller.start();
      if (!mounted ||
          !identical(_controller, controller) ||
          !_coordinator.canUseSharedSession ||
          _currentCredentialKey() != key) {
        _credentialRestartPending = mounted && _coordinator.canUseSharedSession;
        if (identical(_controller, controller)) _disposeController();
        return;
      }
      widget.onControllerChanged?.call(controller);
      if (controller.state == SharedSessionViewState.authorizationChanged) {
        await _coordinator.refreshAuthorization();
      }
    } on Object {
      if (mounted && _currentCredentialKey() == key) {
        setState(() => _error = '自动恢复共享会话失败，请检查电脑服务状态。');
      }
    } finally {
      if (_startingCredentialKey == key) _startingCredentialKey = null;
      if (mounted) {
        setState(() => _busy = false);
        if (_credentialRestartPending) {
          _credentialRestartPending = false;
          _scheduleSessionStart();
        }
      }
    }
  }

  String? _currentCredentialKey() {
    final credential = _coordinator.credential;
    return credential == null ? null : _credentialKey(credential);
  }

  void _controllerChanged() {
    final controller = _controller;
    final controllerMatchesCredential =
        controller != null &&
        _startedCredentialKey != null &&
        _startedCredentialKey == _currentCredentialKey();
    if (!controllerMatchesCredential) return;
    if (controller.state == SharedSessionViewState.ready) {
      widget.onControllerChanged?.call(controller);
    }
    if (_controller?.state != SharedSessionViewState.authorizationChanged ||
        _authorizationRefreshRequested) {
      return;
    }
    _authorizationRefreshRequested = true;
    unawaited(_refreshAfterAuthorizationChange());
  }

  Future<void> _refreshAfterAuthorizationChange() async {
    try {
      await _coordinator.refreshAuthorization();
    } finally {
      _authorizationRefreshRequested = false;
    }
  }

  Future<void> _acceptDescriptor(String source) async {
    if (_busy || _scanAccepted || source.trim().isEmpty) return;
    _scanAccepted = true;
    setState(() {
      _busy = true;
      _scannerVisible = false;
      _error = null;
    });
    try {
      final existing = _coordinator.credential;
      if (existing == null) {
        throw const FormatException('credential_missing');
      }
      final descriptor = SharedSessionServiceDescriptor.fromJson(source.trim());
      if (descriptor.hubId != existing.hubId ||
          descriptor.certFingerprint != existing.certFingerprint) {
        throw const FormatException('service_identity_mismatch');
      }
      await _coordinator.updateEndpoint(
        hubId: descriptor.hubId,
        baseUrl: descriptor.baseUrl,
        certFingerprint: descriptor.certFingerprint,
      );
    } on Object {
      if (mounted) {
        setState(() => _error = '服务码无效，或与已配对电脑身份不一致。');
      }
    } finally {
      if (mounted) {
        setState(() {
          _busy = false;
          _scanAccepted = false;
        });
      }
    }
  }

  Future<void> _returnToScanner() async {
    if (_busy) return;
    _disposeController();
    if (mounted) {
      setState(() {
        _scannerVisible = true;
        _error = null;
      });
    }
  }

  Future<void> _retryEstablishedSession() async {
    if (_busy || !_coordinator.canUseSharedSession) return;
    _disposeController();
    await _startFromCoordinator();
  }

  void _disposeController({bool notifyParent = true}) {
    final previous = _controller;
    _controller = null;
    _startedCredentialKey = null;
    previous?.removeListener(_controllerChanged);
    previous?.dispose();
    if (previous != null && notifyParent) {
      widget.onControllerChanged?.call(null);
    }
  }

  @override
  void dispose() {
    _coordinator.removeListener(_coordinatorChanged);
    _disposeController(notifyParent: false);
    if (_ownsCoordinator) _coordinator.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = _controller;
    if (controller != null) {
      return SharedSessionPage(
        controller: controller,
        onRetryConnection: _retryEstablishedSession,
        onReturnToServiceScanner: _returnToScanner,
        initialDraft: widget.initialDraft,
        initialDraftRevision: widget.initialDraftRevision,
        onInitialDraftConsumed: widget.onInitialDraftConsumed,
      );
    }
    return Scaffold(
      appBar: AppBar(title: const Text('共享会话')),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          const Text(
            '应用会优先使用已配对设备凭据自动恢复。部分手机或路由器可能无法自动发现电脑；'
            '此时扫描电脑服务码即可安全更新地址，无需重新配对。',
          ),
          const SizedBox(height: 16),
          if (_coordinator.credential != null)
            ListTile(
              leading: const Icon(Icons.verified_user, color: Colors.green),
              title: const Text('已恢复安全设备身份'),
              subtitle: Text(
                _credentialStatusText(
                  _coordinator.state,
                  refreshDeferred: _coordinator.authorizationRefreshDeferred,
                ),
              ),
            ),
          if (_error case final String value)
            Text(value, key: const Key('c3-mobile-error')),
          if (_endpointRecoveryText(_coordinator.endpointRecoveryState)
              case final String value) ...[
            const SizedBox(height: 8),
            Text(value, key: const Key('s6f-endpoint-recovery-status')),
          ],
          const SizedBox(height: 12),
          if (_coordinator.canRecoverEndpoint) ...[
            OutlinedButton.icon(
              key: const Key('s6f-find-paired-computer'),
              onPressed: _busy || _coordinator.busy
                  ? null
                  : _coordinator.findPairedHub,
              icon: const Icon(Icons.wifi_find),
              label: const Text('寻找已配对电脑'),
            ),
            const SizedBox(height: 8),
            FilledButton.icon(
              key: const Key('c3-open-scanner'),
              onPressed: _busy
                  ? null
                  : () => setState(() => _scannerVisible = !_scannerVisible),
              icon: const Icon(Icons.qr_code_scanner),
              label: Text(_scannerVisible ? '关闭扫码' : '扫描服务码更新地址'),
            ),
          ],
          if (_coordinator.state == StewardCredentialState.ready) ...[
            const SizedBox(height: 8),
            OutlinedButton.icon(
              key: const Key('s5-resume-established-session'),
              onPressed: _busy ? null : _retryEstablishedSession,
              icon: const Icon(Icons.play_circle_outline),
              label: const Text('立即恢复会话'),
            ),
          ],
          if (const {
            StewardCredentialState.unpaired,
            StewardCredentialState.capabilityDenied,
            StewardCredentialState.revoked,
            StewardCredentialState.invalid,
          }.contains(_coordinator.state)) ...[
            const SizedBox(height: 8),
            OutlinedButton.icon(
              key: const Key('s6-open-secure-pairing'),
              onPressed: _busy ? null : widget.onOpenPairing,
              icon: const Icon(Icons.link),
              label: const Text('前往安全配对'),
            ),
          ],
          if (_scannerVisible && _coordinator.canRecoverEndpoint) ...[
            const SizedBox(height: 12),
            SizedBox(
              height: 300,
              child: ClipRRect(
                borderRadius: BorderRadius.circular(16),
                child: MobileScanner(
                  onDetect: (capture) {
                    for (final barcode in capture.barcodes) {
                      final value = barcode.rawValue;
                      if (value != null) {
                        unawaited(_acceptDescriptor(value));
                        break;
                      }
                    }
                  },
                ),
              ),
            ),
          ],
          if (_busy || _coordinator.busy) ...[
            const SizedBox(height: 16),
            const Center(child: CircularProgressIndicator()),
          ],
        ],
      ),
    );
  }
}

String _credentialKey(ActiveDeviceCredential credential) =>
    '${credential.hubId}:${credential.deviceId}:${credential.capabilityEpoch}:'
    '${credential.baseUrl}:${credential.certFingerprint}';

Future<SharedSessionController> _createAuthenticatedController(
  ActiveDeviceCredential credential,
) => createSharedSessionController(
  config: DemoHubConfig.authenticated(
    httpBase: credential.baseUrl,
    websocketBase: credential.baseUrl.replace(scheme: 'wss'),
    actorDeviceId: credential.deviceId,
    activeCredential: credential,
  ),
);

String _credentialStatusText(
  StewardCredentialState state, {
  required bool refreshDeferred,
}) => switch (state) {
  StewardCredentialState.loading => '正在核对电脑端实时授权…',
  StewardCredentialState.ready =>
    refreshDeferred ? '会话保持连接；实时授权刷新将在网络稳定后重试。' : '授权有效，正在自动恢复共享会话。',
  StewardCredentialState.offline => '电脑暂时离线；已保留凭据，不会反复重试。',
  StewardCredentialState.capabilityDenied => '当前设备未获得共享会话权限。',
  StewardCredentialState.revoked => '设备授权已撤销，已停止重连。',
  StewardCredentialState.invalid => '设备身份校验失败，请重新安全配对。',
  StewardCredentialState.unpaired => '请先在“安全配对”页连接电脑。',
};

String? _endpointRecoveryText(EndpointRecoveryState state) => switch (state) {
  EndpointRecoveryState.idle => null,
  EndpointRecoveryState.searching => '正在安全查找已配对电脑；本次只尝试一次。',
  EndpointRecoveryState.recovered => '已找到已配对电脑的新地址，并通过安全身份验证。',
  EndpointRecoveryState.notFound =>
    '暂未找到已配对电脑；不会自动重复尝试。可扫描电脑服务码更新地址，原配对与权限会保留。',
  EndpointRecoveryState.rejected => '发现结果无法安全确认；已停止并保留原凭据。可扫描电脑服务码完成安全地址更新。',
};

bool _privateIpv4(String host) {
  final parts = host.split('.').map(int.tryParse).toList();
  if (parts.length != 4 ||
      parts.any((value) => value == null || value < 0 || value > 255)) {
    return false;
  }
  return parts[0] == 10 ||
      (parts[0] == 172 && parts[1]! >= 16 && parts[1]! <= 31) ||
      (parts[0] == 192 && parts[1] == 168);
}
