import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'operator_control_transport.dart';
import 'pairing_operator.dart';
import 'supervised_pairing_runtime.dart';

final class PairingHostConnection {
  const PairingHostConnection({
    required this.controlUrl,
    required this.advertisedUrl,
    required this.certFingerprint,
    required this.operatorToken,
  });

  final Uri controlUrl;
  final Uri advertisedUrl;
  final String certFingerprint;
  final String operatorToken;
}

final class PairingHostPage extends StatefulWidget {
  const PairingHostPage({
    super.key,
    this.controller,
    this.runtime,
    this.sharedHubConnection,
    this.embedded = false,
  });

  final PairingHostController? controller;
  final PairingRuntime? runtime;
  final PairingHostConnection? sharedHubConnection;
  final bool embedded;

  @override
  State<PairingHostPage> createState() => _PairingHostPageState();
}

final class _PairingHostPageState extends State<PairingHostPage> {
  late final PairingHostController _controller =
      widget.controller ??
      PairingHostController(
        client: const PairingOperatorClient(http: IoOperatorControlTransport()),
      );
  final _controlUrl = TextEditingController(text: 'https://127.0.0.1:9443');
  final _advertisedUrl = TextEditingController();
  final _fingerprint = TextEditingController();
  final _operatorToken = TextEditingController();
  late final SupervisedPairingEnvironment? _supervisedEnvironment =
      widget.runtime == null
      ? SupervisedPairingEnvironment.fromEnvironment(Platform.environment)
      : widget.runtime!.environment;
  late final PairingRuntime? _runtime =
      widget.runtime ??
      (_supervisedEnvironment == null
          ? null
          : SupervisedPairingRuntime(environment: _supervisedEnvironment));
  bool _runtimeBusy = false;
  String? _runtimeError;

  @override
  void initState() {
    super.initState();
    _controller.addListener(_changed);
  }

  @override
  void dispose() {
    _controller.removeListener(_changed);
    if (widget.controller == null) _controller.dispose();
    for (final controller in [
      _controlUrl,
      _advertisedUrl,
      _fingerprint,
      _operatorToken,
    ]) {
      controller.dispose();
    }
    unawaited(_runtime?.close());
    super.dispose();
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  Future<void> _create() async {
    final token = _operatorToken.text;
    await _controller.create(
      controlUrl: _controlUrl.text,
      advertisedUrl: _advertisedUrl.text,
      fingerprint: _fingerprint.text.trim(),
      operatorToken: token,
    );
    _operatorToken.clear();
  }

  Future<void> _startSupervised() async {
    final runtime = _runtime;
    if (runtime == null || _runtimeBusy) return;
    setState(() {
      _runtimeBusy = true;
      _runtimeError = null;
    });
    try {
      final ready = await runtime.start();
      await _controller.create(
        controlUrl: ready.controlUrl.toString(),
        advertisedUrl: ready.pairingUrl.toString(),
        fingerprint: ready.certFingerprint,
        operatorToken: ready.operatorToken,
      );
      if (_controller.state == PairingHostState.failed) {
        await runtime.stop();
      }
    } on Object {
      _runtimeError = 'c2_runtime_unavailable';
      await runtime.stop();
    } finally {
      if (mounted) setState(() => _runtimeBusy = false);
    }
  }

  Future<void> _startFromSharedHub() async {
    final connection = widget.sharedHubConnection;
    if (connection == null || _runtimeBusy) return;
    setState(() {
      _runtimeBusy = true;
      _runtimeError = null;
    });
    try {
      await _controller.create(
        controlUrl: connection.controlUrl.toString(),
        advertisedUrl: connection.advertisedUrl.toString(),
        fingerprint: connection.certFingerprint,
        operatorToken: connection.operatorToken,
      );
    } on Object {
      _runtimeError = 'shared_hub_pairing_unavailable';
    } finally {
      if (mounted) setState(() => _runtimeBusy = false);
    }
  }

  Future<void> _refresh() async {
    await _controller.refresh();
    if (_controller.status?.isActive ?? false) await _runtime?.stop();
  }

  Future<void> _confirm() async {
    await _controller.confirm();
    if (_controller.status?.isActive ?? false) await _runtime?.stop();
  }

  Future<void> _cancel() async {
    await _controller.cancel();
    await _runtime?.stop();
  }

  Future<void> _finish() async {
    _controller.reset();
    await _runtime?.stop();
  }

  @override
  Widget build(BuildContext context) {
    final status = _controller.status;
    return Scaffold(
      appBar: widget.embedded
          ? null
          : AppBar(title: const Text('安全配对 · 电脑端确认')),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          const Text(
            '只有电脑端本地操作者和手机端同时确认相同短码，才会激活设备凭据。',
            style: TextStyle(fontWeight: FontWeight.w600),
          ),
          const SizedBox(height: 8),
          const Text('配对码为一次性数据；操作口令仅保存在本轮内存，不写入设置、日志或二维码。'),
          const SizedBox(height: 20),
          if (_controller.state == PairingHostState.setup ||
              _controller.state == PairingHostState.failed) ...[
            if (widget.sharedHubConnection != null) ...[
              const Card(
                child: ListTile(
                  leading: Icon(Icons.security),
                  title: Text('使用当前安全会话服务'),
                  subtitle: Text('Hub 地址、证书指纹和本轮操作口令仅在进程内传递，不显示、不持久化。'),
                ),
              ),
              FilledButton.icon(
                key: const Key('pairing-shared-hub-start'),
                onPressed: _runtimeBusy ? null : _startFromSharedHub,
                icon: const Icon(Icons.qr_code_2),
                label: const Text('生成本轮安全配对二维码'),
              ),
              if (_runtimeBusy) const LinearProgressIndicator(),
              if (_runtimeError case final String code) Text('安全失败：$code'),
            ] else if (_runtime != null) ...[
              const Card(
                child: ListTile(
                  leading: Icon(Icons.lan),
                  title: Text('C2 受监督真实设备模式'),
                  subtitle: Text('仅在已通过启动脚本确认的专用网络上，启动本机控制与手机配对两个隔离监听面。'),
                ),
              ),
              FilledButton.icon(
                key: const Key('pairing-c2-start'),
                onPressed: _runtimeBusy ? null : _startSupervised,
                icon: const Icon(Icons.phonelink_lock),
                label: const Text('启动安全配对并生成二维码'),
              ),
              if (_runtimeBusy) const LinearProgressIndicator(),
              if (_runtimeError case final String code) Text('安全失败：$code'),
            ] else ...[
              TextField(
                controller: _controlUrl,
                decoration: const InputDecoration(
                  labelText: '本机控制地址（HTTPS）',
                  helperText: '示例：https://127.0.0.1:9443',
                ),
              ),
              TextField(
                controller: _advertisedUrl,
                decoration: const InputDecoration(
                  labelText: '手机可访问的 Hub 地址（HTTPS）',
                  helperText: '手工模式仅用于受控测试',
                ),
              ),
              TextField(
                controller: _fingerprint,
                autocorrect: false,
                decoration: const InputDecoration(labelText: '证书 SHA-256 指纹'),
              ),
              TextField(
                controller: _operatorToken,
                obscureText: true,
                enableSuggestions: false,
                autocorrect: false,
                decoration: const InputDecoration(labelText: '本轮本地操作口令'),
              ),
              const SizedBox(height: 16),
              FilledButton.icon(
                key: const Key('pairing-create'),
                onPressed: _controller.state == PairingHostState.creating
                    ? null
                    : _create,
                icon: const Icon(Icons.qr_code_2),
                label: const Text('创建一次性配对码'),
              ),
            ],
          ],
          if (_controller.safeErrorCode case final String code) ...[
            const SizedBox(height: 16),
            Text('安全失败：$code', key: const Key('pairing-safe-error')),
          ],
          if (_controller.qrPayload case final String payload) ...[
            const SizedBox(height: 20),
            Center(
              child: Semantics(
                label: '一次性安全配对二维码',
                child: QrImageView(
                  data: payload,
                  size: 260,
                  backgroundColor: Colors.white,
                ),
              ),
            ),
            const Center(child: Text('请用 Data Steward 手机端扫描；不要截图转发。')),
          ],
          if (status != null) ...[
            const SizedBox(height: 20),
            _StatusCard(controller: _controller, status: status),
            const SizedBox(height: 12),
            Wrap(
              spacing: 12,
              runSpacing: 8,
              children: [
                OutlinedButton.icon(
                  key: const Key('pairing-refresh'),
                  onPressed: _refresh,
                  icon: const Icon(Icons.refresh),
                  label: const Text('刷新手机请求'),
                ),
                if (status.hasClientRequest && !status.hubConfirmed)
                  FilledButton.icon(
                    key: const Key('pairing-hub-confirm'),
                    onPressed: _controller.selectedGrants.isEmpty
                        ? null
                        : _confirm,
                    icon: const Icon(Icons.verified_user),
                    label: const Text('短码一致，批准所选权限'),
                  ),
                if (!status.isActive)
                  TextButton(
                    key: const Key('pairing-cancel'),
                    onPressed: _cancel,
                    child: const Text('取消本次配对'),
                  ),
                if (status.isActive)
                  FilledButton(onPressed: _finish, child: const Text('完成')),
              ],
            ),
          ],
        ],
      ),
    );
  }
}

final class _StatusCard extends StatelessWidget {
  const _StatusCard({required this.controller, required this.status});

  final PairingHostController controller;
  final PairingOperatorStatus status;

  @override
  Widget build(BuildContext context) {
    final visibleShortCode = status.isActive ? null : status.shortCode;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '状态：${status.isActive
                  ? '已安全配对'
                  : status.hasClientRequest
                  ? '等待双方确认'
                  : '等待手机扫码'}',
            ),
            if (status.displayName != null)
              Text('设备：${status.displayName}（${status.platform ?? 'unknown'}）'),
            if (visibleShortCode case final String code) ...[
              const SizedBox(height: 12),
              const Text('请逐字核对手机端短码：'),
              SelectableText(
                code,
                key: const Key('pairing-short-code'),
                style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                  letterSpacing: 4,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
            if (status.requestedCapabilities.isNotEmpty) ...[
              const SizedBox(height: 12),
              const Text('手机请求的权限（可缩减，不可扩大）：'),
              for (final capability in status.requestedCapabilities)
                CheckboxListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  value: controller.selectedGrants.contains(capability),
                  title: Text(capability),
                  onChanged: status.hubConfirmed
                      ? null
                      : (value) =>
                            controller.toggleGrant(capability, value ?? false),
                ),
            ],
            if (status.hubConfirmed && !status.isActive)
              const Text('电脑端已确认，等待手机端确认。'),
            if (status.isActive) const Text('凭据已激活；一次性二维码与本地操作口令已从内存清除。'),
          ],
        ),
      ),
    );
  }
}
