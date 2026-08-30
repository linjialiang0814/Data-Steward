import 'dart:async';

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../secure_pairing/method_channel_pairing_vault.dart';
import '../secure_pairing/pairing_client.dart';
import '../secure_pairing/pairing_controller.dart';
import '../secure_pairing/pairing_errors.dart';
import '../secure_pairing/pinned_transport.dart';
import '../secure_pairing/pairing_vault.dart';

final class MobilePairingPage extends StatefulWidget {
  const MobilePairingPage({
    super.key,
    this.controller,
    this.vault,
    this.onCredentialChanged,
  });

  final SecurePairingController? controller;
  final PairingVault? vault;
  final Future<void> Function()? onCredentialChanged;

  @override
  State<MobilePairingPage> createState() => _MobilePairingPageState();
}

final class _MobilePairingPageState extends State<MobilePairingPage> {
  late final SecurePairingController _controller =
      widget.controller ??
      SecurePairingController(
        client: const SecurePairingClient(http: IoPinFirstTransport()),
        vault: widget.vault ?? const MethodChannelPairingVault(),
      );
  final _manual = TextEditingController();
  StreamSubscription<SecurePairingState>? _states;
  bool _scannerVisible = false;
  bool _busy = false;
  bool _scanAccepted = false;
  String? _safeErrorCode;

  @override
  void initState() {
    super.initState();
    _states = _controller.states.listen((_) {
      if (mounted) setState(() {});
    });
    unawaited(_initialize());
  }

  Future<void> _initialize() async {
    try {
      await _controller.initialize();
    } on SecurePairingException catch (error) {
      if (mounted) setState(() => _safeErrorCode = error.code);
    }
  }

  @override
  void dispose() {
    unawaited(_states?.cancel());
    _manual.dispose();
    if (widget.controller == null) unawaited(_controller.close());
    super.dispose();
  }

  Future<void> _acceptPayload(String value) async {
    if (_busy || _scanAccepted || value.trim().isEmpty) return;
    _scanAccepted = true;
    setState(() {
      _busy = true;
      _scannerVisible = false;
      _safeErrorCode = null;
    });
    final payload = value.trim();
    _manual.clear();
    try {
      await _controller.begin(
        qrJson: payload,
        requestedCapabilities: const [
          'catalog.sync',
          'content.analyze',
          'files.organize',
          'files.read',
          'session.sync',
          'artifact.export',
        ],
        displayName: 'Huawei Android',
      );
    } on SecurePairingException catch (error) {
      _safeErrorCode = error.code;
    } finally {
      if (mounted) {
        setState(() {
          _busy = false;
          _scanAccepted = false;
        });
      }
    }
  }

  Future<void> _confirm() => _run(() async {
    await _controller.confirm();
    await widget.onCredentialChanged?.call();
  });

  Future<void> _recover() => _run(() async {
    await _controller.recoverAfterConfirmLoss();
    if (_controller.state == SecurePairingState.active) {
      await widget.onCredentialChanged?.call();
    }
  });

  Future<void> _retry() => _run(() async {
    await _controller.retryAfterStable(displayName: 'Huawei Android');
  });

  Future<void> _reset() => _run(() async {
    await _controller.reset();
    await widget.onCredentialChanged?.call();
  });

  Future<void> _run(Future<void> Function() operation) async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _safeErrorCode = null;
    });
    try {
      await operation();
    } on SecurePairingException catch (error) {
      _safeErrorCode = error.code;
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = _controller.state;
    return Scaffold(
      appBar: AppBar(title: const Text('安全连接电脑')),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          const Text('先验证电脑证书指纹，再发送一次性配对请求。只有手机和电脑显示相同短码并分别确认，凭据才会激活。'),
          const SizedBox(height: 12),
          if (state == SecurePairingState.idle) ...[
            FilledButton.icon(
              key: const Key('pairing-open-scanner'),
              onPressed: _busy
                  ? null
                  : () => setState(() => _scannerVisible = !_scannerVisible),
              icon: const Icon(Icons.qr_code_scanner),
              label: Text(_scannerVisible ? '关闭扫码' : '扫描电脑配对码'),
            ),
            if (_scannerVisible) ...[
              const SizedBox(height: 12),
              SizedBox(
                height: 280,
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(16),
                  child: MobileScanner(
                    onDetect: (capture) {
                      for (final barcode in capture.barcodes) {
                        final value = barcode.rawValue;
                        if (value != null) {
                          unawaited(_acceptPayload(value));
                          break;
                        }
                      }
                    },
                  ),
                ),
              ),
            ],
            const SizedBox(height: 16),
            ExpansionTile(
              title: const Text('无法使用相机？粘贴配对内容'),
              children: [
                TextField(
                  key: const Key('pairing-manual-payload'),
                  controller: _manual,
                  minLines: 2,
                  maxLines: 4,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: const InputDecoration(
                    hintText: '仅接受由电脑端本轮生成的完整配对 JSON',
                  ),
                ),
                const SizedBox(height: 8),
                OutlinedButton(
                  onPressed: _busy ? null : () => _acceptPayload(_manual.text),
                  child: const Text('验证并连接'),
                ),
              ],
            ),
          ],
          if (_controller.safeHubLabel case final String label) ...[
            const SizedBox(height: 16),
            Text(label, key: const Key('pairing-safe-hub-label')),
          ],
          if (_controller.shortCode case final String code) ...[
            const SizedBox(height: 20),
            const Text('请与电脑端逐字核对：'),
            SelectableText(
              code,
              key: const Key('pairing-mobile-short-code'),
              style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                letterSpacing: 4,
                fontWeight: FontWeight.bold,
              ),
            ),
            const SizedBox(height: 8),
            const Text('短码不一致时不要确认，请立即取消并重新生成配对码。'),
          ],
          if (state == SecurePairingState.awaitingHumanConfirmation)
            FilledButton.icon(
              key: const Key('pairing-mobile-confirm'),
              onPressed: _busy ? null : _confirm,
              icon: const Icon(Icons.verified_user),
              label: const Text('短码一致，确认连接'),
            ),
          if (state == SecurePairingState.awaitingHubConfirmation) ...[
            const Text('手机端已确认，等待电脑端批准。'),
            OutlinedButton.icon(
              key: const Key('pairing-mobile-recover'),
              onPressed: _busy ? null : _recover,
              icon: const Icon(Icons.refresh),
              label: const Text('电脑确认后查询结果'),
            ),
          ],
          if (state == SecurePairingState.active) ...[
            const ListTile(
              leading: Icon(Icons.verified, color: Colors.green),
              title: Text('已安全连接'),
              subtitle: Text('长期凭据由 Android Keystore 保护，应用界面不会显示。'),
            ),
            if (_controller.activeGrants.isNotEmpty)
              Text('已授予：${_controller.activeGrants.join('、')}'),
            TextButton(
              key: const Key('pairing-mobile-forget'),
              onPressed: _busy ? null : _reset,
              child: const Text('忘记本机凭据'),
            ),
          ],
          if (state == SecurePairingState.waitStable) ...[
            const Text('网络暂不稳定。已保留同一次尝试，请勿反复扫码；网络稳定后再恢复。'),
            OutlinedButton.icon(
              key: const Key('pairing-mobile-retry'),
              onPressed: _busy ? null : _retry,
              icon: const Icon(Icons.wifi_find),
              label: const Text('网络稳定后重试同一次请求'),
            ),
          ],
          if (state == SecurePairingState.awaitingHumanConfirmation ||
              state == SecurePairingState.awaitingHubConfirmation ||
              state == SecurePairingState.waitStable ||
              state == SecurePairingState.failed)
            TextButton.icon(
              key: const Key('pairing-mobile-cancel-pending'),
              onPressed: _busy ? null : _reset,
              icon: const Icon(Icons.close),
              label: const Text('取消本次配对并返回扫码'),
            ),
          if (_safeErrorCode case final String code) ...[
            const SizedBox(height: 12),
            Text('安全失败：$code', key: const Key('pairing-mobile-error')),
          ],
          if (_busy) const Center(child: CircularProgressIndicator()),
        ],
      ),
    );
  }
}
