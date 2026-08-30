import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import 'shared_session_bootstrap.dart';
import 'shared_session_controller.dart';
import 'shared_session_page.dart';
import 'supervised_shared_session_runtime.dart';
import 'device_admin_client.dart';
import 'device_authorization_panel.dart';
import 'pc_file_scope_panel.dart';
import 'memory_center_controller.dart';

final class WindowsC3Workspace {
  const WindowsC3Workspace({
    required this.ready,
    required this.memoryController,
    required this.authorizationController,
    required this.fileScopeController,
  });

  final SupervisedSessionReady ready;
  final MemoryCenterController memoryController;
  final DeviceAuthorizationController authorizationController;
  final PcFileScopeController fileScopeController;
}

final class WindowsC3Bootstrap extends StatefulWidget {
  const WindowsC3Bootstrap({
    super.key,
    this.onReady,
    this.onWorkspaceReady,
    this.showManagement = true,
    this.initialDraft,
    this.initialDraftRevision = 0,
    this.onInitialDraftConsumed,
  });

  final ValueChanged<SupervisedSessionReady>? onReady;
  final ValueChanged<WindowsC3Workspace>? onWorkspaceReady;
  final bool showManagement;
  final String? initialDraft;
  final int initialDraftRevision;
  final ValueChanged<int>? onInitialDraftConsumed;

  @override
  State<WindowsC3Bootstrap> createState() => _WindowsC3BootstrapState();
}

final class _WindowsC3BootstrapState extends State<WindowsC3Bootstrap> {
  SupervisedSharedSessionRuntime? _runtime;
  SharedSessionController? _controller;
  SupervisedSessionReady? _ready;
  DeviceAuthorizationController? _authorizationController;
  PcFileScopeController? _fileScopeController;
  String? _error;

  @override
  void initState() {
    super.initState();
    unawaited(_start());
  }

  Future<void> _start() async {
    final environment = SupervisedSessionEnvironment.fromEnvironment(
      Platform.environment,
    );
    if (environment == null) {
      setState(() => _error = 'C3 Demo 尚未通过受控启动脚本配置。');
      return;
    }
    final runtime = SupervisedSharedSessionRuntime(environment: environment);
    _runtime = runtime;
    try {
      final ready = await runtime.start();
      final controller = await createSharedSessionController(
        config: DemoHubConfig(ready.localUrl.port),
      );
      final authorizationController = DeviceAuthorizationController(
        api: DeviceAdminClient(
          baseUri: ready.localUrl,
          operatorToken: ready.operatorToken,
        ),
      );
      final fileScopeController = PcFileScopeController(
        api: PcFileScopeClient(
          baseUri: ready.localUrl,
          operatorToken: ready.operatorToken,
        ),
      );
      await Future.wait([
        authorizationController.load(),
        fileScopeController.load(),
      ]);
      if (!mounted) {
        controller.dispose();
        authorizationController.dispose();
        fileScopeController.dispose();
        await runtime.stop();
        return;
      }
      setState(() {
        _ready = ready;
        _controller = controller;
        _authorizationController = authorizationController;
        _fileScopeController = fileScopeController;
      });
      widget.onReady?.call(ready);
      widget.onWorkspaceReady?.call(
        WindowsC3Workspace(
          ready: ready,
          memoryController: controller,
          authorizationController: authorizationController,
          fileScopeController: fileScopeController,
        ),
      );
      unawaited(controller.start());
    } on Object {
      await runtime.stop();
      if (mounted) setState(() => _error = 'C3 安全会话服务启动失败。');
    }
  }

  @override
  void dispose() {
    _controller?.dispose();
    _authorizationController?.dispose();
    _fileScopeController?.dispose();
    unawaited(_runtime?.stop());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = _controller;
    final ready = _ready;
    if (controller != null && ready != null) {
      return SharedSessionPage(
        controller: controller,
        serviceDescriptorJson: widget.showManagement
            ? ready.serviceDescriptorJson
            : null,
        deviceAuthorizationController: widget.showManagement
            ? _authorizationController
            : null,
        pcFileScopeController: widget.showManagement
            ? _fileScopeController
            : null,
        agentMode: ready.agentMode,
        initialDraft: widget.initialDraft,
        initialDraftRevision: widget.initialDraftRevision,
        onInitialDraftConsumed: widget.onInitialDraftConsumed,
      );
    }
    return Scaffold(
      appBar: AppBar(title: const Text('Data Steward')),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: _error == null
              ? const Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    CircularProgressIndicator(),
                    SizedBox(height: 16),
                    Text('正在启动认证共享会话服务…'),
                  ],
                )
              : Text(_error!, key: const Key('c3-runtime-error')),
        ),
      ),
    );
  }
}
