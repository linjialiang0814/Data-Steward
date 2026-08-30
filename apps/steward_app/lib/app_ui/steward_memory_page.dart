import 'dart:async';

import 'package:flutter/material.dart';

import '../shared_session/protocol_models.dart';
import '../shared_session_ui/memory_center_controller.dart';

final class StewardMemoryPage extends StatefulWidget {
  const StewardMemoryPage({
    required this.controller,
    required this.onOpenSession,
    this.initialSnapshot,
    this.snapshotIdentityKey,
    this.onSnapshotChanged,
    super.key,
  });

  final MemoryCenterController? controller;
  final VoidCallback onOpenSession;
  final MemoryCenterSnapshot? initialSnapshot;
  final Object? snapshotIdentityKey;
  final ValueChanged<MemoryCenterSnapshot>? onSnapshotChanged;

  @override
  State<StewardMemoryPage> createState() => _StewardMemoryPageState();
}

final class _StewardMemoryPageState extends State<StewardMemoryPage> {
  MemoryCenterSnapshot? _snapshot;
  bool _loading = false;
  bool _loadFailed = false;

  @override
  void initState() {
    super.initState();
    _snapshot = widget.initialSnapshot;
    _attach(widget.controller);
  }

  @override
  void didUpdateWidget(covariant StewardMemoryPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    final identityChanged =
        oldWidget.snapshotIdentityKey != widget.snapshotIdentityKey;
    if (identityChanged) {
      _snapshot = widget.initialSnapshot;
      _loadFailed = false;
    } else if (!identical(oldWidget.initialSnapshot, widget.initialSnapshot) &&
        widget.initialSnapshot != null) {
      _snapshot = widget.initialSnapshot;
    }
    if (identical(oldWidget.controller, widget.controller)) return;
    _detach(oldWidget.controller);
    _loadFailed = false;
    _attach(widget.controller);
  }

  void _attach(MemoryCenterController? controller) {
    controller?.addListener(_controllerChanged);
    if (controller?.canLoadMemory ?? false) unawaited(_refresh());
  }

  void _detach(MemoryCenterController? controller) {
    controller?.removeListener(_controllerChanged);
  }

  void _controllerChanged() {
    if (!mounted) return;
    setState(() {});
    final controller = widget.controller;
    if ((controller?.canLoadMemory ?? false) &&
        !(controller?.actionBusy ?? false)) {
      unawaited(_refresh());
    }
  }

  Future<void> _refresh() async {
    final controller = widget.controller;
    final identityKey = widget.snapshotIdentityKey;
    if (controller == null || !controller.canLoadMemory || _loading) return;
    setState(() {
      _loading = true;
      _loadFailed = false;
    });
    final value = await controller.memoryCenter();
    if (!mounted) return;
    if (!identical(controller, widget.controller) ||
        identityKey != widget.snapshotIdentityKey) {
      setState(() => _loading = false);
      if (widget.controller?.canLoadMemory ?? false) unawaited(_refresh());
      return;
    }
    setState(() {
      if (value != null) _snapshot = value;
      _loading = false;
      _loadFailed = value == null;
    });
    if (value != null) widget.onSnapshotChanged?.call(value);
  }

  Future<void> _execute(ProductAction action) async {
    final controller = widget.controller;
    if (controller == null || controller.actionBusy) return;
    if (action.requiresConfirmation) {
      final approved = await showDialog<bool>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text(action.label),
          content: Text(action.description),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('取消'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, true),
              child: const Text('确认'),
            ),
          ],
        ),
      );
      if (approved != true) return;
    }
    try {
      await controller.executeAction(action);
      await _refresh();
    } on Object {
      if (!mounted) return;
      setState(() => _loadFailed = true);
    }
  }

  @override
  void dispose() {
    _detach(widget.controller);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: const Text('记忆'),
      actions: [
        IconButton(
          key: const Key('memory-page-refresh'),
          onPressed: widget.controller?.canLoadMemory == true && !_loading
              ? _refresh
              : null,
          tooltip: '刷新记忆状态',
          icon: const Icon(Icons.refresh),
        ),
      ],
    ),
    body: _body(context),
  );

  Widget _body(BuildContext context) {
    final controller = widget.controller;
    if (controller == null || !controller.canLoadMemory) {
      final cached = _snapshot;
      if (cached != null) {
        return Column(
          children: [
            MaterialBanner(
              key: const Key('memory-page-offline-cache'),
              content: const Text('已显示最近一次安全同步的记忆。连接电脑后可刷新；离线时不会执行记忆操作。'),
              actions: [
                TextButton(
                  onPressed: widget.onOpenSession,
                  child: const Text('前往共享会话'),
                ),
              ],
            ),
            Expanded(
              child: _MemorySnapshotView(
                snapshot: cached,
                busy: true,
                onAction: _execute,
                onOpenSession: widget.onOpenSession,
              ),
            ),
          ],
        );
      }
      return _MemoryEmptyState(
        icon: Icons.cloud_off_outlined,
        title: '记忆服务尚未就绪',
        description: '连接共享会话后，这里会显示同一份实时整理偏好。',
        actionLabel: '前往共享会话',
        onAction: widget.onOpenSession,
      );
    }
    if (_snapshot == null && _loading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_snapshot == null) {
      return _MemoryEmptyState(
        icon: Icons.sync_problem_outlined,
        title: '记忆状态暂时不可用',
        description: '等待网络稳定后手动刷新一次，系统不会反复重试。',
        actionLabel: '刷新一次',
        onAction: _refresh,
      );
    }
    if (_loadFailed) {
      return Column(
        children: [
          MaterialBanner(
            key: const Key('memory-page-stale-cache'),
            content: const Text('本次刷新未完成，已保留最近一次安全同步的记忆；恢复连接前不会执行记忆操作。'),
            actions: [
              TextButton(onPressed: _refresh, child: const Text('刷新一次')),
            ],
          ),
          Expanded(
            child: _MemorySnapshotView(
              snapshot: _snapshot!,
              busy: true,
              onAction: _execute,
              onOpenSession: widget.onOpenSession,
            ),
          ),
        ],
      );
    }
    return _MemorySnapshotView(
      snapshot: _snapshot!,
      busy: controller.actionBusy,
      onAction: _execute,
      onOpenSession: widget.onOpenSession,
    );
  }
}

final class _MemorySnapshotView extends StatelessWidget {
  const _MemorySnapshotView({
    required this.snapshot,
    required this.busy,
    required this.onAction,
    required this.onOpenSession,
  });

  final MemoryCenterSnapshot snapshot;
  final bool busy;
  final ValueChanged<ProductAction> onAction;
  final VoidCallback onOpenSession;

  @override
  Widget build(BuildContext context) {
    final status = switch (snapshot.status) {
      'learning' => ('正在学习', Icons.school_outlined),
      'candidate' => ('等待你启用', Icons.lightbulb_outline),
      'active' => ('已启用', Icons.verified_outlined),
      'forgotten' => ('已停用', Icons.pause_circle_outline),
      _ => ('尚未形成偏好', Icons.psychology_alt_outlined),
    };
    final description = switch (snapshot.status) {
      'learning' => '继续通过建议卡明确做出选择，系统才会累积学习。',
      'candidate' => '你已多次选择同一种整理方式，是否跨会话启用仍由你决定。',
      'active' => '管家可在后续会话中主动参考这项偏好，但移动文件仍需单独确认。',
      'forgotten' => '这项偏好不会再被调用；三次学习证据仍保留，你可以随时重新启用。',
      _ => '当你接受归档建议后，学习进度会出现在这里。',
    };
    return ListView(
      padding: const EdgeInsets.all(24),
      children: [
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 720),
          child: Card(
            key: const Key('memory-page-snapshot'),
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(status.$2, size: 32),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              '默认工作区·按类型整理',
                              style: Theme.of(context).textTheme.titleLarge,
                            ),
                            Text(status.$1),
                          ],
                        ),
                      ),
                      if (snapshot.version case final int version)
                        Chip(label: Text('v$version')),
                    ],
                  ),
                  const SizedBox(height: 20),
                  LinearProgressIndicator(
                    value:
                        (snapshot.supportCount / snapshot.activationThreshold)
                            .clamp(0, 1)
                            .toDouble(),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    '学习进度 ${snapshot.supportCount}/${snapshot.activationThreshold}',
                    key: const Key('memory-page-progress'),
                  ),
                  const SizedBox(height: 16),
                  Text(description),
                  if (snapshot.actions.isNotEmpty) ...[
                    const SizedBox(height: 20),
                    for (final action in snapshot.actions)
                      Padding(
                        padding: const EdgeInsets.only(bottom: 8),
                        child: FilledButton.tonalIcon(
                          key: Key('memory-page-action-${action.kind}'),
                          onPressed: busy || action.status != 'available'
                              ? null
                              : () => onAction(action),
                          icon: Icon(
                            action.kind == 'memory_forget'
                                ? Icons.visibility_off_outlined
                                : Icons.check_circle_outline,
                          ),
                          label: Text(action.label),
                        ),
                      ),
                  ],
                ],
              ),
            ),
          ),
        ),
        const SizedBox(height: 16),
        Align(
          alignment: Alignment.centerLeft,
          child: TextButton.icon(
            onPressed: onOpenSession,
            icon: const Icon(Icons.forum_outlined),
            label: const Text('返回共享会话'),
          ),
        ),
      ],
    );
  }
}

final class _MemoryEmptyState extends StatelessWidget {
  const _MemoryEmptyState({
    required this.icon,
    required this.title,
    required this.description,
    required this.actionLabel,
    required this.onAction,
  });

  final IconData icon;
  final String title;
  final String description;
  final String actionLabel;
  final VoidCallback onAction;

  @override
  Widget build(BuildContext context) => Center(
    child: SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 560),
        child: Card(
          child: Padding(
            padding: const EdgeInsets.all(28),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(icon, size: 52),
                const SizedBox(height: 16),
                Text(title, style: Theme.of(context).textTheme.headlineSmall),
                const SizedBox(height: 10),
                Text(description, textAlign: TextAlign.center),
                const SizedBox(height: 20),
                FilledButton(onPressed: onAction, child: Text(actionLabel)),
              ],
            ),
          ),
        ),
      ),
    ),
  );
}
