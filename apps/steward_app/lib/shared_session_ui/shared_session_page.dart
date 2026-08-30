import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../app_ui/steward_theme.dart';
import '../shared_session/protocol_models.dart';
import 'shared_session_bootstrap.dart';
import 'shared_session_controller.dart';
import 'device_authorization_panel.dart';
import 'pc_file_scope_panel.dart';

final class WindowsSharedSessionBootstrap extends StatefulWidget {
  const WindowsSharedSessionBootstrap({
    super.key,
    this.controllerFactory = createDefaultSharedSessionController,
  });

  final SharedSessionControllerFactory controllerFactory;

  @override
  State<WindowsSharedSessionBootstrap> createState() =>
      _WindowsSharedSessionBootstrapState();
}

final class _WindowsSharedSessionBootstrapState
    extends State<WindowsSharedSessionBootstrap> {
  SharedSessionController? _controller;
  bool _busy = false;
  String? _safeError;
  int _generation = 0;

  @override
  void initState() {
    super.initState();
    _create();
  }

  Future<void> _create() async {
    if (_busy) return;
    final generation = ++_generation;
    setState(() {
      _busy = true;
      _safeError = null;
    });
    SharedSessionController? controller;
    try {
      controller = await widget.controllerFactory();
      if (!mounted || generation != _generation) {
        controller.dispose();
        return;
      }
      setState(() {
        _controller = controller;
        _busy = false;
      });
      unawaited(controller.start());
    } on Object {
      controller?.dispose();
      if (!mounted || generation != _generation) return;
      setState(() {
        _busy = false;
        _safeError = '应用私有状态初始化失败，未显示底层路径或异常。';
      });
    }
  }

  @override
  void dispose() {
    _generation += 1;
    _controller?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = _controller;
    if (controller == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Data Steward')),
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 480),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (_busy) ...[
                    const CircularProgressIndicator(),
                    const SizedBox(height: 16),
                    const Text('正在初始化应用私有同步状态…'),
                  ] else ...[
                    const Icon(Icons.shield_outlined, size: 48),
                    const SizedBox(height: 16),
                    Text(
                      '本地初始化失败',
                      style: Theme.of(context).textTheme.headlineSmall,
                    ),
                    const SizedBox(height: 8),
                    Text(_safeError ?? '应用私有状态尚未初始化。'),
                    const SizedBox(height: 16),
                    FilledButton(
                      key: const Key('bootstrap-retry-button'),
                      onPressed: _create,
                      child: const Text('重试初始化'),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      );
    }
    return SharedSessionPage(controller: controller);
  }
}

final class SharedSessionPage extends StatefulWidget {
  const SharedSessionPage({
    required this.controller,
    this.serviceDescriptorJson,
    this.deviceAuthorizationController,
    this.pcFileScopeController,
    this.agentMode,
    this.onRetryConnection,
    this.onReturnToServiceScanner,
    this.initialDraft,
    this.initialDraftRevision = 0,
    this.onInitialDraftConsumed,
    super.key,
  });

  final SharedSessionController controller;
  final String? serviceDescriptorJson;
  final DeviceAuthorizationController? deviceAuthorizationController;
  final PcFileScopeController? pcFileScopeController;
  final String? agentMode;
  final Future<void> Function()? onRetryConnection;
  final Future<void> Function()? onReturnToServiceScanner;
  final String? initialDraft;
  final int initialDraftRevision;
  final ValueChanged<int>? onInitialDraftConsumed;

  @override
  State<SharedSessionPage> createState() => _SharedSessionPageState();
}

final class _SharedSessionPageState extends State<SharedSessionPage> {
  final TextEditingController _message = TextEditingController();
  final ScrollController _timeline = ScrollController();
  var _observedEventCount = 0;
  final Map<String, List<ProductAction>> _actions = {};
  final Set<String> _loadingActions = {};
  MemoryCenterSnapshot? _memory;
  bool _memoryLoading = false;

  @override
  void initState() {
    super.initState();
    _observedEventCount = widget.controller.events.length;
    widget.controller.addListener(_changed);
    _applyInitialDraft();
    _loadVisibleActions();
    _loadMemory();
  }

  @override
  void didUpdateWidget(SharedSessionPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.controller != widget.controller) {
      oldWidget.controller.removeListener(_changed);
      widget.controller.addListener(_changed);
      _observedEventCount = widget.controller.events.length;
      _actions.clear();
      _loadingActions.clear();
      _loadVisibleActions();
      _loadMemory();
    }
    if (oldWidget.initialDraftRevision != widget.initialDraftRevision) {
      _applyInitialDraft();
    }
  }

  void _applyInitialDraft() {
    final value = widget.initialDraft?.trim();
    if (value == null || value.isEmpty) return;
    _message
      ..text = value
      ..selection = TextSelection.collapsed(offset: value.length);
    final consumedRevision = widget.initialDraftRevision;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && widget.initialDraftRevision == consumedRevision) {
        widget.onInitialDraftConsumed?.call(consumedRevision);
      }
    });
  }

  @override
  void dispose() {
    widget.controller.removeListener(_changed);
    _message.dispose();
    _timeline.dispose();
    super.dispose();
  }

  void _changed() {
    if (!mounted) return;
    final shouldScroll = widget.controller.events.length != _observedEventCount;
    _observedEventCount = widget.controller.events.length;
    setState(() {});
    _loadVisibleActions();
    if (widget.controller.state == SharedSessionViewState.ready) _loadMemory();
    if (shouldScroll) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _scrollToEnd());
    }
  }

  void _loadVisibleActions() {
    for (final event in widget.controller.events) {
      if (event.payload.role == 'user') continue;
      final messageId = event.payload.messageId;
      if (_actions.containsKey(messageId) ||
          _loadingActions.contains(messageId)) {
        continue;
      }
      _loadingActions.add(messageId);
      unawaited(_loadActions(messageId));
    }
  }

  Future<void> _loadActions(String messageId, {bool refresh = false}) async {
    if (refresh) _loadingActions.add(messageId);
    final values = await widget.controller.actionsFor(messageId);
    if (!mounted) return;
    setState(() {
      _actions[messageId] = values;
      _loadingActions.remove(messageId);
    });
  }

  Future<void> _loadMemory() async {
    if (_memoryLoading) return;
    _memoryLoading = true;
    final value = await widget.controller.memoryCenter();
    if (!mounted) return;
    setState(() {
      _memory = value;
      _memoryLoading = false;
    });
  }

  Future<void> _executeAction(ProductAction action) async {
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
      final execution = await widget.controller.executeAction(action);
      if (!mounted) return;
      setState(() {
        _actions[execution.event.payload.messageId] = List.unmodifiable(
          execution.actions,
        );
        _loadingActions.remove(execution.event.payload.messageId);
      });
      await _loadActions(action.assistantMessageId, refresh: true);
      await _loadMemory();
    } on Object {
      // Controller exposes only a sanitized error.
    }
  }

  void _scrollToEnd() {
    if (!_timeline.hasClients) return;
    final reduceMotion =
        MediaQuery.maybeOf(context)?.disableAnimations ?? false;
    if (reduceMotion) {
      _timeline.jumpTo(_timeline.position.maxScrollExtent);
    } else {
      _timeline.animateTo(
        _timeline.position.maxScrollExtent,
        duration: const Duration(milliseconds: 220),
        curve: Curves.easeOutCubic,
      );
    }
  }

  void _useExample(String value) {
    _message
      ..text = value
      ..selection = TextSelection.collapsed(offset: value.length);
  }

  Future<void> _send() async {
    final content = _message.text;
    try {
      await widget.controller.send(content);
      if (widget.controller.pendingContent == null) _message.clear();
    } on Object {
      // Controller exposes only a sanitized visible error.
    }
  }

  KeyEventResult _handleComposerKeyEvent(
    SharedSessionController controller,
    KeyEvent event,
  ) {
    if (event is! KeyDownEvent ||
        (event.logicalKey != LogicalKeyboardKey.enter &&
            event.logicalKey != LogicalKeyboardKey.numpadEnter)) {
      return KeyEventResult.ignored;
    }
    if (HardwareKeyboard.instance.isShiftPressed) {
      return KeyEventResult.ignored;
    }
    final composing = _message.value.composing;
    if (composing.isValid && !composing.isCollapsed) {
      return KeyEventResult.ignored;
    }
    if (controller.canSend && _message.text.trim().isNotEmpty) {
      unawaited(_send());
    }
    return KeyEventResult.handled;
  }

  Future<void> _confirmReset() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('重置应用私有同步游标？'),
        content: const Text(
          '此操作只删除当前会话的应用私有同步游标，不删除 Hub 会话或消息。'
          '重启 Demo 后将从 Hub 重新验证完整投影。',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('确认重置'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await widget.controller.resetCursor();
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('同步游标已重置，请重新启动 Demo。')));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final controller = widget.controller;
    final colorScheme = Theme.of(context).colorScheme;
    final stateTone = _stateTone(controller.state);
    final hasManagement =
        widget.serviceDescriptorJson != null ||
        widget.deviceAuthorizationController != null ||
        widget.pcFileScopeController != null;
    return Scaffold(
      appBar: AppBar(
        title: const Text('智能会话'),
        actions: [
          if (widget.agentMode != null)
            Padding(
              padding: const EdgeInsets.only(right: 4),
              child: Center(
                child: StewardStatusPill(
                  label: widget.agentMode == 'hermes'
                      ? 'Hermes 智能规划'
                      : '本地可靠模式',
                  tone: widget.agentMode == 'hermes'
                      ? StewardStatusTone.positive
                      : StewardStatusTone.neutral,
                ),
              ),
            ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Center(
              child: StewardStatusPill(
                label: _stateLabel(controller.state),
                tone: stateTone,
              ),
            ),
          ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 4, 16, 8),
              child: Card(
                child: Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 16,
                    vertical: 12,
                  ),
                  child: Row(
                    children: [
                      Icon(
                        stateTone == StewardStatusTone.positive
                            ? Icons.lock_outline
                            : Icons.sync_problem_outlined,
                        color: colorScheme.primary,
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          '连接状态：${_stateLabel(controller.state)}',
                          key: const Key('connection-status'),
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                      ),
                      Tooltip(
                        message: '已安全同步 ${controller.lastConversationSeq} 条事件',
                        child: Text('#${controller.lastConversationSeq}'),
                      ),
                    ],
                  ),
                ),
              ),
            ),
            if (controller.safeError != null ||
                (_canRetrySameEndpoint(controller.state) &&
                    widget.onRetryConnection != null))
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: MaterialBanner(
                  content: Text(
                    controller.safeError ?? '网络连接已中断。请等待网络稳定后再手动重连一次。',
                  ),
                  leading: Icon(
                    Icons.shield_outlined,
                    color: colorScheme.error,
                  ),
                  actions: _recoveryActions(controller),
                ),
              ),
            Expanded(
              child: ListView(
                key: const Key('message-timeline'),
                controller: _timeline,
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 20),
                children: [
                  if (hasManagement) ...[
                    _managementCard(),
                    const SizedBox(height: 16),
                  ],
                  if (_memory case final MemoryCenterSnapshot memory) ...[
                    _MemoryCenterCard(
                      memory: memory,
                      busy: widget.controller.actionBusy,
                      onAction: _executeAction,
                    ),
                    const SizedBox(height: 12),
                  ],
                  if (controller.events.isEmpty)
                    _EmptyConversation(onExample: _useExample)
                  else
                    for (
                      var index = 0;
                      index < controller.events.length;
                      index++
                    )
                      _eventBubble(
                        controller.events[index],
                        grouped:
                            index > 0 &&
                            controller.events[index - 1].actorDeviceId ==
                                controller.events[index].actorDeviceId &&
                            controller.events[index - 1].payload.role ==
                                controller.events[index].payload.role,
                      ),
                ],
              ),
            ),
            _composer(controller),
          ],
        ),
      ),
    );
  }

  List<Widget> _recoveryActions(SharedSessionController controller) => [
    if (_canRetrySameEndpoint(controller.state) &&
        widget.onRetryConnection != null)
      TextButton.icon(
        key: const Key('s4-retry-established-session'),
        onPressed: widget.onRetryConnection,
        icon: const Icon(Icons.wifi_find),
        label: const Text('网络稳定后重连'),
      ),
    if (_canReturnToServiceScanner(controller.state) &&
        widget.onReturnToServiceScanner != null &&
        (!_canRetrySameEndpoint(controller.state) ||
            widget.onRetryConnection == null))
      TextButton(
        key: const Key('c3-return-to-service-scanner'),
        onPressed: widget.onReturnToServiceScanner,
        child: Text(
          controller.state == SharedSessionViewState.authorizationChanged
              ? '重新安全配对'
              : '更新电脑地址',
        ),
      ),
    if (controller.state == SharedSessionViewState.cursorAhead ||
        controller.state == SharedSessionViewState.localStateCorrupt)
      TextButton(onPressed: _confirmReset, child: const Text('重置同步游标')),
    if (!_hasRecoveryAction(controller.state, widget))
      TextButton(onPressed: () {}, child: const Text('了解')),
  ];

  Widget _managementCard() => Card(
    child: ExpansionTile(
      leading: const Icon(Icons.tune_outlined),
      title: const Text('连接与权限'),
      subtitle: const Text('日常无需操作；仅在连接新设备或调整授权时展开'),
      childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
      children: [
        if (widget.serviceDescriptorJson case final String payload)
          Wrap(
            spacing: 20,
            runSpacing: 12,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              QrImageView(
                key: const Key('c3-service-qr'),
                data: payload,
                size: 140,
                backgroundColor: Colors.white,
              ),
              const SizedBox(
                width: 340,
                child: Text('仅当已配对手机无法找到电脑的新地址时扫描。服务码不包含设备凭据。'),
              ),
            ],
          ),
        if (widget.deviceAuthorizationController
            case final DeviceAuthorizationController admin) ...[
          const SizedBox(height: 12),
          DeviceAuthorizationPanel(controller: admin),
        ],
        if (widget.pcFileScopeController
            case final PcFileScopeController scope) ...[
          const SizedBox(height: 12),
          PcFileScopePanel(controller: scope),
        ],
      ],
    ),
  );

  Widget _composer(SharedSessionController controller) => SafeArea(
    top: false,
    child: Container(
      padding: const EdgeInsets.fromLTRB(16, 10, 16, 12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        border: Border(
          top: BorderSide(color: Theme.of(context).colorScheme.outlineVariant),
        ),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          Expanded(
            child: Focus(
              onKeyEvent: (_, event) =>
                  _handleComposerKeyEvent(controller, event),
              child: TextField(
                key: const Key('message-input'),
                controller: _message,
                maxLength: 2000,
                minLines: 1,
                maxLines: 4,
                textInputAction: TextInputAction.newline,
                decoration: InputDecoration(
                  hintText: controller.canSend ? '告诉管家你想查找或整理什么…' : '连接成功后即可发送',
                  counterText: '',
                ),
              ),
            ),
          ),
          const SizedBox(width: 10),
          if (controller.canRetry)
            IconButton.filledTonal(
              tooltip: '重试上一条消息',
              onPressed: () async {
                try {
                  await controller.retryPending();
                } on Object {
                  // Sanitized state is already visible.
                }
              },
              icon: const Icon(Icons.refresh),
            ),
          IconButton.filled(
            key: const Key('send-button'),
            tooltip: controller.pendingContent == null
                ? '发送消息'
                : controller.busy
                ? '正在等待确认'
                : '消息可重试',
            onPressed: controller.canSend ? _send : null,
            icon: controller.busy
                ? const SizedBox.square(
                    dimension: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.arrow_upward),
          ),
        ],
      ),
    ),
  );

  Widget _eventBubble(WireEvent event, {required bool grouped}) {
    final user = event.payload.role == 'user';
    final agent = !user;
    final scheme = Theme.of(context).colorScheme;
    final bubbleColor = user
        ? scheme.primaryContainer
        : scheme.surfaceContainerHigh;
    final foreground = user ? scheme.onPrimaryContainer : scheme.onSurface;
    return Padding(
      padding: EdgeInsets.only(top: grouped ? 4 : 14),
      child: Align(
        alignment: user ? Alignment.centerRight : Alignment.centerLeft,
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 680),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.end,
            textDirection: user ? TextDirection.rtl : TextDirection.ltr,
            children: [
              if (!grouped)
                CircleAvatar(
                  radius: 17,
                  backgroundColor: agent
                      ? scheme.tertiaryContainer
                      : scheme.primary,
                  foregroundColor: agent
                      ? scheme.onTertiaryContainer
                      : scheme.onPrimary,
                  child: Icon(
                    agent
                        ? _sourceIcon(event.actorDeviceId)
                        : Icons.person_outline,
                    size: 18,
                  ),
                )
              else
                const SizedBox(width: 34),
              const SizedBox(width: 8),
              Flexible(
                child: Container(
                  padding: const EdgeInsets.fromLTRB(14, 11, 14, 8),
                  decoration: BoxDecoration(
                    color: bubbleColor,
                    borderRadius: BorderRadius.only(
                      topLeft: const Radius.circular(18),
                      topRight: const Radius.circular(18),
                      bottomLeft: Radius.circular(user ? 18 : 6),
                      bottomRight: Radius.circular(user ? 6 : 18),
                    ),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      if (!grouped)
                        Padding(
                          padding: const EdgeInsets.only(bottom: 5),
                          child: Text(
                            user ? '你' : _sourceLabel(event.actorDeviceId),
                            style: Theme.of(context).textTheme.labelLarge
                                ?.copyWith(
                                  color: foreground.withValues(alpha: .78),
                                  fontWeight: FontWeight.w700,
                                ),
                          ),
                        ),
                      SelectableText(
                        event.payload.content,
                        style: Theme.of(
                          context,
                        ).textTheme.bodyLarge?.copyWith(color: foreground),
                      ),
                      if (_actions[event.payload.messageId]
                          case final List<ProductAction> actions
                          when actions.isNotEmpty) ...[
                        const SizedBox(height: 10),
                        _ProductActionCard(
                          actions: actions,
                          busy: widget.controller.actionBusy,
                          onAction: _executeAction,
                        ),
                      ],
                      Material(
                        color: Colors.transparent,
                        child: Theme(
                          data: Theme.of(
                            context,
                          ).copyWith(dividerColor: Colors.transparent),
                          child: ExpansionTile(
                            tilePadding: EdgeInsets.zero,
                            childrenPadding: EdgeInsets.zero,
                            minTileHeight: 40,
                            title: Text(
                              '查看消息详情',
                              style: Theme.of(context).textTheme.labelMedium
                                  ?.copyWith(
                                    color: foreground.withValues(alpha: .7),
                                  ),
                            ),
                            children: [
                              Align(
                                alignment: Alignment.centerLeft,
                                child: Text(
                                  '来源：${_sourceLabel(event.actorDeviceId)} · '
                                  '角色：${event.payload.role} · '
                                  '序号：${event.conversationSeq}',
                                  style: Theme.of(context).textTheme.bodySmall
                                      ?.copyWith(
                                        color: foreground.withValues(
                                          alpha: .72,
                                        ),
                                      ),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _MemoryCenterCard extends StatelessWidget {
  const _MemoryCenterCard({
    required this.memory,
    required this.busy,
    required this.onAction,
  });

  final MemoryCenterSnapshot memory;
  final bool busy;
  final ValueChanged<ProductAction> onAction;

  @override
  Widget build(BuildContext context) => Card(
    key: const Key('memory-center-card'),
    child: ExpansionTile(
      leading: const Icon(Icons.psychology_alt_outlined),
      title: const Text('整理偏好'),
      subtitle: Text(_memorySummary(memory)),
      childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
      children: [
        LinearProgressIndicator(
          value: memory.activationThreshold == 0
              ? 0
              : (memory.supportCount / memory.activationThreshold)
                    .clamp(0, 1)
                    .toDouble(),
        ),
        const SizedBox(height: 10),
        Text(_memoryDescription(memory)),
        if (memory.actions.isNotEmpty) ...[
          const SizedBox(height: 12),
          _ProductActionCard(
            actions: memory.actions,
            busy: busy,
            onAction: onAction,
          ),
        ],
      ],
    ),
  );
}

String _memorySummary(MemoryCenterSnapshot memory) => switch (memory.status) {
  'active' => '已启用，会在合适时主动参考',
  'candidate' => '已形成候选，等待你的确认',
  'learning' => '正在学习 ${memory.supportCount}/${memory.activationThreshold}',
  'forgotten' => '已停用',
  _ => '尚未形成整理偏好',
};

String _memoryDescription(MemoryCenterSnapshot memory) =>
    switch (memory.status) {
      'active' => '管家只会使用你明确批准的偏好；任何文件移动仍需单独确认。',
      'candidate' => '已有足够的独立选择，可以决定是否跨会话启用。',
      'learning' => '继续通过建议卡作出选择，系统会逐步形成候选偏好。',
      'forgotten' => '后续会话不会再调用，可由你重新启用。',
      _ => '你接受归档建议后，学习进度会显示在这里。',
    };

class _ProductActionCard extends StatelessWidget {
  const _ProductActionCard({
    required this.actions,
    required this.busy,
    required this.onAction,
  });

  final List<ProductAction> actions;
  final bool busy;
  final ValueChanged<ProductAction> onAction;

  @override
  Widget build(BuildContext context) => Container(
    key: const Key('product-action-card'),
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(
      color: Theme.of(context).colorScheme.surfaceContainerLowest,
      borderRadius: BorderRadius.circular(14),
      border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('下一步', style: Theme.of(context).textTheme.labelLarge),
        const SizedBox(height: 8),
        for (final action in actions) ...[
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(action.label),
                    Text(
                      action.description,
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              if (action.status == 'completed')
                const Chip(label: Text('已完成'))
              else
                FilledButton.tonal(
                  key: Key('product-action-${action.kind}'),
                  onPressed: busy ? null : () => onAction(action),
                  child: Text(action.label),
                ),
            ],
          ),
          if (action != actions.last) const Divider(height: 18),
        ],
      ],
    ),
  );
}

class _EmptyConversation extends StatelessWidget {
  const _EmptyConversation({required this.onExample});

  final ValueChanged<String> onExample;

  @override
  Widget build(BuildContext context) => Center(
    child: ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 620),
      child: Card(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              Icon(
                Icons.auto_awesome_outlined,
                size: 42,
                color: Theme.of(context).colorScheme.primary,
              ),
              const SizedBox(height: 12),
              Text('从一个安全任务开始', style: Theme.of(context).textTheme.titleLarge),
              const SizedBox(height: 6),
              const Text('管家只会在已授权范围内执行，归档类操作会先给出建议。'),
              const SizedBox(height: 16),
              Wrap(
                alignment: WrapAlignment.center,
                spacing: 8,
                runSpacing: 8,
                children: [
                  ActionChip(
                    label: const Text('看下电脑有几个图片文件'),
                    onPressed: () => onExample('看下电脑授权目录有几个图片文件'),
                  ),
                  ActionChip(
                    label: const Text('帮我找训练营文件'),
                    onPressed: () => onExample('帮我找文件名包含“训练营”的文件'),
                  ),
                  ActionChip(
                    label: const Text('给出智能归档建议'),
                    onPressed: () => onExample('根据当前文件给出智能归档建议'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    ),
  );
}

String _stateLabel(SharedSessionViewState state) => switch (state) {
  SharedSessionViewState.unconfigured => '未配置',
  SharedSessionViewState.connecting => '连接中',
  SharedSessionViewState.replaying => '回放中',
  SharedSessionViewState.ready => '已连接',
  SharedSessionViewState.reconnecting => '重连中',
  SharedSessionViewState.offline => 'Hub 离线',
  SharedSessionViewState.protocolError => '协议错误',
  SharedSessionViewState.authorizationChanged => '授权已变更',
  SharedSessionViewState.localStateCorrupt => '本地状态损坏',
  SharedSessionViewState.cursorAhead => '同步状态需修复',
  SharedSessionViewState.closed => 'Hub 离线',
};

StewardStatusTone _stateTone(SharedSessionViewState state) => switch (state) {
  SharedSessionViewState.ready => StewardStatusTone.positive,
  SharedSessionViewState.connecting ||
  SharedSessionViewState.replaying ||
  SharedSessionViewState.reconnecting => StewardStatusTone.neutral,
  SharedSessionViewState.offline ||
  SharedSessionViewState.closed ||
  SharedSessionViewState.unconfigured => StewardStatusTone.warning,
  _ => StewardStatusTone.danger,
};

bool _canReturnToServiceScanner(SharedSessionViewState state) =>
    switch (state) {
      SharedSessionViewState.authorizationChanged ||
      SharedSessionViewState.offline ||
      SharedSessionViewState.protocolError ||
      SharedSessionViewState.closed => true,
      _ => false,
    };

bool _canRetrySameEndpoint(SharedSessionViewState state) =>
    state == SharedSessionViewState.offline ||
    state == SharedSessionViewState.closed;

bool _hasRecoveryAction(SharedSessionViewState state, SharedSessionPage page) =>
    (_canRetrySameEndpoint(state) && page.onRetryConnection != null) ||
    (_canReturnToServiceScanner(state) &&
        page.onReturnToServiceScanner != null) ||
    state == SharedSessionViewState.cursorAhead ||
    state == SharedSessionViewState.localStateCorrupt;

String _sourceLabel(String actor) => switch (actor) {
  'windows-demo' => 'Windows',
  'windows-pc-executor' => '电脑执行器',
  'phone-sim' => '手机',
  'pad-sim' => 'Pad',
  _ => '已认证设备',
};

IconData _sourceIcon(String actor) => switch (actor) {
  'windows-pc-executor' => Icons.computer_outlined,
  'windows-demo' => Icons.desktop_windows_outlined,
  'phone-sim' => Icons.smartphone_outlined,
  'pad-sim' => Icons.tablet_mac_outlined,
  _ => Icons.auto_awesome_outlined,
};
