import 'dart:async';

import 'package:flutter/material.dart';

import 'catalog_sync_client.dart';
import 'knowledge_export_client.dart';
import 'proactive_suggestion_client.dart';

typedef SuggestedOrganizationPreview =
    Future<ClusterOrganizationPreview> Function(String clusterId);
typedef SuggestedOrganizationExecute =
    Future<ClusterOrganizationReceipt> Function(
      ClusterOrganizationPreview preview,
    );

final class ProactiveSuggestionView extends StatefulWidget {
  const ProactiveSuggestionView({
    required this.client,
    required this.knowledgeClient,
    required this.active,
    required this.canObserve,
    required this.onPreviewOrganization,
    required this.onExecuteOrganization,
    super.key,
  });

  final ProactiveSuggestionClient? client;
  final KnowledgeExportClient? knowledgeClient;
  final bool active;
  final bool canObserve;
  final SuggestedOrganizationPreview? onPreviewOrganization;
  final SuggestedOrganizationExecute? onExecuteOrganization;

  @override
  State<ProactiveSuggestionView> createState() =>
      _ProactiveSuggestionViewState();
}

final class _ProactiveSuggestionViewState
    extends State<ProactiveSuggestionView> {
  ProactiveSuggestionSettings? _settings;
  List<ProactiveActionCard> _cards = const [];
  ProactiveActionCard? _selected;
  ClusterOrganizationPreview? _organizationPreview;
  KnowledgeExportPreview? _exportPreview;
  KnowledgeExportStatus? _exportStatus;
  String? _exportIdempotencyKey;
  Timer? _stabilityTimer;
  bool _busy = false;
  bool _automaticObservationUsed = false;
  String? _message;
  bool _messageIsError = false;

  @override
  void initState() {
    super.initState();
    unawaited(_load());
  }

  @override
  void didUpdateWidget(covariant ProactiveSuggestionView oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.client != widget.client) {
      _stabilityTimer?.cancel();
      _automaticObservationUsed = false;
      unawaited(_load());
    } else if (widget.active && !oldWidget.active) {
      _automaticObservationUsed = false;
      unawaited(_maybeObserveAutomatically());
    } else if (!widget.active && oldWidget.active) {
      _stabilityTimer?.cancel();
    }
  }

  @override
  void dispose() {
    _stabilityTimer?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    final client = widget.client;
    if (client == null) {
      if (mounted) {
        setState(() {
          _settings = null;
          _cards = const [];
        });
      }
      return;
    }
    try {
      final settings = await client.settings();
      final cards = await client.inbox();
      if (!mounted || client != widget.client) return;
      setState(() {
        _settings = settings;
        _cards = cards;
      });
      await _maybeObserveAutomatically();
    } on ProactiveSuggestionFailure catch (error) {
      _showError(error.code);
    }
  }

  Future<void> _maybeObserveAutomatically() async {
    if (!widget.active ||
        !widget.canObserve ||
        _settings?.enabled != true ||
        _automaticObservationUsed) {
      return;
    }
    _automaticObservationUsed = true;
    await _observe(scheduleStableFollowUp: true);
  }

  Future<void> _toggle(bool enabled) async {
    final client = widget.client;
    final current = _settings;
    if (_busy || client == null || current == null) return;
    setState(() => _busy = true);
    try {
      final value = await client.updateSettings(
        enabled: enabled,
        disabledCategories: current.disabledCategories,
      );
      if (!mounted) return;
      setState(() {
        _settings = value;
        _message = enabled
            ? '已开启。资料状态稳定后，Hermes 最多生成一条待确认建议。'
            : '主动建议已关闭；已有文件和操作状态不会改变。';
        _messageIsError = false;
        if (!enabled) _cards = const [];
      });
      _stabilityTimer?.cancel();
      if (enabled) {
        _automaticObservationUsed = false;
        await _maybeObserveAutomatically();
      }
    } on ProactiveSuggestionFailure catch (error) {
      _showError(error.code);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _observe({bool scheduleStableFollowUp = false}) async {
    final client = widget.client;
    if (_busy || client == null || _settings?.enabled != true) return;
    setState(() {
      _busy = true;
      _message = null;
      _messageIsError = false;
    });
    try {
      final result = await client.observe();
      if (!mounted) return;
      setState(() {
        _cards = result.suggestions;
        _message = _observationText(result.state);
        _messageIsError = result.state == 'unavailable';
      });
      if (result.state == 'stabilizing' && scheduleStableFollowUp) {
        _stabilityTimer?.cancel();
        _stabilityTimer = Timer(const Duration(seconds: 11), () {
          if (mounted && widget.active) {
            unawaited(_observe());
          }
        });
      }
    } on ProactiveSuggestionFailure catch (error) {
      _stabilityTimer?.cancel();
      _showError(error.code);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _dismiss(ProactiveActionCard card) async {
    final client = widget.client;
    if (_busy || client == null) return;
    setState(() => _busy = true);
    try {
      await client.dismiss(card.suggestionId);
      if (!mounted) return;
      setState(() {
        _cards = _cards
            .where((item) => item.suggestionId != card.suggestionId)
            .toList(growable: false);
        _message = '已忽略本次建议；没有执行任何操作。';
        _messageIsError = false;
      });
    } on ProactiveSuggestionFailure catch (error) {
      _showError(error.code);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _disableCategory(ProactiveActionCard card) async {
    final client = widget.client;
    if (_busy || client == null) return;
    setState(() => _busy = true);
    try {
      final settings = await client.disableCategory(card.suggestionId);
      if (!mounted) return;
      setState(() {
        _settings = settings;
        _cards = _cards
            .where((item) => item.category != card.category)
            .toList(growable: false);
        _message = '已关闭这类建议；可在主动建议设置中重新开启。';
        _messageIsError = false;
      });
    } on ProactiveSuggestionFailure catch (error) {
      _showError(error.code);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _accept(ProactiveActionCard card) async {
    final client = widget.client;
    if (_busy || client == null) return;
    setState(() => _busy = true);
    try {
      final accepted = await client.accept(card.suggestionId);
      if (accepted.actionTarget == null) {
        throw const ProactiveSuggestionFailure('protocol_integrity_error');
      }
      ClusterOrganizationPreview? organizationPreview;
      KnowledgeExportPreview? exportPreview;
      if (accepted.actionType == 'organize_selected') {
        final callback = widget.onPreviewOrganization;
        if (callback == null) {
          throw const ProactiveSuggestionFailure('capability_denied');
        }
        organizationPreview = await callback(accepted.actionTarget!);
      } else {
        final knowledge = widget.knowledgeClient;
        if (knowledge == null) {
          throw const ProactiveSuggestionFailure('capability_denied');
        }
        exportPreview = await knowledge.prepare(
          kind: accepted.actionTarget!,
          request: accepted.request,
        );
      }
      if (!mounted) return;
      setState(() {
        _cards = _cards
            .where((item) => item.suggestionId != card.suggestionId)
            .toList(growable: false);
        _selected = accepted;
        _organizationPreview = organizationPreview;
        _exportPreview = exportPreview;
        _exportIdempotencyKey = exportPreview == null
            ? null
            : newKnowledgeExportIdempotencyKey();
        _message = '已生成操作预览；确认前不会移动或创建文件。';
        _messageIsError = false;
      });
    } on ProactiveSuggestionFailure catch (error) {
      _showError(error.code);
    } on KnowledgeExportFailure catch (error) {
      _showError(error.code);
    } on Object {
      _showError('action_preview_failed');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _confirmSelected() async {
    final selected = _selected;
    if (_busy || selected == null) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(
          selected.actionType == 'organize_selected'
              ? '确认整理这些文件？'
              : '确认导出 Markdown？',
        ),
        content: Text(
          selected.actionType == 'organize_selected'
              ? '只移动预览中的电脑授权目录直接子文件；完成后可安全撤销。'
              : '只会在电脑授权目录中新建一个 Markdown；不会覆盖文件或修改原始资料。',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('确认执行'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    setState(() => _busy = true);
    try {
      if (selected.actionType == 'organize_selected') {
        final preview = _organizationPreview;
        final callback = widget.onExecuteOrganization;
        if (preview == null || callback == null) {
          throw const ProactiveSuggestionFailure('action_preview_failed');
        }
        await callback(preview);
        if (mounted) {
          setState(() {
            _message = '整理已完成；可在今日资料分组中撤销。';
            _messageIsError = false;
            _selected = null;
            _organizationPreview = null;
          });
        }
      } else {
        final preview = _exportPreview;
        final key = _exportIdempotencyKey;
        final client = widget.knowledgeClient;
        if (preview == null || key == null || client == null) {
          throw const ProactiveSuggestionFailure('action_preview_failed');
        }
        final status = await client.execute(preview, idempotencyKey: key);
        if (mounted) {
          setState(() {
            _exportStatus = status;
            _message = '资料包已安全导出；原始资料未被修改。';
            _messageIsError = false;
            _selected = null;
            _exportPreview = null;
          });
        }
      }
    } on KnowledgeExportFailure catch (error) {
      _showError(error.code);
    } on Object {
      _showError('action_execution_failed');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _undoExport() async {
    final token = _exportStatus?.undoToken;
    final client = widget.knowledgeClient;
    if (_busy || token == null || client == null) return;
    setState(() => _busy = true);
    try {
      final status = await client.undo(token);
      if (!mounted) return;
      setState(() {
        _exportStatus = status;
        _message = '导出已撤销；原始资料保持不变。';
        _messageIsError = false;
      });
    } on KnowledgeExportFailure catch (error) {
      _showError(error.code);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  void _showError(String code) {
    if (!mounted) return;
    setState(() {
      _message = _safeError(code);
      _messageIsError = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final settings = _settings;
    return Card(
      key: const Key('proactive-suggestion-card'),
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.auto_awesome, color: theme.colorScheme.primary),
                const SizedBox(width: 10),
                Expanded(
                  child: Text('管家主动建议', style: theme.textTheme.titleLarge),
                ),
              ],
            ),
            const SizedBox(height: 6),
            const Text('Hermes 可在资料稳定后提出下一步，但任何文件操作仍需你查看预览并确认。'),
            SwitchListTile.adaptive(
              key: const Key('proactive-suggestion-toggle'),
              contentPadding: EdgeInsets.zero,
              title: const Text('允许主动生成建议'),
              subtitle: const Text('默认关闭 · 30 分钟冷却 · 每日最多 3 条'),
              value: settings?.enabled ?? false,
              onChanged: settings != null && !_busy ? _toggle : null,
            ),
            if (_message != null) ...[
              _SuggestionNotice(message: _message!, isError: _messageIsError),
              const SizedBox(height: 10),
            ],
            if (settings?.enabled == true)
              Align(
                alignment: Alignment.centerRight,
                child: OutlinedButton.icon(
                  key: const Key('proactive-suggestion-refresh'),
                  onPressed: !_busy && widget.canObserve
                      ? () => _observe(scheduleStableFollowUp: true)
                      : null,
                  icon: const Icon(Icons.refresh),
                  label: const Text('刷新建议'),
                ),
              ),
            for (final card in _cards) ...[
              const Divider(height: 24),
              _ActionProposalCard(
                card: card,
                busy: _busy,
                onAccept: () => _accept(card),
                onDismiss: () => _dismiss(card),
                onDisableCategory: () => _disableCategory(card),
              ),
            ],
            if (_selected != null) ...[
              const Divider(height: 24),
              Text(_selected!.title, style: theme.textTheme.titleMedium),
              const SizedBox(height: 6),
              Text(_selected!.reason),
              const SizedBox(height: 10),
              if (_organizationPreview case final preview?)
                Text(
                  '将整理 ${preview.pcFileCount} 个电脑文件'
                  '${preview.virtualFileCount == 0 ? '' : ' · ${preview.virtualFileCount} 个跨设备资料仅作参考'}',
                ),
              if (_exportPreview case final preview?)
                Text(
                  '将新建 ${preview.filename} · 来源 ${preview.pack.citations.length} 项',
                ),
              const SizedBox(height: 10),
              FilledButton.icon(
                key: const Key('proactive-action-confirm'),
                onPressed: !_busy ? _confirmSelected : null,
                icon: const Icon(Icons.check_circle_outline),
                label: const Text('确认执行'),
              ),
            ],
            if (_exportStatus?.canUndo == true) ...[
              const Divider(height: 24),
              OutlinedButton.icon(
                key: const Key('proactive-export-undo'),
                onPressed: !_busy ? _undoExport : null,
                icon: const Icon(Icons.undo),
                label: const Text('撤销本次资料包导出'),
              ),
            ],
            if (_busy) ...[
              const SizedBox(height: 12),
              const LinearProgressIndicator(),
            ],
          ],
        ),
      ),
    );
  }

  String _observationText(String state) => switch (state) {
    'stabilizing' => '正在等待资料状态稳定；期间不会调用 Hermes。',
    'ready' => _cards.isEmpty ? '当前没有新的建议。' : 'Hermes 已生成一条待确认建议。',
    'cooldown' => '建议正在冷却中，避免频繁打扰。',
    'daily_limit' => '今天的主动建议已达上限。',
    'category_paused' => '这类建议今天已暂停。',
    'handled' => '当前资料对应的建议已经处理，不会重复生成。',
    'disabled' => '主动建议已关闭。',
    _ => '主动建议暂时不可用；系统不会自动重试。',
  };

  String _safeError(String code) => switch (code) {
    'capability_denied' => '当前设备缺少内容理解或操作权限，请重新安全配对。',
    'transient_network' => '电脑暂时不可用；请等待网络稳定后手动刷新，不会自动重试。',
    'artifact_modified' ||
    'artifact_recovery_required' => '导出文件已被修改，系统已保留文件并停止撤销。',
    'knowledge_pack_snapshot_stale' ||
    'artifact_preview_stale' ||
    'catalog_projection_stale' => '资料已经变化，请刷新今日资料后重新生成建议。',
    'suggestion_agent_unavailable' ||
    'suggestion_generation_failed' => 'Hermes 暂时不可用；系统不会自动重试。',
    _ => '本次建议操作已安全停止；没有自动执行或重试。',
  };
}

final class _ActionProposalCard extends StatelessWidget {
  const _ActionProposalCard({
    required this.card,
    required this.busy,
    required this.onAccept,
    required this.onDismiss,
    required this.onDisableCategory,
  });

  final ProactiveActionCard card;
  final bool busy;
  final VoidCallback onAccept;
  final VoidCallback onDismiss;
  final VoidCallback onDisableCategory;

  @override
  Widget build(BuildContext context) => Container(
    key: Key('proactive-action-${card.actionType}'),
    width: double.infinity,
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(
      color: Theme.of(context).colorScheme.secondaryContainer,
      borderRadius: BorderRadius.circular(14),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(card.title, style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 6),
        Text(card.reason),
        const SizedBox(height: 6),
        Text(
          '由 Hermes 基于当前授权资料提出 · 尚未执行',
          style: Theme.of(context).textTheme.bodySmall,
        ),
        const SizedBox(height: 10),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            FilledButton(
              key: Key('proactive-accept-${card.actionType}'),
              onPressed: busy ? null : onAccept,
              child: const Text('查看操作预览'),
            ),
            TextButton(
              onPressed: busy ? null : onDismiss,
              child: const Text('忽略'),
            ),
            TextButton(
              onPressed: busy ? null : onDisableCategory,
              child: const Text('不再提示此类'),
            ),
          ],
        ),
      ],
    ),
  );
}

final class _SuggestionNotice extends StatelessWidget {
  const _SuggestionNotice({required this.message, required this.isError});

  final String message;
  final bool isError;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    final background = isError
        ? colors.errorContainer
        : colors.primaryContainer;
    final foreground = isError
        ? colors.onErrorContainer
        : colors.onPrimaryContainer;
    return Container(
      key: Key(isError ? 'proactive-error-notice' : 'proactive-info-notice'),
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Text(
        message,
        style: TextStyle(color: foreground, fontWeight: FontWeight.w600),
      ),
    );
  }
}
