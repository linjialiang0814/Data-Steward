import 'dart:async';

import 'package:flutter/material.dart';

import 'knowledge_export_client.dart';

const defaultKnowledgePackRequest = '请结合今天的跨设备资料生成学习资料包';

final class KnowledgeExportView extends StatefulWidget {
  const KnowledgeExportView({
    required this.client,
    required this.enabled,
    required this.active,
    this.migrationRequired = false,
    super.key,
  });

  final KnowledgeExportClient? client;
  final bool enabled;
  final bool active;
  final bool migrationRequired;

  @override
  State<KnowledgeExportView> createState() => _KnowledgeExportViewState();
}

final class _KnowledgeExportViewState extends State<KnowledgeExportView> {
  final TextEditingController _request = TextEditingController();
  KnowledgeExportPreview? _preview;
  KnowledgeExportStatus? _status;
  String? _idempotencyKey;
  String _kind = 'learning';
  String? _message;
  bool _messageIsError = false;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    if (widget.active && widget.enabled) unawaited(_refreshStatus());
  }

  @override
  void didUpdateWidget(covariant KnowledgeExportView oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.active &&
        widget.enabled &&
        (!oldWidget.active ||
            !oldWidget.enabled ||
            oldWidget.client != widget.client)) {
      unawaited(_refreshStatus());
    }
  }

  @override
  void dispose() {
    _request.dispose();
    super.dispose();
  }

  Future<void> _run(Future<void> Function(KnowledgeExportClient) action) async {
    final client = widget.client;
    if (_busy || client == null || !widget.enabled) return;
    setState(() {
      _busy = true;
      _message = null;
      _messageIsError = false;
    });
    try {
      await action(client);
    } on KnowledgeExportFailure catch (error) {
      KnowledgeExportStatus? recovered;
      if (error.code == 'artifact_modified' ||
          error.code == 'artifact_recovery_required') {
        try {
          recovered = await client.status();
        } on Object {
          // One read-only reconciliation attempt only; never retry the mutation.
        }
      }
      if (mounted) {
        setState(() {
          _message = _safeError(error.code);
          _messageIsError = true;
          if (recovered != null) _status = recovered;
        });
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _prepare() => _run((client) async {
    final preview = await client.prepare(
      kind: _kind,
      request: _request.text.trim().isEmpty
          ? defaultKnowledgePackRequest
          : _request.text.trim(),
    );
    if (mounted) {
      setState(() {
        _preview = preview;
        _idempotencyKey = newKnowledgeExportIdempotencyKey();
        _message = '预览已生成；确认前不会创建或修改文件。';
        _messageIsError = false;
      });
    }
  });

  Future<void> _execute() async {
    final preview = _preview;
    final idempotencyKey = _idempotencyKey;
    if (preview == null || idempotencyKey == null || _busy) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('确认导出 Markdown？'),
        content: Text(
          '将在“${preview.targetDisplayName} / ${preview.outputDirectory}”中新建：\n'
          '${preview.filename}\n\n不会覆盖已有文件，也不会修改任何原始资料。',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('确认导出'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await _run((client) async {
      final status = await client.execute(
        preview,
        idempotencyKey: idempotencyKey,
      );
      if (mounted) {
        setState(() {
          _status = status;
          _message = '资料包已安全导出；原始资料未被修改。';
          _messageIsError = false;
        });
      }
    });
  }

  Future<void> _refreshStatus() => _run((client) async {
    final status = await client.status();
    if (mounted) setState(() => _status = status);
  });

  Future<void> _undo() async {
    final token = _status?.undoToken;
    if (token == null || _busy) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('撤销本次导出？'),
        content: const Text('只有导出文件保持完全不变时才会删除；若你已编辑，系统会保留文件并停止。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('保留'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('确认撤销'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await _run((client) async {
      final status = await client.undo(token);
      if (mounted) {
        setState(() {
          _status = status;
          _message = '导出已撤销；原始资料保持不变。';
          _messageIsError = false;
        });
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final preview = _preview;
    final status = _status;
    return Card(
      key: const Key('knowledge-export-card'),
      child: Padding(
        padding: const EdgeInsets.all(18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.inventory_2_outlined,
                  color: theme.colorScheme.primary,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text('跨设备资料包', style: theme.textTheme.titleLarge),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              widget.migrationRequired
                  ? '需要重新安全配对并批准“资料包导出”后使用；不会自动扩大已有授权。'
                  : 'Hermes 只组合已授权资料；先预览来源和落点，明确确认后才新建 Markdown。',
            ),
            if (_message != null) ...[
              const SizedBox(height: 12),
              _KnowledgeExportNotice(
                message: _message!,
                isError: _messageIsError,
              ),
            ],
            const SizedBox(height: 12),
            DropdownButtonFormField<String>(
              key: const Key('knowledge-export-kind'),
              initialValue: _kind,
              decoration: const InputDecoration(labelText: '资料包类型'),
              items: const [
                DropdownMenuItem(value: 'learning', child: Text('学习资料包')),
                DropdownMenuItem(value: 'meeting', child: Text('会议简报')),
                DropdownMenuItem(value: 'project', child: Text('项目资料包')),
                DropdownMenuItem(value: 'general', child: Text('综合资料包')),
              ],
              onChanged: widget.enabled && !_busy
                  ? (value) => setState(() => _kind = value!)
                  : null,
            ),
            const SizedBox(height: 10),
            TextField(
              key: const Key('knowledge-export-request'),
              controller: _request,
              enabled: widget.enabled && !_busy,
              maxLength: 500,
              maxLines: 3,
              decoration: const InputDecoration(
                labelText: '希望资料包解决什么问题？',
                hintText: defaultKnowledgePackRequest,
                border: OutlineInputBorder(),
              ),
            ),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.icon(
                key: const Key('knowledge-export-prepare'),
                onPressed: widget.enabled && !_busy ? _prepare : null,
                icon: const Icon(Icons.preview_outlined),
                label: Text(_busy ? '处理中…' : '生成导出预览'),
              ),
            ),
            if (preview != null) ...[
              const Divider(height: 28),
              Text(preview.pack.title, style: theme.textTheme.titleMedium),
              const SizedBox(height: 6),
              Text(preview.pack.summary),
              const SizedBox(height: 8),
              Text(
                preview.pack.source == 'hermes'
                    ? '本次由 Hermes 受控分析生成'
                    : '本次由本机安全摘要生成（Hermes 未产出可采用结果）',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: preview.pack.source == 'hermes'
                      ? theme.colorScheme.primary
                      : theme.colorScheme.tertiary,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 10),
              Text(
                '来源 ${preview.pack.citations.length} 项${preview.pack.crossDevice ? ' · 跨设备' : ''}',
              ),
              for (final source in preview.pack.citations.take(6))
                ListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  leading: Icon(
                    source.platform == 'windows'
                        ? Icons.computer
                        : Icons.phone_android,
                  ),
                  title: Text(source.displayName),
                  subtitle: Text(
                    '${source.sourceDisplayName} · '
                    '${source.basis == 'content_projection' ? '正文/安全投影' : '目录元数据'}',
                  ),
                ),
              Text(
                '将新建：${preview.outputDirectory} / ${preview.filename} · ${preview.byteCount} B',
              ),
              const SizedBox(height: 10),
              FilledButton.icon(
                key: const Key('knowledge-export-execute'),
                onPressed: !_busy ? _execute : null,
                icon: const Icon(Icons.file_download_done_outlined),
                label: const Text('确认并导出 Markdown'),
              ),
            ],
            if (status?.canUndo == true) ...[
              const Divider(height: 28),
              Text('已导出：${status?.filename ?? ''}'),
              const SizedBox(height: 8),
              OutlinedButton.icon(
                key: const Key('knowledge-export-undo'),
                onPressed: !_busy ? _undo : null,
                icon: const Icon(Icons.undo),
                label: const Text('撤销导出'),
              ),
            ],
            if (status?.state == 'recovery_required' && _message == null) ...[
              const SizedBox(height: 10),
              const _KnowledgeExportNotice(
                message: '导出文件状态已变化，系统不会覆盖或删除；请在电脑端检查文件。',
                isError: true,
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

  String _safeError(String code) => switch (code) {
    'capability_denied' => '当前设备尚未获得资料包导出权限，请重新安全配对。',
    'content_opt_in_required' => '请先在电脑端开启内容理解。',
    'knowledge_pack_unavailable' => '请先生成一次资料简报，再创建资料包。',
    'knowledge_pack_snapshot_stale' ||
    'artifact_preview_stale' => '资料已经变化，请刷新后重新预览。',
    'artifact_scope_unconfigured' ||
    'artifact_scope_changed' => '请先在电脑端授权稳定的资料目录。',
    'artifact_target_exists' => '同名导出文件已存在；系统没有覆盖，请重新生成预览。',
    'artifact_modified' ||
    'artifact_recovery_required' => '导出文件已被修改，系统已保留文件并停止撤销。',
    'transient_network' => '电脑暂时不可用；系统不会自动重试，请等待网络稳定后手动刷新状态。',
    _ => '本次资料包操作已安全停止，请刷新状态后再试。',
  };
}

final class _KnowledgeExportNotice extends StatelessWidget {
  const _KnowledgeExportNotice({required this.message, required this.isError});

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
    return Semantics(
      liveRegion: true,
      child: Container(
        key: Key(
          isError
              ? 'knowledge-export-error-notice'
              : 'knowledge-export-info-notice',
        ),
        width: double.infinity,
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: background,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: foreground.withValues(alpha: 0.28)),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(
              isError ? Icons.gpp_maybe_outlined : Icons.info_outline,
              color: foreground,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                message,
                style: TextStyle(
                  color: foreground,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
