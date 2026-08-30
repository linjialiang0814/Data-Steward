import 'package:flutter/material.dart';

import 'steward_theme.dart';

typedef StewardHomeSnapshotLoader = Future<StewardHomeSnapshot> Function();

@immutable
final class StewardHomeSnapshot {
  const StewardHomeSnapshot({
    required this.todayLabel,
    required this.pendingLabel,
    required this.memoryLabel,
  });

  const StewardHomeSnapshot.unavailable()
    : todayLabel = '暂不可用',
      pendingLabel = '暂无新建议',
      memoryLabel = '尚未形成习惯';

  final String todayLabel;
  final String pendingLabel;
  final String memoryLabel;
}

class StewardHomePage extends StatefulWidget {
  const StewardHomePage({
    required this.connectionLabel,
    required this.connectionTone,
    required this.onOpenSession,
    required this.onOpenToday,
    required this.onOpenMemory,
    required this.onStartIntent,
    this.snapshotLoader,
    this.snapshotIdentityKey,
    this.snapshotKey,
    this.onOpenDiagnostics,
    super.key,
  });

  final String connectionLabel;
  final StewardStatusTone connectionTone;
  final VoidCallback onOpenSession;
  final VoidCallback onOpenToday;
  final VoidCallback onOpenMemory;
  final ValueChanged<String> onStartIntent;
  final StewardHomeSnapshotLoader? snapshotLoader;
  final Object? snapshotIdentityKey;
  final Object? snapshotKey;
  final VoidCallback? onOpenDiagnostics;

  @override
  State<StewardHomePage> createState() => _StewardHomePageState();
}

final class _StewardHomePageState extends State<StewardHomePage> {
  StewardHomeSnapshot _snapshot = const StewardHomeSnapshot.unavailable();
  bool _loading = false;
  bool _refreshQueued = false;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  @override
  void didUpdateWidget(covariant StewardHomePage oldWidget) {
    super.didUpdateWidget(oldWidget);
    final identityChanged =
        oldWidget.snapshotIdentityKey != widget.snapshotIdentityKey;
    final becameUnavailable =
        oldWidget.snapshotLoader != null && widget.snapshotLoader == null;
    if (identityChanged || becameUnavailable) {
      setState(() => _snapshot = const StewardHomeSnapshot.unavailable());
    }
    if (identityChanged || oldWidget.snapshotKey != widget.snapshotKey) {
      _refresh();
    }
  }

  Future<void> _refresh() async {
    if (widget.snapshotLoader == null) {
      if (mounted) {
        setState(() => _snapshot = const StewardHomeSnapshot.unavailable());
      }
      return;
    }
    if (_loading) {
      _refreshQueued = true;
      return;
    }
    setState(() => _loading = true);
    try {
      do {
        _refreshQueued = false;
        final loader = widget.snapshotLoader;
        final requestedIdentityKey = widget.snapshotIdentityKey;
        final requestedKey = widget.snapshotKey;
        if (loader == null) break;
        try {
          final value = await loader();
          if (mounted &&
              requestedIdentityKey == widget.snapshotIdentityKey &&
              requestedKey == widget.snapshotKey) {
            setState(() => _snapshot = value);
          }
        } on Object {
          // The dashboard is advisory. Keep the last safe snapshot. A queued
          // refresh only represents a newer explicit snapshot key.
        }
      } while (mounted && _refreshQueued);
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: const Text('首页'),
      actions: [
        if (widget.onOpenDiagnostics != null)
          IconButton(
            key: const Key('open-developer-diagnostics'),
            onPressed: widget.onOpenDiagnostics,
            tooltip: '开发诊断',
            icon: const Icon(Icons.developer_mode_outlined),
          ),
        const SizedBox(width: 8),
      ],
    ),
    body: SafeArea(
      child: LayoutBuilder(
        builder: (context, constraints) => ListView(
          padding: EdgeInsets.fromLTRB(
            constraints.maxWidth < 600 ? 16 : 28,
            8,
            constraints.maxWidth < 600 ? 16 : 28,
            32,
          ),
          children: [
            _HeroCard(
              connectionLabel: widget.connectionLabel,
              connectionTone: widget.connectionTone,
              onOpenSession: widget.onOpenSession,
            ),
            const SizedBox(height: StewardSpacing.lg),
            Text('今日概览', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: StewardSpacing.sm),
            LayoutBuilder(
              builder: (context, metrics) {
                final columns = metrics.maxWidth >= 720 ? 3 : 2;
                final width =
                    (metrics.maxWidth - StewardSpacing.sm * (columns - 1)) /
                    columns;
                return Wrap(
                  spacing: StewardSpacing.sm,
                  runSpacing: StewardSpacing.sm,
                  children: [
                    _MetricCard(
                      width: width,
                      icon: Icons.folder_copy_outlined,
                      label: '今日资料',
                      value: _loading ? '正在同步…' : _snapshot.todayLabel,
                      onTap: widget.onOpenToday,
                    ),
                    _MetricCard(
                      width: width,
                      icon: Icons.fact_check_outlined,
                      label: '主动建议',
                      value: _snapshot.pendingLabel,
                      onTap: widget.onOpenToday,
                    ),
                    _MetricCard(
                      width: width,
                      icon: Icons.psychology_alt_outlined,
                      label: '跨会话记忆',
                      value: _snapshot.memoryLabel,
                      onTap: widget.onOpenMemory,
                    ),
                  ],
                );
              },
            ),
            const SizedBox(height: StewardSpacing.lg),
            Text('快速开始', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: StewardSpacing.sm),
            _QuickAction(
              icon: Icons.auto_awesome_outlined,
              title: '汇总今日跨设备资料',
              subtitle: '综合手机与电脑上的今日资料，提炼主题与下一步',
              onTap: () =>
                  widget.onStartIntent('汇总今天已授权设备上的资料，提炼主要主题、关键信息和下一步。'),
            ),
            const SizedBox(height: StewardSpacing.xs),
            _QuickAction(
              icon: Icons.drive_file_move_outline,
              title: '整理今日资料',
              subtitle: '先生成建议和预览，确认后整理电脑资料，可撤销',
              onTap: () =>
                  widget.onStartIntent('根据今天的资料和我的整理习惯给出归档建议，先不要移动文件。'),
            ),
            const SizedBox(height: StewardSpacing.xs),
            _QuickAction(
              icon: Icons.auto_awesome_outlined,
              title: '生成跨设备资料包',
              subtitle: '综合文档与手机图片，生成带来源的复习或工作资料包',
              onTap: () =>
                  widget.onStartIntent('结合今天手机和电脑上的资料，生成一份带来源的跨设备资料包预览。'),
            ),
          ],
        ),
      ),
    ),
  );
}

class _HeroCard extends StatelessWidget {
  const _HeroCard({
    required this.connectionLabel,
    required this.connectionTone,
    required this.onOpenSession,
  });

  final String connectionLabel;
  final StewardStatusTone connectionTone;
  final VoidCallback onOpenSession;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [scheme.primary, scheme.primaryContainer],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(StewardRadii.lg),
      ),
      child: Wrap(
        alignment: WrapAlignment.spaceBetween,
        crossAxisAlignment: WrapCrossAlignment.center,
        spacing: 20,
        runSpacing: 20,
        children: [
          ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 520),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '你的资料，始终由你掌控',
                  style: Theme.of(
                    context,
                  ).textTheme.headlineMedium?.copyWith(color: scheme.onPrimary),
                ),
                const SizedBox(height: 8),
                Text(
                  '说出你的需求，让已授权设备安全协同；重要操作由你确认，结果跨端同步。',
                  style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                    color: scheme.onPrimary.withValues(alpha: .88),
                  ),
                ),
                const SizedBox(height: 18),
                StewardStatusPill(label: connectionLabel, tone: connectionTone),
              ],
            ),
          ),
          FilledButton.tonalIcon(
            onPressed: onOpenSession,
            icon: const Icon(Icons.arrow_forward),
            label: const Text('进入智能会话'),
          ),
        ],
      ),
    );
  }
}

class _MetricCard extends StatelessWidget {
  const _MetricCard({
    required this.width,
    required this.icon,
    required this.label,
    required this.value,
    required this.onTap,
  });

  final double width;
  final IconData icon;
  final String label;
  final String value;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) => SizedBox(
    width: width,
    child: Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(StewardRadii.md),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(18),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: Theme.of(context).colorScheme.primary),
              const SizedBox(height: 18),
              Text(label, style: Theme.of(context).textTheme.bodyMedium),
              const SizedBox(height: 4),
              Text(
                value,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: Theme.of(context).textTheme.titleMedium,
              ),
            ],
          ),
        ),
      ),
    ),
  );
}

class _QuickAction extends StatelessWidget {
  const _QuickAction({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) => Card(
    child: ListTile(
      minTileHeight: 72,
      leading: CircleAvatar(child: Icon(icon)),
      title: Text(title),
      subtitle: Text(subtitle),
      trailing: const Icon(Icons.chevron_right),
      onTap: onTap,
    ),
  );
}
