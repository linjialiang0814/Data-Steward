import 'dart:async';

import 'package:flutter/material.dart';

import 'catalog_sync_client.dart';
import 'today_materials.dart';

final class TodayMaterialsView extends StatefulWidget {
  const TodayMaterialsView({
    required this.projection,
    required this.loading,
    required this.onRefresh,
    this.onPreviewOrganization,
    this.onExecuteOrganization,
    this.onUndoOrganization,
    this.onRefreshOrganizationStatus,
    this.organizationStatus,
    this.active = true,
    this.errorMessage,
    super.key,
  });

  final TodayMaterialsProjection? projection;
  final bool loading;
  final VoidCallback? onRefresh;
  final String? errorMessage;
  final Future<ClusterOrganizationPreview> Function(
    TodayCluster cluster,
    String projectionSha256,
  )?
  onPreviewOrganization;
  final Future<ClusterOrganizationReceipt> Function(
    ClusterOrganizationPreview preview,
  )?
  onExecuteOrganization;
  final Future<ClusterOrganizationReceipt> Function(String undoToken)?
  onUndoOrganization;
  final Future<void> Function()? onRefreshOrganizationStatus;
  final ClusterOrganizationStatus? organizationStatus;
  final bool active;

  @override
  State<TodayMaterialsView> createState() => _TodayMaterialsViewState();
}

final class _TodayMaterialsViewState extends State<TodayMaterialsView> {
  final Set<String> _accepted = {};
  final Set<String> _needsAdjustment = {};
  final Map<String, ClusterOrganizationReceipt> _organizationReceipts = {};
  final Map<String, String> _organizationMessages = {};
  String? _organizingClusterId;
  String? _pendingOrganizationMessage;
  Timer? _organizationStatusTimer;
  bool _organizationStatusRefreshBusy = false;
  bool _organizationStatusRefreshPaused = false;

  @override
  void initState() {
    super.initState();
    _configureOrganizationStatusRefresh();
  }

  @override
  void didUpdateWidget(covariant TodayMaterialsView oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.projection?.projectionSha256 !=
        widget.projection?.projectionSha256) {
      final current =
          widget.projection?.clusters.map((item) => item.clusterId).toSet() ??
          {};
      _accepted.removeWhere((id) => !current.contains(id));
      _needsAdjustment.removeWhere((id) => !current.contains(id));
      _organizationReceipts.removeWhere((id, _) => !current.contains(id));
      _organizationMessages.removeWhere((id, _) => !current.contains(id));
    }
    if (oldWidget.organizationStatus?.undoToken !=
        widget.organizationStatus?.undoToken) {
      _pendingOrganizationMessage = null;
    }
    if (oldWidget.active != widget.active ||
        (oldWidget.onRefreshOrganizationStatus == null) !=
            (widget.onRefreshOrganizationStatus == null)) {
      _organizationStatusRefreshPaused = false;
      _configureOrganizationStatusRefresh();
    }
  }

  void _configureOrganizationStatusRefresh() {
    _organizationStatusTimer?.cancel();
    _organizationStatusTimer = null;
    if (!widget.active || widget.onRefreshOrganizationStatus == null) return;
    _organizationStatusTimer = Timer.periodic(
      const Duration(seconds: 5),
      (_) => unawaited(_refreshOrganizationStatus()),
    );
  }

  Future<void> _refreshOrganizationStatus() async {
    final callback = widget.onRefreshOrganizationStatus;
    if (callback == null ||
        !widget.active ||
        _organizationStatusRefreshBusy ||
        _organizationStatusRefreshPaused) {
      return;
    }
    _organizationStatusRefreshBusy = true;
    try {
      await callback();
    } on Object {
      _organizationStatusRefreshPaused = true;
    } finally {
      _organizationStatusRefreshBusy = false;
    }
  }

  @override
  void dispose() {
    _organizationStatusTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final projection = widget.projection;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('今日资料', style: theme.textTheme.headlineSmall),
                  const SizedBox(height: 4),
                  Text(
                    projection == null
                        ? '按时间和文件名整理来自手机与电脑的资料'
                        : '${projection.rootCount} 个资料来源 · '
                              '${projection.assetCount} 个今日文件 · 仅元数据模式',
                  ),
                ],
              ),
            ),
            FilledButton.tonalIcon(
              onPressed: widget.loading ? null : widget.onRefresh,
              icon: const Icon(Icons.auto_awesome_outlined),
              label: const Text('刷新今日资料'),
            ),
          ],
        ),
        if (widget.loading) ...[
          const SizedBox(height: 12),
          const LinearProgressIndicator(semanticsLabel: '正在生成今日资料'),
        ],
        if (widget.errorMessage != null) ...[
          const SizedBox(height: 12),
          Text(
            widget.errorMessage!,
            style: TextStyle(color: theme.colorScheme.error),
          ),
        ],
        if (widget.organizationStatus case final status?) ...[
          if (status.state != 'idle') ...[
            const SizedBox(height: 12),
            _pendingOrganizationCard(status),
          ],
        ],
        if (_pendingOrganizationMessage case final message?) ...[
          const SizedBox(height: 8),
          Text(message),
        ],
        const SizedBox(height: 16),
        if (projection == null && !widget.loading)
          const Card(
            child: Padding(
              padding: EdgeInsets.all(18),
              child: Text('同步手机与电脑资料后，点击刷新即可查看今天的分组。'),
            ),
          )
        else if (projection != null && projection.assetCount == 0)
          const Card(
            child: Padding(
              padding: EdgeInsets.all(18),
              child: Text('今天暂时没有新同步的资料。历史目录仍安全保留。'),
            ),
          )
        else if (projection != null) ...[
          for (final cluster in projection.clusters) _clusterCard(cluster),
          if (projection.unassigned.isNotEmpty)
            _unassignedCard(projection.unassigned),
        ],
      ],
    );
  }

  Widget _clusterCard(TodayCluster cluster) {
    final accepted = _accepted.contains(cluster.clusterId);
    final adjusting = _needsAdjustment.contains(cluster.clusterId);
    final receipt = _organizationReceipts[cluster.clusterId];
    final organizing = _organizingClusterId == cluster.clusterId;
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: ExpansionTile(
        key: ValueKey('today-cluster-${cluster.clusterId}'),
        leading: const CircleAvatar(child: Icon(Icons.auto_awesome_outlined)),
        title: Text(cluster.title),
        subtitle: Text(
          '${_timeRange(cluster)} · ${_sources(cluster.sourcePlatforms)} · '
          '${cluster.assetCount} 个文件 · ${_confidence(cluster)}',
        ),
        childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        children: [
          Align(
            alignment: Alignment.centerLeft,
            child: Wrap(
              spacing: 8,
              runSpacing: 6,
              children: [
                for (final reason in cluster.reasons)
                  Chip(
                    avatar: const Icon(Icons.lightbulb_outline, size: 16),
                    label: Text(reason),
                  ),
              ],
            ),
          ),
          const SizedBox(height: 8),
          for (final asset in cluster.assets)
            ListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              leading: Icon(
                asset.platform == 'android'
                    ? Icons.smartphone_outlined
                    : Icons.computer_outlined,
              ),
              title: Text(asset.displayName),
              subtitle: Text(
                '${asset.platform == 'android' ? '来自手机' : '来自电脑'} · '
                '${asset.sourceDisplayName}',
              ),
            ),
          const SizedBox(height: 8),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              FilledButton.tonalIcon(
                onPressed: accepted
                    ? null
                    : () => setState(() {
                        _accepted.add(cluster.clusterId);
                        _needsAdjustment.remove(cluster.clusterId);
                      }),
                icon: Icon(
                  accepted ? Icons.check : Icons.thumb_up_alt_outlined,
                ),
                label: Text(accepted ? '已保留' : '保留这个分组'),
              ),
              if (widget.onPreviewOrganization != null &&
                  widget.onExecuteOrganization != null) ...[
                FilledButton.icon(
                  onPressed: organizing || receipt != null
                      ? null
                      : () => _prepareOrganization(cluster),
                  icon: organizing
                      ? const Icon(Icons.hourglass_top)
                      : const Icon(Icons.drive_file_move_outline),
                  label: Text(receipt == null ? '准备整理' : '已整理'),
                ),
              ],
              TextButton.icon(
                onPressed: () => setState(() {
                  _needsAdjustment.add(cluster.clusterId);
                  _accepted.remove(cluster.clusterId);
                }),
                icon: const Icon(Icons.tune),
                label: Text(adjusting ? '已标记待调整' : '调整分组'),
              ),
            ],
          ),
          if (accepted || adjusting) ...[
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerLeft,
              child: Text(
                accepted ? '已保留为当前页面的虚拟分组；不会移动或修改文件。' : '已在当前页面标记待调整；不会自动改变目录。',
              ),
            ),
          ],
          if (_organizationMessages[cluster.clusterId] != null) ...[
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerLeft,
              child: Text(_organizationMessages[cluster.clusterId]!),
            ),
          ],
          if (receipt != null &&
              widget.organizationStatus?.state != 'undo_available' &&
              widget.onUndoOrganization != null) ...[
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerLeft,
              child: OutlinedButton.icon(
                onPressed: organizing
                    ? null
                    : () => _undoOrganization(cluster, receipt),
                icon: const Icon(Icons.undo),
                label: const Text('撤销本次整理'),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _pendingOrganizationCard(ClusterOrganizationStatus status) {
    final canUndo =
        status.canUndo &&
        status.undoToken != null &&
        widget.onUndoOrganization != null;
    return Card(
      key: const Key('s6-pending-organization-card'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              status.state == 'undo_available' ? '上次整理仍可撤销' : '上次整理需要人工核对',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 6),
            Text(
              status.state == 'undo_available'
                  ? '已移动 ${status.movedCount} 个电脑文件。关闭并重开应用后，撤销入口仍会保留。'
                  : '文件状态或恢复记录发生变化，系统已停止自动处理，也不会删除或覆盖文件。',
            ),
            if (canUndo) ...[
              const SizedBox(height: 10),
              OutlinedButton.icon(
                key: const Key('s6-undo-restored-organization'),
                onPressed: _organizingClusterId == null
                    ? () => _undoPendingOrganization(status)
                    : null,
                icon: const Icon(Icons.undo),
                label: const Text('撤销上次整理'),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Future<void> _undoPendingOrganization(
    ClusterOrganizationStatus status,
  ) async {
    final callback = widget.onUndoOrganization;
    final token = status.undoToken;
    if (callback == null || token == null || _organizingClusterId != null) {
      return;
    }
    setState(() => _organizingClusterId = '__pending__');
    try {
      final result = await callback(token);
      if (!mounted) return;
      setState(() {
        _organizationReceipts.removeWhere(
          (_, receipt) => receipt.undoToken == token,
        );
        _pendingOrganizationMessage =
            '已撤销整理，${result.movedCount} 个电脑文件已回到授权目录。';
      });
    } on CatalogSyncFailure {
      // The parent keeps the authoritative status; a manual refresh is safe.
    } finally {
      if (mounted) setState(() => _organizingClusterId = null);
    }
  }

  Future<void> _prepareOrganization(TodayCluster cluster) async {
    final projection = widget.projection;
    final previewCallback = widget.onPreviewOrganization;
    final executeCallback = widget.onExecuteOrganization;
    if (projection == null ||
        previewCallback == null ||
        executeCallback == null ||
        _organizingClusterId != null) {
      return;
    }
    setState(() {
      _organizingClusterId = cluster.clusterId;
      _organizationMessages.remove(cluster.clusterId);
    });
    try {
      final preview = await previewCallback(
        cluster,
        projection.projectionSha256,
      );
      if (!mounted) return;
      final confirmed =
          await showDialog<bool>(
            context: context,
            builder: (context) => AlertDialog(
              title: Text('整理“${preview.clusterTitle}”中的电脑文件？'),
              content: Text(
                '将移动 ${preview.pcFileCount} 个电脑文件到 Data Steward 固定分类目录。'
                '${preview.virtualFileCount == 0 ? '' : '\n${preview.virtualFileCount} 个手机文件只保留为虚拟分组，不会被移动。'}'
                '\n不会覆盖或删除文件，完成后可撤销。',
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context, false),
                  child: const Text('取消'),
                ),
                FilledButton(
                  onPressed: () => Navigator.pop(context, true),
                  child: const Text('确认整理'),
                ),
              ],
            ),
          ) ??
          false;
      if (!confirmed) return;
      final receipt = await executeCallback(preview);
      if (!mounted) return;
      setState(() {
        _organizationReceipts[cluster.clusterId] = receipt;
        _organizationMessages[cluster.clusterId] =
            '已整理 ${receipt.movedCount} 个电脑文件；未移动手机文件，也没有覆盖或删除文件。';
      });
    } on CatalogSyncFailure catch (failure) {
      if (!mounted) return;
      setState(() {
        _organizationMessages[cluster.clusterId] = _organizationError(
          failure.code,
        );
      });
    } finally {
      if (mounted) setState(() => _organizingClusterId = null);
    }
  }

  Future<void> _undoOrganization(
    TodayCluster cluster,
    ClusterOrganizationReceipt receipt,
  ) async {
    final callback = widget.onUndoOrganization;
    if (callback == null || _organizingClusterId != null) return;
    setState(() => _organizingClusterId = cluster.clusterId);
    try {
      final result = await callback(receipt.undoToken);
      if (!mounted) return;
      setState(() {
        _organizationReceipts.remove(cluster.clusterId);
        _organizationMessages[cluster.clusterId] =
            '已撤销整理，${result.movedCount} 个电脑文件已回到授权目录。';
      });
    } on CatalogSyncFailure catch (failure) {
      if (!mounted) return;
      setState(() {
        _organizationMessages[cluster.clusterId] = _organizationError(
          failure.code,
        );
      });
    } finally {
      if (mounted) setState(() => _organizingClusterId = null);
    }
  }

  String _organizationError(String code) => switch (code) {
    'capability_denied' => '当前设备没有真实整理权限，请在电脑端调整授权后重新配对。',
    'catalog_projection_stale' ||
    'organization_preview_stale' ||
    'organizer_selection_stale' => '资料已经发生变化，请手动刷新“今日资料”后重新预览。',
    'cluster_has_no_pc_files' => '这个分组只有虚拟或手机资料，没有可移动的电脑文件。',
    'organizer_undo_required' => '请先撤销上一次尚未结束的整理。',
    'transient_network' ||
    'catalog_timeout' => '电脑暂时不可用；系统没有自动重试，请等待网络稳定后手动刷新。',
    _ => '本次整理已安全停止；请刷新目录确认状态，系统不会自动重试。',
  };

  Widget _unassignedCard(List<TodayAsset> assets) => Card(
    margin: const EdgeInsets.only(bottom: 12),
    child: ExpansionTile(
      key: const Key('today-unassigned'),
      leading: const CircleAvatar(child: Icon(Icons.help_outline)),
      title: const Text('待确认'),
      subtitle: Text('${assets.length} 个文件 · 信息不足，未强制归类'),
      children: [
        for (final asset in assets)
          ListTile(
            leading: Icon(
              asset.platform == 'android'
                  ? Icons.smartphone_outlined
                  : Icons.computer_outlined,
            ),
            title: Text(asset.displayName),
            subtitle: Text(asset.platform == 'android' ? '来自手机' : '来自电脑'),
          ),
      ],
    ),
  );

  String _timeRange(TodayCluster cluster) {
    final start = DateTime.fromMillisecondsSinceEpoch(
      cluster.startAtMillis,
    ).toLocal();
    final end = DateTime.fromMillisecondsSinceEpoch(
      cluster.endAtMillis,
    ).toLocal();
    String value(DateTime time) =>
        '${time.hour.toString().padLeft(2, '0')}:'
        '${time.minute.toString().padLeft(2, '0')}';
    return start == end ? value(start) : '${value(start)}–${value(end)}';
  }

  String _sources(List<String> platforms) {
    if (platforms.length == 2) return '手机 + 电脑';
    return platforms.single == 'android' ? '手机' : '电脑';
  }

  String _confidence(TodayCluster cluster) =>
      cluster.confidenceBand == 'high' ? '较可靠' : '建议确认';
}
