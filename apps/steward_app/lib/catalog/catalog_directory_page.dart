import 'dart:async';

import 'package:flutter/material.dart';

import '../secure_pairing/pairing_vault.dart';
import 'android_ocr_client.dart';
import 'catalog_bridge.dart';
import 'catalog_sync_client.dart';
import 'content_insight.dart';
import 'content_insight_client.dart';
import 'content_insight_view.dart';
import 'knowledge_export_client.dart';
import 'knowledge_export_view.dart';
import 'proactive_suggestion_client.dart';
import 'proactive_suggestion_view.dart';
import 'today_materials.dart';
import 'today_materials_view.dart';

final class CatalogDirectoryPage extends StatefulWidget {
  const CatalogDirectoryPage({
    this.bridge = const MethodChannelCatalogBridge(),
    this.credential,
    this.active = true,
    super.key,
  });

  final CatalogBridge bridge;
  final ActiveDeviceCredential? credential;
  final bool active;

  @override
  State<CatalogDirectoryPage> createState() => _CatalogDirectoryPageState();
}

final class _CatalogDirectoryPageState extends State<CatalogDirectoryPage>
    with WidgetsBindingObserver {
  CatalogDirectoryState _directory =
      const CatalogDirectoryState.notAuthorized();
  CatalogSnapshot? _snapshot;
  TodayMaterialsProjection? _today;
  StudyPack? _studyPack;
  ClusterOrganizationStatus? _organizationStatus;
  String? _errorCode;
  String? _syncStatus;
  String? _contentMessage;
  String? _ocrMessage;
  var _busy = false;
  KnowledgeExportClient? _knowledgeExportClient;
  ProactiveSuggestionClient? _suggestionClient;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _attachKnowledgeClient(widget.credential);
    _attachSuggestionClient(widget.credential);
    unawaited(_restore());
  }

  @override
  void didUpdateWidget(covariant CatalogDirectoryPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(oldWidget.credential, widget.credential)) {
      _knowledgeExportClient?.close();
      _suggestionClient?.close();
      _attachKnowledgeClient(widget.credential);
      _attachSuggestionClient(widget.credential);
    }
    if (widget.active && !oldWidget.active && _directory.authorized && !_busy) {
      unawaited(_refresh());
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed &&
        widget.active &&
        _directory.authorized &&
        !_busy) {
      unawaited(_refresh());
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _knowledgeExportClient?.close();
    _suggestionClient?.close();
    super.dispose();
  }

  void _attachKnowledgeClient(ActiveDeviceCredential? credential) {
    _knowledgeExportClient = credential == null
        ? null
        : KnowledgeExportClient.device(credential: credential);
  }

  void _attachSuggestionClient(ActiveDeviceCredential? credential) {
    _suggestionClient = credential == null
        ? null
        : ProactiveSuggestionClient.device(credential: credential);
  }

  Future<ClusterOrganizationPreview> _previewSuggestedOrganization(
    String clusterId,
  ) async {
    final today = _today;
    if (today == null) {
      throw const CatalogSyncFailure('catalog_projection_stale');
    }
    final matches = today.clusters.where((item) => item.clusterId == clusterId);
    if (matches.length != 1) {
      throw const CatalogSyncFailure('catalog_projection_stale');
    }
    return _previewOrganization(matches.single, today.projectionSha256);
  }

  Future<void> _restore() => _run(() async {
    final state = await widget.bridge.getCatalogState();
    if (!mounted) return;
    setState(() => _directory = state);
  });

  Future<void> _select() => _run(() async {
    final state = await widget.bridge.selectCatalogDirectory();
    if (!mounted) return;
    setState(() {
      _directory = state;
      _snapshot = null;
      _ocrMessage = null;
    });
  });

  Future<void> _refresh() => _run(() async {
    final snapshot = await widget.bridge.buildCatalogSnapshot();
    if (!mounted) return;
    if (snapshot.catalogRootId != _directory.catalogRootId) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    setState(() {
      _snapshot = snapshot;
      _syncStatus = '本地清单已刷新，共 ${snapshot.itemCount} 个文件；正在同步到电脑…';
    });
    final credential = widget.credential;
    if (credential == null ||
        !credential.grantedCapabilities.contains('catalog.sync')) {
      if (mounted) {
        setState(
          () => _syncStatus = '本地清单已刷新，共 ${snapshot.itemCount} 个文件；尚未连接电脑。',
        );
      }
      return;
    }
    await _syncSnapshot(snapshot, credential);
  });

  Future<void> _sync() => _run(() async {
    final credential = widget.credential;
    if (credential == null) throw const CatalogFailure('not_paired');
    final snapshot = _snapshot ?? await widget.bridge.buildCatalogSnapshot();
    if (snapshot.catalogRootId != _directory.catalogRootId) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    await _syncSnapshot(snapshot, credential);
  });

  Future<void> _syncSnapshot(
    CatalogSnapshot snapshot,
    ActiveDeviceCredential credential,
  ) async {
    final client = CatalogSyncClient(credential: credential);
    try {
      final receipt = await client.sync(
        snapshot: snapshot,
        provider: _directory.provider ?? 'unknown',
      );
      if (!mounted) return;
      setState(() {
        _snapshot = snapshot;
        _syncStatus =
            '已同步 ${receipt.itemCount} 个文件 · 版本 ${receipt.acceptedSeq}';
      });
    } on CatalogSyncFailure catch (failure) {
      throw CatalogFailure(failure.code);
    } finally {
      client.close();
    }
  }

  Future<void> _setAndroidContentAnalysis(bool enabled) => _run(() async {
    final credential = widget.credential;
    if (enabled &&
        (credential == null ||
            !credential.grantedCapabilities.contains('content.analyze'))) {
      throw const CatalogFailure('capability_denied');
    }
    var remoteForgetPending = false;
    if (!enabled && credential != null && _directory.catalogRootId != null) {
      final client = AndroidOcrSyncClient(credential: credential);
      try {
        await client.forget(_directory.catalogRootId!);
      } on AndroidOcrSyncFailure {
        remoteForgetPending = true;
      } finally {
        client.close();
      }
    }
    final state = await widget.bridge.setContentAnalysisEnabled(enabled);
    final snapshot = await widget.bridge.buildCatalogSnapshot();
    if (!mounted) return;
    setState(() {
      _directory = state;
      _snapshot = snapshot;
      _ocrMessage = enabled
          ? '已允许在手机本地识别图片文字；原图不会发送到电脑。'
          : remoteForgetPending
          ? '手机端识别已关闭；电脑暂时离线，已加密投影会在 7 天内自动过期。'
          : '手机端识别已关闭，电脑中的加密文字投影已移除。';
    });
  });

  Future<void> _analyzeAndSyncImages() => _run(() async {
    final credential = widget.credential;
    if (credential == null) throw const CatalogFailure('not_paired');
    if (!credential.grantedCapabilities.contains('content.analyze') ||
        !credential.grantedCapabilities.contains('catalog.sync')) {
      throw const CatalogFailure('capability_denied');
    }
    final snapshot = await widget.bridge.buildCatalogSnapshot();
    if (!snapshot.contentAnalysisEnabled) {
      throw const CatalogFailure('ocr_opt_in_required');
    }
    final catalogClient = CatalogSyncClient(credential: credential);
    try {
      await catalogClient.sync(
        snapshot: snapshot,
        provider: _directory.provider ?? 'unknown',
      );
    } on CatalogSyncFailure catch (failure) {
      if (failure.code != 'transient_network') {
        throw CatalogFailure(failure.code);
      }
    } finally {
      catalogClient.close();
    }
    final projection = await widget.bridge.analyzeCatalogImages(snapshot);
    final ocrClient = AndroidOcrSyncClient(credential: credential);
    try {
      final receipt = await ocrClient.sync(projection);
      if (!mounted) return;
      setState(() {
        _snapshot = snapshot;
        _ocrMessage =
            '已在手机本地识别 ${receipt.acceptedCount} 张图片，'
            '其中 ${receipt.recognizedCount} 张识别到文字'
            '${receipt.lowConfidenceCount == 0 ? '' : '，${receipt.lowConfidenceCount} 张置信度较低且不会用于 AI 结论'}；'
            '原图未上传。';
      });
    } on AndroidOcrSyncFailure catch (failure) {
      throw CatalogFailure(
        failure.code == 'transient_network'
            ? 'ocr_persistence_unavailable'
            : failure.code,
      );
    } finally {
      ocrClient.close();
    }
  });

  Future<void> _retryPendingOcr() => _run(() async {
    final credential = widget.credential;
    if (credential == null) throw const CatalogFailure('not_paired');
    final catalogClient = CatalogSyncClient(credential: credential);
    try {
      await catalogClient.retryPending();
    } on CatalogSyncFailure catch (failure) {
      if (failure.code != 'outbox_empty') {
        throw CatalogFailure(failure.code);
      }
    } finally {
      catalogClient.close();
    }
    final client = AndroidOcrSyncClient(credential: credential);
    try {
      final receipt = await client.retryPending();
      if (!mounted) return;
      setState(() {
        _ocrMessage = '待发识别结果已同步，共 ${receipt.acceptedCount} 张；没有重新识别图片。';
      });
    } on AndroidOcrSyncFailure catch (failure) {
      throw CatalogFailure(failure.code);
    } finally {
      client.close();
    }
  });

  Future<void> _retryPending() => _run(() async {
    final credential = widget.credential;
    if (credential == null) throw const CatalogFailure('not_paired');
    final client = CatalogSyncClient(credential: credential);
    try {
      final receipt = await client.retryPending();
      if (!mounted) return;
      setState(() => _syncStatus = '待发清单已同步 · 版本 ${receipt.acceptedSeq}');
    } on CatalogSyncFailure catch (failure) {
      throw CatalogFailure(failure.code);
    } finally {
      client.close();
    }
  });

  Future<void> _loadToday() => _run(() async {
    final credential = widget.credential;
    if (credential == null) throw const CatalogFailure('not_paired');
    final client = CatalogSyncClient(credential: credential);
    try {
      final value = await client.fetchToday();
      final organizationStatus = await _loadOrganizationStatus(
        client,
        credential,
      );
      StudyPack? pack;
      if (credential.grantedCapabilities.contains('content.analyze')) {
        final contentClient = ContentInsightClient.device(
          credential: credential,
        );
        try {
          pack = await contentClient.latest();
        } finally {
          contentClient.close();
        }
      }
      if (!mounted) return;
      setState(() {
        _today = value;
        _studyPack = pack;
        _organizationStatus = organizationStatus;
      });
    } on CatalogSyncFailure catch (failure) {
      throw CatalogFailure(failure.code);
    } finally {
      client.close();
    }
  });

  Future<void> _generateStudyPack(String request) => _run(() async {
    final credential = widget.credential;
    if (credential == null) throw const CatalogFailure('not_paired');
    final client = ContentInsightClient.device(credential: credential);
    try {
      final pack = await client.generate(request: request);
      if (!mounted) return;
      setState(() {
        _studyPack = pack;
        _contentMessage = '资料简报已生成；未修改任何文件。';
      });
    } on ContentInsightFailure catch (failure) {
      throw CatalogFailure(
        failure.code == 'transient_network'
            ? 'content_transient_network'
            : failure.code,
      );
    } finally {
      client.close();
    }
  });

  Future<ClusterOrganizationStatus> _loadOrganizationStatus(
    CatalogSyncClient client,
    ActiveDeviceCredential credential,
  ) async {
    if (!credential.grantedCapabilities.contains('files.organize')) {
      return const ClusterOrganizationStatus.idle();
    }
    try {
      return await client.organizationStatus();
    } on CatalogSyncFailure catch (failure) {
      if (const {
        'organizer_journal_unavailable',
        'organizer_unavailable',
      }.contains(failure.code)) {
        return const ClusterOrganizationStatus.recoveryRequired();
      }
      rethrow;
    }
  }

  Future<void> _refreshOrganizationStatusOnly() async {
    final credential = widget.credential;
    if (credential == null ||
        !credential.grantedCapabilities.contains('files.organize')) {
      return;
    }
    final client = CatalogSyncClient(credential: credential);
    try {
      final value = await _loadOrganizationStatus(client, credential);
      if (mounted) setState(() => _organizationStatus = value);
    } finally {
      client.close();
    }
  }

  Future<ClusterOrganizationPreview> _previewOrganization(
    TodayCluster cluster,
    String projectionSha256,
  ) async {
    final credential = widget.credential;
    if (credential == null) {
      throw const CatalogSyncFailure('not_paired');
    }
    final client = CatalogSyncClient(credential: credential);
    try {
      return await client.previewOrganization(
        clusterId: cluster.clusterId,
        projectionSha256: projectionSha256,
      );
    } finally {
      client.close();
    }
  }

  Future<ClusterOrganizationReceipt> _executeOrganization(
    ClusterOrganizationPreview preview,
  ) async {
    final credential = widget.credential;
    if (credential == null) {
      throw const CatalogSyncFailure('not_paired');
    }
    final client = CatalogSyncClient(credential: credential);
    try {
      final receipt = await client.executeOrganization(preview: preview);
      if (mounted) {
        setState(
          () => _organizationStatus = ClusterOrganizationStatus.fromReceipt(
            receipt,
          ),
        );
      }
      return receipt;
    } finally {
      client.close();
    }
  }

  Future<ClusterOrganizationReceipt> _undoOrganization(String undoToken) async {
    final credential = widget.credential;
    if (credential == null) {
      throw const CatalogSyncFailure('not_paired');
    }
    final client = CatalogSyncClient(credential: credential);
    try {
      final receipt = await client.undoOrganization(undoToken);
      if (mounted) {
        setState(
          () => _organizationStatus = const ClusterOrganizationStatus.idle(),
        );
      }
      return receipt;
    } finally {
      client.close();
    }
  }

  Future<void> _forget() async {
    final confirmed =
        await showDialog<bool>(
          context: context,
          builder: (context) => AlertDialog(
            title: const Text('忘记手机资料目录？'),
            content: const Text(
              '这会移除 Data Steward 保存的目录授权和本地定位映射，'
              '不会删除或修改目录中的任何文件。',
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context, false),
                child: const Text('取消'),
              ),
              FilledButton(
                onPressed: () => Navigator.pop(context, true),
                child: const Text('确认忘记'),
              ),
            ],
          ),
        ) ??
        false;
    if (!confirmed || !mounted) return;
    await _run(() async {
      await widget.bridge.forgetCatalogDirectory();
      if (!mounted) return;
      setState(() {
        _directory = const CatalogDirectoryState.notAuthorized();
        _snapshot = null;
        _ocrMessage = null;
      });
    });
  }

  Future<void> _run(Future<void> Function() operation) async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _errorCode = null;
    });
    try {
      await operation();
    } on CatalogFailure catch (failure) {
      if (!mounted) return;
      setState(() {
        _errorCode = failure.code;
        if (const {
          'not_authorized',
          'permission_lost',
          'catalog_state_corrupt',
        }.contains(failure.code)) {
          _directory = const CatalogDirectoryState.notAuthorized();
          _snapshot = null;
        }
      });
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final snapshot = _snapshot;
    return Scaffold(
      appBar: AppBar(title: const Text('今日资料')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            TodayMaterialsView(
              projection: _today,
              loading: _busy,
              onRefresh: widget.credential != null && !_busy
                  ? _loadToday
                  : null,
              onPreviewOrganization:
                  widget.credential?.grantedCapabilities.contains(
                        'files.organize',
                      ) ==
                      true
                  ? _previewOrganization
                  : null,
              onExecuteOrganization:
                  widget.credential?.grantedCapabilities.contains(
                        'files.organize',
                      ) ==
                      true
                  ? _executeOrganization
                  : null,
              onUndoOrganization:
                  widget.credential?.grantedCapabilities.contains(
                        'files.organize',
                      ) ==
                      true
                  ? _undoOrganization
                  : null,
              onRefreshOrganizationStatus:
                  widget.credential?.grantedCapabilities.contains(
                        'files.organize',
                      ) ==
                      true
                  ? _refreshOrganizationStatusOnly
                  : null,
              organizationStatus: _organizationStatus,
              active: widget.active,
            ),
            const SizedBox(height: 24),
            Text('手机资料来源', style: theme.textTheme.headlineSmall),
            const SizedBox(height: 8),
            const Text('默认只同步本级文件元数据。你可以单独开启手机端图片文字识别；任何操作都不会修改原文件。'),
            const SizedBox(height: 16),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      _directory.authorized ? '资料目录已授权' : '尚未授权资料目录',
                      style: theme.textTheme.titleMedium,
                    ),
                    if (_directory.provider != null) ...[
                      const SizedBox(height: 8),
                      Text('系统提供方：${_directory.provider}'),
                    ],
                    if (_directory.authorized) ...[
                      const SizedBox(height: 6),
                      Text(_directory.restored ? '本次由持久授权恢复' : '本次刚刚完成授权'),
                      const SizedBox(height: 6),
                      const Text('手机目录默认只同步元数据；图片文字识别需要单独授权并手动触发'),
                    ],
                    if (_errorCode != null) ...[
                      const SizedBox(height: 10),
                      Text(
                        _safeError(_errorCode!),
                        style: TextStyle(color: theme.colorScheme.error),
                      ),
                    ],
                    if (_syncStatus != null) ...[
                      const SizedBox(height: 10),
                      Text(_syncStatus!),
                    ],
                    if (_busy) ...[
                      const SizedBox(height: 12),
                      const LinearProgressIndicator(
                        semanticsLabel: '资料目录操作进行中',
                      ),
                    ],
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                FilledButton(
                  onPressed: _busy ? null : _select,
                  child: Text(_directory.authorized ? '更换资料目录' : '选择资料目录'),
                ),
                FilledButton.tonal(
                  onPressed: _directory.authorized && !_busy ? _refresh : null,
                  child: Text(
                    widget.credential?.grantedCapabilities.contains(
                              'catalog.sync',
                            ) ==
                            true
                        ? '刷新并同步'
                        : '刷新本地清单',
                  ),
                ),
                FilledButton.tonalIcon(
                  onPressed:
                      _directory.authorized &&
                          !_busy &&
                          widget.credential != null
                      ? _sync
                      : null,
                  icon: const Icon(Icons.sync),
                  label: const Text('再次同步到电脑'),
                ),
                OutlinedButton.icon(
                  onPressed: !_busy && widget.credential != null
                      ? _retryPending
                      : null,
                  icon: const Icon(Icons.outbox_outlined),
                  label: const Text('重试待发清单'),
                ),
                OutlinedButton(
                  onPressed: _directory.authorized && !_busy ? _forget : null,
                  child: const Text('忘记资料目录'),
                ),
              ],
            ),
            if (_directory.authorized) ...[
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      SwitchListTile.adaptive(
                        contentPadding: EdgeInsets.zero,
                        title: const Text('允许手机端识别图片文字'),
                        subtitle: const Text(
                          '仅处理当前授权目录中的 JPG、JPEG、PNG。识别在手机本地完成，原图不会发送到电脑；文字投影会在电脑端加密保存。',
                        ),
                        value: _directory.contentAnalysisEnabled,
                        onChanged: _busy ? null : _setAndroidContentAnalysis,
                      ),
                      const SizedBox(height: 8),
                      Wrap(
                        spacing: 12,
                        runSpacing: 12,
                        children: [
                          FilledButton.icon(
                            onPressed:
                                !_busy &&
                                    _directory.contentAnalysisEnabled &&
                                    widget.credential?.grantedCapabilities
                                            .contains('content.analyze') ==
                                        true
                                ? _analyzeAndSyncImages
                                : null,
                            icon: const Icon(Icons.document_scanner_outlined),
                            label: const Text('识别并同步图片文字'),
                          ),
                          OutlinedButton.icon(
                            onPressed:
                                !_busy &&
                                    _directory.contentAnalysisEnabled &&
                                    widget.credential != null
                                ? _retryPendingOcr
                                : null,
                            icon: const Icon(Icons.outbox_outlined),
                            label: const Text('重试待发识别结果'),
                          ),
                        ],
                      ),
                      if (_ocrMessage != null) ...[
                        const SizedBox(height: 10),
                        Text(_ocrMessage!),
                      ],
                    ],
                  ),
                ),
              ),
            ],
            if (snapshot != null) ...[
              const SizedBox(height: 20),
              Text('本地清单', style: theme.textTheme.titleLarge),
              const SizedBox(height: 8),
              Text(
                '${snapshot.itemCount} 个文件'
                '${snapshot.skippedCount == 0 ? '' : ' · 跳过 ${snapshot.skippedCount} 项'}',
              ),
              const SizedBox(height: 8),
              if (snapshot.items.isEmpty)
                const Card(
                  child: Padding(
                    padding: EdgeInsets.all(16),
                    child: Text('目录中暂时没有可列出的本级文件。'),
                  ),
                )
              else
                Card(
                  child: Column(
                    children: [
                      for (final item in snapshot.items.take(20))
                        ListTile(
                          leading: Icon(_iconFor(item.mimeFamily)),
                          title: Text(item.displayName),
                          subtitle: Text(_itemSubtitle(item)),
                        ),
                      if (snapshot.items.length > 20)
                        Padding(
                          padding: const EdgeInsets.all(12),
                          child: Text(
                            '另有 ${snapshot.items.length - 20} 个文件未展开',
                          ),
                        ),
                    ],
                  ),
                ),
            ],
            const SizedBox(height: 20),
            ContentInsightView(
              pack: _studyPack,
              busy: _busy,
              canGenerate:
                  widget.credential?.grantedCapabilities.contains(
                    'content.analyze',
                  ) ==
                  true,
              onGenerate: _generateStudyPack,
              message: _contentMessage,
            ),
            const SizedBox(height: 12),
            ProactiveSuggestionView(
              client: _suggestionClient,
              knowledgeClient: _knowledgeExportClient,
              active: widget.active,
              canObserve:
                  widget.credential?.grantedCapabilities.contains(
                    'content.analyze',
                  ) ==
                  true,
              onPreviewOrganization:
                  widget.credential?.grantedCapabilities.contains(
                        'files.organize',
                      ) ==
                      true
                  ? _previewSuggestedOrganization
                  : null,
              onExecuteOrganization:
                  widget.credential?.grantedCapabilities.contains(
                        'files.organize',
                      ) ==
                      true
                  ? _executeOrganization
                  : null,
            ),
            const SizedBox(height: 12),
            KnowledgeExportView(
              client: _knowledgeExportClient,
              enabled:
                  widget.credential?.grantedCapabilities.contains(
                        'artifact.export',
                      ) ==
                      true &&
                  widget.credential?.grantedCapabilities.contains(
                        'content.analyze',
                      ) ==
                      true,
              active: widget.active,
              migrationRequired:
                  widget.credential != null &&
                  !widget.credential!.grantedCapabilities.contains(
                    'artifact.export',
                  ),
            ),
          ],
        ),
      ),
    );
  }

  String _safeError(String code) => switch (code) {
    'not_paired' => '请先与电脑完成安全配对。',
    'capability_denied' => '当前设备尚未获得资料同步权限，请重新配对。',
    'content_opt_in_required' => '请先在电脑端为当前资料目录开启内容理解。',
    'content_no_supported_files' => '电脑资料目录中没有可安全理解的文本或 Office/PDF 文件。',
    'content_document_encrypted' => '电脑中存在加密文档；未读取正文，请处理后手动重试。',
    'content_document_text_layer_missing' => 'PDF 没有文本层；当前版本不会自动进行 OCR。',
    'content_document_external_reference' ||
    'content_document_embedded_object' ||
    'content_document_invalid' ||
    'content_document_limit_exceeded' => '检测到异常或超限文档，本轮已安全停止。',
    'content_document_timeout' ||
    'content_document_parser_crashed' ||
    'content_document_parser_unavailable' => '电脑文档解析暂时不可用；系统不会自动重试。',
    'content_snapshot_stale' ||
    'content_revision_changed' => '资料已经变化，请先在电脑端刷新目录。',
    'content_transient_network' => '本轮生成响应超时；结果可能已经完成。请等待网络稳定后手动刷新显示，系统不会自动重试。',
    'ocr_opt_in_required' => '请先开启“允许手机端识别图片文字”。',
    'ocr_no_supported_images' ||
    'ocr_asset_not_allowed' => '当前目录没有可安全识别的 JPG、JPEG 或 PNG 图片。',
    'ocr_image_too_large' => '图片过大；单张最多 12 MiB，本轮最多处理 6 张。',
    'ocr_image_invalid' =>
      '图片无法安全解码或分辨率过高；请使用最长边不超过 8192、总像素不超过 1600 万的 JPG/PNG。',
    'ocr_image_stream_unavailable' => '手机文件服务暂时无法读取这张图片；请确认文件可正常打开后刷新目录。',
    'ocr_image_decode_failed' => '图片编码无法解析；请确认文件确实是有效的 JPG 或 PNG，而不是仅修改了扩展名。',
    'ocr_image_dimensions_unsafe' =>
      '图片分辨率超出安全范围；请使用最长边不超过 8192、总像素不超过 1600 万的图片。',
    'ocr_result_invalid' => '识别结果未通过完整性校验，本轮已停止，原图未修改。',
    'ocr_state_corrupt' => '手机端目录校验状态异常；请重新授权当前资料目录后再试。',
    'ocr_snapshot_stale' || 'ocr_revision_changed' => '目录或图片已经变化，请刷新本地清单后再试。',
    'ocr_timeout' || 'ocr_unavailable' => '手机端文字识别暂时不可用；系统不会自动重试。',
    'ocr_outbox_empty' => '当前没有等待同步的图片文字结果。',
    'ocr_outbox_corrupt' => '待发识别结果未通过完整性校验，已安全停止。',
    'ocr_persistence_unavailable' => '电脑暂时不可用；识别结果已安全保留，请等待网络稳定后手动重试。',
    'catalog_cursor_conflict' => '电脑目录版本已变化，请重新点击“同步到电脑”。',
    'outbox_empty' => '当前没有等待重试的资料清单。',
    'transient_network' ||
    'catalog_timeout' ||
    'catalog_persistence_unavailable' => '电脑暂时不可用，清单已安全保留；网络稳定后再重试。',
    'unsupported' => '当前平台不支持资料目录。',
    'picker_cancelled' => '已取消选择，原授权保持不变。',
    'busy' => '请等待当前目录操作完成。',
    'invalid_directory' => '请选择一个专用资料文件夹，不要选择整个存储空间。',
    'not_authorized' => '请先选择手机资料目录。',
    'permission_lost' => '目录授权已失效，请重新选择。',
    'catalog_state_corrupt' => '本地目录记录异常，请重新选择资料目录。',
    'catalog_too_large' => '目录项目过多，S5-A 最多读取 512 个本级项目。',
    'catalog_duplicate_entry' => '系统文件提供方返回了重复项目，本轮已安全停止。',
    'catalog_invalid_entry' => '系统文件提供方返回了异常元数据，本轮已安全停止。',
    'protocol_integrity_error' => '目录结果未通过完整性校验，本轮已安全停止。',
    _ => '资料目录操作未完成，未暴露底层路径或 URI。',
  };

  IconData _iconFor(String family) => switch (family) {
    'image' => Icons.image_outlined,
    'audio' => Icons.audio_file_outlined,
    'video' => Icons.video_file_outlined,
    'text' || 'document' => Icons.description_outlined,
    'archive' => Icons.archive_outlined,
    _ => Icons.insert_drive_file_outlined,
  };

  String _itemSubtitle(CatalogItem item) {
    final type = item.extension.isEmpty
        ? item.mimeFamily
        : item.extension.toUpperCase();
    final size = item.sizeBytes == null
        ? '大小未知'
        : _formatBytes(item.sizeBytes!);
    return '$type · $size';
  }

  String _formatBytes(int value) {
    if (value < 1024) return '$value B';
    if (value < 1024 * 1024) return '${(value / 1024).toStringAsFixed(1)} KiB';
    return '${(value / (1024 * 1024)).toStringAsFixed(1)} MiB';
  }
}
