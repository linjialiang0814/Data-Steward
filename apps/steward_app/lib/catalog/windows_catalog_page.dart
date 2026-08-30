import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../secure_pairing/pairing_crypto.dart';
import '../secure_pairing/strict_json.dart';
import '../shared_session_ui/windows_c3_bootstrap.dart';
import '../shared_session_ui/pc_file_scope_panel.dart';
import 'content_insight.dart';
import 'content_insight_client.dart';
import 'content_insight_view.dart';
import 'knowledge_export_client.dart';
import 'knowledge_export_view.dart';
import 'proactive_suggestion_client.dart';
import 'proactive_suggestion_view.dart';
import 'catalog_sync_client.dart';
import 'today_materials.dart';
import 'today_materials_view.dart';

final class WindowsCatalogPage extends StatefulWidget {
  const WindowsCatalogPage({
    required this.workspace,
    this.onOpenDevices,
    this.active = true,
    super.key,
  });
  final WindowsC3Workspace? workspace;
  final VoidCallback? onOpenDevices;
  final bool active;

  @override
  State<WindowsCatalogPage> createState() => _WindowsCatalogPageState();
}

final class _WindowsCatalogPageState extends State<WindowsCatalogPage> {
  List<Map<String, Object?>> _roots = const [];
  List<Map<String, Object?>> _assets = const [];
  TodayMaterialsProjection? _today;
  ContentPolicy? _contentPolicy;
  StudyPack? _studyPack;
  ClusterOrganizationStatus? _organizationStatus;
  PcFileScopeView? _pcScope;
  bool _busy = false;
  String? _message;
  String? _todayError;
  String? _contentMessage;
  KnowledgeExportClient? _knowledgeExportClient;
  ProactiveSuggestionClient? _suggestionClient;

  @override
  void initState() {
    super.initState();
    _attachScopeController(widget.workspace?.fileScopeController);
    _attachKnowledgeClient(widget.workspace);
    _attachSuggestionClient(widget.workspace);
  }

  @override
  void didUpdateWidget(covariant WindowsCatalogPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(
      oldWidget.workspace?.fileScopeController,
      widget.workspace?.fileScopeController,
    )) {
      _detachScopeController(oldWidget.workspace?.fileScopeController);
      _attachScopeController(widget.workspace?.fileScopeController);
    }
    if (!identical(oldWidget.workspace, widget.workspace)) {
      _knowledgeExportClient?.close();
      _suggestionClient?.close();
      _attachKnowledgeClient(widget.workspace);
      _attachSuggestionClient(widget.workspace);
    }
    if (oldWidget.workspace == null && widget.workspace != null) {
      unawaited(_load());
    }
  }

  void _attachScopeController(PcFileScopeController? controller) {
    if (controller == null) return;
    _pcScope = controller.scope;
    controller.addListener(_scopeChanged);
  }

  void _attachKnowledgeClient(WindowsC3Workspace? workspace) {
    if (workspace == null) {
      _knowledgeExportClient = null;
      return;
    }
    _knowledgeExportClient = KnowledgeExportClient.operator(
      baseUri: workspace.ready.localUrl,
      operatorToken: workspace.ready.operatorToken,
    );
  }

  void _attachSuggestionClient(WindowsC3Workspace? workspace) {
    if (workspace == null) {
      _suggestionClient = null;
      return;
    }
    _suggestionClient = ProactiveSuggestionClient.operator(
      baseUri: workspace.ready.localUrl,
      operatorToken: workspace.ready.operatorToken,
    );
  }

  void _detachScopeController(PcFileScopeController? controller) {
    controller?.removeListener(_scopeChanged);
  }

  void _scopeChanged() {
    final value = widget.workspace?.fileScopeController.scope;
    if (!mounted || value == null) return;
    final previous = _pcScope;
    setState(() => _pcScope = value);
    if (previous?.configured != value.configured ||
        previous?.rootId != value.rootId) {
      unawaited(_refresh());
    }
  }

  @override
  void dispose() {
    _detachScopeController(widget.workspace?.fileScopeController);
    _knowledgeExportClient?.close();
    _suggestionClient?.close();
    super.dispose();
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

  Future<void> _load() => _run(refreshPc: false);
  Future<void> _refresh() => _run(refreshPc: true);

  Future<void> _run({required bool refreshPc}) async {
    final workspace = widget.workspace;
    if (_busy || workspace == null) return;
    setState(() {
      _busy = true;
      _message = null;
      _todayError = null;
      _contentMessage = null;
    });
    final client = http.Client();
    try {
      final pcScope = await _loadPcScope();
      final headers = {
        'accept': 'application/json',
        'authorization':
            'DataSteward-Operator ${workspace.ready.operatorToken}',
        'x-datasteward-protocol': pairingProtocolVersion,
      };
      if (refreshPc && pcScope.configured) {
        final response = await client
            .post(
              workspace.ready.localUrl.replace(
                path: '/v1/operator/catalog/refresh-pc',
              ),
              headers: headers,
            )
            .timeout(const Duration(seconds: 12));
        if (response.statusCode != 200) throw const FormatException();
      }
      final contentClient = ContentInsightClient.operator(
        baseUri: workspace.ready.localUrl,
        operatorToken: workspace.ready.operatorToken,
        client: client,
      );
      final contentPolicy = await contentClient.status();
      if (!mounted) return;
      setState(() => _contentPolicy = contentPolicy);
      final studyPack = await contentClient.latest();
      if (!mounted) return;
      setState(() => _studyPack = studyPack);
      final response = await client
          .get(
            workspace.ready.localUrl.replace(
              path: '/v1/operator/catalog/summary',
            ),
            headers: headers,
          )
          .timeout(const Duration(seconds: 12));
      if (response.statusCode != 200 ||
          !(response.headers['content-type']?.toLowerCase().startsWith(
                'application/json',
              ) ??
              false) ||
          response.bodyBytes.length > 768 * 1024) {
        throw const FormatException();
      }
      final value = decodeStrictJsonObject(
        utf8.decode(response.bodyBytes),
        maxUtf8Bytes: 768 * 1024,
      );
      const summaryKeys = {
        'roots',
        'assets',
        'root_count',
        'asset_count',
        'projection_sha256',
      };
      if (value.length != summaryKeys.length ||
          !value.keys.toSet().containsAll(summaryKeys) ||
          value['roots'] is! List<Object?> ||
          value['assets'] is! List<Object?> ||
          value['root_count'] is! int ||
          value['asset_count'] is! int) {
        throw const FormatException();
      }
      final roots = (value['roots']! as List<Object?>)
          .map(_object)
          .toList(growable: false);
      final assets = (value['assets']! as List<Object?>)
          .map(_object)
          .toList(growable: false);
      if (value['root_count'] != roots.length ||
          value['asset_count'] != assets.length) {
        throw const FormatException();
      }
      final todayResponse = await client
          .get(
            workspace.ready.localUrl.replace(
              path: '/v1/operator/catalog/today',
            ),
            headers: headers,
          )
          .timeout(const Duration(seconds: 12));
      if (todayResponse.statusCode != 200 ||
          !(todayResponse.headers['content-type']?.toLowerCase().startsWith(
                'application/json',
              ) ??
              false) ||
          todayResponse.bodyBytes.length > 768 * 1024) {
        throw const FormatException();
      }
      final today = TodayMaterialsProjection.fromJson(
        decodeStrictJsonObject(
          utf8.decode(todayResponse.bodyBytes),
          maxUtf8Bytes: 768 * 1024,
        ),
      );
      final organizationStatus = await _loadOrganizationStatus();
      if (!mounted) return;
      setState(() {
        _roots = roots;
        _assets = assets;
        _today = today;
        _organizationStatus = organizationStatus;
        _pcScope = pcScope;
        _todayError = pcScope.configured
            ? null
            : '电脑目录授权已失效，旧清单只供查看。请前往“设备”重新授权；系统不会自动整理文件。';
        _message = refreshPc
            ? pcScope.configured
                  ? '电脑目录已刷新，双设备目录已合并。'
                  : '请先在“设备”重新授权电脑目录。'
            : null;
      });
    } on Object {
      if (mounted) {
        setState(() {
          _message = '目录暂时不可用，请等待服务稳定后重试。';
          _todayError = '今日资料暂时不可用；系统没有循环重试。';
        });
      }
    } finally {
      client.close();
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<PcFileScopeView> _loadPcScope() async {
    final workspace = widget.workspace;
    if (workspace == null) {
      throw const CatalogSyncFailure('transient_network');
    }
    final client = PcFileScopeClient(
      baseUri: workspace.ready.localUrl,
      operatorToken: workspace.ready.operatorToken,
    );
    try {
      return await client.status();
    } finally {
      client.close();
    }
  }

  Future<void> _toggleContent(bool enabled) async {
    final workspace = widget.workspace;
    if (_busy || workspace == null) return;
    if (enabled) {
      final confirmed =
          await showDialog<bool>(
            context: context,
            builder: (context) => AlertDialog(
              title: const Text('允许 AI 理解此电脑资料？'),
              content: const Text(
                '仅会读取当前授权目录本级、清单修订一致的 TXT/MD 文本。'
                '单文件和单次分析均有上限；不会执行文档中的指令，也不会修改文件。',
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.pop(context, false),
                  child: const Text('取消'),
                ),
                FilledButton(
                  onPressed: () => Navigator.pop(context, true),
                  child: const Text('允许内容理解'),
                ),
              ],
            ),
          ) ??
          false;
      if (!confirmed || !mounted) return;
    }
    setState(() {
      _busy = true;
      _contentMessage = null;
    });
    final client = ContentInsightClient.operator(
      baseUri: workspace.ready.localUrl,
      operatorToken: workspace.ready.operatorToken,
    );
    try {
      final policy = await client.setOptIn(enabled);
      if (!mounted) return;
      setState(() {
        _contentPolicy = policy;
        _contentMessage = enabled
            ? '已允许受控理解 TXT/MD；系统不会自动分析。'
            : '内容理解已关闭；后续不会读取正文或调用 AI。';
      });
    } on ContentInsightFailure catch (failure) {
      if (mounted) {
        setState(() => _contentMessage = _safeContentError(failure.code));
      }
    } finally {
      client.close();
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _generateStudyPack(String request) async {
    final workspace = widget.workspace;
    if (_busy || workspace == null) return;
    setState(() {
      _busy = true;
      _contentMessage = null;
    });
    final client = ContentInsightClient.operator(
      baseUri: workspace.ready.localUrl,
      operatorToken: workspace.ready.operatorToken,
    );
    try {
      final pack = await client.generate(request: request);
      if (!mounted) return;
      setState(() {
        _studyPack = pack;
        _contentMessage = '资料简报已生成；未修改任何文件。';
      });
    } on ContentInsightFailure catch (failure) {
      if (mounted) {
        setState(() => _contentMessage = _safeContentError(failure.code));
      }
    } finally {
      client.close();
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<ClusterOrganizationPreview> _previewOrganization(
    TodayCluster cluster,
    String projectionSha256,
  ) async {
    final value = await _organizationPost('/preview', {
      'schema_version': clusterOrganizationSchema,
      'cluster_id': cluster.clusterId,
      'projection_sha256': projectionSha256,
    });
    const keys = {
      'schema_version',
      'cluster_id',
      'cluster_title',
      'projection_sha256',
      'preview_sha256',
      'pc_file_count',
      'virtual_file_count',
      'category_counts',
      'can_execute',
    };
    if (value.length != keys.length ||
        !value.keys.toSet().containsAll(keys) ||
        value['schema_version'] != clusterOrganizationSchema ||
        value['cluster_id'] != cluster.clusterId ||
        value['projection_sha256'] != projectionSha256 ||
        value['can_execute'] != true) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return ClusterOrganizationPreview(
      clusterId: cluster.clusterId,
      clusterTitle: _organizationString(value['cluster_title']),
      projectionSha256: projectionSha256,
      previewSha256: _organizationDigest(value['preview_sha256']),
      pcFileCount: _organizationCount(value['pc_file_count']),
      virtualFileCount: _organizationCount(value['virtual_file_count']),
      categoryCounts: _organizationCategories(value['category_counts']),
    );
  }

  Future<ClusterOrganizationReceipt> _executeOrganization(
    ClusterOrganizationPreview preview,
  ) async {
    final receipt = _organizationReceipt(
      await _organizationPost('/execute', {
        'schema_version': clusterOrganizationSchema,
        'cluster_id': preview.clusterId,
        'projection_sha256': preview.projectionSha256,
        'preview_sha256': preview.previewSha256,
      }),
      'organize',
    );
    if (mounted) {
      setState(
        () => _organizationStatus = ClusterOrganizationStatus.fromReceipt(
          receipt,
        ),
      );
    }
    return receipt;
  }

  Future<ClusterOrganizationReceipt> _undoOrganization(String undoToken) async {
    final receipt = _organizationReceipt(
      await _organizationPost('/undo', {
        'schema_version': clusterOrganizationSchema,
        'undo_token': undoToken,
      }),
      'undo',
    );
    if (mounted) {
      setState(
        () => _organizationStatus = const ClusterOrganizationStatus.idle(),
      );
    }
    return receipt;
  }

  Future<ClusterOrganizationStatus> _loadOrganizationStatus() async {
    try {
      return ClusterOrganizationStatus.fromJson(
        await _organizationGet('/status'),
      );
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
    final value = await _loadOrganizationStatus();
    if (mounted) setState(() => _organizationStatus = value);
  }

  Future<Map<String, Object?>> _organizationGet(String operation) async {
    final workspace = widget.workspace;
    if (workspace == null) {
      throw const CatalogSyncFailure('transient_network');
    }
    final client = http.Client();
    try {
      final response = await client
          .get(
            workspace.ready.localUrl.replace(
              path: '/v1/operator/catalog/organization$operation',
            ),
            headers: {
              'accept': 'application/json',
              'authorization':
                  'DataSteward-Operator ${workspace.ready.operatorToken}',
              'x-datasteward-protocol': pairingProtocolVersion,
            },
          )
          .timeout(const Duration(seconds: 12));
      if (!(response.headers['content-type']?.toLowerCase().startsWith(
            'application/json',
          ) ??
          false)) {
        throw const CatalogSyncFailure('protocol_integrity_error');
      }
      final value = decodeStrictJsonObject(
        utf8.decode(response.bodyBytes),
        maxUtf8Bytes: 768 * 1024,
      );
      if (response.statusCode != 200) {
        final code = value['error_code'];
        if (code is! String || value['message_key'] != code) {
          throw const CatalogSyncFailure('protocol_integrity_error');
        }
        throw CatalogSyncFailure(code);
      }
      return value;
    } on CatalogSyncFailure {
      rethrow;
    } on Object {
      throw const CatalogSyncFailure('transient_network');
    } finally {
      client.close();
    }
  }

  Future<Map<String, Object?>> _organizationPost(
    String operation,
    Map<String, Object?> body,
  ) async {
    final workspace = widget.workspace;
    if (workspace == null) {
      throw const CatalogSyncFailure('transient_network');
    }
    final client = http.Client();
    try {
      final response = await client
          .post(
            workspace.ready.localUrl.replace(
              path: '/v1/operator/catalog/organization$operation',
            ),
            headers: {
              'accept': 'application/json',
              'content-type': 'application/json',
              'authorization':
                  'DataSteward-Operator ${workspace.ready.operatorToken}',
              'x-datasteward-protocol': pairingProtocolVersion,
            },
            body: jsonEncode(body),
          )
          .timeout(const Duration(seconds: 12));
      if (!(response.headers['content-type']?.toLowerCase().startsWith(
            'application/json',
          ) ??
          false)) {
        throw const CatalogSyncFailure('protocol_integrity_error');
      }
      final value = decodeStrictJsonObject(
        utf8.decode(response.bodyBytes),
        maxUtf8Bytes: 768 * 1024,
      );
      if (response.statusCode != 200) {
        final code = value['error_code'];
        if (code is! String || value['message_key'] != code) {
          throw const CatalogSyncFailure('protocol_integrity_error');
        }
        throw CatalogSyncFailure(code);
      }
      return value;
    } on CatalogSyncFailure {
      rethrow;
    } on Object {
      throw const CatalogSyncFailure('transient_network');
    } finally {
      client.close();
    }
  }

  ClusterOrganizationReceipt _organizationReceipt(
    Map<String, Object?> value,
    String operation,
  ) {
    const keys = {
      'schema_version',
      'operation',
      'cluster_id',
      'moved_count',
      'category_counts',
      'undo_token',
      'catalog_refresh_pending',
    };
    if (value.length != keys.length ||
        !value.keys.toSet().containsAll(keys) ||
        value['schema_version'] != clusterOrganizationSchema ||
        value['operation'] != operation ||
        value['catalog_refresh_pending'] is! bool) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return ClusterOrganizationReceipt(
      operation: operation,
      clusterId: value['cluster_id'] is String
          ? value['cluster_id']! as String
          : throw const CatalogSyncFailure('protocol_integrity_error'),
      movedCount: _organizationCount(value['moved_count']),
      categoryCounts: _organizationCategories(value['category_counts']),
      undoToken: _organizationString(value['undo_token']),
      catalogRefreshPending: value['catalog_refresh_pending']! as bool,
    );
  }

  String _organizationString(Object? value) {
    if (value is! String || value.isEmpty || value.length > 128) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return value;
  }

  String _organizationDigest(Object? value) {
    final result = _organizationString(value);
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(result)) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return result;
  }

  int _organizationCount(Object? value) {
    if (value is! int || value < 0 || value > 512) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return value;
  }

  Map<String, int> _organizationCategories(Object? value) {
    const categories = {'images', 'documents', 'media', 'archives', 'other'};
    if (value is! Map<String, Object?> ||
        value.length != categories.length ||
        !value.keys.toSet().containsAll(categories)) {
      throw const CatalogSyncFailure('protocol_integrity_error');
    }
    return {
      for (final category in categories)
        category: _organizationCount(value[category]),
    };
  }

  String _formatCounts(Map<String, int> counts) {
    if (counts.isEmpty) return '';
    const labels = {
      'txt': 'TXT',
      'md': 'Markdown',
      'docx': 'DOCX',
      'pptx': 'PPTX',
      'pdf': 'PDF',
    };
    final parts = counts.entries
        .map((entry) => '${labels[entry.key]} ${entry.value}')
        .join(' · ');
    return '（$parts）';
  }

  String _safeContentError(String code) => switch (code) {
    'content_scope_unconfigured' => '请先授权并刷新电脑资料目录。',
    'content_opt_in_required' => '请先明确开启此目录的内容理解。',
    'content_no_supported_files' => '当前目录没有可安全理解的文本或 Office/PDF 文件。',
    'content_document_encrypted' => '检测到加密文档；未读取正文，请解密副本后再试。',
    'content_document_text_layer_missing' => 'PDF 没有可读取的文本层；本轮未执行 OCR。',
    'content_document_external_reference' ||
    'content_document_embedded_object' ||
    'content_document_invalid' ||
    'content_document_limit_exceeded' => '检测到异常或超限文档，内容理解已安全停止。',
    'content_document_timeout' ||
    'content_document_parser_crashed' ||
    'content_document_parser_unavailable' => '文档解析暂时不可用；系统不会自动重试。',
    'content_snapshot_stale' ||
    'content_revision_changed' => '资料已发生变化，请刷新目录后再生成。',
    'transient_network' ||
    'planner_unavailable' ||
    'planner_rate_limited' => 'AI 暂时不可用；请等待网络稳定后再手动尝试。',
    _ => '本轮内容理解已安全停止，没有自动重试。',
  };

  Map<String, Object?> _object(Object? value) {
    if (value is! Map<String, Object?>) throw const FormatException();
    const rootKeys = {
      'device_id',
      'catalog_root_id',
      'platform',
      'provider',
      'display_name',
      'catalog_seq',
      'snapshot_sha256',
      'item_count',
      'skipped_count',
      'last_synced_at',
    };
    const assetKeys = {
      'asset_id',
      'device_id',
      'catalog_root_id',
      'platform',
      'source_display_name',
      'locator_token',
      'display_name',
      'extension',
      'mime_family',
      'size_bytes',
      'modified_at_ms',
      'observed_at',
      'revision',
      'content_eligible',
      'catalog_seq',
      'deleted_at',
    };
    final expected = value.containsKey('asset_id') ? assetKeys : rootKeys;
    final displayName = value['display_name'];
    if (value.length != expected.length ||
        !value.keys.toSet().containsAll(expected) ||
        !const {'android', 'windows'}.contains(value['platform']) ||
        displayName is! String ||
        displayName.isEmpty ||
        displayName.length > 255 ||
        displayName.runes.any((rune) => rune < 0x20 || rune == 0x7f)) {
      throw const FormatException();
    }
    return value;
  }

  @override
  Widget build(BuildContext context) {
    final canOrganize =
        widget.workspace != null && _pcScope?.configured == true && !_busy;
    return Scaffold(
      appBar: AppBar(title: const Text('今日资料')),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          TodayMaterialsView(
            projection: _today,
            loading: _busy,
            onRefresh: widget.workspace != null && !_busy ? _refresh : null,
            errorMessage: _todayError,
            onPreviewOrganization: canOrganize ? _previewOrganization : null,
            onExecuteOrganization: canOrganize ? _executeOrganization : null,
            onUndoOrganization: canOrganize ? _undoOrganization : null,
            onRefreshOrganizationStatus: canOrganize
                ? _refreshOrganizationStatusOnly
                : null,
            organizationStatus: _organizationStatus,
            active: widget.active,
          ),
          const SizedBox(height: 16),
          Card(
            child: SwitchListTile(
              title: const Text('允许 AI 理解此电脑资料'),
              subtitle: Text(
                _contentPolicy == null
                    ? '正在读取内容授权状态…'
                    : '当前可安全分析 ${_contentPolicy!.supportedFileCount} 个文件'
                          '${_formatCounts(_contentPolicy!.supportedFormatCounts)}；默认不会自动分析。',
              ),
              value: _contentPolicy?.contentOptIn ?? false,
              onChanged: _contentPolicy?.configured == true && !_busy
                  ? _toggleContent
                  : null,
            ),
          ),
          const SizedBox(height: 12),
          ContentInsightView(
            pack: _studyPack,
            busy: _busy,
            canGenerate: _contentPolicy?.contentOptIn == true,
            onGenerate: _generateStudyPack,
            message: _contentMessage,
          ),
          const SizedBox(height: 12),
          ProactiveSuggestionView(
            client: _suggestionClient,
            knowledgeClient: _knowledgeExportClient,
            active: widget.active,
            canObserve:
                _contentPolicy?.contentOptIn == true &&
                _pcScope?.configured == true,
            onPreviewOrganization: _pcScope?.configured == true
                ? _previewSuggestedOrganization
                : null,
            onExecuteOrganization: _pcScope?.configured == true
                ? _executeOrganization
                : null,
          ),
          const SizedBox(height: 12),
          KnowledgeExportView(
            client: _knowledgeExportClient,
            enabled:
                _contentPolicy?.contentOptIn == true &&
                _pcScope?.configured == true,
            active: widget.active,
          ),
          const SizedBox(height: 24),
          Text('资料来源', style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 8),
          const Text('只同步文件名、类型、大小和时间等元数据；不会读取正文，也不会修改文件。'),
          const SizedBox(height: 6),
          const Text(
            '手机目录由手机 App 进入“今日资料”、从文件管理器返回或点击“刷新并同步”时更新；'
            'Windows 刷新不会越权扫描手机文件。',
          ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 12,
            children: [
              FilledButton.icon(
                onPressed: canOrganize ? _refresh : null,
                icon: const Icon(Icons.sync),
                label: const Text('刷新电脑目录'),
              ),
              OutlinedButton(
                onPressed: widget.workspace != null && !_busy ? _load : null,
                child: const Text('刷新已同步资料'),
              ),
              if (_pcScope?.configured == false && widget.onOpenDevices != null)
                OutlinedButton.icon(
                  key: const Key('s6-open-device-scope'),
                  onPressed: _busy ? null : widget.onOpenDevices,
                  icon: const Icon(Icons.folder_open_outlined),
                  label: const Text('前往设备重新授权'),
                ),
            ],
          ),
          if (_busy) ...[
            const SizedBox(height: 12),
            const LinearProgressIndicator(),
          ],
          if (_message != null) ...[
            const SizedBox(height: 12),
            Text(_message!),
          ],
          const SizedBox(height: 20),
          Text('${_roots.length} 个目录 · ${_assets.length} 个文件'),
          const SizedBox(height: 8),
          for (final asset in _assets.take(40))
            Card(
              child: ListTile(
                leading: Icon(
                  asset['platform'] == 'android'
                      ? Icons.smartphone_outlined
                      : Icons.computer_outlined,
                ),
                title: Text(asset['display_name']?.toString() ?? '未知文件'),
                subtitle: Text(
                  '${asset['source_display_name'] ?? '资料目录'} · '
                  '${asset['platform'] == 'android' ? '手机' : '电脑'}',
                ),
              ),
            ),
        ],
      ),
    );
  }
}
