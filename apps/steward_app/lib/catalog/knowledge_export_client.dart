import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:http/http.dart' as http;

import '../secure_pairing/pairing_crypto.dart';
import '../secure_pairing/pairing_vault.dart';
import '../secure_pairing/pinned_transport.dart';
import '../secure_pairing/strict_json.dart';
import '../shared_session/authenticated_transport.dart';

const knowledgeExportSchema = 'data-steward.artifact-export/v1';
const _maxArtifactResponseBytes = 256 * 1024;
const _artifactTimeout = Duration(seconds: 80);

final class KnowledgeExportFailure implements Exception {
  const KnowledgeExportFailure(this.code);
  final String code;
}

final class KnowledgeCitationView {
  const KnowledgeCitationView({
    required this.platform,
    required this.sourceDisplayName,
    required this.displayName,
    required this.basis,
  });

  final String platform;
  final String sourceDisplayName;
  final String displayName;
  final String basis;
}

final class KnowledgePackView {
  const KnowledgePackView({
    required this.packId,
    required this.kind,
    required this.title,
    required this.summary,
    required this.citations,
    required this.source,
    required this.crossDevice,
  });

  final String packId;
  final String kind;
  final String title;
  final String summary;
  final List<KnowledgeCitationView> citations;
  final String source;
  final bool crossDevice;
}

final class KnowledgeExportPreview {
  const KnowledgeExportPreview({
    required this.pack,
    required this.targetDisplayName,
    required this.outputDirectory,
    required this.filename,
    required this.byteCount,
    required this.previewSha256,
  });

  final KnowledgePackView pack;
  final String targetDisplayName;
  final String outputDirectory;
  final String filename;
  final int byteCount;
  final String previewSha256;
}

final class KnowledgeExportStatus {
  const KnowledgeExportStatus({
    required this.state,
    required this.filename,
    required this.byteCount,
    required this.canUndo,
    required this.undoToken,
  });

  final String state;
  final String? filename;
  final int byteCount;
  final bool canUndo;
  final String? undoToken;
}

final class KnowledgeExportClient {
  factory KnowledgeExportClient.operator({
    required Uri baseUri,
    required String operatorToken,
    http.Client? client,
  }) => KnowledgeExportClient._(
    baseUri,
    null,
    operatorToken,
    client ?? http.Client(),
  );

  factory KnowledgeExportClient.device({
    required ActiveDeviceCredential credential,
    http.Client? client,
  }) => KnowledgeExportClient._(
    credential.baseUrl,
    credential,
    null,
    client ??
        PinnedAuthenticatedHttpClient(
          credential: credential,
          transport: const IoPinFirstTransport(
            timeout: _artifactTimeout,
            maxResponseBytes: _maxArtifactResponseBytes,
          ),
        ),
  );

  KnowledgeExportClient._(
    this._baseUri,
    this._credential,
    this._operatorToken,
    this._client,
  );

  final Uri _baseUri;
  final ActiveDeviceCredential? _credential;
  final String? _operatorToken;
  final http.Client _client;

  Future<KnowledgeExportPreview> prepare({
    required String kind,
    required String request,
  }) async {
    _requireCapabilities(prepare: true);
    final response = await _send(
      'POST',
      '/prepare',
      body: jsonEncode({'kind': kind, 'request': request}),
    );
    if (response.statusCode != 200) _throwResponse(response);
    return _preview(_object(response.body));
  }

  Future<KnowledgeExportStatus> execute(
    KnowledgeExportPreview preview, {
    required String idempotencyKey,
  }) async {
    _requireCapabilities();
    if (!RegExp(r'^export-[0-9a-f]{32}$').hasMatch(idempotencyKey)) {
      throw const KnowledgeExportFailure('artifact_request_invalid');
    }
    final response = await _send(
      'POST',
      '/execute',
      body: jsonEncode({
        'schema_version': knowledgeExportSchema,
        'kind': preview.pack.kind,
        'pack_id': preview.pack.packId,
        'preview_sha256': preview.previewSha256,
        'idempotency_key': idempotencyKey,
      }),
    );
    if (response.statusCode != 200) _throwResponse(response);
    _receipt(response.body);
    return status();
  }

  Future<KnowledgeExportStatus> status() async {
    _requireCapabilities();
    final response = await _send('GET', '/status');
    if (response.statusCode != 200) _throwResponse(response);
    return _status(_object(response.body));
  }

  Future<KnowledgeExportStatus> undo(String undoToken) async {
    _requireCapabilities();
    final response = await _send(
      'POST',
      '/undo',
      body: jsonEncode({
        'schema_version': knowledgeExportSchema,
        'undo_token': undoToken,
      }),
    );
    if (response.statusCode != 200) _throwResponse(response);
    _receipt(response.body);
    return status();
  }

  void _requireCapabilities({bool prepare = false}) {
    final credential = _credential;
    if (credential == null) return;
    final granted = credential.grantedCapabilities;
    if (!granted.contains('artifact.export') ||
        (prepare && !granted.contains('content.analyze'))) {
      throw const KnowledgeExportFailure('capability_denied');
    }
  }

  String get _prefix =>
      _credential == null ? '/v1/operator/artifacts' : '/v1/artifacts';

  Future<http.Response> _send(
    String method,
    String path, {
    String? body,
  }) async {
    try {
      final request = http.Request(
        method,
        _baseUri.replace(path: '$_prefix$path'),
      )..headers['accept'] = 'application/json';
      final token = _operatorToken;
      if (token != null) {
        request.headers['authorization'] = 'DataSteward-Operator $token';
        request.headers['x-datasteward-protocol'] = pairingProtocolVersion;
      }
      if (body != null) {
        request.headers['content-type'] = 'application/json';
        request.body = body;
      }
      final streamed = await _client.send(request).timeout(_artifactTimeout);
      final type = streamed.headers['content-type']?.toLowerCase();
      if (type == null || !type.startsWith('application/json')) {
        throw const KnowledgeExportFailure('protocol_integrity_error');
      }
      final bytes = <int>[];
      await for (final chunk in streamed.stream) {
        if (bytes.length + chunk.length > _maxArtifactResponseBytes) {
          throw const KnowledgeExportFailure('protocol_integrity_error');
        }
        bytes.addAll(chunk);
      }
      return http.Response.bytes(
        bytes,
        streamed.statusCode,
        headers: streamed.headers,
      );
    } on KnowledgeExportFailure {
      rethrow;
    } on Object {
      throw const KnowledgeExportFailure('transient_network');
    }
  }

  Map<String, Object?> _object(String source) {
    try {
      return decodeStrictJsonObject(
        source,
        maxUtf8Bytes: _maxArtifactResponseBytes,
      );
    } on Object {
      throw const KnowledgeExportFailure('protocol_integrity_error');
    }
  }

  KnowledgeExportPreview _preview(Map<String, Object?> value) {
    try {
      _schema(value);
      final pack = _map(value['pack']);
      _exact(value, {
        'schema_version',
        'pack',
        'target_display_name',
        'output_directory',
        'filename',
        'byte_count',
        'preview_sha256',
        'requires_confirmation',
      });
      if (value['requires_confirmation'] != true) throw const FormatException();
      return KnowledgeExportPreview(
        pack: _pack(pack),
        targetDisplayName: _string(value['target_display_name']),
        outputDirectory: _string(value['output_directory']),
        filename: _string(value['filename']),
        byteCount: _integer(value['byte_count']),
        previewSha256: _digest(value['preview_sha256']),
      );
    } on Object {
      throw const KnowledgeExportFailure('protocol_integrity_error');
    }
  }

  KnowledgePackView _pack(Map<String, Object?> value) {
    _exact(value, {
      'schema_version',
      'pack_id',
      'kind',
      'title',
      'summary',
      'topics',
      'review_points',
      'citations',
      'source',
      'cross_device',
      'created_at',
      'projection_sha256',
    });
    if (value['schema_version'] != 'data-steward.knowledge-pack/v1') {
      throw const FormatException();
    }
    final raw = value['citations'];
    if (raw is! List || raw.isEmpty || raw.length > 12) {
      throw const FormatException();
    }
    final citations = raw
        .map((item) {
          final citation = _map(item);
          _exact(citation, {
            'citation_id',
            'platform',
            'source_display_name',
            'display_name',
            'modified_at_ms',
            'basis',
          });
          return KnowledgeCitationView(
            platform: _string(citation['platform']),
            sourceDisplayName: _string(citation['source_display_name']),
            displayName: _string(citation['display_name']),
            basis: _string(citation['basis']),
          );
        })
        .toList(growable: false);
    return KnowledgePackView(
      packId: _string(value['pack_id']),
      kind: _string(value['kind']),
      title: _string(value['title']),
      summary: _string(value['summary']),
      citations: citations,
      source: _string(value['source']),
      crossDevice: value['cross_device'] as bool,
    );
  }

  KnowledgeExportStatus _status(Map<String, Object?> value) {
    try {
      _schema(value);
      _exact(value, {
        'schema_version',
        'state',
        'export_id',
        'pack_id',
        'filename',
        'byte_count',
        'can_undo',
        'undo_token',
      });
      return KnowledgeExportStatus(
        state: _string(value['state']),
        filename: _nullableString(value['filename']),
        byteCount: _integer(value['byte_count'], allowZero: true),
        canUndo: value['can_undo'] as bool,
        undoToken: _nullableString(value['undo_token']),
      );
    } on Object {
      throw const KnowledgeExportFailure('protocol_integrity_error');
    }
  }

  void _receipt(String source) {
    final value = _object(source);
    _schema(value);
    _exact(value, {
      'schema_version',
      'export_id',
      'pack_id',
      'state',
      'filename',
      'byte_count',
      'undo_token',
      'deduplicated',
    });
    if (!RegExp(
          r'^artifact-[0-9a-f]{16}$',
        ).hasMatch(_string(value['export_id'])) ||
        !RegExp(r'^kp-[0-9a-f]{16}$').hasMatch(_string(value['pack_id'])) ||
        !{'completed', 'undone'}.contains(_string(value['state'])) ||
        _string(value['filename']).length > 120 ||
        _integer(value['byte_count']) > 128 * 1024 ||
        value['deduplicated'] is! bool ||
        (value['undo_token'] != null && value['undo_token'] is! String)) {
      throw const KnowledgeExportFailure('protocol_integrity_error');
    }
  }

  Never _throwResponse(http.Response response) {
    final value = _object(response.body);
    final code = value['error_code'];
    final message = value['message_key'];
    if (value.length != 2 ||
        code is! String ||
        message is! String ||
        !{code, 'operator.$code', 'auth.$code'}.contains(message)) {
      throw const KnowledgeExportFailure('protocol_integrity_error');
    }
    throw KnowledgeExportFailure(code);
  }

  void close() => _client.close();
}

Map<String, Object?> _map(Object? value) {
  if (value is! Map<String, Object?>) throw const FormatException();
  return value;
}

void _exact(Map<String, Object?> value, Set<String> keys) {
  if (value.keys.toSet().difference(keys).isNotEmpty ||
      keys.difference(value.keys.toSet()).isNotEmpty) {
    throw const FormatException();
  }
}

void _schema(Map<String, Object?> value) {
  if (value['schema_version'] != knowledgeExportSchema) {
    throw const FormatException();
  }
}

String _string(Object? value) {
  if (value is! String || value.isEmpty) throw const FormatException();
  return value;
}

String _digest(Object? value) {
  final result = _string(value);
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(result)) {
    throw const FormatException();
  }
  return result;
}

String? _nullableString(Object? value) => value == null ? null : _string(value);

int _integer(Object? value, {bool allowZero = false}) {
  if (value is! int || (allowZero ? value < 0 : value <= 0)) {
    throw const FormatException();
  }
  return value;
}

String newKnowledgeExportIdempotencyKey() {
  final random = Random.secure();
  final hex = List.generate(
    16,
    (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
  ).join();
  return 'export-$hex';
}
