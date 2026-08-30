import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';

const String catalogChannelName = 'io.datasteward.app/catalog';
const String catalogStateSchema = 'data-steward.catalog-state/v1';
const String catalogSnapshotSchema = 'data-steward.catalog-snapshot/v1';
const int maxCatalogItems = 512;

final RegExp _sha256Pattern = RegExp(r'^[0-9a-f]{64}$');
final RegExp _providerPattern = RegExp(r'^[A-Za-z0-9._-]{1,253}$');
final RegExp _extensionPattern = RegExp(r'^[a-z0-9]{0,16}$');

final class CatalogFailure implements Exception {
  const CatalogFailure(this.code);

  final String code;
}

final class CatalogDirectoryState {
  const CatalogDirectoryState({
    required this.status,
    required this.authorized,
    required this.canRead,
    required this.restored,
    required this.contentAnalysisEnabled,
    this.provider,
    this.catalogRootId,
    this.permissionReleased,
  });

  const CatalogDirectoryState.notAuthorized()
    : status = 'not_authorized',
      authorized = false,
      canRead = false,
      restored = false,
      contentAnalysisEnabled = false,
      provider = null,
      catalogRootId = null,
      permissionReleased = null;

  factory CatalogDirectoryState.fromMap(Map<Object?, Object?> source) {
    _requireExactKeys(
      source,
      required: const {
        'schemaVersion',
        'status',
        'authorized',
        'canRead',
        'restored',
        'contentAnalysisEnabled',
      },
      optional: const {'provider', 'catalogRootId', 'permissionReleased'},
    );
    if (source['schemaVersion'] != catalogStateSchema) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    final status = _string(source, 'status');
    if (!const {'authorized', 'not_authorized', 'forgotten'}.contains(status)) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    final authorized = _boolean(source, 'authorized');
    final canRead = _boolean(source, 'canRead');
    final restored = _boolean(source, 'restored');
    final contentAnalysisEnabled = _boolean(source, 'contentAnalysisEnabled');
    final provider = _optionalString(source, 'provider');
    final rootId = _optionalString(source, 'catalogRootId');
    final released = source.containsKey('permissionReleased')
        ? _boolean(source, 'permissionReleased')
        : null;

    if (status == 'authorized') {
      if (!authorized || !canRead || provider == null || rootId == null) {
        throw const CatalogFailure('protocol_integrity_error');
      }
      if (!_providerPattern.hasMatch(provider) ||
          !_sha256Pattern.hasMatch(rootId)) {
        throw const CatalogFailure('protocol_integrity_error');
      }
      if (released != null) {
        throw const CatalogFailure('protocol_integrity_error');
      }
    } else if (authorized ||
        canRead ||
        restored ||
        contentAnalysisEnabled ||
        provider != null ||
        rootId != null) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    if (status == 'forgotten' && released == null) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    if (status == 'not_authorized' && released != null) {
      throw const CatalogFailure('protocol_integrity_error');
    }

    return CatalogDirectoryState(
      status: status,
      authorized: authorized,
      canRead: canRead,
      restored: restored,
      contentAnalysisEnabled: contentAnalysisEnabled,
      provider: provider,
      catalogRootId: rootId,
      permissionReleased: released,
    );
  }

  final String status;
  final bool authorized;
  final bool canRead;
  final bool restored;
  final bool contentAnalysisEnabled;
  final String? provider;
  final String? catalogRootId;
  final bool? permissionReleased;
}

final class CatalogItem {
  const CatalogItem({
    required this.locatorToken,
    required this.displayName,
    required this.extension,
    required this.mimeFamily,
    required this.revision,
    required this.contentEligible,
    this.sizeBytes,
    this.modifiedAtMillis,
  });

  factory CatalogItem.fromMap(Map<Object?, Object?> source) {
    _requireExactKeys(
      source,
      required: const {
        'locatorToken',
        'displayName',
        'extension',
        'mimeFamily',
        'sizeBytes',
        'modifiedAtMillis',
        'revision',
        'contentEligible',
      },
    );
    final locatorToken = _digest(source, 'locatorToken');
    final displayName = _string(source, 'displayName');
    final displayBytes = utf8.encode(displayName);
    if (displayName.trim().isEmpty ||
        displayName == '.' ||
        displayName == '..' ||
        displayBytes.length > 255 ||
        displayName.runes.any(_unsafeDisplayRune) ||
        displayName.contains('/') ||
        displayName.contains('\\')) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    final extension = _string(source, 'extension');
    final mimeFamily = _string(source, 'mimeFamily');
    if (!_extensionPattern.hasMatch(extension) ||
        !const {
          'image',
          'audio',
          'video',
          'text',
          'document',
          'archive',
          'other',
        }.contains(mimeFamily)) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    final sizeBytes = _optionalNonNegativeInt(source, 'sizeBytes');
    final modifiedAtMillis = _optionalNonNegativeInt(
      source,
      'modifiedAtMillis',
    );
    return CatalogItem(
      locatorToken: locatorToken,
      displayName: displayName,
      extension: extension,
      mimeFamily: mimeFamily,
      sizeBytes: sizeBytes,
      modifiedAtMillis: modifiedAtMillis,
      revision: _digest(source, 'revision'),
      contentEligible: _boolean(source, 'contentEligible'),
    );
  }

  final String locatorToken;
  final String displayName;
  final String extension;
  final String mimeFamily;
  final int? sizeBytes;
  final int? modifiedAtMillis;
  final String revision;
  final bool contentEligible;
}

bool _unsafeDisplayRune(int rune) =>
    rune < 0x20 ||
    rune == 0x7f ||
    rune == 0x200b ||
    rune == 0x200c ||
    rune == 0x200d ||
    rune == 0x200e ||
    rune == 0x200f ||
    rune == 0x2028 ||
    rune == 0x2029 ||
    (rune >= 0x202a && rune <= 0x202e) ||
    (rune >= 0x2066 && rune <= 0x2069) ||
    rune == 0xfeff;

final class CatalogSnapshot {
  const CatalogSnapshot({
    required this.catalogRootId,
    required this.snapshotSha256,
    required this.generatedAtMillis,
    required this.itemCount,
    required this.skippedCount,
    this.contentAnalysisEnabled = false,
    required this.items,
  });

  factory CatalogSnapshot.fromMap(Map<Object?, Object?> source) {
    _requireExactKeys(
      source,
      required: const {
        'schemaVersion',
        'catalogRootId',
        'snapshotSha256',
        'generatedAtMillis',
        'itemCount',
        'skippedCount',
        'contentAnalysisEnabled',
        'items',
      },
    );
    if (source['schemaVersion'] != catalogSnapshotSchema) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    final rawItems = source['items'];
    if (rawItems is! List<Object?> || rawItems.length > maxCatalogItems) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    final items = <CatalogItem>[];
    for (final value in rawItems) {
      if (value is! Map<Object?, Object?>) {
        throw const CatalogFailure('protocol_integrity_error');
      }
      items.add(CatalogItem.fromMap(value));
    }
    final itemCount = _nonNegativeInt(source, 'itemCount');
    final skippedCount = _nonNegativeInt(source, 'skippedCount');
    if (itemCount != items.length ||
        itemCount + skippedCount > maxCatalogItems) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    final tokens = items.map((item) => item.locatorToken).toList();
    if (tokens.toSet().length != tokens.length || !_isSorted(tokens)) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    final rootId = _digest(source, 'catalogRootId');
    final snapshotSha256 = _digest(source, 'snapshotSha256');
    if (_projectionHash(rootId, items, skippedCount) != snapshotSha256) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    return CatalogSnapshot(
      catalogRootId: rootId,
      snapshotSha256: snapshotSha256,
      generatedAtMillis: _nonNegativeInt(source, 'generatedAtMillis'),
      itemCount: itemCount,
      skippedCount: skippedCount,
      contentAnalysisEnabled: _boolean(source, 'contentAnalysisEnabled'),
      items: List.unmodifiable(items),
    );
  }

  final String catalogRootId;
  final String snapshotSha256;
  final int generatedAtMillis;
  final int itemCount;
  final int skippedCount;
  final bool contentAnalysisEnabled;
  final List<CatalogItem> items;
}

const String androidOcrBatchSchema = 'data-steward.android-ocr-batch/v1';

final class AndroidOcrProjectionItem {
  const AndroidOcrProjectionItem({
    required this.locatorToken,
    required this.revision,
    required this.format,
    required this.status,
    required this.text,
    required this.textSha256,
    required this.charCount,
    required this.truncated,
    required this.confidence,
    required this.languageHints,
    required this.extractorId,
    required this.extractorVersion,
  });

  factory AndroidOcrProjectionItem.fromMap(Map<Object?, Object?> source) {
    _requireExactKeys(
      source,
      required: const {
        'locatorToken',
        'revision',
        'format',
        'status',
        'text',
        'textSha256',
        'charCount',
        'truncated',
        'confidence',
        'languageHints',
        'extractorId',
        'extractorVersion',
      },
    );
    final format = _string(source, 'format');
    final status = _string(source, 'status');
    final text = _stringAllowEmpty(source, 'text');
    final charCount = _nonNegativeInt(source, 'charCount');
    final confidenceValue = source['confidence'];
    final confidence = confidenceValue == null
        ? null
        : confidenceValue is num && confidenceValue >= 0 && confidenceValue <= 1
        ? confidenceValue.toDouble()
        : throw const CatalogFailure('protocol_integrity_error');
    final rawLanguages = source['languageHints'];
    if (!const {'jpg', 'jpeg', 'png'}.contains(format) ||
        !const {'recognized', 'no_text'}.contains(status) ||
        text.runes.length != charCount ||
        charCount > 4000 ||
        (status == 'recognized') != text.isNotEmpty ||
        rawLanguages is! List<Object?> ||
        rawLanguages.length > 8) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    final languages = rawLanguages
        .map((value) => value is String ? value : '')
        .toList(growable: false);
    final languagePattern = RegExp(
      r'^(und|[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*)$',
    );
    if (languages.any((value) => !languagePattern.hasMatch(value)) ||
        languages.toSet().length != languages.length ||
        !_isSorted(languages)) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    final textSha = _digest(source, 'textSha256');
    if (sha256.convert(utf8.encode(text)).toString() != textSha ||
        source['truncated'] is! bool ||
        source['extractorId'] != 'mlkit-chinese-bundled' ||
        source['extractorVersion'] != '16.0.1') {
      throw const CatalogFailure('protocol_integrity_error');
    }
    return AndroidOcrProjectionItem(
      locatorToken: _digest(source, 'locatorToken'),
      revision: _digest(source, 'revision'),
      format: format,
      status: status,
      text: text,
      textSha256: textSha,
      charCount: charCount,
      truncated: source['truncated']! as bool,
      confidence: confidence,
      languageHints: List.unmodifiable(languages),
      extractorId: source['extractorId']! as String,
      extractorVersion: source['extractorVersion']! as String,
    );
  }

  final String locatorToken;
  final String revision;
  final String format;
  final String status;
  final String text;
  final String textSha256;
  final int charCount;
  final bool truncated;
  final double? confidence;
  final List<String> languageHints;
  final String extractorId;
  final String extractorVersion;
}

final class AndroidOcrBatchProjection {
  const AndroidOcrBatchProjection({
    required this.catalogRootId,
    required this.snapshotSha256,
    required this.generatedAtMillis,
    required this.items,
  });

  factory AndroidOcrBatchProjection.fromMap(Map<Object?, Object?> source) {
    _requireExactKeys(
      source,
      required: const {
        'schemaVersion',
        'catalogRootId',
        'snapshotSha256',
        'generatedAtMillis',
        'itemCount',
        'recognizedCount',
        'noTextCount',
        'items',
      },
    );
    final rawItems = source['items'];
    if (source['schemaVersion'] != androidOcrBatchSchema ||
        rawItems is! List<Object?> ||
        rawItems.isEmpty ||
        rawItems.length > 6) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    final items = rawItems
        .map((raw) {
          if (raw is! Map<Object?, Object?>) {
            throw const CatalogFailure('protocol_integrity_error');
          }
          return AndroidOcrProjectionItem.fromMap(raw);
        })
        .toList(growable: false);
    final recognized = items
        .where((item) => item.status == 'recognized')
        .length;
    final noText = items.length - recognized;
    if (_nonNegativeInt(source, 'itemCount') != items.length ||
        _nonNegativeInt(source, 'recognizedCount') != recognized ||
        _nonNegativeInt(source, 'noTextCount') != noText ||
        items.map((item) => item.locatorToken).toSet().length != items.length ||
        !_isSorted(items.map((item) => item.locatorToken).toList())) {
      throw const CatalogFailure('protocol_integrity_error');
    }
    return AndroidOcrBatchProjection(
      catalogRootId: _digest(source, 'catalogRootId'),
      snapshotSha256: _digest(source, 'snapshotSha256'),
      generatedAtMillis: _nonNegativeInt(source, 'generatedAtMillis'),
      items: List.unmodifiable(items),
    );
  }

  final String catalogRootId;
  final String snapshotSha256;
  final int generatedAtMillis;
  final List<AndroidOcrProjectionItem> items;
}

abstract interface class CatalogBridge {
  Future<CatalogDirectoryState> getCatalogState();

  Future<CatalogDirectoryState> selectCatalogDirectory();

  Future<CatalogSnapshot> buildCatalogSnapshot();

  Future<CatalogDirectoryState> setContentAnalysisEnabled(bool enabled);

  Future<AndroidOcrBatchProjection> analyzeCatalogImages(
    CatalogSnapshot snapshot,
  );

  Future<CatalogDirectoryState> forgetCatalogDirectory();
}

final class MethodChannelCatalogBridge implements CatalogBridge {
  const MethodChannelCatalogBridge({
    this.channel = const MethodChannel(catalogChannelName),
  });

  final MethodChannel channel;

  @override
  Future<CatalogDirectoryState> getCatalogState() async =>
      CatalogDirectoryState.fromMap(await _invokeMap('getCatalogState'));

  @override
  Future<CatalogDirectoryState> selectCatalogDirectory() async =>
      CatalogDirectoryState.fromMap(await _invokeMap('selectCatalogDirectory'));

  @override
  Future<CatalogSnapshot> buildCatalogSnapshot() async =>
      CatalogSnapshot.fromMap(await _invokeMap('buildCatalogSnapshot'));

  @override
  Future<CatalogDirectoryState> setContentAnalysisEnabled(bool enabled) async =>
      CatalogDirectoryState.fromMap(
        await _invokeMap('setContentAnalysisEnabled', {'enabled': enabled}),
      );

  @override
  Future<AndroidOcrBatchProjection> analyzeCatalogImages(
    CatalogSnapshot snapshot,
  ) async {
    final selected = snapshot.items
        .where(
          (item) =>
              item.mimeFamily == 'image' &&
              const {'jpg', 'jpeg', 'png'}.contains(item.extension),
        )
        .take(6)
        .toList(growable: false);
    if (selected.isEmpty) throw const CatalogFailure('ocr_no_supported_images');
    return AndroidOcrBatchProjection.fromMap(
      await _invokeMap('analyzeCatalogImages', {
        'catalogRootId': snapshot.catalogRootId,
        'snapshotSha256': snapshot.snapshotSha256,
        'items': [
          for (final item in selected)
            {'locatorToken': item.locatorToken, 'revision': item.revision},
        ],
      }),
    );
  }

  @override
  Future<CatalogDirectoryState> forgetCatalogDirectory() async =>
      CatalogDirectoryState.fromMap(await _invokeMap('forgetCatalogDirectory'));

  Future<Map<Object?, Object?>> _invokeMap(
    String method, [
    Map<String, Object?>? arguments,
  ]) async {
    try {
      final result = await channel.invokeMethod<Map<Object?, Object?>>(
        method,
        arguments,
      );
      if (result == null) {
        throw const CatalogFailure('protocol_integrity_error');
      }
      return result;
    } on MissingPluginException {
      throw const CatalogFailure('unsupported');
    } on PlatformException catch (error) {
      throw CatalogFailure(_knownCode(error.code));
    }
  }

  String _knownCode(String code) =>
      const {
        'unsupported',
        'not_authorized',
        'picker_cancelled',
        'busy',
        'invalid_directory',
        'permission_lost',
        'catalog_state_corrupt',
        'catalog_too_large',
        'catalog_duplicate_entry',
        'catalog_invalid_entry',
        'catalog_policy_invalid',
        'ocr_request_invalid',
        'ocr_result_invalid',
        'ocr_result_too_large',
        'ocr_opt_in_required',
        'ocr_snapshot_stale',
        'ocr_state_corrupt',
        'ocr_asset_not_allowed',
        'ocr_revision_changed',
        'ocr_image_too_large',
        'ocr_image_invalid',
        'ocr_image_stream_unavailable',
        'ocr_image_decode_failed',
        'ocr_image_dimensions_unsafe',
        'ocr_permission_lost',
        'ocr_timeout',
        'ocr_busy',
        'ocr_unavailable',
        'ocr_io_error',
        'io_error',
      }.contains(code)
      ? code
      : 'io_error';
}

String _stringAllowEmpty(Map<Object?, Object?> source, String key) {
  final value = source[key];
  if (value is! String) throw const CatalogFailure('protocol_integrity_error');
  return value;
}

String _projectionHash(
  String rootId,
  List<CatalogItem> items,
  int skippedCount,
) {
  final buffer = StringBuffer()
    ..write(_canonicalFields([catalogSnapshotSchema, rootId]));
  for (final item in items) {
    buffer.write(
      _canonicalFields([
        item.locatorToken,
        item.displayName,
        item.extension,
        item.mimeFamily,
        item.sizeBytes?.toString() ?? 'null',
        item.modifiedAtMillis?.toString() ?? 'null',
        item.revision,
        item.contentEligible.toString(),
      ]),
    );
  }
  buffer.write(_canonicalFields(['skipped', skippedCount.toString()]));
  return sha256.convert(utf8.encode(buffer.toString())).toString();
}

String _canonicalFields(List<String> fields) =>
    '${fields.map((field) => '${utf8.encode(field).length}:$field').join()}\n';

bool _isSorted(List<String> values) {
  for (var index = 1; index < values.length; index += 1) {
    if (values[index - 1].compareTo(values[index]) > 0) return false;
  }
  return true;
}

void _requireExactKeys(
  Map<Object?, Object?> source, {
  required Set<String> required,
  Set<String> optional = const {},
}) {
  final keys = source.keys;
  if (keys.any((key) => key is! String)) {
    throw const CatalogFailure('protocol_integrity_error');
  }
  final actual = keys.cast<String>().toSet();
  if (!actual.containsAll(required) ||
      actual.difference(required.union(optional)).isNotEmpty) {
    throw const CatalogFailure('protocol_integrity_error');
  }
}

String _string(Map<Object?, Object?> source, String key) {
  final value = source[key];
  if (value is! String) {
    throw const CatalogFailure('protocol_integrity_error');
  }
  return value;
}

String? _optionalString(Map<Object?, Object?> source, String key) {
  final value = source[key];
  if (value == null) return null;
  if (value is! String) {
    throw const CatalogFailure('protocol_integrity_error');
  }
  return value;
}

String _digest(Map<Object?, Object?> source, String key) {
  final value = _string(source, key);
  if (!_sha256Pattern.hasMatch(value)) {
    throw const CatalogFailure('protocol_integrity_error');
  }
  return value;
}

bool _boolean(Map<Object?, Object?> source, String key) {
  final value = source[key];
  if (value is! bool) {
    throw const CatalogFailure('protocol_integrity_error');
  }
  return value;
}

int _nonNegativeInt(Map<Object?, Object?> source, String key) {
  final value = source[key];
  if (value is! int || value < 0) {
    throw const CatalogFailure('protocol_integrity_error');
  }
  return value;
}

int? _optionalNonNegativeInt(Map<Object?, Object?> source, String key) {
  if (source[key] == null) return null;
  return _nonNegativeInt(source, key);
}
