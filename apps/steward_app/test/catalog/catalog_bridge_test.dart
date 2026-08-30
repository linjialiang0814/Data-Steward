import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:steward_app/catalog/catalog_bridge.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('test/catalog');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  tearDown(() => messenger.setMockMethodCallHandler(channel, null));

  test('authorized state requires the exact S5-A contract', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      expect(call.method, 'getCatalogState');
      return authorizedState(restored: true);
    });

    final state = await const MethodChannelCatalogBridge(
      channel: channel,
    ).getCatalogState();

    expect(state.authorized, isTrue);
    expect(state.canRead, isTrue);
    expect(state.restored, isTrue);
    expect(state.contentAnalysisEnabled, isFalse);
    expect(state.provider, 'com.android.externalstorage.documents');
  });

  test('not-authorized and forgotten states remain distinct', () {
    final missing = CatalogDirectoryState.fromMap(notAuthorizedState());
    final forgotten = CatalogDirectoryState.fromMap({
      ...notAuthorizedState(),
      'status': 'forgotten',
      'permissionReleased': false,
    });

    expect(missing.status, 'not_authorized');
    expect(missing.permissionReleased, isNull);
    expect(forgotten.status, 'forgotten');
    expect(forgotten.permissionReleased, isFalse);
  });

  test('valid snapshot is hash-checked and parsed', () async {
    final body = snapshotBody([
      item(token: 'a' * 64, name: '课堂笔记.md', revision: 'b' * 64),
      item(
        token: 'c' * 64,
        name: 'IMG_20260804.jpg',
        revision: 'd' * 64,
        extension: 'jpg',
        family: 'image',
        eligible: false,
      ),
    ], skipped: 1);
    messenger.setMockMethodCallHandler(channel, (call) async {
      expect(call.method, 'buildCatalogSnapshot');
      return body;
    });

    final snapshot = await const MethodChannelCatalogBridge(
      channel: channel,
    ).buildCatalogSnapshot();

    expect(snapshot.itemCount, 2);
    expect(snapshot.skippedCount, 1);
    expect(snapshot.items.first.displayName, '课堂笔记.md');
    expect(snapshot.items.last.mimeFamily, 'image');
  });

  test('tampered snapshot hash fails closed', () {
    final body = snapshotBody([
      item(token: 'a' * 64, name: '课堂笔记.md', revision: 'b' * 64),
    ])..['snapshotSha256'] = 'f' * 64;

    expect(
      () => CatalogSnapshot.fromMap(body),
      throwsA(
        isA<CatalogFailure>().having(
          (e) => e.code,
          'code',
          'protocol_integrity_error',
        ),
      ),
    );
  });

  test('duplicate or unsorted locator tokens fail closed', () {
    final duplicate = item(token: 'a' * 64, name: 'b.md', revision: 'c' * 64);
    final bodies = [
      snapshotBody([
        item(token: 'a' * 64, name: 'a.md', revision: 'b' * 64),
        duplicate,
      ]),
      snapshotBody([
        item(token: 'b' * 64, name: 'a.md', revision: 'c' * 64),
        item(token: 'a' * 64, name: 'b.md', revision: 'd' * 64),
      ]),
    ];

    for (final body in bodies) {
      expect(
        () => CatalogSnapshot.fromMap(body),
        throwsA(isA<CatalogFailure>()),
      );
    }
  });

  test('unsafe display names and unexpected keys fail closed', () {
    for (final name in [
      '../secret.txt',
      r'C:\secret.txt',
      'bad\u0000.txt',
      'safe\u202efdp.exe',
    ]) {
      final value = item(token: 'a' * 64, name: name, revision: 'b' * 64);
      expect(() => CatalogItem.fromMap(value), throwsA(isA<CatalogFailure>()));
    }
    final value = item(token: 'a' * 64, name: 'safe.txt', revision: 'b' * 64)
      ..['rawUri'] = 'content://private';
    expect(() => CatalogItem.fromMap(value), throwsA(isA<CatalogFailure>()));
  });

  test('content-enabled payload is accepted only as an explicit boolean', () {
    final state = authorizedState()..['contentAnalysisEnabled'] = true;
    final snapshot = snapshotBody([])..['contentAnalysisEnabled'] = true;

    expect(CatalogDirectoryState.fromMap(state).contentAnalysisEnabled, isTrue);
    expect(CatalogSnapshot.fromMap(snapshot).contentAnalysisEnabled, isTrue);
    state['contentAnalysisEnabled'] = 'true';
    expect(
      () => CatalogDirectoryState.fromMap(state),
      throwsA(isA<CatalogFailure>()),
    );
  });

  test('OCR projection validates text hash, counts and extractor identity', () {
    final text = '高等数学 极限与连续';
    final item = <Object?, Object?>{
      'locatorToken': 'a' * 64,
      'revision': 'b' * 64,
      'format': 'jpg',
      'status': 'recognized',
      'text': text,
      'textSha256': sha256.convert(utf8.encode(text)).toString(),
      'charCount': text.runes.length,
      'truncated': false,
      'confidence': 0.9,
      'languageHints': ['zh'],
      'extractorId': 'mlkit-chinese-bundled',
      'extractorVersion': '16.0.1',
    };
    final body = <Object?, Object?>{
      'schemaVersion': androidOcrBatchSchema,
      'catalogRootId': 'e' * 64,
      'snapshotSha256': 'f' * 64,
      'generatedAtMillis': 1,
      'itemCount': 1,
      'recognizedCount': 1,
      'noTextCount': 0,
      'items': [item],
    };
    final parsed = AndroidOcrBatchProjection.fromMap(body);
    expect(parsed.items.single.text, text);
    item['textSha256'] = 'c' * 64;
    expect(
      () => AndroidOcrBatchProjection.fromMap(body),
      throwsA(isA<CatalogFailure>()),
    );
  });

  test('platform exception details are discarded', () async {
    messenger.setMockMethodCallHandler(channel, (_) async {
      throw PlatformException(
        code: 'catalog_invalid_entry',
        message: r'content://private C:\Users\private secret-body',
      );
    });

    await expectLater(
      const MethodChannelCatalogBridge(channel: channel).buildCatalogSnapshot(),
      throwsA(
        isA<CatalogFailure>()
            .having((e) => e.code, 'code', 'catalog_invalid_entry')
            .having(
              (e) => e.toString(),
              'text',
              isNot(contains('secret-body')),
            ),
      ),
    );
  });

  test('unknown native error becomes io_error', () async {
    messenger.setMockMethodCallHandler(channel, (_) async {
      throw PlatformException(code: 'provider_secret_failure');
    });

    await expectLater(
      const MethodChannelCatalogBridge(channel: channel).getCatalogState(),
      throwsA(isA<CatalogFailure>().having((e) => e.code, 'code', 'io_error')),
    );
  });
}

Map<Object?, Object?> authorizedState({bool restored = false}) => {
  'schemaVersion': catalogStateSchema,
  'status': 'authorized',
  'authorized': true,
  'canRead': true,
  'restored': restored,
  'provider': 'com.android.externalstorage.documents',
  'catalogRootId': 'e' * 64,
  'contentAnalysisEnabled': false,
};

Map<Object?, Object?> notAuthorizedState() => {
  'schemaVersion': catalogStateSchema,
  'status': 'not_authorized',
  'authorized': false,
  'canRead': false,
  'restored': false,
  'contentAnalysisEnabled': false,
};

Map<Object?, Object?> item({
  required String token,
  required String name,
  required String revision,
  String extension = 'md',
  String family = 'text',
  bool eligible = true,
}) => {
  'locatorToken': token,
  'displayName': name,
  'extension': extension,
  'mimeFamily': family,
  'sizeBytes': 12,
  'modifiedAtMillis': 1000,
  'revision': revision,
  'contentEligible': eligible,
};

Map<Object?, Object?> snapshotBody(
  List<Map<Object?, Object?>> items, {
  int skipped = 0,
}) {
  final rootId = 'e' * 64;
  final parsed = items.map(CatalogItem.fromMap).toList();
  final projection = StringBuffer()
    ..write(canonicalFields([catalogSnapshotSchema, rootId]));
  for (final value in parsed) {
    projection.write(
      canonicalFields([
        value.locatorToken,
        value.displayName,
        value.extension,
        value.mimeFamily,
        value.sizeBytes?.toString() ?? 'null',
        value.modifiedAtMillis?.toString() ?? 'null',
        value.revision,
        value.contentEligible.toString(),
      ]),
    );
  }
  projection.write(canonicalFields(['skipped', skipped.toString()]));
  return {
    'schemaVersion': catalogSnapshotSchema,
    'catalogRootId': rootId,
    'snapshotSha256': sha256
        .convert(utf8.encode(projection.toString()))
        .toString(),
    'generatedAtMillis': 1234,
    'itemCount': items.length,
    'skippedCount': skipped,
    'contentAnalysisEnabled': false,
    'items': items,
  };
}

String canonicalFields(List<String> fields) =>
    '${fields.map((field) => '${utf8.encode(field).length}:$field').join()}\n';
