import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:steward_app/catalog/android_ocr_client.dart';
import 'package:steward_app/catalog/catalog_bridge.dart';
import 'package:steward_app/secure_pairing/pairing_vault.dart';

final class MemoryOcrOutbox implements AndroidOcrOutbox {
  String? payload;
  int saves = 0;
  int clears = 0;

  @override
  Future<String?> load() async => payload;

  @override
  Future<String> save(String value) async {
    payload = value;
    saves += 1;
    return sha256.convert(utf8.encode(value)).toString();
  }

  @override
  Future<void> clear(String expectedSha256) async {
    if (payload == null ||
        sha256.convert(utf8.encode(payload!)).toString() != expectedSha256) {
      throw StateError('digest mismatch');
    }
    payload = null;
    clears += 1;
  }
}

void main() {
  const deviceId = '01ARZ3NDEKTSV4RRFFQ69G5FAV';
  const rootId =
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  final credential = ActiveDeviceCredential(
    deviceId: deviceId,
    hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAW',
    baseUrl: Uri.parse('https://192.0.2.1:9443'),
    certFingerprint: 'b' * 64,
    deviceCredential: 'A' * 43,
    capabilityEpoch: 1,
    grantedCapabilities: const [
      'catalog.sync',
      'content.analyze',
      'session.sync',
    ],
  );
  const text = '高等数学 极限与连续';
  final projection = AndroidOcrBatchProjection(
    catalogRootId: rootId,
    snapshotSha256: 'c' * 64,
    generatedAtMillis: 1785805200000,
    items: [
      AndroidOcrProjectionItem(
        locatorToken: 'd' * 64,
        revision: 'e' * 64,
        format: 'jpg',
        status: 'recognized',
        text: text,
        textSha256: sha256.convert(utf8.encode(text)).toString(),
        charCount: text.runes.length,
        truncated: false,
        confidence: 0.9,
        languageHints: const ['zh'],
        extractorId: 'mlkit-chinese-bundled',
        extractorVersion: '16.0.1',
      ),
    ],
  );

  http.Response receipt({bool deduplicated = false}) => http.Response(
    jsonEncode({
      'schema_version': androidOcrSyncSchema,
      'device_id': deviceId,
      'catalog_root_id': rootId,
      'accepted_count': 1,
      'recognized_count': 1,
      'no_text_count': 0,
      'low_confidence_count': 0,
      'deduplicated': deduplicated,
      'projection_sha256': 'f' * 64,
    }),
    200,
    headers: {'content-type': 'application/json'},
  );

  test(
    'queues before upload and clears only after validated receipt',
    () async {
      final outbox = MemoryOcrOutbox();
      final client = AndroidOcrSyncClient(
        credential: credential,
        outbox: outbox,
        client: MockClient((request) async {
          expect(request.url.path, '/v1/content/android-ocr');
          final body = jsonDecode(request.body) as Map<String, Object?>;
          expect(body['schema_version'], androidOcrSyncSchema);
          final item =
              (body['items']! as List<Object?>).single as Map<String, Object?>;
          expect(item['text'], text);
          expect(item.containsKey('uri'), isFalse);
          expect(item.containsKey('path'), isFalse);
          return receipt();
        }),
      );
      final value = await client.sync(projection);
      expect(value.acceptedCount, 1);
      expect(outbox.saves, 1);
      expect(outbox.clears, 1);
      expect(outbox.payload, isNull);
      client.close();
    },
  );

  test(
    'network failure retains latest-only outbox without automatic retry',
    () async {
      final outbox = MemoryOcrOutbox();
      var calls = 0;
      final client = AndroidOcrSyncClient(
        credential: credential,
        outbox: outbox,
        client: MockClient((_) async {
          calls += 1;
          throw StateError('offline');
        }),
      );
      await expectLater(
        client.sync(projection),
        throwsA(
          isA<AndroidOcrSyncFailure>().having(
            (error) => error.code,
            'code',
            'transient_network',
          ),
        ),
      );
      expect(calls, 1);
      expect(outbox.payload, isNotNull);
      expect(outbox.clears, 0);
      client.close();
    },
  );

  test('manual pending retry sends retained payload once', () async {
    final outbox = MemoryOcrOutbox();
    final seed = AndroidOcrSyncClient(
      credential: credential,
      outbox: outbox,
      client: MockClient((_) async => throw StateError('offline')),
    );
    await expectLater(
      seed.sync(projection),
      throwsA(isA<AndroidOcrSyncFailure>()),
    );
    seed.close();
    var calls = 0;
    final retry = AndroidOcrSyncClient(
      credential: credential,
      outbox: outbox,
      client: MockClient((_) async {
        calls += 1;
        return receipt(deduplicated: true);
      }),
    );
    expect((await retry.retryPending()).deduplicated, isTrue);
    expect(calls, 1);
    expect(outbox.payload, isNull);
    retry.close();
  });

  test(
    'forget uses authenticated content surface and validates receipt',
    () async {
      final client = AndroidOcrSyncClient(
        credential: credential,
        client: MockClient((request) async {
          expect(request.method, 'DELETE');
          expect(request.url.path, '/v1/content/android-ocr/$rootId');
          return http.Response(
            jsonEncode({'status': 'forgotten', 'deleted_count': 1}),
            200,
            headers: {'content-type': 'application/json'},
          );
        }),
      );
      expect(await client.forget(rootId), 1);
      client.close();
    },
  );
}
