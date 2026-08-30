import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:steward_app/catalog/content_insight.dart';
import 'package:steward_app/catalog/content_insight_client.dart';
import 'package:steward_app/catalog/content_insight_view.dart';
import 'package:steward_app/secure_pairing/pairing_vault.dart';

void main() {
  test('content deadlines cover the bounded multi-turn Hermes request', () {
    expect(
      contentInsightTransportTimeout,
      greaterThan(const Duration(seconds: 65)),
    );
    expect(
      contentInsightTransportTimeout,
      lessThan(contentInsightRequestTimeout),
    );
    expect(contentInsightRequestTimeout, const Duration(seconds: 75));
  });

  final digest = List.filled(64, 'a').join();
  final secret = List.filled(43, 'x').join();
  const packJson = <String, Object?>{
    'schema_version': 'data-steward.study-pack/v1',
    'title': '高等数学复习要点',
    'summary': '围绕极限和连续复习定义并完成习题。',
    'topics': ['极限', '连续'],
    'review_points': ['复习定义', '完成习题'],
    'source': 'hermes',
    'created_at': '2026-08-04T10:00:00.000Z',
  };

  test('strict public projection rejects internal fields and paths', () {
    final pack = StudyPack.fromJson(packJson);
    expect(pack.source, 'hermes');
    expect(
      () => StudyPack.fromJson({...packJson, 'snapshot_sha256': digest}),
      throwsFormatException,
    );
    expect(
      () => StudyPack.fromJson({...packJson, 'summary': r'C:\Users\x\secret'}),
      throwsFormatException,
    );
  });

  test('operator client sends exact auth and parses policy', () async {
    late http.Request captured;
    final client = ContentInsightClient.operator(
      baseUri: Uri.parse('http://127.0.0.1:4123'),
      operatorToken: secret,
      client: MockClient((request) async {
        captured = request;
        return http.Response(
          jsonEncode({
            'configured': true,
            'catalog_root_id': 'pc-123456789abc',
            'display_name': 'Demo',
            'content_opt_in': false,
            'eligible_file_count': 2,
            'supported_file_count': 1,
            'supported_format_counts': {'docx': 1},
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      }),
    );
    final status = await client.status();
    expect(status.supportedFileCount, 1);
    expect(status.supportedFormatCounts, {'docx': 1});
    expect(captured.url.path, '/v1/operator/content/status');
    expect(captured.headers['authorization'], 'DataSteward-Operator $secret');
    client.close();
  });

  test('policy rejects unknown formats and inconsistent counts', () {
    const base = <String, Object?>{
      'configured': true,
      'catalog_root_id': 'pc-123456789abc',
      'display_name': 'Demo',
      'content_opt_in': true,
      'eligible_file_count': 3,
      'supported_file_count': 2,
      'supported_format_counts': {'docx': 1, 'pdf': 1},
    };
    expect(ContentPolicy.fromJson(base).supportedFileCount, 2);
    expect(
      () => ContentPolicy.fromJson({
        ...base,
        'supported_format_counts': {'docx': 1, 'exe': 1},
      }),
      throwsFormatException,
    );
    expect(
      () => ContentPolicy.fromJson({
        ...base,
        'supported_format_counts': {'docx': 1},
      }),
      throwsFormatException,
    );
  });

  test(
    'device client refuses missing content capability before network',
    () async {
      var requests = 0;
      final client = ContentInsightClient.device(
        credential: ActiveDeviceCredential(
          deviceId: '01ARZ3NDEKTSV4RRFFQ69G5FAW',
          hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
          baseUrl: Uri.parse('https://192.168.50.10:9443'),
          certFingerprint: digest,
          deviceCredential: secret,
          capabilityEpoch: 1,
          grantedCapabilities: const ['catalog.sync'],
        ),
        client: MockClient((_) async {
          requests += 1;
          return http.Response('', 500);
        }),
      );
      await expectLater(
        client.generate(),
        throwsA(
          isA<ContentInsightFailure>().having(
            (value) => value.code,
            'code',
            'capability_denied',
          ),
        ),
      );
      expect(requests, 0);
      client.close();
    },
  );

  testWidgets('product card shows insight without internal identifiers', (
    tester,
  ) async {
    final requests = <String>[];
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: ContentInsightView(
            pack: StudyPack.fromJson(packJson),
            busy: false,
            canGenerate: true,
            onGenerate: requests.add,
          ),
        ),
      ),
    );
    expect(find.text('高等数学复习要点'), findsOneWidget);
    expect(find.text('由 Hermes 受控分析生成'), findsOneWidget);
    expect(find.textContaining('snapshot'), findsNothing);
    expect(find.textContaining('asset'), findsNothing);
    expect(find.textContaining('hash'), findsNothing);
    await tester.tap(find.byKey(const Key('content-insight-submit')));
    expect(requests, [defaultStudyPackRequest]);
  });

  testWidgets('custom insight request uses enter and shift enter is newline', (
    tester,
  ) async {
    final requests = <String>[];
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: ContentInsightView(
            pack: null,
            busy: false,
            canGenerate: true,
            onGenerate: requests.add,
          ),
        ),
      ),
    );
    final input = find.byKey(const Key('content-insight-request'));
    await tester.enterText(input, '找出高数资料');
    await tester.sendKeyDownEvent(LogicalKeyboardKey.enter);
    await tester.sendKeyUpEvent(LogicalKeyboardKey.enter);
    expect(requests, ['找出高数资料']);

    requests.clear();
    await tester.sendKeyDownEvent(LogicalKeyboardKey.shiftLeft);
    await tester.sendKeyDownEvent(LogicalKeyboardKey.enter);
    await tester.sendKeyUpEvent(LogicalKeyboardKey.enter);
    await tester.sendKeyUpEvent(LogicalKeyboardKey.shiftLeft);
    expect(requests, isEmpty);
  });
}
