import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:steward_app/catalog/knowledge_export_client.dart';
import 'package:steward_app/catalog/knowledge_export_view.dart';

void main() {
  test(
    'operator client prepares cross-device pack and uses confirmation contract',
    () async {
      final paths = <String>[];
      final client = KnowledgeExportClient.operator(
        baseUri: Uri.parse('https://127.0.0.1:9443'),
        operatorToken: 'fixture-token',
        client: MockClient((request) async {
          paths.add(request.url.path);
          expect(
            request.headers['authorization'],
            'DataSteward-Operator fixture-token',
          );
          if (request.url.path.endsWith('/prepare')) {
            return _json(_previewBody());
          }
          if (request.url.path.endsWith('/execute')) {
            final body = jsonDecode(request.body) as Map<String, Object?>;
            expect(body['schema_version'], knowledgeExportSchema);
            expect(
              body['idempotency_key'],
              matches(RegExp(r'^export-[0-9a-f]{32}$')),
            );
            return _json(_receiptBody());
          }
          if (request.url.path.endsWith('/status')) {
            return _json(_statusBody());
          }
          throw StateError('unexpected request');
        }),
      );

      final preview = await client.prepare(kind: 'learning', request: '生成资料包');
      final status = await client.execute(
        preview,
        idempotencyKey: 'export-${_digest('a').substring(0, 32)}',
      );

      expect(preview.pack.crossDevice, isTrue);
      expect(preview.pack.citations.map((value) => value.platform), [
        'windows',
        'android',
      ]);
      expect(status.canUndo, isTrue);
      expect(paths, [
        '/v1/operator/artifacts/prepare',
        '/v1/operator/artifacts/execute',
        '/v1/operator/artifacts/status',
      ]);
      client.close();
    },
  );

  testWidgets(
    'old credential shows explicit migration instead of silent expansion',
    (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: KnowledgeExportView(
              client: null,
              enabled: false,
              active: true,
              migrationRequired: true,
            ),
          ),
        ),
      );

      expect(find.textContaining('重新安全配对'), findsOneWidget);
      expect(
        tester
            .widget<FilledButton>(
              find.byKey(const Key('knowledge-export-prepare')),
            )
            .onPressed,
        isNull,
      );
    },
  );

  testWidgets('modified artifact becomes a prominent fail-closed notice', (
    tester,
  ) async {
    var statusCalls = 0;
    final client = KnowledgeExportClient.operator(
      baseUri: Uri.parse('https://127.0.0.1:9443'),
      operatorToken: 'fixture-token',
      client: MockClient((request) async {
        if (request.url.path.endsWith('/status')) {
          statusCalls += 1;
          return _json(
            statusCalls == 1 ? _statusBody() : _recoveryStatusBody(),
          );
        }
        if (request.url.path.endsWith('/undo')) {
          return http.Response(
            jsonEncode({
              'error_code': 'artifact_modified',
              'message_key': 'operator.artifact_modified',
            }),
            409,
            headers: {'content-type': 'application/json'},
          );
        }
        throw StateError('unexpected request');
      }),
    );
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SingleChildScrollView(
            child: KnowledgeExportView(
              client: client,
              enabled: true,
              active: true,
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('knowledge-export-undo')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('确认撤销'));
    await tester.pumpAndSettle();

    expect(
      find.byKey(const Key('knowledge-export-error-notice')),
      findsOneWidget,
    );
    expect(find.textContaining('系统已保留文件'), findsOneWidget);
    expect(find.byKey(const Key('knowledge-export-undo')), findsNothing);
    client.close();
  });
}

http.Response _json(Map<String, Object?> body) => http.Response(
  jsonEncode(body),
  200,
  headers: {'content-type': 'application/json'},
);

Map<String, Object?> _previewBody() => {
  'schema_version': knowledgeExportSchema,
  'pack': {
    'schema_version': 'data-steward.knowledge-pack/v1',
    'pack_id': 'kp-1234567890abcdef',
    'kind': 'learning',
    'title': '学习资料包｜高等数学',
    'summary': '结合电脑课件与手机课堂图片生成。',
    'topics': ['极限'],
    'review_points': ['复习定义'],
    'citations': [
      {
        'citation_id': 'S1',
        'platform': 'windows',
        'source_display_name': '课程资料',
        'display_name': '课堂笔记.md',
        'modified_at_ms': 1,
        'basis': 'content_projection',
      },
      {
        'citation_id': 'S2',
        'platform': 'android',
        'source_display_name': '手机资料',
        'display_name': '课堂图片.png',
        'modified_at_ms': 2,
        'basis': 'catalog_metadata',
      },
    ],
    'source': 'hermes',
    'cross_device': true,
    'created_at': '2026-08-05T10:00:00.000Z',
    'projection_sha256': _digest('e'),
  },
  'target_display_name': 'student-materials',
  'output_directory': 'Data Steward 输出',
  'filename': '2026-08-05-learning.md',
  'byte_count': 512,
  'preview_sha256': _digest('f'),
  'requires_confirmation': true,
};

Map<String, Object?> _receiptBody() => {
  'schema_version': knowledgeExportSchema,
  'export_id': 'artifact-1234567890abcdef',
  'pack_id': 'kp-1234567890abcdef',
  'state': 'completed',
  'filename': '2026-08-05-learning.md',
  'byte_count': 512,
  'undo_token': 'artifact-1234567890abcdef',
  'deduplicated': false,
};

Map<String, Object?> _statusBody() => {
  'schema_version': knowledgeExportSchema,
  'state': 'undo_available',
  'export_id': 'artifact-1234567890abcdef',
  'pack_id': 'kp-1234567890abcdef',
  'filename': '2026-08-05-learning.md',
  'byte_count': 512,
  'can_undo': true,
  'undo_token': 'artifact-1234567890abcdef',
};

Map<String, Object?> _recoveryStatusBody() => {
  'schema_version': knowledgeExportSchema,
  'state': 'recovery_required',
  'export_id': 'artifact-1234567890abcdef',
  'pack_id': 'kp-1234567890abcdef',
  'filename': '2026-08-05-learning.md',
  'byte_count': 512,
  'can_undo': false,
  'undo_token': null,
};

String _digest(String value) => List.filled(64, value).join();
