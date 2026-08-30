import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:steward_app/catalog/catalog_sync_client.dart';
import 'package:steward_app/catalog/proactive_suggestion_client.dart';
import 'package:steward_app/catalog/proactive_suggestion_view.dart';

void main() {
  test('operator client hides target until explicit accept', () async {
    final client = ProactiveSuggestionClient.operator(
      baseUri: Uri.parse('https://127.0.0.1:9443'),
      operatorToken: 'fixture-token',
      client: MockClient((request) async {
        expect(
          request.headers['authorization'],
          'DataSteward-Operator fixture-token',
        );
        if (request.url.path.endsWith('/settings')) {
          return _json(_settings(enabled: true));
        }
        if (request.url.path.endsWith('/inbox')) {
          return _json({
            'schema_version': proactiveActionCardSchema,
            'suggestions': [_card()],
          });
        }
        if (request.url.path.endsWith('/accept')) {
          return _json({
            ..._card(status: 'accepted'),
            'action_target': _cluster,
          });
        }
        throw StateError('unexpected request');
      }),
    );

    expect((await client.settings()).enabled, isTrue);
    final card = (await client.inbox()).single;
    expect(card.actionTarget, isNull);
    expect(card.source, 'hermes');
    final accepted = await client.accept(card.suggestionId);
    expect(accepted.actionTarget, _cluster);
    client.close();
  });

  test('strict client rejects an unknown action type', () async {
    final client = ProactiveSuggestionClient.operator(
      baseUri: Uri.parse('https://127.0.0.1:9443'),
      operatorToken: 'fixture-token',
      client: MockClient(
        (request) async => _json({
          'schema_version': proactiveActionCardSchema,
          'suggestions': [
            {..._card(), 'action_type': 'shell'},
          ],
        }),
      ),
    );
    await expectLater(
      client.inbox(),
      throwsA(
        isA<ProactiveSuggestionFailure>().having(
          (error) => error.code,
          'code',
          'protocol_integrity_error',
        ),
      ),
    );
    client.close();
  });

  testWidgets(
    'stable foreground snapshot creates one card and accept only opens preview',
    (tester) async {
      var observeCalls = 0;
      var previewCalls = 0;
      var executeCalls = 0;
      final client = ProactiveSuggestionClient.operator(
        baseUri: Uri.parse('https://127.0.0.1:9443'),
        operatorToken: 'fixture-token',
        client: MockClient((request) async {
          if (request.url.path.endsWith('/settings')) {
            return _json(_settings(enabled: true));
          }
          if (request.url.path.endsWith('/inbox')) {
            return _json({
              'schema_version': proactiveActionCardSchema,
              'suggestions': <Object?>[],
            });
          }
          if (request.url.path.endsWith('/observe')) {
            observeCalls += 1;
            return _json({
              'schema_version': proactiveActionCardSchema,
              'state': observeCalls == 1 ? 'stabilizing' : 'ready',
              'message_key': observeCalls == 1
                  ? 'suggestion_stabilizing'
                  : 'suggestion_ready',
              'suggestions': observeCalls == 1 ? <Object?>[] : [_card()],
            });
          }
          if (request.url.path.endsWith('/accept')) {
            return _json({
              ..._card(status: 'accepted'),
              'action_target': _cluster,
            });
          }
          throw StateError('unexpected request ${request.url.path}');
        }),
      );
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: ProactiveSuggestionView(
                client: client,
                knowledgeClient: null,
                active: true,
                canObserve: true,
                onPreviewOrganization: (clusterId) async {
                  previewCalls += 1;
                  expect(clusterId, _cluster);
                  return const ClusterOrganizationPreview(
                    clusterId: _cluster,
                    clusterTitle: '高等数学资料',
                    projectionSha256: _digest,
                    previewSha256: _digest,
                    pcFileCount: 2,
                    virtualFileCount: 1,
                    categoryCounts: {'文档': 2},
                  );
                },
                onExecuteOrganization: (preview) async {
                  executeCalls += 1;
                  return const ClusterOrganizationReceipt(
                    operation: 'organize',
                    clusterId: _cluster,
                    movedCount: 2,
                    categoryCounts: {'文档': 2},
                    undoToken: 'undo-fixture',
                    catalogRefreshPending: false,
                  );
                },
              ),
            ),
          ),
        ),
      );
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 100));
      expect(observeCalls, 1);
      expect(
        find.byKey(const Key('proactive-action-organize_selected')),
        findsNothing,
      );

      await tester.pump(const Duration(seconds: 11));
      await tester.pump();
      expect(observeCalls, 2);
      expect(
        find.byKey(const Key('proactive-action-organize_selected')),
        findsOneWidget,
      );

      await tester.tap(
        find.byKey(const Key('proactive-accept-organize_selected')),
      );
      await tester.pumpAndSettle();
      expect(previewCalls, 1);
      expect(executeCalls, 0);
      expect(find.textContaining('确认前不会移动'), findsOneWidget);
      expect(find.byKey(const Key('proactive-action-confirm')), findsOneWidget);
      client.close();
    },
  );
}

const _cluster = 'cl-1111111111111111';
const _digest =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

http.Response _json(Map<String, Object?> body) => http.Response(
  jsonEncode(body),
  200,
  headers: {'content-type': 'application/json'},
);

Map<String, Object?> _settings({required bool enabled}) => {
  'schema_version': proactiveActionCardSchema,
  'enabled': enabled,
  'disabled_categories': <Object?>[],
};

Map<String, Object?> _card({String status = 'available'}) => {
  'schema_version': proactiveActionCardSchema,
  'suggestion_id': 'ps-11111111111111111111',
  'action_type': 'organize_selected',
  'category': 'organization',
  'title': '整理今日高等数学资料',
  'reason': '这些资料在相近时间出现，并包含相同课程关键词。',
  'request': '预览整理 2 个电脑文件',
  'source': 'hermes',
  'status': status,
  'created_at': '2026-08-06T10:00:00.000Z',
};
