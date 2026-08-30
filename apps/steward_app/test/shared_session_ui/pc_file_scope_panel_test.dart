import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:steward_app/shared_session_ui/pc_file_scope_panel.dart';

const _operatorToken = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

void main() {
  test(
    'scope client stays loopback and sends path only to operator API',
    () async {
      late http.Request captured;
      final client = PcFileScopeClient(
        baseUri: Uri.parse('http://127.0.0.1:8123'),
        operatorToken: _operatorToken,
        client: MockClient((request) async {
          captured = request;
          return http.Response(
            jsonEncode(_scopeJson()),
            200,
            headers: {'content-type': 'application/json'},
          );
        }),
      );

      final scope = await client.authorize(r'C:\Demo\DataStewardPcDemo');

      expect(scope.configured, isTrue);
      expect(captured.method, 'PUT');
      expect(
        captured.url.toString(),
        'http://127.0.0.1:8123/v1/operator/file-scope',
      );
      expect(
        captured.headers['authorization'],
        'DataSteward-Operator $_operatorToken',
      );
      expect(jsonDecode(captured.body)['path'], r'C:\Demo\DataStewardPcDemo');
      expect(jsonDecode(captured.body)['remember'], isTrue);
      client.close();
    },
  );

  testWidgets('picker authorization and revoke never render absolute path', (
    tester,
  ) async {
    final api = _FakeScopeApi();
    final controller = PcFileScopeController(
      api: api,
      directoryPicker: () async => r'C:\Private\DataStewardPcDemo',
    );
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: PcFileScopePanel(controller: controller)),
      ),
    );

    await tester.tap(find.byKey(const Key('s2-select-pc-directory')));
    await tester.pumpAndSettle();
    expect(api.authorizeCount, 1);
    expect(find.textContaining('DataStewardPcDemo'), findsOneWidget);
    expect(find.textContaining(r'C:\Private'), findsNothing);
    expect(find.textContaining('启动时安全恢复'), findsOneWidget);

    await tester.tap(find.byKey(const Key('s2-refresh-pc-directory-status')));
    await tester.pumpAndSettle();
    expect(api.statusCount, 1);

    await tester.tap(find.byKey(const Key('s2-revoke-pc-directory')));
    await tester.pumpAndSettle();
    expect(api.revokeCount, 1);
    expect(find.text('尚未授权目录'), findsOneWidget);
    controller.dispose();
  });
}

Map<String, Object?> _scopeJson({bool configured = true}) => {
  'configured': configured,
  'root_id': configured ? 'pc-aabbccddeeff' : null,
  'display_name': configured ? 'DataStewardPcDemo' : null,
  'authorized_at': configured ? '2026-08-02T10:00:00.000Z' : null,
  'remembered': configured,
  'restore_status': configured ? 'active' : 'not_configured',
  'scan_mode': 'direct_children_metadata_only',
};

final class _FakeScopeApi implements PcFileScopeApi {
  PcFileScopeView scope = PcFileScopeView.fromJson(
    jsonEncode(_scopeJson(configured: false)),
  );
  int authorizeCount = 0;
  int revokeCount = 0;
  int statusCount = 0;

  @override
  Future<PcFileScopeView> authorize(String path) async {
    authorizeCount += 1;
    scope = PcFileScopeView.fromJson(jsonEncode(_scopeJson()));
    return scope;
  }

  @override
  Future<PcFileScopeView> revoke() async {
    revokeCount += 1;
    scope = PcFileScopeView.fromJson(jsonEncode(_scopeJson(configured: false)));
    return scope;
  }

  @override
  Future<PcFileScopeView> status() async {
    statusCount += 1;
    return scope;
  }

  @override
  void close() {}
}
