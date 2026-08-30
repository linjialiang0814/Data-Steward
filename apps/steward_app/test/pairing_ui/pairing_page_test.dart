import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/pairing_ui/mobile_pairing_page.dart';
import 'package:steward_app/pairing_ui/pairing_host_page.dart';
import 'package:steward_app/pairing_ui/pairing_operator.dart';
import 'package:steward_app/pairing_ui/supervised_pairing_runtime.dart';
import 'package:steward_app/secure_pairing/pairing_crypto.dart';
import 'package:steward_app/secure_pairing/pinned_transport.dart';

void main() {
  test('C2 environment rejects incomplete and non-private configuration', () {
    expect(SupervisedPairingEnvironment.fromEnvironment(const {}), isNull);
    final base = <String, String>{
      'DATA_STEWARD_C2_SUPERVISED': '1',
      'DATA_STEWARD_C2_PYTHON': 'python.exe',
      'DATA_STEWARD_C2_HUB_ROOT': 'hub',
      'DATA_STEWARD_C2_DATABASE': 'hub.sqlite3',
      'DATA_STEWARD_C2_IDENTITY_ROOT': 'identity',
    };
    expect(
      SupervisedPairingEnvironment.fromEnvironment({
        ...base,
        'DATA_STEWARD_C2_PRIVATE_IPV4': '8.8.8.8',
      }),
      isNull,
    );
    expect(
      SupervisedPairingEnvironment.fromEnvironment({
        ...base,
        'DATA_STEWARD_C2_PRIVATE_IPV4': '192.168.50.25',
      }),
      isNotNull,
    );
  });

  testWidgets(
    'Windows host setup hides operator token and explains dual confirm',
    (tester) async {
      await tester.pumpWidget(const MaterialApp(home: PairingHostPage()));
      expect(find.byKey(const Key('pairing-create')), findsOneWidget);
      final tokenField = tester
          .widgetList<TextField>(find.byType(TextField))
          .last;
      expect(tokenField.obscureText, isTrue);
    },
  );

  testWidgets('Android pairing starts with scanner and safe fallback', (
    tester,
  ) async {
    await tester.pumpWidget(const MaterialApp(home: MobilePairingPage()));
    await tester.pump();
    expect(find.byKey(const Key('pairing-open-scanner')), findsOneWidget);
    expect(find.byType(ExpansionTile), findsOneWidget);
  });

  testWidgets('C2 supervised mode starts runtime without token fields', (
    tester,
  ) async {
    final runtime = _FakeRuntime();
    final controller = PairingHostController(
      client: PairingOperatorClient(http: _C2OperatorTransport()),
    );
    await tester.pumpWidget(
      MaterialApp(
        home: PairingHostPage(controller: controller, runtime: runtime),
      ),
    );
    expect(find.byKey(const Key('pairing-c2-start')), findsOneWidget);
    expect(find.byType(TextField), findsNothing);
    await tester.tap(find.byKey(const Key('pairing-c2-start')));
    await tester.pumpAndSettle();
    expect(runtime.started, isTrue);
    expect(controller.qrPayload, isNotNull);
    expect(controller.qrPayload, isNot(contains(runtime.ready.operatorToken)));
    expect(find.textContaining('不要截图转发'), findsOneWidget);
    controller.dispose();
  });

  testWidgets('shared Hub pairing reuses in-memory connection without fields', (
    tester,
  ) async {
    final controller = PairingHostController(
      client: PairingOperatorClient(http: _C2OperatorTransport()),
    );
    final connection = PairingHostConnection(
      controlUrl: Uri.parse('http://127.0.0.1:41001'),
      advertisedUrl: Uri.parse('https://192.168.50.25:41002'),
      certFingerprint: 'a' * 64,
      operatorToken: encodeBase64UrlNoPadding(List<int>.filled(32, 9)),
    );
    await tester.pumpWidget(
      MaterialApp(
        home: PairingHostPage(
          controller: controller,
          sharedHubConnection: connection,
        ),
      ),
    );

    expect(find.byKey(const Key('pairing-shared-hub-start')), findsOneWidget);
    expect(find.byType(TextField), findsNothing);
    await tester.tap(find.byKey(const Key('pairing-shared-hub-start')));
    await tester.pumpAndSettle();

    expect(controller.qrPayload, isNotNull);
    expect(controller.qrPayload, isNot(contains(connection.operatorToken)));
    controller.dispose();
  });

  test('operator control permits HTTP only on exact IPv4 loopback', () async {
    final controller = PairingHostController(
      client: PairingOperatorClient(http: _C2OperatorTransport()),
    );
    await controller.create(
      controlUrl: 'http://192.168.50.25:41001',
      advertisedUrl: 'https://192.168.50.25:41002',
      fingerprint: 'a' * 64,
      operatorToken: encodeBase64UrlNoPadding(List<int>.filled(32, 9)),
    );
    expect(controller.state, PairingHostState.failed);
    expect(controller.safeErrorCode, 'protocol_integrity_error');
    controller.dispose();
  });

  testWidgets('active host status never renders a returned short code', (
    tester,
  ) async {
    final controller = PairingHostController(
      client: PairingOperatorClient(
        http: _C2OperatorTransport(activeWithUnexpectedCode: true),
      ),
    );
    await controller.create(
      controlUrl: 'https://127.0.0.1:41001',
      advertisedUrl: 'https://192.168.50.25:41002',
      fingerprint: 'a' * 64,
      operatorToken: encodeBase64UrlNoPadding(List<int>.filled(32, 9)),
    );
    await tester.pumpWidget(
      MaterialApp(home: PairingHostPage(controller: controller)),
    );
    expect(controller.status?.isActive, isTrue);
    expect(find.byKey(const Key('pairing-short-code')), findsNothing);
    controller.dispose();
  });
}

final class _FakeRuntime implements PairingRuntime {
  var started = false;
  var stopped = false;

  final ready = SupervisedPairingReady(
    controlUrl: Uri.parse('https://127.0.0.1:41001'),
    pairingUrl: Uri.parse('https://192.168.50.25:41002'),
    hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    certFingerprint: 'a' * 64,
    operatorToken: encodeBase64UrlNoPadding(List<int>.filled(32, 9)),
  );

  @override
  final environment = const SupervisedPairingEnvironment(
    pythonExecutable: 'python.exe',
    hubRoot: 'hub',
    databasePath: 'hub.sqlite3',
    identityRoot: 'identity',
    privateIpv4: '192.168.50.25',
  );

  @override
  bool get running => started && !stopped;

  @override
  Future<SupervisedPairingReady> start() async {
    started = true;
    return ready;
  }

  @override
  Future<void> stop() async => stopped = true;

  @override
  Future<void> close() => stop();
}

final class _C2OperatorTransport implements PairingHttpTransport {
  _C2OperatorTransport({this.activeWithUnexpectedCode = false});

  final bool activeWithUnexpectedCode;
  static const sessionId = '01ARZ3NDEKTSV4RRFFQ69G5FAW';

  @override
  Future<PinnedHttpResponse> send({
    required Uri uri,
    required String expectedFingerprint,
    required String method,
    required Map<String, String> headers,
    String? body,
  }) async {
    if (uri.path == '/v1/operator/pairing/sessions') {
      return _response(201, {
        'protocol_version': pairingProtocolVersion,
        'hub_id': '01ARZ3NDEKTSV4RRFFQ69G5FAV',
        'cert_fingerprint': 'a' * 64,
        'pairing_session_id': sessionId,
        'state': 'PAIRING_ACTIVE',
        'expires_at_server': '2030-01-01T00:05:00Z',
      });
    }
    return _response(200, {
      'protocol_version': pairingProtocolVersion,
      'pairing_session_id': sessionId,
      'hub_id': '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      'state': activeWithUnexpectedCode ? 'ACTIVE_PAIR' : 'PAIRING_ACTIVE',
      'expires_at_server': '2030-01-01T00:05:00Z',
      'terminal_reason': null,
      'pairing_attempt_id': null,
      'device_id': null,
      'short_verification_code': activeWithUnexpectedCode ? '2EJ9Y5EW' : null,
      'requested_capabilities': activeWithUnexpectedCode
          ? <String>['session.sync']
          : <String>[],
      'granted_capabilities': activeWithUnexpectedCode
          ? <String>['session.sync']
          : <String>[],
      'display_name': null,
      'platform': null,
      'client_confirmed': activeWithUnexpectedCode,
      'hub_confirmed': activeWithUnexpectedCode,
      'credential_status': activeWithUnexpectedCode ? 'ACTIVE' : null,
      'capability_epoch': activeWithUnexpectedCode ? 1 : 0,
    });
  }

  PinnedHttpResponse _response(int status, Map<String, Object?> value) =>
      PinnedHttpResponse(
        statusCode: status,
        body: jsonEncode(value),
        headers: const {},
      );
}
