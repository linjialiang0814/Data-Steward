import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/pairing_ui/pairing_operator.dart';
import 'package:steward_app/secure_pairing/pairing_crypto.dart';
import 'package:steward_app/secure_pairing/pinned_transport.dart';

const _hubId = '01ARZ3NDEKTSV4RRFFQ69G5FAV';
const _sessionId = '01ARZ3NDEKTSV4RRFFQ69G5FAW';
const _attemptId = '01ARZ3NDEKTSV4RRFFQ69G5FAX';
const _deviceId = '01ARZ3NDEKTSV4RRFFQ69G5FAY';
const _fingerprint =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
final _operatorToken = encodeBase64UrlNoPadding(List<int>.filled(32, 7));

void main() {
  test('operator flow keeps bearer out of QR and approves a subset', () async {
    final transport = _OperatorTransport();
    final controller = PairingHostController(
      client: PairingOperatorClient(http: transport),
    );
    await controller.create(
      controlUrl: 'https://127.0.0.1:9443',
      advertisedUrl: 'https://192.168.1.8:9443',
      fingerprint: _fingerprint,
      operatorToken: _operatorToken,
    );
    expect(controller.state, PairingHostState.waitingForPhone);
    final qr = controller.qrPayload!;
    expect(qr, isNot(contains(_operatorToken)));
    expect(qr, contains('192.168.1.8'));
    expect(
      transport.requests
          .singleWhere((value) => value.path.endsWith('sessions'))
          .authorization,
      'DataSteward-Operator $_operatorToken',
    );

    await controller.refresh();
    expect(controller.state, PairingHostState.awaitingApproval);
    expect(controller.qrPayload, isNull);
    expect(controller.status!.shortCode, '2EJ9Y5EW');
    expect(controller.selectedGrants, {'files.read', 'session.sync'});

    controller.toggleGrant('files.read', false);
    await controller.confirm();
    expect(transport.confirmedGrants, ['session.sync']);
    expect(controller.status!.hubConfirmed, isTrue);
    controller.dispose();
  });

  test('operator response with grants outside request fails closed', () {
    expect(
      () => PairingOperatorStatus.fromJson(
        _statusJson(
          requested: const ['session.sync'],
          granted: const ['files.write'],
        ),
      ),
      throwsA(isA<Object>()),
    );
  });
}

final class _RequestRecord {
  const _RequestRecord(this.path, this.authorization);

  final String path;
  final String? authorization;
}

final class _OperatorTransport implements PairingHttpTransport {
  final List<_RequestRecord> requests = [];
  List<String>? confirmedGrants;
  var _statusCalls = 0;

  @override
  Future<PinnedHttpResponse> send({
    required Uri uri,
    required String expectedFingerprint,
    required String method,
    required Map<String, String> headers,
    String? body,
  }) async {
    requests.add(_RequestRecord(uri.path, headers['Authorization']));
    if (uri.path == '/v1/operator/pairing/sessions') {
      return _json(
        201,
        jsonEncode({
          'protocol_version': pairingProtocolVersion,
          'hub_id': _hubId,
          'cert_fingerprint': _fingerprint,
          'pairing_session_id': _sessionId,
          'state': 'PAIRING_ACTIVE',
          'expires_at_server': '2030-01-01T00:05:00Z',
        }),
      );
    }
    if (uri.path.endsWith('/confirm')) {
      confirmedGrants =
          (jsonDecode(body!) as Map<String, dynamic>)['granted_capabilities']
              .cast<String>();
      return _json(
        200,
        _statusJson(
          requested: const ['files.read', 'session.sync'],
          granted: confirmedGrants!,
          hubConfirmed: true,
        ),
      );
    }
    _statusCalls++;
    return _json(
      200,
      _statusCalls == 1
          ? _statusJson()
          : _statusJson(requested: const ['files.read', 'session.sync']),
    );
  }

  PinnedHttpResponse _json(int status, String body) =>
      PinnedHttpResponse(statusCode: status, body: body, headers: const {});
}

String _statusJson({
  List<String> requested = const [],
  List<String> granted = const [],
  bool hubConfirmed = false,
}) => jsonEncode({
  'protocol_version': pairingProtocolVersion,
  'pairing_session_id': _sessionId,
  'hub_id': _hubId,
  'state': requested.isEmpty ? 'PAIRING_ACTIVE' : 'AWAITING_CONFIRM',
  'expires_at_server': '2030-01-01T00:05:00Z',
  'terminal_reason': null,
  'pairing_attempt_id': requested.isEmpty ? null : _attemptId,
  'device_id': requested.isEmpty ? null : _deviceId,
  'short_verification_code': requested.isEmpty ? null : '2EJ9Y5EW',
  'requested_capabilities': requested,
  'granted_capabilities': granted,
  'display_name': requested.isEmpty ? null : 'Huawei Android',
  'platform': requested.isEmpty ? null : 'android',
  'client_confirmed': false,
  'hub_confirmed': hubConfirmed,
  'credential_status': requested.isEmpty ? null : 'PENDING',
  'capability_epoch': 0,
});
