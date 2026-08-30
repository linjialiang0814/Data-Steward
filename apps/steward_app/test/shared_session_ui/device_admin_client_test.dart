import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:steward_app/shared_session_ui/device_admin_client.dart';
import 'package:steward_app/shared_session_ui/device_authorization_panel.dart';

const _deviceId = '01ARZ3NDEKTSV4RRFFQ69G5FAX';
const _operatorToken = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

void main() {
  test('operator inventory stays loopback and sends memory bearer', () async {
    late http.Request captured;
    final client = DeviceAdminClient(
      baseUri: Uri.parse('http://127.0.0.1:8123'),
      operatorToken: _operatorToken,
      client: MockClient((request) async {
        captured = request;
        return http.Response(
          jsonEncode({
            'devices': [_deviceJson()],
          }),
          200,
          headers: {'content-type': 'application/json'},
        );
      }),
    );

    final devices = await client.listDevices();

    expect(devices, hasLength(1));
    expect(devices.single.safeIdPrefix, '01AR…');
    expect(captured.url.host, '127.0.0.1');
    expect(
      captured.headers['authorization'],
      'DataSteward-Operator $_operatorToken',
    );
    expect(captured.headers['x-datasteward-protocol'], 'pairing_auth/1');
    client.close();
  });

  testWidgets('downgrade and confirmed revoke are explicit and fail closed', (
    tester,
  ) async {
    final api = _FakeAdminApi();
    final controller = DeviceAuthorizationController(api: api);
    await controller.load();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: DeviceAuthorizationPanel(controller: controller)),
      ),
    );

    expect(find.textContaining('01AR…'), findsOneWidget);
    await tester.tap(find.byKey(const Key('c4-downgrade-capabilities')));
    await tester.pumpAndSettle();
    expect(api.updateCount, 1);
    expect(find.textContaining('设备需重新配对'), findsOneWidget);

    await tester.tap(find.byKey(const Key('c4-revoke-device')));
    await tester.pumpAndSettle();
    expect(find.text('撤销此设备？'), findsOneWidget);
    await tester.tap(find.byKey(const Key('c4-confirm-revoke')));
    await tester.pumpAndSettle();
    expect(api.revokeCount, 1);
    expect(find.textContaining('设备授权已撤销'), findsOneWidget);
    controller.dispose();
  });

  testWidgets('authorization panel refreshes a newly paired active device', (
    tester,
  ) async {
    final api = _FakeAdminApi()
      ..device = ManagedDeviceCredential.fromJson(
        _deviceJson(
          status: 'REVOKED',
          epoch: 2,
          grants: const ['session.sync'],
        ),
      );
    final controller = DeviceAuthorizationController(api: api);
    await controller.load();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: DeviceAuthorizationPanel(controller: controller)),
      ),
    );
    expect(controller.current?.status, 'REVOKED');

    api.device = ManagedDeviceCredential.fromJson(_deviceJson());
    await tester.pump(const Duration(seconds: 3));
    await tester.pump();

    expect(controller.current?.status, 'ACTIVE');
    expect(api.listCount, greaterThanOrEqualTo(2));
    expect(find.byKey(const Key('c4-live-refresh-status')), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
    controller.dispose();
  });
}

Map<String, Object?> _deviceJson({
  String status = 'ACTIVE',
  int epoch = 1,
  List<String> grants = const ['files.read', 'session.sync'],
}) => {
  'device_id': _deviceId,
  'status': status,
  'capability_epoch': epoch,
  'requested_capabilities': ['files.read', 'session.sync'],
  'granted_capabilities': grants,
  'display_name': 'Huawei phone',
  'platform': 'android',
};

final class _FakeAdminApi implements DeviceAdminApi {
  var device = ManagedDeviceCredential.fromJson(_deviceJson());
  int listCount = 0;
  int updateCount = 0;
  int revokeCount = 0;

  @override
  Future<List<ManagedDeviceCredential>> listDevices() async {
    listCount += 1;
    return [device];
  }

  @override
  Future<DeviceAuthorizationTransition> updateCapabilities({
    required String deviceId,
    required int expectedEpoch,
    required List<String> grants,
  }) async {
    updateCount += 1;
    device = ManagedDeviceCredential.fromJson(
      _deviceJson(epoch: 2, grants: const ['session.sync']),
    );
    return const DeviceAuthorizationTransition(
      deviceId: _deviceId,
      status: 'ACTIVE',
      capabilityEpoch: 2,
      grantedCapabilities: ['session.sync'],
      changed: true,
      closedConnectionCount: 1,
    );
  }

  @override
  Future<DeviceAuthorizationTransition> revoke({
    required String deviceId,
    required int expectedEpoch,
  }) async {
    revokeCount += 1;
    device = ManagedDeviceCredential.fromJson(
      _deviceJson(status: 'REVOKED', epoch: 2, grants: const ['session.sync']),
    );
    return const DeviceAuthorizationTransition(
      deviceId: _deviceId,
      status: 'REVOKED',
      capabilityEpoch: 2,
      grantedCapabilities: ['session.sync'],
      changed: true,
      closedConnectionCount: 0,
    );
  }

  @override
  void close() {}
}
