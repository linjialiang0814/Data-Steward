import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/secure_pairing/method_channel_pairing_vault.dart';
import 'package:steward_app/secure_pairing/pairing_crypto.dart';
import 'package:steward_app/secure_pairing/pairing_errors.dart';
import 'package:steward_app/secure_pairing/pairing_vault.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('test/secure_pairing');

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test(
    'method channel vault accepts only exact typed secure results',
    () async {
      final calls = <MethodCall>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls.add(call);
            return switch (call.method) {
              'status' => {'status': 'empty'},
              'createPending' => {
                'pairingAttemptId': '01ARZ3NDEKTSV4RRFFQ69G5FAX',
                'hubId': '01ARZ3NDEKTSV4RRFFQ69G5FAV',
                'baseUrl': 'https://127.0.0.1:9443',
                'certFingerprint': 'a' * 64,
                'pairingSessionId': '01ARZ3NDEKTSV4RRFFQ69G5FAW',
                'requestedCapabilities': ['session.sync'],
                'deviceCredential': encodeBase64UrlNoPadding(
                  List<int>.filled(32, 1),
                ),
                'claimSecret': encodeBase64UrlNoPadding(
                  List<int>.filled(32, 2),
                ),
                'clientNonce': encodeBase64UrlNoPadding(
                  List<int>.filled(16, 3),
                ),
                'deviceId': null,
                'shortCode': null,
              },
              'delete' => {'status': 'empty'},
              _ => throw PlatformException(code: 'secure_storage_state'),
            };
          });
      const vault = MethodChannelPairingVault(channel: channel);
      expect(await vault.status(), PairingVaultStatus.empty);
      expect(
        (await vault.createPending(
          pairingAttemptId: '01ARZ3NDEKTSV4RRFFQ69G5FAX',
          hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
          baseUrl: Uri.parse('https://127.0.0.1:9443'),
          certFingerprint: 'a' * 64,
          pairingSessionId: '01ARZ3NDEKTSV4RRFFQ69G5FAW',
          requestedCapabilities: const ['session.sync'],
        )).clientNonce,
        encodeBase64UrlNoPadding(List<int>.filled(16, 3)),
      );
      await vault.delete();
      expect(calls.map((call) => call.method), [
        'status',
        'createPending',
        'delete',
      ]);
    },
  );

  test(
    'platform errors are sanitized and never expose native message',
    () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            channel,
            (_) async => throw PlatformException(
              code: 'native_unknown',
              message: 'secret=C:/private/value',
            ),
          );
      const vault = MethodChannelPairingVault(channel: channel);
      await expectLater(
        vault.status(),
        throwsA(
          isA<SecurePairingException>()
              .having(
                (value) => value.code,
                'code',
                'secure_storage_unavailable',
              )
              .having(
                (value) => value.toString(),
                'text',
                isNot(contains('private')),
              ),
        ),
      );
    },
  );

  test('active endpoint update returns the same protected identity', () async {
    final secret = encodeBase64UrlNoPadding(List<int>.filled(32, 7));
    final calls = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          return switch (call.method) {
            'updateActiveEndpoint' => {'status': 'active'},
            'loadActive' => {
              'deviceId': '01ARZ3NDEKTSV4RRFFQ69G5FAX',
              'hubId': '01ARZ3NDEKTSV4RRFFQ69G5FAV',
              'baseUrl': 'https://192.168.1.8:9443',
              'certFingerprint': 'a' * 64,
              'deviceCredential': secret,
              'capabilityEpoch': 1,
              'grantedCapabilities': ['session.sync'],
            },
            _ => throw PlatformException(code: 'unexpected'),
          };
        });
    const vault = MethodChannelPairingVault(channel: channel);

    final active = await vault.updateActiveEndpoint(
      hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      baseUrl: Uri.parse('https://192.168.1.8:9443'),
      certFingerprint: 'a' * 64,
    );

    expect(active.baseUrl.host, '192.168.1.8');
    expect(calls.map((value) => value.method), [
      'updateActiveEndpoint',
      'loadActive',
    ]);
  });

  test('authorization refresh atomically advances epoch and grants', () async {
    final secret = encodeBase64UrlNoPadding(List<int>.filled(32, 7));
    final calls = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          return switch (call.method) {
            'updateActiveAuthorization' => {'status': 'active'},
            'loadActive' => {
              'deviceId': '01ARZ3NDEKTSV4RRFFQ69G5FAX',
              'hubId': '01ARZ3NDEKTSV4RRFFQ69G5FAV',
              'baseUrl': 'https://192.168.1.8:9443',
              'certFingerprint': 'a' * 64,
              'deviceCredential': secret,
              'capabilityEpoch': 2,
              'grantedCapabilities': ['session.sync'],
            },
            _ => throw PlatformException(code: 'unexpected'),
          };
        });
    const vault = MethodChannelPairingVault(channel: channel);

    final active = await vault.updateActiveAuthorization(
      deviceId: '01ARZ3NDEKTSV4RRFFQ69G5FAX',
      hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      capabilityEpoch: 2,
      grantedCapabilities: const ['session.sync'],
    );

    expect(active.capabilityEpoch, 2);
    expect(active.grantedCapabilities, ['session.sync']);
    expect(calls.first.arguments, {
      'deviceId': '01ARZ3NDEKTSV4RRFFQ69G5FAX',
      'hubId': '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      'capabilityEpoch': 2,
      'grantedCapabilities': ['session.sync'],
    });
  });

  test(
    'discovered endpoint and authorization are committed together',
    () async {
      final secret = encodeBase64UrlNoPadding(List<int>.filled(32, 7));
      final calls = <MethodCall>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls.add(call);
            return switch (call.method) {
              'updateActiveEndpointAndAuthorization' => {'status': 'active'},
              'loadActive' => {
                'deviceId': '01ARZ3NDEKTSV4RRFFQ69G5FAX',
                'hubId': '01ARZ3NDEKTSV4RRFFQ69G5FAV',
                'baseUrl': 'https://192.168.1.15:9443',
                'certFingerprint': 'a' * 64,
                'deviceCredential': secret,
                'capabilityEpoch': 2,
                'grantedCapabilities': ['session.sync'],
              },
              _ => throw PlatformException(code: 'unexpected'),
            };
          });
      const vault = MethodChannelPairingVault(channel: channel);

      final active = await vault.updateActiveEndpointAndAuthorization(
        deviceId: '01ARZ3NDEKTSV4RRFFQ69G5FAX',
        hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
        baseUrl: Uri.parse('https://192.168.1.15:9443'),
        certFingerprint: 'a' * 64,
        capabilityEpoch: 2,
        grantedCapabilities: const ['session.sync'],
      );

      expect(active.baseUrl.host, '192.168.1.15');
      expect(active.capabilityEpoch, 2);
      expect(calls.map((value) => value.method), [
        'updateActiveEndpointAndAuthorization',
        'loadActive',
      ]);
    },
  );
}
