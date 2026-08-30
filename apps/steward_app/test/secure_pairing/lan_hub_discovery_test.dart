import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/secure_pairing/lan_hub_discovery.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('test.lan.discovery');

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('strict response returns one private HTTPS endpoint', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          expect(call.method, 'discoverHub');
          expect((call.arguments as Map)['protocolVersion'], '1');
          return {
            'schema_version': 'data-steward.lan-discovery/v1',
            'base_url': 'https://192.168.1.15:9443',
          };
        });
    const discovery = MethodChannelHubEndpointDiscovery(channel: channel);

    final result = await discovery.discover(
      hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      certFingerprint: 'a' * 64,
    );

    expect(result, Uri.parse('https://192.168.1.15:9443'));
  });

  test(
    'public, loopback or structurally expanded response fails closed',
    () async {
      for (final value in [
        {
          'schema_version': 'data-steward.lan-discovery/v1',
          'base_url': 'https://8.8.8.8:9443',
        },
        {
          'schema_version': 'data-steward.lan-discovery/v1',
          'base_url': 'https://127.0.0.1:9443',
        },
        {
          'schema_version': 'data-steward.lan-discovery/v1',
          'base_url': 'https://192.168.1.15:9443',
          'host': 'unexpected',
        },
      ]) {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (_) async => value);
        const discovery = MethodChannelHubEndpointDiscovery(channel: channel);
        await expectLater(
          discovery.discover(
            hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
            certFingerprint: 'a' * 64,
          ),
          throwsA(isA<EndpointDiscoveryException>()),
        );
      }
    },
  );

  test('native errors expose only allow-listed stable codes', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          channel,
          (_) async => throw PlatformException(
            code: 'native_secret_detail',
            message: 'content://private/path',
          ),
        );
    const discovery = MethodChannelHubEndpointDiscovery(channel: channel);

    await expectLater(
      discovery.discover(
        hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
        certFingerprint: 'a' * 64,
      ),
      throwsA(
        isA<EndpointDiscoveryException>().having(
          (error) => error.code,
          'code',
          'discovery_unavailable',
        ),
      ),
    );
  });
}
