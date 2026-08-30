import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/app_coordinator/steward_app_coordinator.dart';
import 'package:steward_app/secure_pairing/pairing_vault.dart';
import 'package:steward_app/secure_pairing/lan_hub_discovery.dart';
import 'package:steward_app/shared_session/protocol_models.dart';
import 'package:steward_app/shared_session/shared_session_errors.dart';

void main() {
  test(
    'refresh persists the server epoch and grants as the single truth',
    () async {
      final vault = _MemoryVault(_credential());
      final coordinator = StewardAppCoordinator(
        vault: vault,
        authorizationLoader: (_) async => const DeviceAuthorizationSnapshot(
          hubId: _hubId,
          deviceId: _deviceId,
          capabilityEpoch: 2,
          grantedCapabilities: ['session.sync'],
          displayName: 'Huawei Android',
          platform: 'android',
        ),
      );

      await coordinator.initialize();

      expect(coordinator.state, StewardCredentialState.ready);
      expect(coordinator.credential!.capabilityEpoch, 2);
      expect(coordinator.credential!.grantedCapabilities, ['session.sync']);
      expect(vault.authorizationWriteCount, 1);
    },
  );

  test(
    'transient offline is one attempt and preserves the credential',
    () async {
      var calls = 0;
      final coordinator = StewardAppCoordinator(
        vault: _MemoryVault(_credential()),
        authorizationLoader: (_) async {
          calls += 1;
          throw const TransportException();
        },
      );

      await coordinator.initialize();

      expect(calls, 1);
      expect(coordinator.state, StewardCredentialState.offline);
      expect(coordinator.credential!.deviceId, _deviceId);
    },
  );

  test(
    'foreground refresh failure keeps an established session ready',
    () async {
      var fail = false;
      final coordinator = StewardAppCoordinator(
        vault: _MemoryVault(_credential()),
        authorizationLoader: (_) async {
          if (fail) throw const TransportException();
          return const DeviceAuthorizationSnapshot(
            hubId: _hubId,
            deviceId: _deviceId,
            capabilityEpoch: 1,
            grantedCapabilities: ['files.read', 'session.sync'],
            displayName: 'Huawei Android',
            platform: 'android',
          );
        },
      );
      await coordinator.initialize();
      fail = true;

      await coordinator.refreshAuthorization();

      expect(coordinator.state, StewardCredentialState.ready);
      expect(coordinator.authorizationRefreshDeferred, isTrue);
    },
  );

  test(
    'pairing change queues one refresh behind an in-flight refresh',
    () async {
      final first = Completer<DeviceAuthorizationSnapshot>();
      var calls = 0;
      final coordinator = StewardAppCoordinator(
        vault: _MemoryVault(_credential()),
        authorizationLoader: (_) async {
          calls += 1;
          if (calls == 1) return first.future;
          return const DeviceAuthorizationSnapshot(
            hubId: _hubId,
            deviceId: _deviceId,
            capabilityEpoch: 1,
            grantedCapabilities: ['files.read', 'session.sync'],
            displayName: 'Huawei Android',
            platform: 'android',
          );
        },
      );

      final initial = coordinator.initialize();
      await coordinator.refreshAfterPairingChange();
      first.complete(
        const DeviceAuthorizationSnapshot(
          hubId: _hubId,
          deviceId: _deviceId,
          capabilityEpoch: 1,
          grantedCapabilities: ['files.read', 'session.sync'],
          displayName: 'Huawei Android',
          platform: 'android',
        ),
      );
      await initial;
      await Future<void>.delayed(Duration.zero);

      expect(calls, 2);
      expect(coordinator.state, StewardCredentialState.ready);
    },
  );

  test('revocation is terminal and never erased by a failed refresh', () async {
    final coordinator = StewardAppCoordinator(
      vault: _MemoryVault(_credential()),
      authorizationLoader: (_) async =>
          throw const HubApiException(statusCode: 401, code: 'auth_revoked'),
    );

    await coordinator.initialize();

    expect(coordinator.state, StewardCredentialState.revoked);
    expect(coordinator.canUseSharedSession, isFalse);
  });

  test('unpaired state never invokes the network loader', () async {
    var calls = 0;
    final coordinator = StewardAppCoordinator(
      vault: _MemoryVault(null),
      authorizationLoader: (_) async {
        calls += 1;
        throw StateError('must not run');
      },
    );

    await coordinator.initialize();

    expect(calls, 0);
    expect(coordinator.state, StewardCredentialState.unpaired);
  });

  test('stale endpoint is discovered, authenticated, then persisted', () async {
    final vault = _MemoryVault(_credential());
    final discovery = _Discovery(Uri.parse('https://192.168.1.15:9443'));
    var calls = 0;
    final coordinator = StewardAppCoordinator(
      vault: vault,
      endpointDiscovery: discovery,
      endpointStabilityDelay: Duration.zero,
      authorizationLoader: (credential) async {
        calls += 1;
        if (credential.baseUrl.host != '192.168.1.15') {
          throw const TransportException();
        }
        return const DeviceAuthorizationSnapshot(
          hubId: _hubId,
          deviceId: _deviceId,
          capabilityEpoch: 2,
          grantedCapabilities: ['session.sync'],
          displayName: 'Huawei Android',
          platform: 'android',
        );
      },
    );

    await coordinator.initialize();

    expect(calls, 2);
    expect(discovery.calls, 1);
    expect(vault.endpointWriteCount, 1);
    expect(vault.active!.baseUrl.host, '192.168.1.15');
    expect(coordinator.state, StewardCredentialState.ready);
    expect(coordinator.endpointRecoveryState, EndpointRecoveryState.recovered);
  });

  test(
    'candidate is never persisted before pin and device auth succeed',
    () async {
      final vault = _MemoryVault(_credential());
      final discovery = _Discovery(Uri.parse('https://192.168.1.15:9443'));
      final coordinator = StewardAppCoordinator(
        vault: vault,
        endpointDiscovery: discovery,
        endpointStabilityDelay: Duration.zero,
        authorizationLoader: (_) async => throw const TransportException(),
      );

      await coordinator.initialize();

      expect(discovery.calls, 1);
      expect(vault.endpointWriteCount, 0);
      expect(vault.active!.baseUrl.host, '192.168.1.8');
      expect(coordinator.state, StewardCredentialState.offline);
      expect(coordinator.endpointRecoveryState, EndpointRecoveryState.rejected);
    },
  );

  test(
    'automatic discovery is once; manual find is an explicit new attempt',
    () async {
      final discovery = _Discovery.failure();
      final coordinator = StewardAppCoordinator(
        vault: _MemoryVault(_credential()),
        endpointDiscovery: discovery,
        endpointStabilityDelay: Duration.zero,
        authorizationLoader: (_) async => throw const TransportException(),
      );

      await coordinator.initialize();
      await coordinator.refreshAuthorization();
      expect(discovery.calls, 1);

      await coordinator.findPairedHub();
      expect(discovery.calls, 2);
      expect(coordinator.state, StewardCredentialState.offline);
    },
  );

  test(
    'service-code endpoint is authenticated before atomic persistence',
    () async {
      final vault = _MemoryVault(_credential());
      final coordinator = StewardAppCoordinator(
        vault: vault,
        authorizationLoader: (credential) async {
          if (credential.baseUrl.host != '192.168.1.15') {
            throw const TransportException();
          }
          return const DeviceAuthorizationSnapshot(
            hubId: _hubId,
            deviceId: _deviceId,
            capabilityEpoch: 2,
            grantedCapabilities: ['session.sync'],
            displayName: 'Huawei Android',
            platform: 'android',
          );
        },
      );
      await coordinator.initialize();

      await coordinator.updateEndpoint(
        hubId: _hubId,
        baseUrl: Uri.parse('https://192.168.1.15:9443'),
        certFingerprint: 'a' * 64,
      );

      expect(vault.endpointWriteCount, 1);
      expect(vault.active!.baseUrl.host, '192.168.1.15');
      expect(vault.active!.capabilityEpoch, 2);
    },
  );

  test(
    'unreachable service-code endpoint preserves the prior locator',
    () async {
      final vault = _MemoryVault(_credential());
      final coordinator = StewardAppCoordinator(
        vault: vault,
        authorizationLoader: (_) async => throw const TransportException(),
      );

      await expectLater(
        coordinator.updateEndpoint(
          hubId: _hubId,
          baseUrl: Uri.parse('https://192.168.1.15:9443'),
          certFingerprint: 'a' * 64,
        ),
        throwsA(isA<TransportException>()),
      );

      expect(vault.endpointWriteCount, 0);
      expect(vault.active!.baseUrl.host, '192.168.1.8');
      expect(coordinator.endpointRecoveryState, EndpointRecoveryState.rejected);
    },
  );
}

const _hubId = '01ARZ3NDEKTSV4RRFFQ69G5FAV';
const _deviceId = '01ARZ3NDEKTSV4RRFFQ69G5FAX';

ActiveDeviceCredential _credential() => ActiveDeviceCredential(
  deviceId: _deviceId,
  hubId: _hubId,
  baseUrl: Uri.parse('https://192.168.1.8:9443'),
  certFingerprint: 'a' * 64,
  deviceCredential: 'A' * 43,
  capabilityEpoch: 1,
  grantedCapabilities: const ['files.read', 'session.sync'],
);

final class _MemoryVault implements PairingVault {
  _MemoryVault(this.active);

  ActiveDeviceCredential? active;
  int authorizationWriteCount = 0;
  int endpointWriteCount = 0;

  @override
  Future<PairingVaultStatus> status() async =>
      active == null ? PairingVaultStatus.empty : PairingVaultStatus.active;

  @override
  Future<ActiveDeviceCredential> loadActive() async => active!;

  @override
  Future<ActiveDeviceCredential> updateActiveAuthorization({
    required String deviceId,
    required String hubId,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  }) async {
    authorizationWriteCount += 1;
    final current = active!;
    active = ActiveDeviceCredential(
      deviceId: deviceId,
      hubId: hubId,
      baseUrl: current.baseUrl,
      certFingerprint: current.certFingerprint,
      deviceCredential: current.deviceCredential,
      capabilityEpoch: capabilityEpoch,
      grantedCapabilities: grantedCapabilities,
    );
    return active!;
  }

  @override
  Future<ActiveDeviceCredential> updateActiveEndpoint({
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
  }) async {
    endpointWriteCount += 1;
    final current = active!;
    active = ActiveDeviceCredential(
      deviceId: current.deviceId,
      hubId: hubId,
      baseUrl: baseUrl,
      certFingerprint: certFingerprint,
      deviceCredential: current.deviceCredential,
      capabilityEpoch: current.capabilityEpoch,
      grantedCapabilities: current.grantedCapabilities,
    );
    return active!;
  }

  @override
  Future<ActiveDeviceCredential> updateActiveEndpointAndAuthorization({
    required String deviceId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  }) async {
    endpointWriteCount += 1;
    authorizationWriteCount += 1;
    final current = active!;
    active = ActiveDeviceCredential(
      deviceId: deviceId,
      hubId: hubId,
      baseUrl: baseUrl,
      certFingerprint: certFingerprint,
      deviceCredential: current.deviceCredential,
      capabilityEpoch: capabilityEpoch,
      grantedCapabilities: grantedCapabilities,
    );
    return active!;
  }

  @override
  Future<void> delete() async => active = null;

  @override
  Future<void> activate({
    required String deviceId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  }) => throw UnimplementedError();

  @override
  Future<PendingPairingMaterial> createPending({
    required String pairingAttemptId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required String pairingSessionId,
    required List<String> requestedCapabilities,
  }) => throw UnimplementedError();

  @override
  Future<PendingPairingMaterial> loadPending() => throw UnimplementedError();

  @override
  Future<void> saveHello({
    required String deviceId,
    required String shortCode,
  }) => throw UnimplementedError();
}

final class _Discovery implements HubEndpointDiscovery {
  _Discovery(this.value) : error = null;
  _Discovery.failure()
    : value = null,
      error = const EndpointDiscoveryException('discovery_not_found');

  final Uri? value;
  final EndpointDiscoveryException? error;
  int calls = 0;

  @override
  Future<Uri> discover({
    required String hubId,
    required String certFingerprint,
    Duration timeout = const Duration(seconds: 6),
  }) async {
    calls += 1;
    if (error case final failure?) throw failure;
    return value!;
  }

  @override
  Future<void> cancel() async {}
}
