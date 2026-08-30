import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:steward_app/app_coordinator/steward_app_coordinator.dart';
import 'package:steward_app/secure_pairing/pairing_vault.dart';
import 'package:steward_app/shared_session/hub_websocket_client.dart';
import 'package:steward_app/shared_session/protocol_models.dart';
import 'package:steward_app/shared_session/session_projection.dart';
import 'package:steward_app/shared_session/shared_session_errors.dart';
import 'package:steward_app/shared_session_ui/mobile_authenticated_session_page.dart';
import 'package:steward_app/shared_session_ui/shared_session_controller.dart';

import '../shared_session/test_helpers.dart';

void main() {
  testWidgets('ready credential starts once after the first frame', (
    tester,
  ) async {
    final coordinator = _readyCoordinator();
    await coordinator.initialize();
    var starts = 0;
    SharedSessionController? published;

    await tester.pumpWidget(
      MaterialApp(
        home: MobileAuthenticatedSessionPage(
          coordinator: coordinator,
          controllerFactory: (_) async {
            starts += 1;
            return _unconfiguredController();
          },
          onControllerChanged: (value) => published = value,
        ),
      ),
    );
    await tester.pump();
    await tester.pump();

    expect(starts, 1);
    expect(published, isNotNull);
    expect(find.text('已恢复安全设备身份'), findsNothing);

    await tester.pumpWidget(const MaterialApp(home: SizedBox()));
    coordinator.dispose();
  });

  testWidgets('failed automatic start offers one explicit recovery action', (
    tester,
  ) async {
    final coordinator = _readyCoordinator();
    await coordinator.initialize();
    var starts = 0;

    await tester.pumpWidget(
      MaterialApp(
        home: MobileAuthenticatedSessionPage(
          coordinator: coordinator,
          controllerFactory: (_) async {
            starts += 1;
            if (starts == 1) throw StateError('fixture start failure');
            return _unconfiguredController();
          },
        ),
      ),
    );
    await tester.pump();
    await tester.pump();

    expect(starts, 1);
    expect(
      find.byKey(const Key('s5-resume-established-session')),
      findsOneWidget,
    );

    await tester.tap(find.byKey(const Key('s5-resume-established-session')));
    await tester.pump();
    await tester.pump();

    expect(starts, 2);
    expect(find.text('已恢复安全设备身份'), findsNothing);

    await tester.pumpWidget(const MaterialApp(home: SizedBox()));
    coordinator.dispose();
  });

  testWidgets('terminal authorization state can return to secure pairing', (
    tester,
  ) async {
    final coordinator = StewardAppCoordinator(
      vault: _MemoryVault(_credential),
      authorizationLoader: (_) async =>
          throw const HubApiException(statusCode: 401, code: 'auth_revoked'),
    );
    await coordinator.initialize();
    var opened = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: MobileAuthenticatedSessionPage(
          coordinator: coordinator,
          onOpenPairing: () => opened += 1,
        ),
      ),
    );
    await tester.pump();
    expect(find.textContaining('设备授权已撤销'), findsOneWidget);
    expect(find.byKey(const Key('s6-open-secure-pairing')), findsOneWidget);
    expect(find.byKey(const Key('s6f-find-paired-computer')), findsNothing);
    expect(find.byKey(const Key('c3-open-scanner')), findsNothing);
    await tester.tap(find.byKey(const Key('s6-open-secure-pairing')));
    expect(opened, 1);
    expect(
      find.byKey(const Key('s4-retry-after-stable-network')),
      findsNothing,
    );
    coordinator.dispose();
  });

  testWidgets('endpoint change replaces the controller exactly once', (
    tester,
  ) async {
    final vault = _MemoryVault(_credential);
    final coordinator = _coordinatorForVault(vault);
    await coordinator.initialize();
    final startedWith = <ActiveDeviceCredential>[];
    final published = <SharedSessionController?>[];

    await tester.pumpWidget(
      MaterialApp(
        home: MobileAuthenticatedSessionPage(
          coordinator: coordinator,
          controllerFactory: (credential) async {
            startedWith.add(credential);
            return _unconfiguredController();
          },
          onControllerChanged: published.add,
        ),
      ),
    );
    await _pumpSessionStart(tester);
    expect(startedWith, hasLength(1));

    vault.active = _copyCredential(
      vault.active,
      baseUrl: Uri.parse('https://192.168.50.21:9443'),
    );
    await coordinator.refreshAfterPairingChange();
    await _pumpSessionStart(tester);

    expect(startedWith, hasLength(2));
    expect(startedWith.last.baseUrl.host, '192.168.50.21');
    expect(published.where((value) => value == null), hasLength(1));

    await coordinator.refreshAuthorization();
    await _pumpSessionStart(tester);
    expect(startedWith, hasLength(2));

    await tester.pumpWidget(const MaterialApp(home: SizedBox()));
    coordinator.dispose();
  });

  testWidgets('epoch and device identity changes each replace once', (
    tester,
  ) async {
    final vault = _MemoryVault(_credential);
    final coordinator = _coordinatorForVault(vault);
    await coordinator.initialize();
    final startedWith = <ActiveDeviceCredential>[];

    await tester.pumpWidget(
      MaterialApp(
        home: MobileAuthenticatedSessionPage(
          coordinator: coordinator,
          controllerFactory: (credential) async {
            startedWith.add(credential);
            return _unconfiguredController();
          },
        ),
      ),
    );
    await _pumpSessionStart(tester);

    vault.active = _copyCredential(vault.active, capabilityEpoch: 2);
    await coordinator.refreshAfterPairingChange();
    await _pumpSessionStart(tester);
    expect(startedWith.map((value) => value.capabilityEpoch), [1, 2]);

    vault.active = ActiveDeviceCredential(
      deviceId: '01ARZ3NDEKTSV4RRFFQ69G5FAY',
      hubId: '01ARZ3NDEKTSV4RRFFQ69G5FAZ',
      baseUrl: vault.active.baseUrl,
      certFingerprint: 'b' * 64,
      deviceCredential: 'B' * 43,
      capabilityEpoch: 1,
      grantedCapabilities: const ['content.analyze', 'session.sync'],
    );
    await coordinator.refreshAfterPairingChange();
    await _pumpSessionStart(tester);

    expect(startedWith, hasLength(3));
    expect(startedWith.last.deviceId, vault.active.deviceId);
    expect(startedWith.last.hubId, vault.active.hubId);

    await coordinator.refreshAuthorization();
    await _pumpSessionStart(tester);
    expect(startedWith, hasLength(3));

    await tester.pumpWidget(const MaterialApp(home: SizedBox()));
    coordinator.dispose();
  });

  testWidgets(
    'credential change during async creation publishes only new controller',
    (tester) async {
      final vault = _MemoryVault(_credential);
      final coordinator = _coordinatorForVault(vault);
      await coordinator.initialize();
      final firstController = Completer<SharedSessionController>();
      final startedWith = <ActiveDeviceCredential>[];
      final published = <SharedSessionController?>[];

      await tester.pumpWidget(
        MaterialApp(
          home: MobileAuthenticatedSessionPage(
            coordinator: coordinator,
            controllerFactory: (credential) {
              startedWith.add(credential);
              if (startedWith.length == 1) return firstController.future;
              return Future.value(_unconfiguredController());
            },
            onControllerChanged: published.add,
          ),
        ),
      );
      await tester.pump();
      await tester.pump();
      expect(startedWith, hasLength(1));

      vault.active = _copyCredential(
        vault.active,
        baseUrl: Uri.parse('https://192.168.50.22:9443'),
      );
      await coordinator.refreshAfterPairingChange();
      firstController.complete(_unconfiguredController());
      await _pumpSessionStart(tester);

      expect(startedWith, hasLength(2));
      expect(startedWith.last.baseUrl.host, '192.168.50.22');
      expect(published.whereType<SharedSessionController>(), hasLength(1));

      await tester.pumpWidget(const MaterialApp(home: SizedBox()));
      coordinator.dispose();
    },
  );

  testWidgets(
    'credential change during async start never publishes stale ready controller',
    (tester) async {
      final vault = _MemoryVault(_credential);
      final authorizationGate = Completer<DeviceAuthorizationSnapshot>();
      var authorizationCalls = 0;
      final coordinator = StewardAppCoordinator(
        vault: vault,
        authorizationLoader: (credential) {
          authorizationCalls += 1;
          if (authorizationCalls == 1) {
            return Future.value(_authorizationFor(credential));
          }
          return authorizationGate.future;
        },
      );
      await coordinator.initialize();
      final healthGate = Completer<void>();
      final controllerCredentials =
          <SharedSessionController, ActiveDeviceCredential>{};
      final publishedCredentials = <ActiveDeviceCredential>[];
      var staleReadyObserved = false;

      await tester.pumpWidget(
        MaterialApp(
          home: MobileAuthenticatedSessionPage(
            coordinator: coordinator,
            controllerFactory: (credential) async {
              final controller = controllerCredentials.isEmpty
                  ? _delayedReadyController(credential, healthGate)
                  : _unconfiguredController();
              if (controllerCredentials.isEmpty) {
                controller.addListener(() {
                  if (controller.state == SharedSessionViewState.ready) {
                    staleReadyObserved = true;
                  }
                });
              }
              controllerCredentials[controller] = credential;
              return controller;
            },
            onControllerChanged: (controller) {
              if (controller != null) {
                publishedCredentials.add(controllerCredentials[controller]!);
              }
            },
          ),
        ),
      );
      await tester.pump();
      await tester.pump();
      expect(controllerCredentials, hasLength(1));

      vault.active = _copyCredential(
        vault.active,
        baseUrl: Uri.parse('https://192.168.50.23:9443'),
      );
      final refresh = coordinator.refreshAfterPairingChange();
      await tester.pump();
      expect(coordinator.credential?.baseUrl.host, '192.168.50.23');

      healthGate.complete();
      for (var index = 0; index < 20 && !staleReadyObserved; index += 1) {
        await tester.pump(const Duration(milliseconds: 1));
      }
      expect(staleReadyObserved, isTrue);
      expect(
        publishedCredentials.where(
          (credential) => credential.baseUrl.host == '192.168.50.20',
        ),
        isEmpty,
      );

      authorizationGate.complete(_authorizationFor(vault.active));
      await refresh;
      await _pumpSessionStart(tester);
      expect(
        publishedCredentials.map((credential) => credential.baseUrl.host),
        everyElement('192.168.50.23'),
      );

      await tester.pumpWidget(const MaterialApp(home: SizedBox()));
      coordinator.dispose();
    },
  );
}

StewardAppCoordinator _readyCoordinator() => StewardAppCoordinator(
  vault: _MemoryVault(_credential),
  authorizationLoader: (_) async => const DeviceAuthorizationSnapshot(
    hubId: _hubId,
    deviceId: _deviceId,
    capabilityEpoch: 1,
    grantedCapabilities: ['content.analyze', 'session.sync'],
    displayName: 'Huawei Android',
    platform: 'android',
  ),
);

StewardAppCoordinator _coordinatorForVault(_MemoryVault vault) =>
    StewardAppCoordinator(
      vault: vault,
      authorizationLoader: (credential) async => _authorizationFor(credential),
    );

DeviceAuthorizationSnapshot _authorizationFor(
  ActiveDeviceCredential credential,
) => DeviceAuthorizationSnapshot(
  hubId: credential.hubId,
  deviceId: credential.deviceId,
  capabilityEpoch: credential.capabilityEpoch,
  grantedCapabilities: credential.grantedCapabilities,
  displayName: 'Huawei Android',
  platform: 'android',
);

Future<void> _pumpSessionStart(WidgetTester tester) async {
  await tester.pump();
  await tester.pump();
  await tester.pump();
}

ActiveDeviceCredential _copyCredential(
  ActiveDeviceCredential source, {
  Uri? baseUrl,
  int? capabilityEpoch,
}) => ActiveDeviceCredential(
  deviceId: source.deviceId,
  hubId: source.hubId,
  baseUrl: baseUrl ?? source.baseUrl,
  certFingerprint: source.certFingerprint,
  deviceCredential: source.deviceCredential,
  capabilityEpoch: capabilityEpoch ?? source.capabilityEpoch,
  grantedCapabilities: source.grantedCapabilities,
);

SharedSessionController _unconfiguredController() => SharedSessionController(
  config: null,
  cursorStore: MemoryCursorStore(),
  transportFactory: (_) => throw StateError('unused transport'),
  socketFactory: (_, _) => throw StateError('unused socket'),
);

SharedSessionController _delayedReadyController(
  ActiveDeviceCredential credential,
  Completer<void> healthGate,
) => SharedSessionController(
  config: DemoHubConfig.authenticated(
    httpBase: credential.baseUrl,
    websocketBase: credential.baseUrl.replace(scheme: 'wss'),
    actorDeviceId: credential.deviceId,
    activeCredential: credential,
  ),
  cursorStore: MemoryCursorStore(),
  transportFactory: (_) => _DelayedHealthTransport(healthGate),
  socketFactory: (_, projection) {
    final socket = FakeHubSocket();
    return HubWebSocketClient(
      baseUri: credential.baseUrl.replace(scheme: 'wss'),
      conversationId: demoConversationId,
      projection: projection,
      authenticatedPrivateLan: true,
      connector: (_) async {
        Timer.run(
          () => socket.add('{"kind":"ready","last_conversation_seq":0}'),
        );
        return socket;
      },
    );
  },
);

final class _DelayedHealthTransport implements SharedSessionTransport {
  _DelayedHealthTransport(this.healthGate);

  final Completer<void> healthGate;

  @override
  Future<HealthStatus> health() async {
    await healthGate.future;
    return const HealthStatus(protocolVersion: 1, databaseReady: true);
  }

  @override
  Future<ConversationCreation> createDemoConversation() async =>
      const ConversationCreation(
        conversationId: demoConversationId,
        alreadyExisted: true,
      );

  @override
  Future<ReplayPage> replay({
    required int afterSeq,
    required int limit,
  }) async => ReplayPage(events: const [], lastConversationSeq: afterSeq);

  @override
  Future<AppendMessageResult> append({
    required String clientMessageId,
    required String content,
  }) => throw UnimplementedError();

  @override
  void close() {}
}

const _hubId = '01ARZ3NDEKTSV4RRFFQ69G5FAV';
const _deviceId = '01ARZ3NDEKTSV4RRFFQ69G5FAX';
final _credential = ActiveDeviceCredential(
  deviceId: _deviceId,
  hubId: _hubId,
  baseUrl: Uri.parse('https://192.168.50.20:9443'),
  certFingerprint: 'a' * 64,
  deviceCredential: 'A' * 43,
  capabilityEpoch: 1,
  grantedCapabilities: const ['content.analyze', 'session.sync'],
);

final class _MemoryVault implements PairingVault {
  _MemoryVault(this.active);

  ActiveDeviceCredential active;

  @override
  Future<PairingVaultStatus> status() async => PairingVaultStatus.active;

  @override
  Future<ActiveDeviceCredential> loadActive() async => active;

  @override
  Future<ActiveDeviceCredential> updateActiveAuthorization({
    required String deviceId,
    required String hubId,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  }) async {
    active = ActiveDeviceCredential(
      deviceId: deviceId,
      hubId: hubId,
      baseUrl: active.baseUrl,
      certFingerprint: active.certFingerprint,
      deviceCredential: active.deviceCredential,
      capabilityEpoch: capabilityEpoch,
      grantedCapabilities: grantedCapabilities,
    );
    return active;
  }

  @override
  Future<ActiveDeviceCredential> updateActiveEndpoint({
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
  }) async => active;

  @override
  Future<ActiveDeviceCredential> updateActiveEndpointAndAuthorization({
    required String deviceId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  }) async {
    active = ActiveDeviceCredential(
      deviceId: deviceId,
      hubId: hubId,
      baseUrl: baseUrl,
      certFingerprint: certFingerprint,
      deviceCredential: active.deviceCredential,
      capabilityEpoch: capabilityEpoch,
      grantedCapabilities: grantedCapabilities,
    );
    return active;
  }

  @override
  Future<void> activate({
    required String deviceId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  }) async => throw UnsupportedError('unused');

  @override
  Future<PendingPairingMaterial> createPending({
    required String pairingAttemptId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required String pairingSessionId,
    required List<String> requestedCapabilities,
  }) async => throw UnsupportedError('unused');

  @override
  Future<void> saveHello({
    required String deviceId,
    required String shortCode,
  }) async => throw UnsupportedError('unused');

  @override
  Future<PendingPairingMaterial> loadPending() async =>
      throw UnsupportedError('unused');

  @override
  Future<void> delete() async => throw UnsupportedError('unused');
}
