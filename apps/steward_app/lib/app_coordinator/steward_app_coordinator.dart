import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../secure_pairing/method_channel_pairing_vault.dart';
import '../secure_pairing/lan_hub_discovery.dart';
import '../secure_pairing/pairing_vault.dart';
import '../shared_session/authenticated_transport.dart';
import '../shared_session/protocol_models.dart';
import '../shared_session/shared_session_errors.dart';

enum StewardCredentialState {
  loading,
  unpaired,
  ready,
  offline,
  capabilityDenied,
  revoked,
  invalid,
}

enum EndpointRecoveryState { idle, searching, recovered, notFound, rejected }

typedef DeviceAuthorizationLoader =
    Future<DeviceAuthorizationSnapshot> Function(
      ActiveDeviceCredential credential,
    );

final class StewardAppCoordinator extends ChangeNotifier {
  StewardAppCoordinator({
    PairingVault? vault,
    DeviceAuthorizationLoader? authorizationLoader,
    HubEndpointDiscovery? endpointDiscovery,
    this.endpointStabilityDelay = const Duration(seconds: 3),
  }) : vault = vault ?? const MethodChannelPairingVault(),
       _authorizationLoader =
           authorizationLoader ?? _loadCurrentDeviceAuthorization,
       _endpointDiscovery =
           endpointDiscovery ??
           (Platform.isAndroid
               ? const MethodChannelHubEndpointDiscovery()
               : null);

  final PairingVault vault;
  final DeviceAuthorizationLoader _authorizationLoader;
  final HubEndpointDiscovery? _endpointDiscovery;
  final Duration endpointStabilityDelay;

  StewardCredentialState _state = StewardCredentialState.loading;
  ActiveDeviceCredential? _credential;
  bool _busy = false;
  bool _authorizationRefreshDeferred = false;
  bool _refreshQueued = false;
  bool _disposed = false;
  bool _autoDiscoveryAttempted = false;
  EndpointRecoveryState _endpointRecoveryState = EndpointRecoveryState.idle;
  int _generation = 0;

  StewardCredentialState get state => _state;
  ActiveDeviceCredential? get credential => _credential;
  bool get busy => _busy;
  bool get authorizationRefreshDeferred => _authorizationRefreshDeferred;
  EndpointRecoveryState get endpointRecoveryState => _endpointRecoveryState;
  bool get canUseSharedSession =>
      _state == StewardCredentialState.ready &&
      (_credential?.grantedCapabilities.contains('session.sync') ?? false);
  bool get canRecoverEndpoint =>
      _credential != null &&
      const {
        StewardCredentialState.ready,
        StewardCredentialState.offline,
      }.contains(_state);

  Future<void> initialize() => refreshAuthorization();

  Future<void> findPairedHub() async {
    if (!canRecoverEndpoint) return;
    await _refreshAuthorization(forceDiscovery: true);
  }

  Future<void> refreshAfterPairingChange() async {
    if (_disposed) return;
    if (_busy) {
      _refreshQueued = true;
      return;
    }
    await refreshAuthorization();
  }

  Future<void> refreshAuthorization() => _refreshAuthorization();

  Future<void> _refreshAuthorization({bool forceDiscovery = false}) async {
    if (_busy || _disposed) return;
    final generation = ++_generation;
    final previousState = _state;
    _busy = true;
    if (_credential == null) _setState(StewardCredentialState.loading);
    try {
      if (await vault.status() != PairingVaultStatus.active) {
        _credential = null;
        _setState(StewardCredentialState.unpaired);
        return;
      }
      final cached = await vault.loadActive();
      _credential = cached;
      if (forceDiscovery) _autoDiscoveryAttempted = true;
      final current = forceDiscovery
          ? await _discoverAndVerify(
              cached,
              generation,
              waitForStability: false,
            )
          : await _loadWithOneDiscovery(cached, generation);
      if (generation != _generation || _disposed) return;
      if (current.deviceId != cached.deviceId ||
          current.hubId != cached.hubId) {
        _setState(StewardCredentialState.invalid);
        return;
      }
      final refreshed = await vault.updateActiveAuthorization(
        deviceId: current.deviceId,
        hubId: current.hubId,
        capabilityEpoch: current.capabilityEpoch,
        grantedCapabilities: current.grantedCapabilities,
      );
      if (generation != _generation || _disposed) return;
      _credential = refreshed;
      _autoDiscoveryAttempted = false;
      _authorizationRefreshDeferred = false;
      _setState(
        refreshed.grantedCapabilities.contains('session.sync')
            ? StewardCredentialState.ready
            : StewardCredentialState.capabilityDenied,
      );
    } on HubApiException catch (error) {
      if (generation != _generation || _disposed) return;
      if (_endpointRecoveryState == EndpointRecoveryState.searching) {
        _endpointRecoveryState = EndpointRecoveryState.rejected;
      }
      if (error.code == 'auth_unavailable' &&
          previousState == StewardCredentialState.ready) {
        _authorizationRefreshDeferred = true;
        _setState(StewardCredentialState.ready);
        return;
      }
      _authorizationRefreshDeferred = false;
      _setState(
        error.code == 'auth_revoked'
            ? StewardCredentialState.revoked
            : error.code == 'auth_unavailable'
            ? StewardCredentialState.offline
            : StewardCredentialState.invalid,
      );
    } on TransportException {
      if (generation == _generation && !_disposed) {
        if (_endpointRecoveryState == EndpointRecoveryState.searching) {
          _endpointRecoveryState = EndpointRecoveryState.rejected;
        }
        if (previousState == StewardCredentialState.ready) {
          _authorizationRefreshDeferred = true;
          _setState(StewardCredentialState.ready);
        } else {
          _setState(StewardCredentialState.offline);
        }
      }
    } on EndpointDiscoveryException catch (error) {
      if (generation == _generation && !_disposed) {
        _authorizationRefreshDeferred =
            previousState == StewardCredentialState.ready;
        _endpointRecoveryState =
            const {
              'discovery_ambiguous',
              'discovery_saturated',
              'discovery_busy',
              'discovery_integrity',
              'discovery_identity_mismatch',
            }.contains(error.code)
            ? EndpointRecoveryState.rejected
            : EndpointRecoveryState.notFound;
        _setState(
          previousState == StewardCredentialState.ready
              ? StewardCredentialState.ready
              : StewardCredentialState.offline,
        );
      }
    } on Object {
      if (generation == _generation && !_disposed) {
        _authorizationRefreshDeferred = false;
        _setState(StewardCredentialState.invalid);
      }
    } finally {
      if (generation == _generation && !_disposed) {
        _busy = false;
        notifyListeners();
        if (_refreshQueued) {
          _refreshQueued = false;
          unawaited(refreshAuthorization());
        }
      }
    }
  }

  Future<DeviceAuthorizationSnapshot> _loadWithOneDiscovery(
    ActiveDeviceCredential cached,
    int generation,
  ) async {
    try {
      return await _authorizationLoader(cached);
    } on HubApiException catch (error) {
      if (error.code != 'auth_unavailable' ||
          _endpointDiscovery == null ||
          _autoDiscoveryAttempted) {
        rethrow;
      }
    } on TransportException {
      if (_endpointDiscovery == null || _autoDiscoveryAttempted) rethrow;
    }
    _autoDiscoveryAttempted = true;
    return _discoverAndVerify(cached, generation, waitForStability: true);
  }

  Future<DeviceAuthorizationSnapshot> _discoverAndVerify(
    ActiveDeviceCredential cached,
    int generation, {
    required bool waitForStability,
  }) async {
    final discovery = _endpointDiscovery;
    if (discovery == null) {
      throw const EndpointDiscoveryException('discovery_unavailable');
    }
    _endpointRecoveryState = EndpointRecoveryState.searching;
    notifyListeners();
    if (waitForStability && endpointStabilityDelay > Duration.zero) {
      await Future<void>.delayed(endpointStabilityDelay);
      if (generation != _generation || _disposed) {
        throw const EndpointDiscoveryException('discovery_cancelled');
      }
    }
    final baseUrl = await discovery.discover(
      hubId: cached.hubId,
      certFingerprint: cached.certFingerprint,
    );
    if (generation != _generation || _disposed) {
      throw const EndpointDiscoveryException('discovery_cancelled');
    }
    return _verifyAndPersistEndpoint(cached, baseUrl, generation);
  }

  Future<DeviceAuthorizationSnapshot> _verifyAndPersistEndpoint(
    ActiveDeviceCredential cached,
    Uri baseUrl,
    int generation,
  ) async {
    final candidate = ActiveDeviceCredential(
      deviceId: cached.deviceId,
      hubId: cached.hubId,
      baseUrl: baseUrl,
      certFingerprint: cached.certFingerprint,
      deviceCredential: cached.deviceCredential,
      capabilityEpoch: cached.capabilityEpoch,
      grantedCapabilities: cached.grantedCapabilities,
    );
    final current = await _authorizationLoader(candidate);
    if (generation != _generation || _disposed) {
      throw const EndpointDiscoveryException('discovery_cancelled');
    }
    if (current.deviceId != cached.deviceId || current.hubId != cached.hubId) {
      throw const EndpointDiscoveryException('discovery_identity_mismatch');
    }
    _credential = await vault.updateActiveEndpointAndAuthorization(
      deviceId: current.deviceId,
      hubId: cached.hubId,
      baseUrl: baseUrl,
      certFingerprint: cached.certFingerprint,
      capabilityEpoch: current.capabilityEpoch,
      grantedCapabilities: current.grantedCapabilities,
    );
    _endpointRecoveryState = EndpointRecoveryState.recovered;
    notifyListeners();
    return current;
  }

  Future<void> updateEndpoint({
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
  }) async {
    if (_disposed) return;
    if (_busy) throw StateError('coordinator_busy');
    final generation = ++_generation;
    final previousState = _state;
    _busy = true;
    notifyListeners();
    try {
      final cached = _credential ?? await vault.loadActive();
      if (cached.hubId != hubId || cached.certFingerprint != certFingerprint) {
        throw const FormatException('service_identity_mismatch');
      }
      final current = await _verifyAndPersistEndpoint(
        cached,
        baseUrl,
        generation,
      );
      if (generation != _generation || _disposed) return;
      _autoDiscoveryAttempted = false;
      _authorizationRefreshDeferred = false;
      _setState(
        current.grantedCapabilities.contains('session.sync')
            ? StewardCredentialState.ready
            : StewardCredentialState.capabilityDenied,
      );
    } on Object {
      if (generation == _generation && !_disposed) {
        _endpointRecoveryState = EndpointRecoveryState.rejected;
        _setState(previousState);
      }
      rethrow;
    } finally {
      if (generation == _generation && !_disposed) {
        _busy = false;
        notifyListeners();
      }
    }
  }

  Future<void> forgetCredential() async {
    if (_disposed) return;
    if (_busy) throw StateError('coordinator_busy');
    _generation += 1;
    _busy = true;
    notifyListeners();
    try {
      await vault.delete();
      _credential = null;
      _autoDiscoveryAttempted = false;
      _endpointRecoveryState = EndpointRecoveryState.idle;
      _authorizationRefreshDeferred = false;
      _setState(StewardCredentialState.unpaired);
    } finally {
      if (!_disposed) {
        _busy = false;
        notifyListeners();
      }
    }
  }

  void _setState(StewardCredentialState value) {
    if (_state == value || _disposed) return;
    _state = value;
    notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    _generation += 1;
    unawaited(_endpointDiscovery?.cancel());
    super.dispose();
  }
}

Future<DeviceAuthorizationSnapshot> _loadCurrentDeviceAuthorization(
  ActiveDeviceCredential credential,
) async {
  final client = createAuthenticatedHubRestClient(credential);
  try {
    return await client.deviceSelf();
  } finally {
    client.close();
  }
}
