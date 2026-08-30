enum PairingVaultStatus { empty, pending, active }

final class PendingPairingMaterial {
  const PendingPairingMaterial({
    required this.pairingAttemptId,
    required this.hubId,
    required this.baseUrl,
    required this.certFingerprint,
    required this.pairingSessionId,
    required this.requestedCapabilities,
    required this.deviceCredential,
    required this.claimSecret,
    required this.clientNonce,
    this.deviceId,
    this.shortCode,
  });

  final String pairingAttemptId;
  final String hubId;
  final Uri baseUrl;
  final String certFingerprint;
  final String pairingSessionId;
  final List<String> requestedCapabilities;
  final String deviceCredential;
  final String claimSecret;
  final String clientNonce;
  final String? deviceId;
  final String? shortCode;
}

final class ActiveDeviceCredential {
  const ActiveDeviceCredential({
    required this.deviceId,
    required this.hubId,
    required this.baseUrl,
    required this.certFingerprint,
    required this.deviceCredential,
    required this.capabilityEpoch,
    required this.grantedCapabilities,
  });

  final String deviceId;
  final String hubId;
  final Uri baseUrl;
  final String certFingerprint;
  final String deviceCredential;
  final int capabilityEpoch;
  final List<String> grantedCapabilities;
}

abstract interface class PairingVault {
  Future<PairingVaultStatus> status();
  Future<PendingPairingMaterial> createPending({
    required String pairingAttemptId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required String pairingSessionId,
    required List<String> requestedCapabilities,
  });
  Future<PendingPairingMaterial> loadPending();
  Future<void> saveHello({required String deviceId, required String shortCode});
  Future<void> activate({
    required String deviceId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  });
  Future<ActiveDeviceCredential> loadActive();
  Future<ActiveDeviceCredential> updateActiveEndpoint({
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
  });
  Future<ActiveDeviceCredential> updateActiveAuthorization({
    required String deviceId,
    required String hubId,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  });
  Future<ActiveDeviceCredential> updateActiveEndpointAndAuthorization({
    required String deviceId,
    required String hubId,
    required Uri baseUrl,
    required String certFingerprint,
    required int capabilityEpoch,
    required List<String> grantedCapabilities,
  });
  Future<void> delete();
}
