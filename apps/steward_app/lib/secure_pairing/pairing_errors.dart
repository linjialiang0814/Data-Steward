enum PairingFailureKind { permanent, transient, integrity, unsupported }

final class SecurePairingException implements Exception {
  const SecurePairingException(this.code, this.kind);

  final String code;
  final PairingFailureKind kind;

  bool get retryable => kind == PairingFailureKind.transient;

  @override
  String toString() => 'SecurePairingException($code)';
}

Never securePairingFailure(String code, PairingFailureKind kind) {
  throw SecurePairingException(code, kind);
}

const permanentPairingErrors = <String>{
  'protocol_version_rejected',
  'pairing_expired',
  'pairing_rejected',
  'pairing_busy',
  'pairing_attempt_conflict',
  'claim_missing',
  'claim_invalid',
  'claim_expired',
  'short_code_mismatch',
  'auth_invalid',
  'auth_revoked',
  'capability_denied',
  'capability_epoch_stale',
  'policy_violation',
  'payload_too_large',
};

const transientPairingErrors = <String>{
  'auth_unavailable',
  'pairing_unavailable',
  'rate_limited',
  'transient_network',
};

SecurePairingException classifyPairingError(String code) {
  if (permanentPairingErrors.contains(code)) {
    return SecurePairingException(code, PairingFailureKind.permanent);
  }
  if (transientPairingErrors.contains(code)) {
    return SecurePairingException(code, PairingFailureKind.transient);
  }
  return const SecurePairingException(
    'protocol_integrity_error',
    PairingFailureKind.integrity,
  );
}
