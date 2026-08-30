import 'dart:convert';

import 'pairing_crypto.dart';
import 'pairing_errors.dart';
import 'pairing_models.dart';
import 'pinned_transport.dart';
import 'strict_json.dart';

final class SecurePairingClient {
  const SecurePairingClient({required this.http});

  final PairingHttpTransport http;

  Future<ClientHelloResponse> hello({
    required PairingQrDescriptor qr,
    required String pairingAttemptId,
    required String pairingToken,
    required String claimSecret,
    required String deviceCredentialDigest,
    required String clientNonce,
    required List<String> requestedCapabilities,
    String? displayName,
  }) async {
    final response = await http.send(
      uri: _pairingUri(qr, 'client_hello'),
      expectedFingerprint: qr.certFingerprint,
      method: 'POST',
      headers: const {'X-DataSteward-Protocol': pairingProtocolVersion},
      body: jsonEncode({
        'protocol_version': pairingProtocolVersion,
        'pairing_attempt_id': pairingAttemptId,
        'pairing_token': pairingToken,
        'claim_secret': claimSecret,
        'device_credential_digest': deviceCredentialDigest,
        'client_nonce': clientNonce,
        'requested_capabilities': requestedCapabilities,
        'platform': 'android',
        'display_name': displayName,
      }),
    );
    _throwIfError(response);
    final result = ClientHelloResponse.fromJson(response.body);
    if (result.pairingSessionId != qr.pairingSessionId ||
        result.pairingAttemptId != pairingAttemptId) {
      _integrity();
    }
    return result;
  }

  Future<ClientConfirmResponse> confirm({
    required PairingQrDescriptor qr,
    required String pairingAttemptId,
    required String claimSecret,
    required String shortCode,
  }) async {
    final response = await http.send(
      uri: _pairingUri(qr, 'client_confirm'),
      expectedFingerprint: qr.certFingerprint,
      method: 'POST',
      headers: {
        'Authorization': 'Pairing $claimSecret',
        'X-DataSteward-Protocol': pairingProtocolVersion,
      },
      body: jsonEncode({
        'protocol_version': pairingProtocolVersion,
        'pairing_attempt_id': pairingAttemptId,
        'short_verification_code': shortCode,
      }),
    );
    _throwIfError(response);
    final result = ClientConfirmResponse.fromJson(response.body);
    if (result.pairingAttemptId != pairingAttemptId) _integrity();
    return result;
  }

  Future<PairingStatusResponse> status({
    required PairingQrDescriptor qr,
    required String pairingAttemptId,
    required String claimSecret,
  }) async {
    final response = await http.send(
      uri: _pairingUri(
        qr,
        'status',
      ).replace(queryParameters: {'pairing_attempt_id': pairingAttemptId}),
      expectedFingerprint: qr.certFingerprint,
      method: 'GET',
      headers: {
        'Authorization': 'Pairing $claimSecret',
        'X-DataSteward-Protocol': pairingProtocolVersion,
      },
    );
    _throwIfError(response);
    final result = PairingStatusResponse.fromJson(response.body);
    if (result.pairingSessionId != qr.pairingSessionId ||
        result.pairingAttemptId != pairingAttemptId) {
      _integrity();
    }
    return result;
  }

  Uri _pairingUri(PairingQrDescriptor qr, String action) => qr.baseUrl.replace(
    path:
        '/v1/pairing/sessions/${Uri.encodeComponent(qr.pairingSessionId)}/$action',
    query: null,
    fragment: null,
  );

  void _throwIfError(PinnedHttpResponse response) {
    if (response.statusCode == 200) return;
    final error = decodeStrictJsonObject(response.body, maxUtf8Bytes: 4096);
    requireExactKeys(error, const {'error_code', 'message_key'});
    final code = error['error_code'];
    final message = error['message_key'];
    if (code is! String || message is! String || message != 'pairing.$code') {
      _integrity();
    }
    throw classifyPairingError(code);
  }
}

Never _integrity() => throw const SecurePairingException(
  'protocol_integrity_error',
  PairingFailureKind.integrity,
);
