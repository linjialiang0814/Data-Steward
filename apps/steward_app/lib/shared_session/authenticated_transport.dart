import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../secure_pairing/pairing_vault.dart';
import '../secure_pairing/pinned_transport.dart';
import 'hub_rest_client.dart';
import 'hub_websocket_client.dart';

final class PinnedAuthenticatedHttpClient extends http.BaseClient {
  PinnedAuthenticatedHttpClient({
    required this.credential,
    this.transport = const IoPinFirstTransport(),
  });

  final ActiveDeviceCredential credential;
  final PairingHttpTransport transport;
  bool _closed = false;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (_closed) throw StateError('client_closed');
    final bodyBytes = await request.finalize().fold<List<int>>(
      <int>[],
      (result, chunk) => result..addAll(chunk),
    );
    final headers = <String, String>{
      ...request.headers,
      ...deviceAuthorizationHeaders(
        ActiveCredentialView(
          deviceId: credential.deviceId,
          deviceCredential: credential.deviceCredential,
          capabilityEpoch: credential.capabilityEpoch,
        ),
      ),
    };
    final response = await transport.send(
      uri: request.url,
      expectedFingerprint: credential.certFingerprint,
      method: request.method,
      headers: headers,
      body: bodyBytes.isEmpty
          ? null
          : utf8.decode(bodyBytes, allowMalformed: false),
    );
    return http.StreamedResponse(
      Stream<List<int>>.value(utf8.encode(response.body)),
      response.statusCode,
      headers: {'content-type': 'application/json', ...response.headers},
      contentLength: utf8.encode(response.body).length,
      request: request,
    );
  }

  @override
  void close() => _closed = true;
}

final class PinnedAuthenticatedHubSocket implements HubSocket {
  PinnedAuthenticatedHubSocket(this._socket);

  final AuthenticatedPinnedWebSocket _socket;

  @override
  int? get closeCode => _socket.closeCode;

  @override
  Stream<Object?> get frames => _socket.frames;

  @override
  Future<void> close([int? code, String? reason]) => _socket.close();
}

HubRestClient createAuthenticatedHubRestClient(
  ActiveDeviceCredential credential,
) => HubRestClient(
  baseUri: credential.baseUrl,
  client: PinnedAuthenticatedHttpClient(credential: credential),
  authenticatedPrivateLan: true,
  expectedTransportScope: 'private_lan_authenticated_service',
);

HubSocketConnector authenticatedHubSocketConnector(
  ActiveDeviceCredential credential,
) =>
    (uri) async => PinnedAuthenticatedHubSocket(
      await AuthenticatedPinnedWebSocket.connect(
        uri: uri,
        expectedFingerprint: credential.certFingerprint,
        deviceId: credential.deviceId,
        credential: credential.deviceCredential,
        capabilityEpoch: credential.capabilityEpoch,
      ),
    );
