import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'pairing_crypto.dart';
import 'pairing_errors.dart';
import 'strict_json.dart';

final class PinnedHttpResponse {
  const PinnedHttpResponse({
    required this.statusCode,
    required this.body,
    required this.headers,
  });

  final int statusCode;
  final String body;
  final Map<String, String> headers;
}

abstract interface class PairingHttpTransport {
  Future<PinnedHttpResponse> send({
    required Uri uri,
    required String expectedFingerprint,
    required String method,
    required Map<String, String> headers,
    String? body,
  });
}

final class IoPinFirstTransport implements PairingHttpTransport {
  const IoPinFirstTransport({
    this.timeout = const Duration(seconds: 10),
    this.maxResponseBytes = 65536,
  });

  final Duration timeout;
  final int maxResponseBytes;

  @override
  Future<PinnedHttpResponse> send({
    required Uri uri,
    required String expectedFingerprint,
    required String method,
    required Map<String, String> headers,
    String? body,
  }) async {
    _validateHttpsUri(uri);
    _validateFingerprint(expectedFingerprint);
    if (!const {'GET', 'POST', 'PUT'}.contains(method)) _integrity();
    final context = SecurityContext(withTrustedRoots: false);
    final client = HttpClient(context: context);
    client.findProxy = (_) => 'DIRECT';
    client.connectionTimeout = timeout;
    client.idleTimeout = timeout;
    client.autoUncompress = false;
    var pinVerified = false;
    var pinRejected = false;
    client.badCertificateCallback = (certificate, host, port) {
      final actual = sha256Hex(certificate.der);
      pinVerified = constantTimeEquals(
        utf8.encode(actual),
        utf8.encode(expectedFingerprint),
      );
      pinRejected = !pinVerified;
      return pinVerified;
    };
    try {
      final request = await client.openUrl(method, uri).timeout(timeout);
      request.followRedirects = false;
      request.maxRedirects = 0;
      request.persistentConnection = false;
      for (final entry in headers.entries) {
        _validateHeader(entry.key, entry.value);
        request.headers.set(entry.key, entry.value, preserveHeaderCase: true);
      }
      if (body != null) {
        final encoded = utf8.encode(body);
        if (encoded.length > 16384) {
          throw const SecurePairingException(
            'payload_too_large',
            PairingFailureKind.permanent,
          );
        }
        request.headers.contentType = ContentType.json;
        request.headers.contentLength = encoded.length;
        request.add(encoded);
      }
      final response = await request.close().timeout(timeout);
      if (!pinVerified) _pinFailure();
      if (response.isRedirect ||
          response.headers.value('transfer-encoding') != null) {
        _integrity();
      }
      final contentType = response.headers.contentType;
      if (contentType?.mimeType != 'application/json') _integrity();
      final bytes = <int>[];
      await for (final chunk in response.timeout(timeout)) {
        bytes.addAll(chunk);
        if (bytes.length > maxResponseBytes) {
          throw const SecurePairingException(
            'payload_too_large',
            PairingFailureKind.permanent,
          );
        }
      }
      final text = utf8.decode(bytes, allowMalformed: false);
      final retryAfter = response.headers.value('retry-after');
      final responseHeaders = switch (retryAfter) {
        final String value => <String, String>{'retry-after': value},
        null => <String, String>{},
      };
      return PinnedHttpResponse(
        statusCode: response.statusCode,
        body: text,
        headers: responseHeaders,
      );
    } on SecurePairingException {
      rethrow;
    } on Object {
      if (pinRejected) _pinFailure();
      throw const SecurePairingException(
        'transient_network',
        PairingFailureKind.transient,
      );
    } finally {
      client.close(force: true);
    }
  }
}

final class AuthenticatedPinnedWebSocket {
  AuthenticatedPinnedWebSocket._(
    this._socket,
    this.capabilityEpoch,
    this._frames,
    this._subscription,
    this._client,
  );

  final WebSocket _socket;
  final int capabilityEpoch;
  final StreamController<Object?> _frames;
  final StreamSubscription<Object?> _subscription;
  final HttpClient _client;
  bool _closed = false;

  Stream<Object?> get frames => _frames.stream;
  int? get closeCode => _socket.closeCode;

  static Future<AuthenticatedPinnedWebSocket> connect({
    required Uri uri,
    required String expectedFingerprint,
    required String deviceId,
    required String credential,
    required int capabilityEpoch,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    _validateWssUri(uri);
    _validateFingerprint(expectedFingerprint);
    requireCredential(credential);
    if (!RegExp(r'^[0-7][0-9A-HJKMNP-TV-Z]{25}$').hasMatch(deviceId)) {
      _integrity();
    }
    if (capabilityEpoch < 1) _integrity();
    final context = SecurityContext(withTrustedRoots: false);
    final client = HttpClient(context: context);
    client.findProxy = (_) => 'DIRECT';
    client.connectionTimeout = timeout;
    client.idleTimeout = timeout;
    var pinVerified = false;
    var pinRejected = false;
    client.badCertificateCallback = (certificate, host, port) {
      final actual = sha256Hex(certificate.der);
      pinVerified = constantTimeEquals(
        utf8.encode(actual),
        utf8.encode(expectedFingerprint),
      );
      pinRejected = !pinVerified;
      return pinVerified;
    };
    WebSocket? socket;
    StreamController<Object?>? forwarded;
    StreamSubscription<Object?>? subscription;
    try {
      socket = await WebSocket.connect(
        uri.toString(),
        headers: const <String, dynamic>{},
        compression: CompressionOptions.compressionOff,
        customClient: client,
      ).timeout(timeout);
      if (!pinVerified) _pinFailure();
      final firstFrame = Completer<Object?>();
      final frameController = StreamController<Object?>();
      forwarded = frameController;
      subscription = socket.listen(
        (frame) {
          if (!firstFrame.isCompleted) {
            firstFrame.complete(frame);
          } else if (!frameController.isClosed) {
            frameController.add(frame);
          }
        },
        onError: (Object error) {
          if (!firstFrame.isCompleted) {
            firstFrame.completeError(error);
          } else if (!frameController.isClosed) {
            frameController.addError(
              const SecurePairingException(
                'transient_network',
                PairingFailureKind.transient,
              ),
            );
          }
        },
        onDone: () {
          if (!firstFrame.isCompleted) {
            firstFrame.completeError(
              const SecurePairingException(
                'transient_network',
                PairingFailureKind.transient,
              ),
            );
          }
          unawaited(frameController.close());
        },
      );
      socket.add(
        jsonEncode({
          'kind': 'auth',
          'protocol_version': pairingProtocolVersion,
          'device_id': deviceId,
          'capability_epoch': capabilityEpoch,
          'credential': credential,
        }),
      );
      final first = await firstFrame.future.timeout(timeout);
      if (first is! String) _integrity();
      final decoded = decodeStrictJsonObject(first, maxUtf8Bytes: 4096);
      if (decoded['kind'] == 'auth_failed') {
        requireExactKeys(decoded, const {'kind', 'error_code', 'message_key'});
        final code = decoded['error_code'];
        if (code is! String || decoded['message_key'] != 'auth.$code') {
          _integrity();
        }
        throw classifyPairingError(code);
      }
      requireExactKeys(decoded, const {
        'kind',
        'protocol_version',
        'capability_epoch',
      });
      if (decoded['kind'] != 'auth_ok' ||
          decoded['protocol_version'] != pairingProtocolVersion ||
          decoded['capability_epoch'] != capabilityEpoch) {
        _integrity();
      }
      return AuthenticatedPinnedWebSocket._(
        socket,
        capabilityEpoch,
        forwarded,
        subscription,
        client,
      );
    } on SecurePairingException {
      await subscription?.cancel();
      await socket?.close(1008, 'client rejected');
      if (forwarded != null && !forwarded.isClosed) await forwarded.close();
      client.close(force: true);
      rethrow;
    } on Object {
      await subscription?.cancel();
      await socket?.close();
      if (forwarded != null && !forwarded.isClosed) await forwarded.close();
      client.close(force: true);
      if (pinRejected) _pinFailure();
      throw const SecurePairingException(
        'transient_network',
        PairingFailureKind.transient,
      );
    }
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _subscription.cancel();
    await _socket.close(1000, 'client closed');
    await _frames.close();
    _client.close(force: true);
  }
}

Map<String, String> deviceAuthorizationHeaders(
  ActiveCredentialView credential,
) => {
  'Authorization': 'Bearer ${credential.deviceCredential}',
  'X-DataSteward-Protocol': pairingProtocolVersion,
  'X-DataSteward-Device-Id': credential.deviceId,
  'X-DataSteward-Capability-Epoch': '${credential.capabilityEpoch}',
};

final class ActiveCredentialView {
  const ActiveCredentialView({
    required this.deviceId,
    required this.deviceCredential,
    required this.capabilityEpoch,
  });

  final String deviceId;
  final String deviceCredential;
  final int capabilityEpoch;
}

void requireCredential(String value) => decodeBase64UrlExact(value, 32);

void _validateHttpsUri(Uri uri) {
  if (uri.scheme != 'https' ||
      !uri.hasAuthority ||
      uri.host.isEmpty ||
      uri.host == '0.0.0.0' ||
      uri.userInfo.isNotEmpty ||
      uri.fragment.isNotEmpty) {
    _integrity();
  }
  const forbiddenQueryKeys = {
    'pairing_token',
    'claim_secret',
    'credential',
    'authorization',
  };
  if (uri.queryParametersAll.keys.any(forbiddenQueryKeys.contains)) {
    _integrity();
  }
}

void _validateWssUri(Uri uri) {
  if (uri.scheme != 'wss' ||
      !uri.hasAuthority ||
      uri.host.isEmpty ||
      uri.host == '0.0.0.0' ||
      uri.userInfo.isNotEmpty ||
      uri.fragment.isNotEmpty) {
    _integrity();
  }
  final afterValues = uri.queryParametersAll['after_seq'];
  if (uri.queryParametersAll.length != 1 ||
      afterValues == null ||
      afterValues.length != 1 ||
      !RegExp(r'^(?:0|[1-9][0-9]*)$').hasMatch(afterValues.single)) {
    _integrity();
  }
}

void _validateFingerprint(String value) {
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(value)) _integrity();
}

void _validateHeader(String name, String value) {
  if (!RegExp(r'^[A-Za-z0-9-]+$').hasMatch(name) ||
      value.contains(RegExp(r'[\r\n]'))) {
    _integrity();
  }
}

Never _pinFailure() => throw const SecurePairingException(
  'tls_pin_mismatch',
  PairingFailureKind.permanent,
);

Never _integrity() => throw const SecurePairingException(
  'protocol_integrity_error',
  PairingFailureKind.integrity,
);
