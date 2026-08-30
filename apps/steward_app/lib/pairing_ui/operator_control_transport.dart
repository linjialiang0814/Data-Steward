import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../secure_pairing/pairing_errors.dart';
import '../secure_pairing/pinned_transport.dart';

final class IoOperatorControlTransport implements PairingHttpTransport {
  const IoOperatorControlTransport({
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
  }) {
    if (uri.scheme == 'https') {
      return IoPinFirstTransport(
        timeout: timeout,
        maxResponseBytes: maxResponseBytes,
      ).send(
        uri: uri,
        expectedFingerprint: expectedFingerprint,
        method: method,
        headers: headers,
        body: body,
      );
    }
    return _sendLoopback(
      uri: uri,
      expectedFingerprint: expectedFingerprint,
      method: method,
      headers: headers,
      body: body,
    );
  }

  Future<PinnedHttpResponse> _sendLoopback({
    required Uri uri,
    required String expectedFingerprint,
    required String method,
    required Map<String, String> headers,
    String? body,
  }) async {
    if (uri.scheme != 'http' ||
        uri.host != '127.0.0.1' ||
        !uri.hasAuthority ||
        uri.userInfo.isNotEmpty ||
        uri.query.isNotEmpty ||
        uri.fragment.isNotEmpty ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(expectedFingerprint) ||
        !const {'GET', 'POST'}.contains(method)) {
      _integrity();
    }
    for (final entry in headers.entries) {
      if (!RegExp(r'^[A-Za-z0-9-]+$').hasMatch(entry.key) ||
          entry.value.contains(RegExp(r'[\r\n]'))) {
        _integrity();
      }
    }

    final client = HttpClient();
    client.findProxy = (_) => 'DIRECT';
    client.connectionTimeout = timeout;
    client.idleTimeout = timeout;
    client.autoUncompress = false;
    try {
      final request = await client.openUrl(method, uri).timeout(timeout);
      request.followRedirects = false;
      request.maxRedirects = 0;
      request.persistentConnection = false;
      for (final entry in headers.entries) {
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
      if (response.isRedirect ||
          response.headers.value('transfer-encoding') != null ||
          response.headers.contentType?.mimeType != 'application/json') {
        _integrity();
      }
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
      return PinnedHttpResponse(
        statusCode: response.statusCode,
        body: utf8.decode(bytes, allowMalformed: false),
        headers: switch (response.headers.value('retry-after')) {
          final String value => {'retry-after': value},
          null => const {},
        },
      );
    } on SecurePairingException {
      rethrow;
    } on Object {
      throw const SecurePairingException(
        'transient_network',
        PairingFailureKind.transient,
      );
    } finally {
      client.close(force: true);
    }
  }
}

Never _integrity() => throw const SecurePairingException(
  'protocol_integrity_error',
  PairingFailureKind.integrity,
);
