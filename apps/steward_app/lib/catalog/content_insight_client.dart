import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../secure_pairing/pairing_crypto.dart';
import '../secure_pairing/pinned_transport.dart';
import '../secure_pairing/pairing_vault.dart';
import '../secure_pairing/strict_json.dart';
import '../shared_session/authenticated_transport.dart';
import 'content_insight.dart';

const _maxContentResponseBytes = 96 * 1024;
const contentInsightTransportTimeout = Duration(seconds: 70);
const contentInsightRequestTimeout = Duration(seconds: 75);

final class ContentInsightFailure implements Exception {
  const ContentInsightFailure(this.code);
  final String code;
}

final class ContentInsightClient {
  factory ContentInsightClient.operator({
    required Uri baseUri,
    required String operatorToken,
    http.Client? client,
  }) => ContentInsightClient._(
    baseUri,
    null,
    operatorToken,
    client ?? http.Client(),
  );

  factory ContentInsightClient.device({
    required ActiveDeviceCredential credential,
    http.Client? client,
  }) => ContentInsightClient._(
    credential.baseUrl,
    credential,
    null,
    client ??
        PinnedAuthenticatedHttpClient(
          credential: credential,
          transport: const IoPinFirstTransport(
            timeout: contentInsightTransportTimeout,
            maxResponseBytes: _maxContentResponseBytes,
          ),
        ),
  );

  ContentInsightClient._(
    this._baseUri,
    this._credential,
    this._operatorToken,
    this._client,
  );

  final Uri _baseUri;
  final ActiveDeviceCredential? _credential;
  final String? _operatorToken;
  final http.Client _client;

  Future<ContentPolicy> status() async {
    _requireOperator();
    final response = await _send('GET', '/v1/operator/content/status');
    if (response.statusCode != 200) _throwResponse(response);
    return _policy(response.body);
  }

  Future<ContentPolicy> setOptIn(bool enabled) async {
    _requireOperator();
    final response = await _send(
      'POST',
      '/v1/operator/content/opt-in',
      body: jsonEncode({'enabled': enabled}),
    );
    if (response.statusCode != 200) _throwResponse(response);
    return _policy(response.body);
  }

  Future<StudyPack?> latest() async {
    _requireContentCapability();
    final path = _credential == null
        ? '/v1/operator/content/study-pack'
        : '/v1/content/study-pack';
    final response = await _send('GET', path);
    if (response.statusCode == 404) return null;
    if (response.statusCode != 200) _throwResponse(response);
    return _pack(response.body);
  }

  Future<StudyPack> generate({String request = '请结合今天的资料生成一份重点简报'}) async {
    _requireContentCapability();
    final path = _credential == null
        ? '/v1/operator/content/study-pack'
        : '/v1/content/study-pack';
    final response = await _send(
      'POST',
      path,
      body: jsonEncode({'request': request}),
    );
    if (response.statusCode != 200) _throwResponse(response);
    return _pack(response.body);
  }

  void _requireOperator() {
    if (_operatorToken == null) {
      throw const ContentInsightFailure('operator_required');
    }
  }

  void _requireContentCapability() {
    final credential = _credential;
    if (credential != null &&
        !credential.grantedCapabilities.contains('content.analyze')) {
      throw const ContentInsightFailure('capability_denied');
    }
  }

  ContentPolicy _policy(String source) {
    try {
      return ContentPolicy.fromJson(_object(source));
    } on FormatException {
      throw const ContentInsightFailure('protocol_integrity_error');
    }
  }

  StudyPack _pack(String source) {
    try {
      return StudyPack.fromJson(_object(source));
    } on FormatException {
      throw const ContentInsightFailure('protocol_integrity_error');
    }
  }

  Future<http.Response> _send(
    String method,
    String path, {
    String? body,
  }) async {
    try {
      final request = http.Request(method, _baseUri.replace(path: path))
        ..headers['accept'] = 'application/json';
      final token = _operatorToken;
      if (token != null) {
        request.headers['authorization'] = 'DataSteward-Operator $token';
        request.headers['x-datasteward-protocol'] = pairingProtocolVersion;
      }
      if (body != null) {
        request.headers['content-type'] = 'application/json';
        request.body = body;
      }
      final streamed = await _client
          .send(request)
          .timeout(contentInsightRequestTimeout);
      final contentType = streamed.headers['content-type']?.toLowerCase();
      if (contentType == null || !contentType.startsWith('application/json')) {
        throw const ContentInsightFailure('protocol_integrity_error');
      }
      final bytes = <int>[];
      await for (final chunk in streamed.stream) {
        if (bytes.length + chunk.length > _maxContentResponseBytes) {
          throw const ContentInsightFailure('protocol_integrity_error');
        }
        bytes.addAll(chunk);
      }
      return http.Response.bytes(
        bytes,
        streamed.statusCode,
        headers: streamed.headers,
      );
    } on ContentInsightFailure {
      rethrow;
    } on Object {
      throw const ContentInsightFailure('transient_network');
    }
  }

  Never _throwResponse(http.Response response) {
    final value = _object(response.body);
    final code = value['error_code'];
    final message = value['message_key'];
    if (value.length != 2 ||
        code is! String ||
        message is! String ||
        !{code, 'operator.$code', 'auth.$code'}.contains(message)) {
      throw const ContentInsightFailure('protocol_integrity_error');
    }
    throw ContentInsightFailure(code);
  }

  Map<String, Object?> _object(String source) {
    try {
      return decodeStrictJsonObject(
        source,
        maxUtf8Bytes: _maxContentResponseBytes,
      );
    } on Object {
      throw const ContentInsightFailure('protocol_integrity_error');
    }
  }

  void close() => _client.close();
}
